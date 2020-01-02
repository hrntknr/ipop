package main

import (
	"context"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net"
	"net/http"

	_shodan "github.com/ns3777k/go-shodan/v4/shodan"
)

type shodanResult struct {
	Link     string
	Services []shodanPort
}
type shodanPort struct {
	ID       uint16
	Protocol string
	SSL      []string
}

func shodan(ip net.IP, currentConfig config) (shodanResult, error) {
	client := _shodan.NewClient(http.DefaultClient, currentConfig.Shodan.Token)
	host, err := client.GetServicesForHost(context.Background(), ip.String(), &_shodan.HostServicesOptions{})
	if err != nil {
		return shodanResult{}, err
	}
	services := []shodanPort{}
	for _, data := range host.Data {
		service := shodanPort{
			ID:       uint16(data.Port),
			Protocol: data.Transport,
		}
		if data.SSL != nil {
			service.SSL = data.SSL.Versions
		}
		services = append(services, service)
	}
	link := fmt.Sprintf("https://www.shodan.io/host/%s", ip.String())
	rclient := resty.New()
	if _, err := rclient.R().Get(link); err != nil {
		link = ""
	}
	return shodanResult{
		Link:     link,
		Services: services,
	}, nil
}
