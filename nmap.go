package main

import (
	"net"

	_nmap "github.com/Ullaakut/nmap"
)

type nmapResult struct {
	Warning []string
	Ports   []nmapPort
}
type nmapPort struct {
	ID       uint16
	Protocol string
	State    string
	Service  string
}

func nmap(ip net.IP) (nmapResult, error) {
	var scanner *_nmap.Scanner
	var err error
	if isIPv4(ip) {
		scanner, err = _nmap.NewScanner(
			_nmap.WithTargets(ip.String()),
			_nmap.WithSkipHostDiscovery(),
		)
	} else {
		scanner, err = _nmap.NewScanner(
			_nmap.WithTargets(ip.String()),
			_nmap.WithSkipHostDiscovery(),
			_nmap.WithIPv6Scanning(),
		)
	}
	if err != nil {
		return nmapResult{}, err
	}
	scanResult, warning, err := scanner.Run()
	if err != nil {
		return nmapResult{}, err
	}
	result := nmapResult{}
	result.Warning = warning

	for _, host := range scanResult.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		if host.Addresses[0].String() == ip.String() {
			ports := []nmapPort{}
			for _, port := range host.Ports {
				ports = append(ports, nmapPort{
					ID:       port.ID,
					Protocol: port.Protocol,
					State:    port.State.String(),
					Service:  port.Service.Name,
				})
			}
			result.Ports = ports
		}
	}
	return result, nil
}
