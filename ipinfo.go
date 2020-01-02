package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/go-resty/resty/v2"
)

type ipinfoResult struct {
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Bogon    bool   `json:"bogon"`
}

func ipinfo(ip net.IP) (ipinfoResult, error) {
	client := resty.New()
	resp, err := client.R().
		SetHeader("Accept", "application/json").
		Get(fmt.Sprintf("https://ipinfo.io/%s", ip.String()))
	if err != nil {
		return ipinfoResult{}, err
	}
	var result ipinfoResult
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return ipinfoResult{}, err
	}
	return result, nil
}
