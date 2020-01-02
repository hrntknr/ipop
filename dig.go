package main

import (
	"fmt"
	"net"

	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
)

type digResult []net.IP

func dig(target string, server string) (digResult, error) {
	var dig dnsutil.Dig
	dig.SetDNS(server)

	a, err := dig.A(target)
	if err != nil {
		return digResult{}, err
	}
	aaaa, err := dig.AAAA(target)
	if err != nil {
		return digResult{}, err
	}
	result := digResult{}
	for _, a := range a {
		result = append(result, a.A)
	}
	for _, aaaa := range aaaa {
		result = append(result, aaaa.AAAA)
	}
	return result, nil
}

func digsoa(target string, server string) (string, error) {
	var dig dnsutil.Dig
	dig.SetDNS(server)
	soa, err := dig.GetMsg(dns.TypeSOA, target)
	if err != nil {
		return "", err
	}
	ns := ""
	for _, rr := range soa.Answer {
		switch soa := rr.(type) {
		case *dns.SOA:
			ns = soa.Ns
		}
	}
	if ns == "" {
		return "", fmt.Errorf("not found")
	}
	return ns, nil
}

func digptr(ip net.IP, server string) ([]string, error) {
	var dig dnsutil.Dig
	dig.SetDNS(server)
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return []string{}, err
	}
	ptr, err := dig.PTR(arpa)
	if err != nil {
		return []string{}, err
	}
	if len(ptr) == 0 {
		return []string{}, fmt.Errorf("ptr record not found")
	}
	result := []string{}
	for _, ptr := range ptr {
		result = append(result, ptr.Ptr)
	}
	return result, nil
}
