package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nlopes/slack"
	"gopkg.in/yaml.v2"
)

var configPath = flag.String("c", "./config.yml", "path of configuration file")

var linkRegexp = regexp.MustCompile(`\<(.*)\|(.*)\>`)

type config struct {
	Slack  slackConfig  `yaml:"slack"`
	DNS    dnsConfig    `yaml:"dns"`
	Shodan shodanConfig `yaml:"shodan"`
}
type slackConfig struct {
	Token string `yaml:"token"`
}
type dnsConfig struct {
	Server string `yaml:"server"`
}
type shodanConfig struct {
	Token string `yaml:"token"`
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	buf, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var currentConfig config
	if err := yaml.Unmarshal(buf, &currentConfig); err != nil {
		log.Fatal(err)
	}
	api := slack.New(currentConfig.Slack.Token)
	rtm := api.NewRTM()
	go rtm.ManageConnection()

	for msg := range rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.MessageEvent:
			cmds := strings.Split(ev.Text, " ")
			user, err := api.GetUserInfo(ev.User)
			if err != nil {
				continue
			}
			if !user.IsBot && len(cmds) == 1 && cmds[0] != "" {
				api.SendMessage(
					ev.Channel,
					slack.MsgOptionAttachments(
						slack.Attachment{
							Color: "#2eb886",
							Title: fmt.Sprintf("Analyzing %s...", cmds[0]),
						},
					),
					slack.MsgOptionAsUser(true),
				)
				result, err := handleCmd(cmds[0], currentConfig)
				if err != nil {
					continue
				}
				for _, attachment := range result {
					api.SendMessage(
						ev.Channel,
						slack.MsgOptionAttachments(attachment),
						slack.MsgOptionAsUser(true),
					)
				}
			}
		case *slack.RTMError:
			log.Println(ev)
		case *slack.InvalidAuthEvent:
			log.Println("Invalid credentials")
		}
	}
}

func handleCmd(target string, currentConfig config) ([]slack.Attachment, error) {
	match := linkRegexp.FindStringSubmatch(target)
	fmt.Print()
	if len(match) >= 3 {
		target = match[2]
	}
	targetType := "dns"
	var ip net.IP
	ip = net.ParseIP(target)
	if ip != nil {
		targetType = "ip"
	}
	cidr, _, err := net.ParseCIDR(target)
	if err == nil {
		targetType = "ip"
		ip = cidr
	}
	results := []slack.Attachment{}
	switch targetType {
	case "dns":
		result := slack.Attachment{
			Color:     "#2eb886",
			Title:     target,
			TitleLink: fmt.Sprintf("https://%s", target),
			Fields:    []slack.AttachmentField{},
		}
		attachment, ips := handleDNS(target, currentConfig)
		result.Fields = append(result.Fields, attachment...)
		results = append(results, result)
		for _, ip := range ips {
			result := slack.Attachment{
				Color:  "#c7bc43",
				Title:  ip.String(),
				Fields: handleIP(ip, currentConfig),
			}
			results = append(results, result)
		}
		break
	case "ip":
		result := slack.Attachment{
			Color:  "#2eb886",
			Title:  ip.String(),
			Fields: handleIP(ip, currentConfig),
		}
		results = append(results, result)
	}
	return results, nil
}

func handleDNS(target string, currentConfig config) ([]slack.AttachmentField, []net.IP) {
	ips := []net.IP{}
	var wg sync.WaitGroup
	result := make([]slack.AttachmentField, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		ips, err = dig(target, currentConfig.DNS.Server)
		if err == nil {
			value := ""
			for _, ip := range ips {
				value += ip.String() + "\n"
			}
			result[0] = slack.AttachmentField{
				Title: "dig",
				Value: value,
				Short: true,
			}
		} else {
			result[0] = slack.AttachmentField{
				Title: "dig",
				Value: err.Error(),
				Short: true,
			}
		}
	}()
	wg.Wait()
	return result, ips
}

func handleIP(ip net.IP, currentConfig config) []slack.AttachmentField {
	var wg sync.WaitGroup
	result := make([]slack.AttachmentField, 5)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pingResult, err := pingCmd(10, 100*time.Millisecond, ip)
		if err == nil {
			success := 0
			for _, step := range pingResult.step {
				if step.err == nil {
					success = success + 1
				}
			}
			result[0] = slack.AttachmentField{
				Title: "ping",
				Value: fmt.Sprintf("%d/%d success.", 10, success),
				Short: true,
			}
		} else {
			result[0] = slack.AttachmentField{
				Title: "ping",
				Value: err.Error(),
				Short: true,
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ptr, err := digptr(ip, currentConfig.DNS.Server)
		if err == nil {
			result[1] = slack.AttachmentField{
				Title: "ptr",
				Value: strings.Join(ptr, "\n"),
				Short: true,
			}
		} else {
			result[1] = slack.AttachmentField{
				Title: "ptr",
				Value: err.Error(),
				Short: true,
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ipinfoResult, err := ipinfo(ip)
		if err == nil {
			result[2] = slack.AttachmentField{
				Title: "ipinfo",
				Value: fmt.Sprintf(
					"city: %s, region: %s\norg: %s",
					ipinfoResult.City,
					ipinfoResult.Region,
					ipinfoResult.Org,
				),
				Short: false,
			}
		} else {
			result[2] = slack.AttachmentField{
				Title: "ipinfo",
				Value: err.Error(),
				Short: false,
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		nmapResult, err := nmap(ip)
		if err == nil {
			value := []string{}
			for _, warning := range nmapResult.Warning {
				value = append(value, warning)
			}
			for _, port := range nmapResult.Ports {
				value = append(value, fmt.Sprintf("%d/%s %s %s", port.ID, port.Protocol, port.State, port.Service))
			}
			result[3] = slack.AttachmentField{
				Title: "nmap",
				Value: strings.Join(value, "\n"),
				Short: true,
			}
		} else {
			result[3] = slack.AttachmentField{
				Title: "nmap",
				Value: err.Error(),
				Short: true,
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		shodanResult, err := shodan(ip, currentConfig)
		if err == nil {
			value := []string{}
			for _, service := range shodanResult.Services {
				value = append(value, fmt.Sprintf("%d/%s", service.ID, service.Protocol))
			}
			if shodanResult.Link != "" {
				value = append(value, fmt.Sprintf("<%s|Shodan Host Page>", shodanResult.Link))
			}
			result[4] = slack.AttachmentField{
				Title: "shodan",
				Value: strings.Join(value, "\n"),
				Short: true,
			}
		} else {
			result[4] = slack.AttachmentField{
				Title: "shodan",
				Value: err.Error(),
				Short: true,
			}
		}
	}()
	wg.Wait()
	return result
}
