package main

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type icmpResult struct {
	step []icmpStep
}

type icmpStep struct {
	ttl uint
	rtt time.Duration
	err error
}

var timeRegexp = regexp.MustCompile(`time=(\d+\.\d+)`)
var timeRegexp2 = regexp.MustCompile(`time=(\d+)`)
var ttlRegexp = regexp.MustCompile(`ttl=(\d+)`)
var ttlRegexp2 = regexp.MustCompile(`hlim=(\d+)`)

func pingCmd(n int, interval time.Duration, ip net.IP) (icmpResult, error) {
	var cmdStr string
	var baseOpt []string
	if runtime.GOOS == "linux" {
		if isIPv4(ip) {
			cmdStr = "ping"
			baseOpt = []string{"-W 1", "-c 1"}
		} else {
			cmdStr = "ping6"
			baseOpt = []string{"-i 1", "-c 1"}
		}
	} else if runtime.GOOS == "darwin" {
		if isIPv4(ip) {
			cmdStr = "ping"
			baseOpt = []string{"-W 1000", "-c 1"}
		} else {
			cmdStr = "ping6"
			baseOpt = []string{"-i 1", "-c 1"}
		}
	} else {
		return icmpResult{}, fmt.Errorf("Unsupported os")
	}

	result := icmpResult{
		step: make([]icmpStep, n),
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(cmdStr, append(baseOpt, ip.String())...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				if len(stderr.Bytes()) == 0 {
					result.step[i] = icmpStep{err: err}
					return
				}
				result.step[i] = icmpStep{
					err: fmt.Errorf("%s", stderr.Bytes()),
				}
				return
			}
			cmdResultStr := string(stdout.Bytes())
			var rttm, ttlm []string
			rttm = timeRegexp.FindStringSubmatch(cmdResultStr)
			if len(rttm) == 0 {
				rttm = timeRegexp2.FindStringSubmatch(cmdResultStr)
			}
			ttlm = ttlRegexp.FindStringSubmatch(cmdResultStr)
			if len(ttlm) == 0 {
				ttlm = ttlRegexp2.FindStringSubmatch(cmdResultStr)
			}
			if len(rttm) == 0 {
				result.step[i] = icmpStep{
					err: fmt.Errorf("%s", stderr.Bytes()),
				}
				return
			}
			rtt, err := strconv.ParseFloat(rttm[1], 64)
			if err != nil {
				result.step[i] = icmpStep{err: err}
				return
			}
			ttl, err := strconv.ParseUint(ttlm[1], 10, 64)
			if err != nil {
				result.step[i] = icmpStep{err: err}
				return
			}
			result.step[i] = icmpStep{
				rtt: time.Duration(rtt*1000) * time.Millisecond,
				ttl: uint(ttl),
			}
		}(i)
		time.Sleep(interval)
	}
	wg.Wait()
	return result, nil
}
