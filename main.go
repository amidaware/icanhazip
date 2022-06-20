package main

// env CGO_ENABLED=0 go build -ldflags "-s -w"

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
)

const version = "1.1.0"

func main() {
	ver := flag.Bool("version", false, "Prints version")
	flag.Parse()

	if *ver {
		fmt.Println(version)
		bi, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println(bi.String())
		}
		return
	}

	http.HandleFunc("/", getIPAdress)
	http.ListenAndServe(":8091", nil)
}

// https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html

//ipRange - a structure that holds the start and end of a range of ip addresses
type ipRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	if bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0 {
		return true
	}
	return false
}

var privateRanges = []ipRange{
	ipRange{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	ipRange{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	ipRange{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	ipRange{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	ipRange{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	ipRange{
		start: net.ParseIP("198.18.0.0"),
		end:   net.ParseIP("198.19.255.255"),
	},
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	// my use case is only concerned with ipv4 atm
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

func getIPAdress(w http.ResponseWriter, r *http.Request) {
	// will match either ipv4 , or ipv4:port
	var ipPort = regexp.MustCompile(`[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?`)

	ret := r.RemoteAddr

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			ret = ip
			break
		}
	}

	if ipPort.MatchString(ret) && strings.Contains(ret, ":") {
		ret = strings.Split(ret, ":")[0]
	}

	fmt.Fprintf(w, ret+"\n")
}
