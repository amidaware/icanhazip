package main

// env CGO_ENABLED=0 go build -ldflags "-s -w"

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
)

const version = "1.2.0"

func main() {
	ver := flag.Bool("version", false, "Prints version")
	flag.Parse()

	if *ver {
		fmt.Println(version)
		if bi, ok := debug.ReadBuildInfo(); ok {
			fmt.Println(bi.String())
			return
		}
	}

	http.HandleFunc("/", getIPAddress)
	http.ListenAndServe(":8091", nil)
}

// https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html

// ipRange - a structure that holds the start and end of a range of ip addresses
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
	{
		start: net.ParseIP("10.0.0.0"),
		end:   net.ParseIP("10.255.255.255"),
	},
	{
		start: net.ParseIP("100.64.0.0"),
		end:   net.ParseIP("100.127.255.255"),
	},
	{
		start: net.ParseIP("172.16.0.0"),
		end:   net.ParseIP("172.31.255.255"),
	},
	{
		start: net.ParseIP("192.0.0.0"),
		end:   net.ParseIP("192.0.0.255"),
	},
	{
		start: net.ParseIP("192.168.0.0"),
		end:   net.ParseIP("192.168.255.255"),
	},
	{
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

func getIPAddress(w http.ResponseWriter, r *http.Request) {
	var ipv4 string
	var ipv6 string

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		for i := len(addresses) - 1; i >= 0; i-- {
			ip, _, err := net.SplitHostPort(strings.TrimSpace(addresses[i]))
			if err != nil {
				ip = strings.TrimSpace(addresses[i]) // In case there's no port
			}
			realIP := net.ParseIP(ip)
			if realIP == nil {
				continue
			}
			if ipv4Address := realIP.To4(); ipv4Address != nil {
				if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
					continue
				}
				ipv4 = ip
				break // Found a valid IPv4 address
			} else if ipv6 == "" && realIP.IsGlobalUnicast() && !isPrivateSubnet(realIP) {
				ipv6 = ip // Store first valid IPv6 address
			}
		}
		if ipv4 != "" {
			fmt.Fprintf(w, ipv4+"\n")
			return
		}
	}

	if ipv6 != "" { // Use IPv6 if no IPv4 was found
		fmt.Fprintf(w, ipv6+"\n")
	} else {
		ret := r.RemoteAddr
		ip, _, _ := net.SplitHostPort(ret)
		fmt.Fprintf(w, ip+"\n")
	}
}
