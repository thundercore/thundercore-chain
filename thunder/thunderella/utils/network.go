package utils

import (
	"fmt"
	"net"
)

// Copied from https://stackoverflow.com/a/50825191 - begin

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// Return true when the format of `s` is valid and is a private IP.
func IsPrivateIPByString(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return IsPrivateIP(ip)
}

func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Copied from https://stackoverflow.com/a/50825191 - end

func StripPort(ipAndPort string) string {
	h, _, err := net.SplitHostPort(ipAndPort)
	if err != nil {
		return h
	}
	return ipAndPort
}
