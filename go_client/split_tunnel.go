package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func ModifyConfigForSplitTunnel(conf string, peerIP net.IP) string {
	var excludes [][2]uint32 // [ip, bits]

	if ip4 := peerIP.To4(); ip4 != nil {
		excludes = append(excludes, [2]uint32{binary.BigEndian.Uint32(ip4), 32})
	}

	cidrs := []string{
		"95.163.0.0/16",
		"87.240.0.0/16",
		"93.186.224.0/20",
		"185.32.248.0/22",
		"185.29.130.0/24",
		"217.20.144.0/20",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, c := range cidrs {
		if parsed := parseCIDR(c); parsed != nil {
			excludes = append(excludes, *parsed)
		}
	}

	allowed := calcAllowedIPs(excludes)

	var lines []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AllowedIPs") {
			lines = append(lines, fmt.Sprintf("AllowedIPs = %s", allowed))
		} else {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func parseCIDR(s string) *[2]uint32 {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return nil
	}
	ones, _ := ipNet.Mask.Size()
	result := [2]uint32{binary.BigEndian.Uint32(ip4), uint32(ones)}
	return &result
}

func calcAllowedIPs(excludes [][2]uint32) string {
	var result [][2]uint32

	containsFn := func(container, target [2]uint32) bool {
		if container[1] > target[1] {
			return false
		}
		var mask uint32
		if container[1] > 0 {
			mask = 0xFFFFFFFF << (32 - container[1])
		}
		return (container[0] & mask) == (target[0] & mask)
	}

	overlapsFn := func(a, b [2]uint32) bool {
		minBits := a[1]
		if b[1] < minBits {
			minBits = b[1]
		}
		var mask uint32
		if minBits > 0 {
			mask = 0xFFFFFFFF << (32 - minBits)
		}
		return (a[0] & mask) == (b[0] & mask)
	}

	var splitRec func(block [2]uint32)
	splitRec = func(block [2]uint32) {
		for _, ex := range excludes {
			if containsFn(ex, block) {
				return
			}
		}

		hasOverlap := false
		for _, ex := range excludes {
			if overlapsFn(block, ex) {
				hasOverlap = true
				break
			}
		}
		if !hasOverlap {
			result = append(result, block)
			return
		}
		if block[1] >= 32 {
			return
		}

		next := block[1] + 1
		bit := uint32(1) << (32 - next)
		splitRec([2]uint32{block[0], next})
		splitRec([2]uint32{block[0] | bit, next})
	}

	splitRec([2]uint32{0, 0})

	parts := make([]string, len(result))
	for i, r := range result {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, r[0])
		parts[i] = fmt.Sprintf("%s/%d", ip, r[1])
	}
	return strings.Join(parts, ", ")
}
