package main

import (
	"fmt"

	"github.com/alexkarlov/sniffer/listeners"
)

func main() {
	ipOut := listeners.ListenIP("any")
	dnsOut := listeners.ListenDNS("any")
	var ipPackets, dnsPackets string
	// ANSI control symbol - save the cursor position
	// more details here http://ascii-table.com/ansi-escape-sequences.php
	fmt.Print("\033[s")
	for {
		select {
		case ipPackets = <-ipOut:
			fmt.Print("\033[u")
			fmt.Print("\033[J")
			fmt.Print(ipPackets, dnsPackets)
		case dnsPackets = <-dnsOut:
			fmt.Print("\033[u")
			fmt.Print("\033[J")
			fmt.Print(ipPackets, dnsPackets)
		}
	}
}
