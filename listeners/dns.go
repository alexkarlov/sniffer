package listeners

import (
	"fmt"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	BPFDNS = "udp and port 53"
)

// DNSPackets describes IP trafic
type DNSPackets map[string]DNS

// DNS describes DNS requests by particular domain
type DNS struct {
	domain string
	count  int32
}

func (m DNSPackets) String() string {
	// convert map to slice for sorting
	sortedPackets := make([]DNS, 0)
	for _, p := range m {
		sortedPackets = append(sortedPackets, p)
	}

	// sort DNS packets by length
	sort.Slice(sortedPackets, func(i, j int) bool {
		return sortedPackets[i].count > sortedPackets[j].count
	})

	// prepare output
	out := "DNS packets:\n"
	lim := 10
	for i, p := range sortedPackets {
		if i == lim {
			return out
		}
		out += p.String()
	}
	return out
}

func (p *DNS) String() string {
	return fmt.Sprintf("Domain: %s\nCount: %d\n", p.domain, p.count)
}

// ListenDNS captures all DNS trafic
func ListenDNS(device string) chan string {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFFilter(BPFDNS); err != nil {
		panic(err)
	}

	// TODO: move to the config
	batchSize := 10
	i := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	out := make(chan string)
	go func() {
		packets := DNSPackets{}
		for packet := range packetSource.Packets() {
			dns, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
			if !ok || len(dns.Questions) <= 0 {
				// skip useless trafic
				continue
			}
			for _, q := range dns.Questions {
				domain := string(q.Name)
				p, ok := packets[domain]
				if !ok {
					p = DNS{
						domain: domain,
					}
				}
				p.count++
				packets[domain] = p
				i++
				// flush and send statistics
				if i == batchSize {
					i = 0
					// update statistics
					out <- packets.String()
				}
			}
		}
	}()
	return out
}
