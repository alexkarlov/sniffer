package listeners

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"sort"
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
	out := ""
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

func ListenDNS() chan string {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	bpfInstructions := []pcap.BPFInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 6, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 0, 15, 0x00000011},
		{0x28, 0, 0, 0x00000036},
		{0x15, 12, 0, 0x00000035},
		{0x28, 0, 0, 0x00000038},
		{0x15, 10, 11, 0x00000035},
		{0x15, 0, 10, 0x00000800},
		{0x30, 0, 0, 0x00000017},
		{0x15, 0, 8, 0x00000011},
		{0x28, 0, 0, 0x00000014},
		{0x45, 6, 0, 0x00001fff},
		{0xb1, 0, 0, 0x0000000e},
		{0x48, 0, 0, 0x0000000e},
		{0x15, 2, 0, 0x00000035},
		{0x48, 0, 0, 0x00000010},
		{0x15, 0, 1, 0x00000035},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}

	if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
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
			if ok && len(dns.Questions) > 0 {
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
		}
	}()
	return out
}
