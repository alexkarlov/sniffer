package listeners

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
	"net"
	"sort"
)

// IPPackets describes IP trafic
type IPPackets map[uint32]IP

// IP describes trafic by particular IP
type IP struct {
	addr         net.IP
	length       uint16
	location     string
	organization string
	hostname     string
}

func (p *IP) String() string {
	return fmt.Sprintf("IP: %s; Length:%d; Location:%s; Organization: %s\n\n", p.addr, p.length, p.location, p.organization)
}

func (m IPPackets) String() string {
	// convert map to slice for sorting
	ips := make([]IP, 0)
	for _, p := range m {
		ips = append(ips, p)
	}

	// sort IP packets by length
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].length > ips[j].length
	})

	// prepare output
	out := ""
	lim := 10
	for i, p := range ips {
		if i == lim {
			return out
		}
		out += p.String()
	}
	return out
}

func ListenIP() chan string {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	bpfInstructions := []pcap.BPFInstruction{
		{0x6, 0, 0, 0x00040000},
	}

	if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
		panic(err)
	}

	out := make(chan string)
	packets := make(IPPackets)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		dbCity, err := geoip2.Open("./GeoIP2-City.mmdb")
		if err != nil {
			panic(err)
		}
		defer dbCity.Close()
		dbASN, err := geoip2.Open("./GeoLite2-ASN.mmdb")
		if err != nil {
			panic(err)
		}
		defer dbASN.Close()
		i := 0
		batchSize := 100
		for packet := range packetSource.Packets() {
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ip.DstIP.IsLoopback() || ip.DstIP.IsLinkLocalMulticast() {
				//skip non ipv4, local and multicast packets
				continue
			}
			dstIP := binary.BigEndian.Uint32(ip.DstIP)
			p, ok := packets[dstIP]
			if !ok {
				p = IP{
					addr: ip.DstIP,
				}
				loc, err := dbCity.City(ip.DstIP)
				// do we need to log errors?
				if err == nil {
					p.location = loc.Country.Names["en"] + ", " + loc.City.Names["en"]
				}
				isp, err := dbASN.ASN(ip.DstIP)
				if err == nil {
					p.organization = isp.AutonomousSystemOrganization
				}
			}
			p.length += ip.Length
			packets[dstIP] = p
			i++
			// flush and send statistics
			if i == batchSize {
				i = 0
				// update statistics
				out <- packets.String()
			}

		}
	}()
	return out
}
