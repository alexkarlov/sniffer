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

var (
	BPFIP = []pcap.BPFInstruction{
		{0x6, 0, 0, 0x00040000},
	}
)

// IPPackets describes IP trafic
type IPPackets map[uint32]IP

type ByteSize float64

// list of size format
const (
	_           = iota // ignore first value by assigning to blank identifier
	KB ByteSize = 1 << (10 * iota)
	MB
	GB
	TB
	PB
)

// IP describes trafic by particular IP
type IP struct {
	addr         net.IP
	length       ByteSize
	location     string
	organization string
	hostname     string
}

var dbCity, dbASN *geoip2.Reader

func init() {
	var err error
	dbCity, err = geoip2.Open("./GeoIP2-City.mmdb")
	if err != nil {
		panic(err)
	}
	dbASN, err = geoip2.Open("./GeoLite2-ASN.mmdb")
	if err != nil {
		panic(err)
	}
}

func (p *IP) String() string {
	l := p.length / KB
	return fmt.Sprintf("IP: %s; Length:%.2fKB; Location:%s; Organization: %s\n\n", p.addr, l, p.location, p.organization)
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
	out := "IP packets:\n"
	lim := 10
	for i, p := range ips {
		if i == lim {
			return out
		}
		out += p.String()
	}
	return out
}

// ListenIP captures all IP trafic
func ListenIP(device string) chan string {
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	if err := handle.SetBPFInstructionFilter(BPFIP); err != nil {
		panic(err)
	}

	out := make(chan string)
	packets := make(IPPackets)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		// TODO: move it to something like finalize func
		defer dbASN.Close()
		defer dbCity.Close()
		i := 0
		batchSize := 100
		for packet := range packetSource.Packets() {
			ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || isLocal(ip.DstIP) {
				//skip non ipv4, local and multicast packets
				continue
			}
			dstIP := binary.BigEndian.Uint32(ip.DstIP)
			p, ok := packets[dstIP]
			if !ok {
				p = newIP(ip.DstIP)
			}
			p.length += ByteSize(ip.Length)
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

func newIP(ip net.IP) IP {
	p := IP{
		addr: ip,
	}
	loc, err := dbCity.City(ip)
	// do we need to log errors?
	if err == nil {
		p.location = loc.Country.Names["en"] + ", " + loc.City.Names["en"]

	}
	isp, err := dbASN.ASN(ip)
	if err == nil {
		p.organization = isp.AutonomousSystemOrganization
	}
	return p
}

func isLocal(ip net.IP) bool {
	// local networks
	_, maskA, _ := net.ParseCIDR("10.0.0.0/8")
	_, maskB, _ := net.ParseCIDR("172.16.0.0/12")
	_, maskC, _ := net.ParseCIDR("192.168.0.0/16")
	return ip.IsLoopback() || ip.IsLinkLocalMulticast() || maskA.Contains(ip) || maskB.Contains(ip) || maskC.Contains(ip)
}
