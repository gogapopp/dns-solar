package dns

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func AnalyzeDNS(packet gopacket.Packet) (gopacket.Packet, bool) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		for _, q := range dns.Questions {
			// strange host name
			if len(q.Name) > 50 || len(strings.Split(string(q.Name), ".")) > 3 {
				return packet, true
			}
			// unusual dns type
			if q.Type != layers.DNSTypeA && q.Type != layers.DNSTypeAAAA && q.Type != layers.DNSTypeCNAME {
				return packet, true
			}
		}
		// too many dns responses
		if len(dns.Answers) > 10 {
			return packet, true
		}
		ipAddresses := make(map[string]bool)
		for _, a := range dns.Answers {
			// low ttl
			if a.TTL < 10 {
				return packet, true
			}
			if a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA {
				ipAddresses[a.IP.String()] = true
			}
			if len(ipAddresses) > 10 {
				return packet, true
			}
		}
		// failed dns requests
		if dns.ResponseCode != layers.DNSResponseCodeNoErr {
			return packet, true
		}
	}
	return packet, false
}
