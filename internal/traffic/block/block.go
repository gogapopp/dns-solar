package block

import (
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func BlockIP(packet gopacket.Packet) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip.SrcIP.String(), "-j", "DROP")
		err := cmd.Run()
		if err != nil {
			return err
		}
	}
	return nil
}
