package traffic

import (
	"log"

	"github.com/gogapopp/dns-solar/internal/config"
	"github.com/gogapopp/dns-solar/internal/traffic/analyze/dns"
	"github.com/gogapopp/dns-solar/internal/traffic/block"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type TrafficMonitor struct {
	config *config.Config
	logger *zap.SugaredLogger
}

func NewTrafficMonitor(config *config.Config, logger *zap.SugaredLogger) *TrafficMonitor {
	return &TrafficMonitor{
		config: config,
		logger: logger,
	}
}

func (tm *TrafficMonitor) Start() (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(tm.config.Device, tm.config.Snapshot_len, tm.config.Promiscuous, tm.config.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	return handle, err
}

func (tm *TrafficMonitor) Scan(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		unsafePacket, ok := dns.AnalyzeDNS(packet)
		if ok {
			err := block.BlockIP(unsafePacket)
			tm.logger.Infof("tm scanner block this packet: %s", unsafePacket)
			if err != nil {
				tm.logger.Errorf("traffic scan error: %v", err)
			}
		}
	}
}
