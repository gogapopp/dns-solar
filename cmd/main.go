package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gogapopp/dns-solar/internal/config"
	"github.com/gogapopp/dns-solar/internal/logger"
	"github.com/gogapopp/dns-solar/internal/traffic"
)

func main() {
	logger, err := logger.NewLogger()
	if err != nil {
		logger.Fatal(err)
	}
	config, err := config.NewConfig()
	if err != nil {
		logger.Fatal(err)
	}

	trmn := traffic.NewTrafficMonitor(config, logger)
	packetHandle, err := trmn.Start()
	if err != nil {
		logger.Fatal(err)
	}
	defer packetHandle.Close()
	go trmn.Scan(packetHandle)

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	<-sigint
}
