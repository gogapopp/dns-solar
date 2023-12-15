package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

const configPath = "../.env"

type Config struct {
	Device       string        `env:"DEVICE"`
	Snapshot_len int32         `env:"SNAPSHOT_LEN"`
	Promiscuous  bool          `env:"PROMISCUOUS"`
	Timeout      time.Duration `env:"TIMEOUT"`
}

func NewConfig() (*Config, error) {
	var cfg Config
	err := cleanenv.ReadConfig(configPath, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
