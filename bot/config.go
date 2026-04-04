package main

// config.go — YAML configuration types, loading, and runtime patching.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Services ServicesConfig `yaml:"services"`
	Scanner  ScannerConfig  `yaml:"scanner"`
	Health   HealthConfig   `yaml:"health"`
}

type TelegramConfig struct {
	Token     string `yaml:"token"`
	OwnerID   int64  `yaml:"owner_id"`
	UsersFile string `yaml:"users_file"` // path to the persistent user registry
}

type ServicesConfig struct {
	VPN     string `yaml:"vpn"`
	Scanner string `yaml:"scanner"`
}

type ScannerConfig struct {
	LogFile string `yaml:"log_file"`
	Domain  string `yaml:"domain"`
}

type HealthConfig struct {
	PingTarget    string        `yaml:"ping_target"`
	Interval      time.Duration `yaml:"interval"`
	LossThreshold int           `yaml:"loss_threshold"`
}

// loadConfig reads and parses the YAML configuration file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg := &Config{
		Services: ServicesConfig{
			VPN:     "masterdnsvpn.service",
			Scanner: "echocatcher.service",
		},
		Scanner: ScannerConfig{
			LogFile: "/var/log/echocatcher/working_dns.json",
		},
		Health: HealthConfig{
			PingTarget:    "8.8.8.8",
			Interval:      5 * time.Minute,
			LossThreshold: 60,
		},
		Telegram: TelegramConfig{
			UsersFile: "/opt/dns-orchestrator/users.json",
		},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Telegram.Token == "" {
		return nil, fmt.Errorf("telegram.token must be set in config")
	}
	if cfg.Telegram.OwnerID == 0 {
		return nil, fmt.Errorf("telegram.owner_id must be set in config")
	}
	return cfg, nil
}

// writeDomainToConfig patches the "domain:" key inside the "scanner:" section
// of the YAML config file at cfgPath. Creates the key if absent.
func writeDomainToConfig(cfgPath, domain string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	inScanner, written := false, false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 && !strings.HasPrefix(trimmed, "#") &&
			strings.HasSuffix(trimmed, ":") &&
			!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inScanner = trimmed == "scanner:"
		}
		if inScanner && !written && strings.HasPrefix(trimmed, "domain:") {
			lines[i] = `  domain: "` + domain + `"`
			written = true
		}
	}
	if !written {
		for i, line := range lines {
			if strings.TrimSpace(line) == "scanner:" {
				lines = append(lines[:i+1], append([]string{`  domain: "` + domain + `"`}, lines[i+1:]...)...)
				break
			}
		}
	}
	return os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")), 0o600)
}
