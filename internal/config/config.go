package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ThreatIntel ThreatIntelConfig `yaml:"threatintel"`
	Anomaly     AnomalyConfig     `yaml:"anomaly"`
	Alerting    AlertingConfig    `yaml:"alerting"`
	Namespaces  NamespacesConfig  `yaml:"namespaces"`
}

type ThreatIntelConfig struct {
	RefreshInterval duration `yaml:"refresh_interval"`
	Feeds           []string `yaml:"feeds"`
}

type AnomalyConfig struct {
	Window     duration         `yaml:"window"`
	Thresholds ThresholdConfig  `yaml:"thresholds"`
}

type ThresholdConfig struct {
	PPS              uint64 `yaml:"pps"`
	UniqueDstIPs     uint64 `yaml:"unique_dst_ips"`
	Port25Conns      uint64 `yaml:"port25_connections"`
	SYNRate          uint64 `yaml:"syn_rate"`
}

type AlertingConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Webhook    WebhookConfig    `yaml:"webhook"`
	Email      EmailConfig      `yaml:"email"`
}

type PrometheusConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

type EmailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type NamespacesConfig struct {
	Whitelist []string `yaml:"whitelist"`
}

// duration is a yaml-deserializable time.Duration
type duration struct {
	time.Duration
}

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	d.Duration = dur
	return nil
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	cfg := defaults()
	if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		ThreatIntel: ThreatIntelConfig{
			RefreshInterval: duration{time.Hour},
			Feeds: []string{
				"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
				"https://www.spamhaus.org/drop/drop.txt",
				"https://www.spamhaus.org/drop/edrop.txt",
			},
		},
		Anomaly: AnomalyConfig{
			Window: duration{10 * time.Second},
			Thresholds: ThresholdConfig{
				PPS:          10000,
				UniqueDstIPs: 500,
				Port25Conns:  20,
				SYNRate:      1000,
			},
		},
		Alerting: AlertingConfig{
			Prometheus: PrometheusConfig{
				Enabled: true,
				Port:    9090,
			},
		},
	}
}
