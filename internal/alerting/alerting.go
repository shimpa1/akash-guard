package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shimpa1/akash-guard/internal/config"
)

type EventType string

const (
	EventThreatIntelHit  EventType = "threat_intel_hit"
	EventHighPPS         EventType = "high_pps"
	EventHighUniqueDstIP EventType = "high_unique_dst_ips"
	EventPort25Egress    EventType = "port25_egress"
	EventHighSYNRate     EventType = "high_syn_rate"
)

type Event struct {
	Time       time.Time         `json:"time"`
	Type       EventType         `json:"type"`
	Namespace  string            `json:"namespace"`
	PodName    string            `json:"pod_name,omitempty"`
	DstIP      string            `json:"dst_ip,omitempty"`
	FeedSource string            `json:"feed_source,omitempty"`
	Value      uint64            `json:"value,omitempty"`
	Threshold  uint64            `json:"threshold,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

var alertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "akash_guard_alerts_total",
	Help: "Total number of abuse alerts fired.",
}, []string{"type", "namespace"})

type Alerter struct {
	cfg *config.AlertingConfig
}

func New(cfg *config.AlertingConfig) *Alerter {
	return &Alerter{cfg: cfg}
}

func (a *Alerter) Fire(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}

	// Always emit structured log
	slog.Warn("abuse detected",
		"type", ev.Type,
		"namespace", ev.Namespace,
		"pod", ev.PodName,
		"dst_ip", ev.DstIP,
		"feed_source", ev.FeedSource,
		"value", ev.Value,
		"threshold", ev.Threshold,
	)

	// Prometheus counter
	alertsTotal.WithLabelValues(string(ev.Type), ev.Namespace).Inc()

	if a.cfg.Webhook.Enabled && a.cfg.Webhook.URL != "" {
		go a.sendWebhook(ev)
	}

	if a.cfg.Email.Enabled && len(a.cfg.Email.To) > 0 {
		go a.sendEmail(ev)
	}
}

func (a *Alerter) sendWebhook(ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Error("webhook marshal failed", "err", err)
		return
	}
	resp, err := http.Post(a.cfg.Webhook.URL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		slog.Error("webhook delivery failed", "err", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("webhook non-2xx response", "status", resp.StatusCode)
	}
}

func (a *Alerter) sendEmail(ev Event) {
	ec := &a.cfg.Email
	subject := fmt.Sprintf("[akash-guard] %s in namespace %s", ev.Type, ev.Namespace)
	body, _ := json.MarshalIndent(ev, "", "  ")
	msg := "From: " + ec.From + "\r\n" +
		"To: " + strings.Join(ec.To, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		string(body)

	addr := fmt.Sprintf("%s:%d", ec.SMTPHost, ec.SMTPPort)
	var auth smtp.Auth
	if ec.Username != "" {
		auth = smtp.PlainAuth("", ec.Username, ec.Password, ec.SMTPHost)
	}
	if err := smtp.SendMail(addr, auth, ec.From, ec.To, []byte(msg)); err != nil {
		slog.Error("email delivery failed", "err", err)
	}
}
