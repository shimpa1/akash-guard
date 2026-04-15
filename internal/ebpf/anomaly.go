package ebpf

import (
	"context"
	"log/slog"
	"time"

	"github.com/shimpa1/akash-guard/internal/alerting"
	"github.com/shimpa1/akash-guard/internal/config"
)

// AnomalyDetector reads snapshots from the Monitor on each window tick,
// evaluates thresholds, fires alerts, then resets the window.
type AnomalyDetector struct {
	monitor   *Monitor
	cfg       *config.AnomalyConfig
	alerter   *alerting.Alerter
	whitelist map[string]struct{}
}

func NewAnomalyDetector(
	monitor *Monitor,
	cfg *config.AnomalyConfig,
	alerter *alerting.Alerter,
	whitelist []string,
) *AnomalyDetector {
	wl := make(map[string]struct{}, len(whitelist))
	for _, ns := range whitelist {
		wl[ns] = struct{}{}
	}
	return &AnomalyDetector{
		monitor:   monitor,
		cfg:       cfg,
		alerter:   alerter,
		whitelist: wl,
	}
}

// Run evaluates anomalies on each window tick. Blocks until ctx is done.
func (d *AnomalyDetector) Run(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.Window.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.evaluate()
		}
	}
}

func (d *AnomalyDetector) evaluate() {
	snapshots := d.monitor.Snapshot()
	t := d.cfg.Thresholds

	for _, s := range snapshots {
		if _, whitelisted := d.whitelist[s.Namespace]; whitelisted {
			continue
		}

		windowSec := uint64(d.cfg.Window.Duration.Seconds())
		if windowSec == 0 {
			windowSec = 1
		}
		pps := s.Packets / windowSec

		// high_pps is only suspicious when packets are small (flood/amplification traffic).
		// Legitimate bulk transfers (downloads, backups) send large packets near MTU and
		// can easily exceed 10k pps at gigabit speeds — those should not fire.
		// If MinPacketBytes == 0, skip the size guard (backward compat with old configs).
		avgPktBytes := uint64(0)
		if s.Packets > 0 {
			avgPktBytes = s.Bytes / s.Packets
		}
		smallPackets := t.MinPacketBytes == 0 || avgPktBytes < t.MinPacketBytes
		if pps > t.PPS && smallPackets {
			slog.Warn("anomaly: high PPS", "namespace", s.Namespace, "pod", s.PodName,
				"pps", pps, "threshold", t.PPS,
				"avg_pkt_bytes", avgPktBytes, "min_pkt_bytes", t.MinPacketBytes)
			d.alerter.Fire(alerting.Event{
				Type:      alerting.EventHighPPS,
				Namespace: s.Namespace,
				PodName:   s.PodName,
				Value:     pps,
				Threshold: t.PPS,
			})
		}

		uniqueDst := uint64(len(s.UniqueDstIPs))
		if uniqueDst > t.UniqueDstIPs {
			slog.Warn("anomaly: high unique dst IPs", "namespace", s.Namespace, "pod", s.PodName,
				"unique_dst", uniqueDst, "threshold", t.UniqueDstIPs)
			d.alerter.Fire(alerting.Event{
				Type:      alerting.EventHighUniqueDstIP,
				Namespace: s.Namespace,
				PodName:   s.PodName,
				Value:     uniqueDst,
				Threshold: t.UniqueDstIPs,
			})
		}

		if s.Port25Conns > t.Port25Conns {
			slog.Warn("anomaly: port 25 egress", "namespace", s.Namespace, "pod", s.PodName,
				"conns", s.Port25Conns, "threshold", t.Port25Conns)
			d.alerter.Fire(alerting.Event{
				Type:      alerting.EventPort25Egress,
				Namespace: s.Namespace,
				PodName:   s.PodName,
				Value:     s.Port25Conns,
				Threshold: t.Port25Conns,
			})
		}

		synRate := s.SYNPackets / windowSec
		if synRate > t.SYNRate {
			slog.Warn("anomaly: high SYN rate", "namespace", s.Namespace, "pod", s.PodName,
				"syn_rate", synRate, "threshold", t.SYNRate)
			d.alerter.Fire(alerting.Event{
				Type:      alerting.EventHighSYNRate,
				Namespace: s.Namespace,
				PodName:   s.PodName,
				Value:     synRate,
				Threshold: t.SYNRate,
			})
		}
	}

	d.monitor.ResetWindow()
}
