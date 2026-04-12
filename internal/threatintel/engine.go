package threatintel

import (
	"context"
	"log/slog"
	"time"

	"github.com/shimpa1/akash-guard/internal/alerting"
	"github.com/shimpa1/akash-guard/internal/config"
	"k8s.io/client-go/dynamic"
)

// Engine periodically fetches threat intel feeds, syncs the Calico policy,
// and fires alerts when the policy hits occur (via Calico flow logs read
// externally — here we alert at sync time for new entries).
type Engine struct {
	cfg     *config.ThreatIntelConfig
	fetcher *Fetcher
	policy  *PolicyManager
	alerter *alerting.Alerter
}

func NewEngine(cfg *config.ThreatIntelConfig, dynClient dynamic.Interface, alerter *alerting.Alerter) *Engine {
	return &Engine{
		cfg:     cfg,
		fetcher: NewFetcher(),
		policy:  NewPolicyManager(dynClient),
		alerter: alerter,
	}
}

// Run starts the periodic refresh loop. Blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.refresh(ctx)

	ticker := time.NewTicker(e.cfg.RefreshInterval.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.refresh(ctx)
		}
	}
}

func (e *Engine) refresh(ctx context.Context) {
	slog.Info("refreshing threat intel feeds")

	entries, err := e.fetcher.FetchAll(ctx, e.cfg.Feeds)
	if err != nil {
		slog.Error("feed fetch error", "err", err)
		return
	}

	if err := e.policy.Sync(ctx, entries); err != nil {
		slog.Error("calico policy sync error", "err", err)
	}
}
