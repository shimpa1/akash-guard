package enforcement

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	bpfpkg "github.com/shimpa1/akash-guard/bpf"
	"github.com/shimpa1/akash-guard/internal/config"
)

// Enforcer writes token-bucket rate limit entries into the iface_ratelimit eBPF
// map when a namespace exceeds a detection threshold, and removes them after the
// configured cooldown period.
//
// Each entry in iface_ratelimit is keyed by ifindex. The eBPF TC hook checks this
// map on every packet and drops packets that exceed the allowed rate.
// Stats recording happens before the rate limit check, so anomaly detection
// continues to fire even while enforcement is active.
type Enforcer struct {
	cfg    config.EnforcementConfig
	rlMap  *ebpf.Map // iface_ratelimit — may be nil when eBPF is unavailable
	mu     sync.Mutex
	active map[string][]uint32       // namespace → tracked ifindices
	timers map[string]*time.Timer    // namespace → cooldown timer
}

// New returns an Enforcer. rlMap may be nil; in that case all calls are no-ops.
func New(cfg config.EnforcementConfig, rlMap *ebpf.Map) *Enforcer {
	return &Enforcer{
		cfg:    cfg,
		rlMap:  rlMap,
		active: make(map[string][]uint32),
		timers: make(map[string]*time.Timer),
	}
}

// RateLimit installs a token-bucket entry for each ifindex belonging to namespace.
// If the namespace is already rate-limited the cooldown timer is reset.
// This is a no-op when enforcement is disabled or the eBPF map is unavailable.
func (e *Enforcer) RateLimit(namespace string, ifindices []uint32) {
	if !e.cfg.Enabled || e.rlMap == nil || len(ifindices) == 0 {
		return
	}

	burst := e.cfg.RateLimitBPS // 1-second burst capacity

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, ifidx := range ifindices {
		state := bpfpkg.TcEgressRatelimitState{
			Tokens:  burst,
			RateBps: e.cfg.RateLimitBPS,
			Burst:   burst,
			// Lock and Pad are zero — kernel manages the spin lock value.
			// LastNs is zero; the eBPF program caps the first elapsed window at 1s,
			// so tokens stay at burst on the first packet.
		}
		if err := e.rlMap.Put(ifidx, state); err != nil {
			slog.Warn("enforcement: write rate limit entry", "ifindex", ifidx, "err", err)
			continue
		}
	}

	slog.Warn("enforcement: rate-limiting namespace",
		"namespace", namespace,
		"ifindices", ifindices,
		"rate_bps", e.cfg.RateLimitBPS,
		"cooldown", e.cfg.Cooldown.Duration,
	)

	e.active[namespace] = ifindices

	// Reset existing timer or start a new one.
	if t, ok := e.timers[namespace]; ok {
		t.Reset(e.cfg.Cooldown.Duration)
	} else {
		e.timers[namespace] = time.AfterFunc(e.cfg.Cooldown.Duration, func() {
			e.clearRateLimit(namespace)
		})
	}
}

// clearRateLimit removes the rate limit entries for namespace from the eBPF map.
// Called automatically when the cooldown timer fires.
func (e *Enforcer) clearRateLimit(namespace string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	ifindices, ok := e.active[namespace]
	if !ok {
		return
	}

	for _, ifidx := range ifindices {
		if err := e.rlMap.Delete(ifidx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			slog.Warn("enforcement: delete rate limit entry", "ifindex", ifidx, "err", err)
		}
	}

	delete(e.active, namespace)
	delete(e.timers, namespace)

	slog.Info("enforcement: rate limit cleared", "namespace", namespace)
}
