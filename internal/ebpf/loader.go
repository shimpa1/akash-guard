package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	bpfpkg "github.com/shimpa1/akash-guard/bpf"
)

// PktEvent mirrors the C struct pkt_event from tc_egress.c.
type PktEvent struct {
	Ifindex  uint32
	DstIP    uint32
	Proto    uint8
	_        [1]byte
	DstPort  uint16
	TCPFlags uint8
	_        [3]byte
}

// IfaceStats holds aggregated per-interface statistics over a time window.
type IfaceStats struct {
	Ifindex      uint32
	Namespace    string
	PodName      string
	Packets      uint64
	Bytes        uint64
	SYNPackets   uint64
	Port25Conns  uint64
	UniqueDstIPs map[uint32]struct{}
}

type ifaceMeta struct {
	namespace string
	podName   string
}

// Monitor loads the TC eBPF program, attaches it to pod veth interfaces,
// and exposes aggregated stats per interface.
type Monitor struct {
	objs      *bpfpkg.TcEgressObjects
	mu        sync.RWMutex
	stats     map[uint32]*IfaceStats // keyed by ifindex
	links     map[uint32]link.Link
	ifaceInfo map[uint32]ifaceMeta
}

func NewMonitor() *Monitor {
	return &Monitor{
		stats:     make(map[uint32]*IfaceStats),
		links:     make(map[uint32]link.Link),
		ifaceInfo: make(map[uint32]ifaceMeta),
	}
}

// Load loads the compiled eBPF object into the kernel.
func (m *Monitor) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs, err := bpfpkg.Load()
	if err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	m.objs = objs
	return nil
}

// Close releases all eBPF resources and detaches TC hooks.
func (m *Monitor) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.links {
		l.Close()
	}
	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			slog.Warn("close eBPF objects", "err", err)
		}
	}
}

// Run starts the veth watcher and ring buffer consumer. Blocks until ctx done.
func (m *Monitor) Run(ctx context.Context) {
	go m.watchVeths(ctx)
	if m.objs != nil {
		go m.consumeRingBuf(ctx)
	}
	<-ctx.Done()
	m.Close()
}

func (m *Monitor) watchVeths(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncVeths(ctx)
		}
	}
}

func (m *Monitor) syncVeths(ctx context.Context) {
	ifaces, err := net.Interfaces()
	if err != nil {
		slog.Error("list interfaces", "err", err)
		return
	}

	active := make(map[uint32]struct{})
	for _, iface := range ifaces {
		if !strings.HasPrefix(iface.Name, "veth") && !strings.HasPrefix(iface.Name, "cali") {
			continue
		}
		idx := uint32(iface.Index)
		active[idx] = struct{}{}

		m.mu.Lock()
		if _, exists := m.links[idx]; !exists {
			meta := m.resolveIfaceMeta(iface.Name)
			m.ifaceInfo[idx] = meta
			m.stats[idx] = &IfaceStats{
				Ifindex:      idx,
				Namespace:    meta.namespace,
				PodName:      meta.podName,
				UniqueDstIPs: make(map[uint32]struct{}),
			}
			if m.objs != nil {
				if err := m.attachTC(ctx, iface, idx); err != nil {
					slog.Warn("attach TC failed", "iface", iface.Name, "err", err)
				} else {
					slog.Info("attached TC egress hook", "iface", iface.Name,
						"ifindex", idx, "namespace", meta.namespace, "pod", meta.podName)
				}
			}
		}
		m.mu.Unlock()
	}

	m.mu.Lock()
	for idx, l := range m.links {
		if _, ok := active[idx]; !ok {
			l.Close()
			delete(m.links, idx)
			delete(m.stats, idx)
			delete(m.ifaceInfo, idx)
		}
	}
	m.mu.Unlock()
}

func (m *Monitor) attachTC(_ context.Context, iface net.Interface, idx uint32) error {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   m.objs.TcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("AttachTCX on %s: %w", iface.Name, err)
	}
	m.links[idx] = l
	return nil
}

// resolveIfaceMeta attempts to resolve namespace and pod name for a veth.
// Falls back to "unknown" if not resolvable.
func (m *Monitor) resolveIfaceMeta(ifaceName string) ifaceMeta {
	netnsDir := "/var/run/netns"
	entries, err := os.ReadDir(netnsDir)
	if err != nil {
		return ifaceMeta{namespace: "unknown", podName: ifaceName}
	}
	for _, e := range entries {
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) == 2 {
			_, err := os.Readlink(filepath.Join(netnsDir, e.Name()))
			if err != nil {
				continue
			}
		}
	}
	return ifaceMeta{namespace: "unknown", podName: ifaceName}
}

// consumeRingBuf reads packet events from the eBPF ring buffer and
// updates unique-dst-IP sets per interface.
func (m *Monitor) consumeRingBuf(ctx context.Context) {
	rd, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		slog.Error("ringbuf reader", "err", err)
		return
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("ringbuf read", "err", err)
			continue
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(PktEvent{})) {
			continue
		}
		ev := (*PktEvent)(unsafe.Pointer(&rec.RawSample[0]))
		// DstIP is in network byte order from the kernel; treat the raw bytes
		// as a uint32 key for consistent per-IP deduplication.
		dstIP := binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&ev.DstIP))[:])

		m.mu.Lock()
		if s, ok := m.stats[ev.Ifindex]; ok {
			s.UniqueDstIPs[dstIP] = struct{}{}
		}
		m.mu.Unlock()
	}
}

// Snapshot returns a copy of current stats for all tracked interfaces,
// merging the per-CPU kernel counters into each snapshot.
func (m *Monitor) Snapshot() []*IfaceStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*IfaceStats, 0, len(m.stats))
	for _, s := range m.stats {
		dstCopy := make(map[uint32]struct{}, len(s.UniqueDstIPs))
		for ip := range s.UniqueDstIPs {
			dstCopy[ip] = struct{}{}
		}
		cp := *s
		cp.UniqueDstIPs = dstCopy

		if m.objs != nil {
			if err := mergeCounters(m.objs.Counters, s.Ifindex, &cp); err != nil {
				slog.Warn("merge counters", "ifindex", s.Ifindex, "err", err)
			}
		}
		out = append(out, &cp)
	}
	return out
}

// ResetWindow clears the per-window state for all tracked interfaces.
func (m *Monitor) ResetWindow() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for idx, s := range m.stats {
		s.Packets = 0
		s.Bytes = 0
		s.SYNPackets = 0
		s.Port25Conns = 0
		s.UniqueDstIPs = make(map[uint32]struct{})
		if m.objs != nil {
			_ = m.objs.Counters.Delete(idx)
		}
	}
}

// mergeCounters reads a PERCPU_HASH entry and sums values across all CPUs.
// Uses the bpf2go-generated TcEgressPktCounters type to match the kernel struct layout.
func mergeCounters(m *ebpf.Map, ifindex uint32, s *IfaceStats) error {
	var perCPU []bpfpkg.TcEgressPktCounters
	if err := m.Lookup(ifindex, &perCPU); err != nil {
		return err
	}
	for _, c := range perCPU {
		s.Packets += c.Packets
		s.Bytes += c.Bytes
		s.SYNPackets += c.SynPackets
		s.Port25Conns += c.Port25Conns
	}
	return nil
}
