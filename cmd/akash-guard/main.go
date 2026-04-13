package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shimpa1/akash-guard/internal/alerting"
	"github.com/shimpa1/akash-guard/internal/config"
	ebpfmon "github.com/shimpa1/akash-guard/internal/ebpf"
	"github.com/shimpa1/akash-guard/internal/threatintel"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	cfgPath := os.Getenv("AKASH_GUARD_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/akash-guard/config.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Kubernetes dynamic client (for Calico CRDs).
	dynClient, err := buildDynClient()
	if err != nil {
		slog.Error("failed to build k8s client", "err", err)
		os.Exit(1)
	}

	alerter := alerting.New(&cfg.Alerting)

	// Start Prometheus metrics server.
	if cfg.Alerting.Prometheus.Enabled {
		go serveMetrics(cfg.Alerting.Prometheus.Port)
	}

	// Component 1: Threat Intel Engine.
	tiEngine := threatintel.NewEngine(&cfg.ThreatIntel, dynClient, alerter)
	go tiEngine.Run(ctx)

	// Component 2: eBPF Anomaly Detector.
	monitor := ebpfmon.NewMonitor(dynClient)
	if err := monitor.Load(); err != nil {
		slog.Warn("eBPF monitor load failed — anomaly detection disabled", "err", err)
	} else {
		go monitor.Run(ctx)
		detector := ebpfmon.NewAnomalyDetector(monitor, &cfg.Anomaly, alerter, cfg.Namespaces.Whitelist)
		go detector.Run(ctx)
	}

	slog.Info("akash-guard running")
	<-ctx.Done()
	slog.Info("shutting down")
}

func buildDynClient() (dynamic.Interface, error) {
	// Try in-cluster config first (running inside a pod).
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig (local dev / testing).
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("build kubeconfig: %w", err)
		}
	}
	return dynamic.NewForConfig(restCfg)
}

func serveMetrics(port int) {
	addr := fmt.Sprintf(":%d", port)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	slog.Info("prometheus metrics listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("metrics server", "err", err)
	}
}
