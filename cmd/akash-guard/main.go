package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shimpa1/akash-guard/internal/alerting"
	"github.com/shimpa1/akash-guard/internal/config"
	ebpfmon "github.com/shimpa1/akash-guard/internal/ebpf"
	"github.com/shimpa1/akash-guard/internal/threatintel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
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

	// Kubernetes clients.
	dynClient, kubeClient, err := buildClients()
	if err != nil {
		slog.Error("failed to build k8s clients", "err", err)
		os.Exit(1)
	}

	alerter := alerting.New(&cfg.Alerting)

	// Start Prometheus metrics server.
	if cfg.Alerting.Prometheus.Enabled {
		go serveMetrics(cfg.Alerting.Prometheus.Port)
	}

	// Component 1: Threat Intel Engine — run only on the elected leader.
	// All nodes participate in the election; the winner runs the engine and
	// writes the Calico GlobalNetworkPolicy. If leadership is lost the engine
	// stops; the existing policy stays in place until a new leader takes over.
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName, _ = os.Hostname()
	}
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		podNamespace = "kube-system"
	}
	go runLeaderElection(ctx, kubeClient, podName, podNamespace, func(leaderCtx context.Context) {
		slog.Info("became leader, starting threat intel engine", "identity", podName)
		tiEngine := threatintel.NewEngine(&cfg.ThreatIntel, dynClient, alerter)
		tiEngine.Run(leaderCtx) // blocks until leadership lost or ctx cancelled
	})

	// Component 2: eBPF Anomaly Detector — runs on every node regardless of leader status.
	monitor := ebpfmon.NewMonitor(dynClient)
	if err := monitor.Load(); err != nil {
		slog.Warn("eBPF monitor load failed — anomaly detection disabled", "err", err)
	} else {
		go monitor.Run(ctx)
		detector := ebpfmon.NewAnomalyDetector(monitor, &cfg.Anomaly, alerter, cfg.Namespaces)
		go detector.Run(ctx)
	}

	slog.Info("akash-guard running")
	<-ctx.Done()
	slog.Info("shutting down")
}

func buildClients() (dynamic.Interface, kubernetes.Interface, error) {
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, fmt.Errorf("build kubeconfig: %w", err)
		}
	}
	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamic client: %w", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("kube client: %w", err)
	}
	return dynClient, kubeClient, nil
}

func runLeaderElection(ctx context.Context, client kubernetes.Interface, id, ns string, onLeading func(context.Context)) {
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      "akash-guard-leader",
			Namespace: ns,
		},
		Client: client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: onLeading,
			OnStoppedLeading: func() {
				slog.Info("lost leader election, threat intel engine stopped", "identity", id)
			},
			OnNewLeader: func(identity string) {
				if identity != id {
					slog.Info("new threat intel leader", "leader", identity)
				}
			},
		},
	})
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
