package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	policyName = "akash-guard-threatintel-egress-deny"
	// Calico splits rules into chunks to stay within k8s object size limits.
	// 250 CIDRs per rule is a safe upper bound.
	cidrChunkSize = 250
)

var gnpGVR = schema.GroupVersionResource{
	Group:    "crd.projectcalico.org",
	Version:  "v1",
	Resource: "globalnetworkpolicies",
}

// PolicyManager creates and updates Calico GlobalNetworkPolicy objects
// to deny egress to threat-intel IPs.
type PolicyManager struct {
	dynClient dynamic.Interface
}

func NewPolicyManager(dynClient dynamic.Interface) *PolicyManager {
	return &PolicyManager{dynClient: dynClient}
}

// Sync creates or replaces the deny-egress GlobalNetworkPolicy with the
// current set of blocked CIDRs. Each Entry carries its feed source in
// metadata annotations for audit purposes.
func (pm *PolicyManager) Sync(ctx context.Context, entries []Entry) error {
	if len(entries) == 0 {
		slog.Info("no threat intel entries, skipping policy sync")
		return nil
	}

	// Build CIDR chunks as separate egress deny rules.
	rules := buildDenyRules(entries)

	// Collect source annotations (deduplicated feed URLs).
	sources := uniqueSources(entries)

	gnp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "crd.projectcalico.org/v1",
			"kind":       "GlobalNetworkPolicy",
			"metadata": map[string]interface{}{
				"name": policyName,
				"annotations": map[string]interface{}{
					"akash-guard/feed-sources": joinStrings(sources),
					"akash-guard/entry-count":  fmt.Sprintf("%d", len(entries)),
				},
			},
			"spec": map[string]interface{}{
				"order":  1000.0,
				"types":  []interface{}{"Egress"},
				"egress": rules,
			},
		},
	}

	existing, err := pm.dynClient.Resource(gnpGVR).Get(ctx, policyName, metav1.GetOptions{})
	if err != nil {
		// Assume not found — create.
		_, err = pm.dynClient.Resource(gnpGVR).Create(ctx, gnp, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("create GlobalNetworkPolicy: %w", err)
		}
		slog.Info("created Calico GlobalNetworkPolicy", "name", policyName, "entries", len(entries))
		return nil
	}

	gnp.SetResourceVersion(existing.GetResourceVersion())
	_, err = pm.dynClient.Resource(gnpGVR).Update(ctx, gnp, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update GlobalNetworkPolicy: %w", err)
	}
	slog.Info("updated Calico GlobalNetworkPolicy", "name", policyName, "entries", len(entries))
	return nil
}

// buildDenyRules chunks CIDRs into separate deny rules with log action.
func buildDenyRules(entries []Entry) []interface{} {
	var rules []interface{}
	for i := 0; i < len(entries); i += cidrChunkSize {
		end := i + cidrChunkSize
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[i:end]

		nets := make([]interface{}, len(chunk))
		for j, e := range chunk {
			nets[j] = e.CIDR
		}

		// Log rule: matches and logs before the deny fires.
		rules = append(rules, map[string]interface{}{
			"action": "Log",
			"destination": map[string]interface{}{
				"nets": nets,
			},
		})
		// Deny rule.
		rules = append(rules, map[string]interface{}{
			"action": "Deny",
			"destination": map[string]interface{}{
				"nets": nets,
			},
		})
	}
	return rules
}

func uniqueSources(entries []Entry) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, e := range entries {
		if _, ok := seen[e.Source]; !ok {
			seen[e.Source] = struct{}{}
			out = append(out, e.Source)
		}
	}
	return out
}

func joinStrings(ss []string) string {
	b, _ := json.Marshal(ss)
	return string(b)
}
