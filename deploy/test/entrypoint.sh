#!/bin/bash
set -euo pipefail

echo "=== akash-guard trigger tester ==="
echo "Signals: port25_egress, high_unique_dst_ips, high_syn_rate, high_pps"
echo ""

# ---- 1. port25_egress -----------------------------------------------
# Threshold: >20 connections to port 25 in a 10s window.
# Opens 30 TCP connections to port 25 on RFC 5737 documentation IPs.
echo "[1/4] port25_egress: 30 TCP connections to port 25..."
for i in $(seq 1 30); do
    (echo QUIT | timeout 2 nc -w1 203.0.113.$i 25 2>/dev/null || true) &
done
wait
echo "      done. Waiting for window reset..."
sleep 15

# ---- 2. high_unique_dst_ips ------------------------------------------
# Threshold: >500 unique destination IPs in a 10s window.
# nmap ping sweep across 3 RFC 5737 /24s = 768 unique IPs.
echo "[2/4] high_unique_dst_ips: nmap sweep of 768 documentation IPs..."
nmap -sn --max-retries 0 --host-timeout 50ms --min-rate 5000 \
    192.0.2.0/24 198.51.100.0/24 203.0.113.0/24 >/dev/null 2>&1 || true
echo "      done. Waiting for window reset..."
sleep 15

# ---- 3. high_syn_rate ------------------------------------------------
# Threshold: >1000 SYN/sec (10000 SYNs in a 10s window).
echo "[3/4] high_syn_rate: SYN flood to 8.8.8.8:80 for 5 seconds..."
timeout 5 hping3 --syn --flood -p 80 8.8.8.8 2>/dev/null || true
echo "      done. Waiting for window reset..."
sleep 15

# ---- 4. high_pps (small packets) ------------------------------------
# Threshold: >10000 pps AND avg bytes/packet < 300.
# -d 40 sets 40-byte payload → 68-byte total packets (below the 300-byte guard).
echo "[4/4] high_pps: UDP flood to 8.8.8.8:53, 68-byte packets, 5 seconds..."
timeout 5 hping3 --udp --flood -d 40 -p 53 8.8.8.8 2>/dev/null || true
echo "      done."

echo ""
echo "All 4 tests complete. Expected alerts:"
echo "  anomaly: port 25 egress"
echo "  anomaly: high unique dst IPs"
echo "  anomaly: high SYN rate"
echo "  anomaly: high PPS"
echo ""
echo "Sleeping to keep lease alive for log inspection."
sleep infinity
