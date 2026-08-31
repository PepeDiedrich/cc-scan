#!/usr/bin/env bash
# Streaming profile for a 4-core i5-6600 and a machine with about 300 GB storage.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== cc-scan 300-GB streaming profile ==="
if ! command -v tailscale >/dev/null 2>&1; then
  echo "[!] Tailscale wurde nicht gefunden; das Dashboard kann nicht ans Tailnet gebunden werden."
  exit 1
fi
TAILNET_IP="$(tailscale ip -4 2>/dev/null | head -n 1)"
if [ -z "$TAILNET_IP" ]; then
  echo "[!] Tailscale ist nicht verbunden; bitte zuerst Tailscale starten."
  exit 1
fi
echo "Dashboard (Tailnet): http://${TAILNET_IP}:8080"
echo "Gemeinsames Download-Limit: 80 Mbit/s"
echo "WARC-Records werden nach jedem analysierten Batch aus dem Cache entfernt."

AVAILABLE_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
MEMORY_GIB="$(( AVAILABLE_KIB / 1024 / 1024 - 2 ))"
if [ "$MEMORY_GIB" -gt 6 ]; then MEMORY_GIB=6; fi
if [ "$MEMORY_GIB" -lt 2 ]; then MEMORY_GIB=2; fi
echo "DuckDB-Speicherbudget: ${MEMORY_GIB}GB"

exec ./start.sh \
  --full \
  --stream-shards \
  --max-candidates 0 \
  --bandwidth-mbit 80 \
  --dashboard \
  --dashboard-host "$TAILNET_IP" \
  --dashboard-port 8080 \
  --threads 4 \
  --memory "${MEMORY_GIB}GB" \
  --workers 12 \
  --parse-workers 8 \
  --batch-size 128 \
  --stage2-prefetch 4 \
  --analysis-workers 4 \
  --warc-cooldown-seconds 180 \
  --runtime-dir .cache/stream \
  --cache-dir .cache/stream/warc \
  --state-file scan-status.json \
  --log-file scan.log \
  --output security_results \
  --min-free-gb 20 \
  "$@"
