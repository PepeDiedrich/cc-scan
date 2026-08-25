#!/usr/bin/env bash
# Streaming profile for a 4-core i5-6600 and a machine with about 300 GB storage.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== cc-scan 300-GB streaming profile ==="
echo "Dashboard (lokal): http://127.0.0.1:8080"
echo "Gemeinsames Download-Limit: 20 Mbit/s"
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
  --bandwidth-mbit 20 \
  --dashboard \
  --dashboard-host 127.0.0.1 \
  --dashboard-port 8080 \
  --threads 4 \
  --memory "${MEMORY_GIB}GB" \
  --workers 8 \
  --parse-workers 4 \
  --batch-size 64 \
  --runtime-dir .cache/stream \
  --cache-dir .cache/stream/warc \
  --state-file scan-status.json \
  --log-file scan.log \
  --output security_results \
  --min-free-gb 20 \
  "$@"
