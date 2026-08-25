#!/usr/bin/env bash
# Full Common-Crawl scan tuned dynamically for this machine. This remains passive.
set -euo pipefail
cd "$(dirname "$0")"

CPU_THREADS="$(nproc)"
TOTAL_KIB="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
AVAILABLE_KIB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
TOTAL_TARGET_GIB="$(( TOTAL_KIB * 75 / 100 / 1024 / 1024 ))"
AVAILABLE_TARGET_GIB="$(( AVAILABLE_KIB / 1024 / 1024 - 3 ))"
MEMORY_GIB="$TOTAL_TARGET_GIB"
if [ "$AVAILABLE_TARGET_GIB" -lt "$MEMORY_GIB" ]; then MEMORY_GIB="$AVAILABLE_TARGET_GIB"; fi
if [ "$MEMORY_GIB" -lt 4 ]; then MEMORY_GIB=4; fi
IO_WORKERS="$(( CPU_THREADS * 3 ))"
if [ "$IO_WORKERS" -gt 64 ]; then IO_WORKERS=64; fi
BATCH_SIZE="$(( IO_WORKERS * 8 ))"
DISK_AVAILABLE="$(df -h . | awk 'NR==2 {print $4}')"

echo "=== FULL PASSIVE SCAN ==="
echo "CPU threads: $CPU_THREADS | DuckDB memory: ${MEMORY_GIB}GB | WARC workers: $IO_WORKERS | batch: $BATCH_SIZE"
echo "Freier Workspace-Speicher: $DISK_AVAILABLE"
echo "Hinweis: Ein kompletter Crawl kann je nach Kandidatenzahl viele Stunden/Tage und sehr viel Cache-Speicher benoetigen."

export PYTHONUNBUFFERED=1
export MALLOC_ARENA_MAX=4

exec ./start.sh \
  --full \
  --max-candidates 0 \
  --threads "$CPU_THREADS" \
  --memory "${MEMORY_GIB}GB" \
  --workers "$IO_WORKERS" \
  --parse-workers "$CPU_THREADS" \
  --batch-size "$BATCH_SIZE" \
  --max-record-bytes 16000000 \
  --max-body-bytes 4000000 \
  --update-cves \
  "$@"
