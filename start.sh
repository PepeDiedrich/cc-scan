#!/usr/bin/env bash
# =============================================================================
# cc-scan Startskript
# Startet die komplette Pipeline:
#   1. Python-Venv pruefen/erstellen + duckdb installieren
#   2. Neuester Common-Crawl-Index wird automatisch ermittelt
#   3. Vulnerability-Scan via DuckDB
#
# Nutzung:
#   ./start.sh                 # Testlauf (5 Shards des neuesten Crawls)
#   ./start.sh -n 50           # 50 Shards
#   ./start.sh --full          # kompletter Crawl (alle ~300 warc-Shards)
#   ./start.sh --crawl CC-MAIN-2026-30 -n 10
#   Alle Argumente werden an pipeline_runner.py durchgereicht.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

VENV_DIR=".venv"

echo "=== cc-scan Setup ==="

# 1. Python pruefen
if ! command -v python3 &>/dev/null; then
    echo "[!] python3 nicht gefunden. Bitte installieren: sudo apt install python3 python3-venv"
    exit 1
fi

# 2. Venv erstellen falls noetig
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Erstelle Virtualenv ..."
    python3 -m venv "$VENV_DIR"
fi

# 3. Abhaengigkeiten installieren/aktualisieren
if ! "$VENV_DIR/bin/python" -c "import duckdb" &>/dev/null; then
    echo "[*] Installiere duckdb ..."
    "$VENV_DIR/bin/pip" install -q --upgrade pip
    "$VENV_DIR/bin/pip" install -q duckdb
fi

echo "[+] duckdb Version: $("$VENV_DIR/bin/python" -c 'import duckdb; print(duckdb.__version__)')"
echo "=== Starte Pipeline ==="

# 4. Pipeline starten (alle Argumente durchreichen)
exec "$VENV_DIR/bin/python" pipeline_runner.py "$@"
