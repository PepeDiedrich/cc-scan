from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Callable


class BandwidthLimiter:
    """Process-wide token bucket shared by index and WARC downloads."""

    def __init__(self, megabits_per_second: float = 0):
        self.bytes_per_second = max(0.0, megabits_per_second) * 1_000_000 / 8
        self.capacity = max(64 * 1024, self.bytes_per_second)
        self.tokens = 0.0
        self.updated = time.monotonic()
        self.condition = threading.Condition()

    def acquire(self, amount: int) -> None:
        if not self.bytes_per_second or amount <= 0:
            return
        remaining = amount
        while remaining:
            requested = min(remaining, int(self.capacity))
            with self.condition:
                while True:
                    now = time.monotonic()
                    self.tokens = min(
                        self.capacity,
                        self.tokens + (now - self.updated) * self.bytes_per_second,
                    )
                    self.updated = now
                    if self.tokens >= requested:
                        self.tokens -= requested
                        break
                    self.condition.wait(timeout=max(0.001, (requested - self.tokens) / self.bytes_per_second))
            remaining -= requested


def copy_limited(source: BinaryIO, destination: BinaryIO, limiter: BandwidthLimiter | None,
                 maximum: int | None = None, chunk_size: int = 64 * 1024,
                 progress: Callable[[int], None] | None = None) -> int:
    total = 0
    while maximum is None or total < maximum:
        wanted = chunk_size if maximum is None else min(chunk_size, maximum - total)
        if not wanted:
            break
        if limiter:
            limiter.acquire(wanted)
        chunk = source.read(wanted)
        if not chunk:
            break
        destination.write(chunk)
        total += len(chunk)
        if progress:
            progress(len(chunk))
        if len(chunk) < wanted:
            break
    return total


class RuntimeMonitor:
    def __init__(self, state_path: str, log_path: str, recent_limit: int = 100,
                 mark_running: bool = True):
        self.state_path = Path(state_path)
        self.log_path = Path(log_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.started = time.time()
        self.track_uptime = mark_running
        self.state = self._load()
        self.recent = deque(self.state.pop("recent_results", []), maxlen=recent_limit)
        self._last_transfer_save = 0.0
        self._transfer_window_started = time.monotonic()
        self._transfer_window_bytes: dict[str, int] = {}
        if mark_running:
            # A resumed run must not present the previous run's terminal state.
            self.state.pop("finished_at", None)
            self.state.pop("error", None)
            self.state.update({"running": True, "started_at": self._timestamp(), "pid": os.getpid()})
        self.state.setdefault("stats", {})
        self.state.setdefault("shards", {})
        if mark_running:
            self._save()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, self.state_path)

    def update(self, **values) -> None:
        with self.lock:
            self.state.update(values)
            self.state["updated_at"] = self._timestamp()
            self._save()

    def reset_progress(self) -> None:
        with self.lock:
            self.state["stats"] = {}
            self.state["shards"] = {}
            self.recent.clear()
            self._save()

    def increment(self, **values: int) -> None:
        with self.lock:
            stats = self.state.setdefault("stats", {})
            for key, value in values.items():
                stats[key] = stats.get(key, 0) + value
            self.state["updated_at"] = self._timestamp()
            self._save()

    def transfer(self, key: str, amount: int) -> None:
        """Update hot byte counters without rewriting the state file per 64 KiB chunk."""
        with self.lock:
            stats = self.state.setdefault("stats", {})
            stats[key] = stats.get(key, 0) + amount
            now = time.monotonic()
            self._transfer_window_bytes[key] = self._transfer_window_bytes.get(key, 0) + amount
            if now - self._last_transfer_save >= 1.0:
                elapsed = max(0.001, now - self._transfer_window_started)
                for transfer_key, transferred in self._transfer_window_bytes.items():
                    stats[transfer_key + "_per_second"] = round(transferred / elapsed)
                self._transfer_window_bytes.clear()
                self._transfer_window_started = now
                self.state["updated_at"] = self._timestamp()
                self._save()
                self._last_transfer_save = now

    def shard(self, shard_id: str, **values) -> None:
        with self.lock:
            item = self.state.setdefault("shards", {}).setdefault(shard_id, {})
            item.update(values)
            item["updated_at"] = self._timestamp()
            self.state["updated_at"] = self._timestamp()
            self._save()

    def add_results(self, rows: list[dict]) -> None:
        fields = ("observed_at", "host", "url", "product", "detected_version", "cve_id",
                  "cve_cvss_score", "cve_severity", "cve_advisory_url",
                  "evidence_state", "overall_confidence", "notes")
        with self.lock:
            for row in rows:
                self.recent.appendleft({key: row.get(key) for key in fields})
            self._save()

    def log(self, message: str) -> None:
        line = f"{self._timestamp()} {message}"
        print(message, flush=True)
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def snapshot(self) -> dict:
        with self.lock:
            result = dict(self.state)
            result["stats"] = dict(self.state.get("stats", {}))
            result["shards"] = {key: dict(value) for key, value in self.state.get("shards", {}).items()}
            result["recent_results"] = list(self.recent)
            if self.track_uptime:
                result["uptime_seconds"] = round(time.time() - self.started)
            return result

    def finish(self, error: str | None = None) -> None:
        self.update(running=False, finished_at=self._timestamp(), error=error)


class DashboardServer:
    def __init__(self, monitor: RuntimeMonitor, host: str = "127.0.0.1", port: int = 8080):
        handler = self._handler(monitor)
        self.server = ThreadingHTTPServer((host, port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="dashboard", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    @staticmethod
    def _handler(monitor: RuntimeMonitor):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/status":
                    self._send("application/json", json.dumps(monitor.snapshot(), ensure_ascii=False).encode())
                elif self.path == "/api/logs":
                    try:
                        lines = monitor.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
                    except OSError:
                        lines = []
                    self._send("text/plain; charset=utf-8", ("\n".join(lines) + "\n").encode())
                elif self.path in ("/", "/index.html"):
                    self._send("text/html; charset=utf-8", DASHBOARD_HTML.encode())
                else:
                    self.send_error(404)

            def _send(self, content_type: str, body: bytes) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        return Handler


DASHBOARD_HTML = r"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>cc-scan</title><style>
:root{color-scheme:dark;--bg:#10151b;--card:#18212b;--line:#2b3947;--green:#55d68b;--muted:#9babb9}
body{font:14px system-ui;margin:0;background:var(--bg);color:#edf3f7}main{max-width:1300px;margin:auto;padding:24px}
h1{font-size:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:14px}.value{font-size:24px;color:var(--green)}table{width:100%;border-collapse:collapse;background:var(--card)}th,td{padding:8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted)}pre{height:260px;overflow:auto;background:#080b0f;padding:12px;border-radius:8px;white-space:pre-wrap}.muted{color:var(--muted)}
</style></head><body><main><h1>cc-scan <span id="run" class="muted"></span></h1><div id="cards" class="grid"></div>
<h2>Letzte Ergebnisse</h2><div style="overflow:auto"><table><thead><tr><th>Status</th><th>Host</th><th>Produkt</th><th>Version/CVE</th><th>CVSS</th><th>Confidence</th><th>URL</th></tr></thead><tbody id="results"></tbody></table></div>
<h2>Log</h2><pre id="logs"></pre></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>new Intl.NumberFormat('de-DE').format(n||0); const mb=n=>(Number(n||0)/1e6).toFixed(1)+' MB';
async function refresh(){try{const s=await fetch('/api/status').then(r=>r.json()),x=s.stats||{};
document.querySelector('#run').textContent=s.running?'läuft':'beendet';
let done=Object.values(s.shards||{}).filter(v=>v.stage2_done).length;
let rate=((x.index_download_bytes_per_second||0)+(x.warc_download_bytes_per_second||0))*8/1e6;
let cards=[['Phase',s.phase||'-'],['Shards',done+' / '+(s.total_shards||0)],['Kandidaten',fmt(x.candidate_count)],['Ergebnisse',fmt(x.result_count)],['Likely/Confirmed',fmt(x.likely_vulnerable_count)+' / '+fmt(x.confirmed_count)],['Download',rate.toFixed(2)+' Mbit/s'],['Index geladen',mb(x.index_download_bytes)],['WARC geladen',mb(x.warc_download_bytes)],['Speicher frei',mb(s.disk_free_bytes)],['Fetch/Parse-Fehler',fmt(x.warc_fetch_failure_count)+' / '+fmt(x.warc_parse_failure_count)],['HTTP 403/429',fmt(x.warc_http_403_count)+' / '+fmt(x.warc_http_429_count)],['Laufzeit',((s.uptime_seconds||0)/3600).toFixed(1)+' h']];
document.querySelector('#cards').innerHTML=cards.map(v=>`<div class="card"><div class="muted">${esc(v[0])}</div><div class="value">${esc(v[1])}</div></div>`).join('');
document.querySelector('#results').innerHTML=(s.recent_results||[]).map(r=>`<tr><td>${esc(r.evidence_state)}</td><td>${esc(r.host)}</td><td>${esc(r.product)}</td><td>${esc([r.detected_version,r.cve_id].filter(Boolean).join(' / '))}</td><td>${esc(r.cve_cvss_score||'')} ${esc(r.cve_severity||'')}</td><td>${esc(r.overall_confidence)}</td><td>${esc(r.url)}</td></tr>`).join('');
const l=await fetch('/api/logs').then(r=>r.text()),e=document.querySelector('#logs');let bottom=e.scrollTop+e.clientHeight>=e.scrollHeight-20;e.textContent=l;if(bottom)e.scrollTop=e.scrollHeight;}catch(e){document.querySelector('#run').textContent='nicht erreichbar'}}
refresh();setInterval(refresh,2000);</script></body></html>"""
