#!/usr/bin/env python3
"""Two-stage passive Common Crawl security candidate pipeline."""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import tempfile
import threading
import urllib.request
import queue
import shutil
from pathlib import Path

try:
    import duckdb
except ImportError:  # pragma: no cover
    duckdb = None

from src.pipeline import enrich_rows, index_soft404_rows
from src.soft404_index import Soft404Index
from src.warc_fetcher import WarcFetcher
from src.runtime import BandwidthLimiter, DashboardServer, RuntimeMonitor, copy_limited

ROOT = Path(__file__).resolve().parent
COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
DATA_BASE = "https://data.commoncrawl.org/"
SQL_FILE = ROOT / "sql" / "01_prefilter.sql"


def http_get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cc-scan/3.0 passive research"})
    return urllib.request.urlopen(request, timeout=timeout).read()


def get_latest_crawl() -> str:
    for crawl in json.loads(http_get(COLLINFO_URL)):
        url = f"{DATA_BASE}crawl-data/{crawl['id']}/cc-index-table.paths.gz"
        try:
            http_get(url, timeout=30)
            return crawl["id"]
        except OSError:
            continue
    raise RuntimeError("No complete Common Crawl URL Index found")


def get_warc_parquet_paths(crawl_id: str) -> list[str]:
    raw = http_get(f"{DATA_BASE}crawl-data/{crawl_id}/cc-index-table.paths.gz")
    return [DATA_BASE + line for line in gzip.decompress(raw).decode().splitlines()
            if line.endswith(".parquet") and "subset=warc" in line]


def _sql_string(value: str) -> str:
    return value.replace("'", "''")


def inspect_schema(connection, parquet_path: str) -> set[str]:
    rows = connection.execute("DESCRIBE SELECT * FROM read_parquet(?)", [parquet_path]).fetchall()
    columns = {row[0] for row in rows}
    required = {"url_host_registered_domain", "url_host_name", "url", "url_path", "url_query",
                "fetch_status", "fetch_time", "content_mime_type", "content_languages",
                "warc_filename", "warc_record_offset", "warc_record_length"}
    missing = sorted(required - columns)
    if missing:
        raise RuntimeError("Common Crawl schema is missing required evidence columns: " + ", ".join(missing))
    return columns


def run_stage1(connection, parquet_paths: list[str], output: str) -> None:
    inspect_schema(connection, parquet_paths[0])
    sql = SQL_FILE.read_text(encoding="utf-8")
    path_sql = ", ".join("'" + _sql_string(path) + "'" for path in parquet_paths)
    sql = sql.replace("__PARQUET_PATHS__", path_sql).replace("__OUTPUT__", _sql_string(output))
    connection.execute(sql)


def write_parquet(connection, rows: list[dict], output: str) -> None:
    if not rows:
        raise RuntimeError("Stage 2 produced no parsed WARC results; Stage-1 parquet remains available")
    handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", encoding="utf-8", delete=False)
    try:
        with handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        _jsonl_to_parquet(connection, handle.name, output)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def _jsonl_to_parquet(connection, jsonl_path: str, output: str) -> None:
    connection.execute(
        f"COPY (SELECT * FROM read_json_auto('{_sql_string(jsonl_path)}', format='newline_delimited')) "
        f"TO '{_sql_string(output)}' (FORMAT PARQUET, COMPRESSION ZSTD)"
    )


def _shard_id(path: str) -> str:
    name = Path(path).name
    return name.split("-", 2)[1] if name.startswith("part-") else name[:24]


def _download_index_shard(url: str, destination: Path, limiter: BandwidthLimiter,
                          monitor: RuntimeMonitor) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    existing = temporary.stat().st_size if temporary.exists() else 0
    headers = {"User-Agent": "cc-scan/3.0 passive research"}
    if existing:
        headers["Range"] = f"bytes={existing}-"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        append = existing > 0 and response.status == 206
        if existing and not append:
            existing = 0
        with temporary.open("ab" if append else "wb") as handle:
            copy_limited(response, handle, limiter,
                         progress=lambda size: monitor.transfer("index_download_bytes", size))
    os.replace(temporary, destination)


def _new_connection(args):
    connection = duckdb.connect()
    connection.execute("SET preserve_insertion_order=false")
    connection.execute(f"SET max_memory='{_sql_string(args.memory)}'")
    connection.execute(f"SET threads={max(1, args.threads)}")
    return connection


def _write_result_batch(connection, rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_suffix(".tmp.parquet")
    handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", encoding="utf-8", delete=False)
    try:
        with handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        _jsonl_to_parquet(connection, handle.name, str(temporary_output))
        os.replace(temporary_output, output)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass


def _compact_result_shard(connection, parts_dir: Path, output: Path) -> None:
    batch_parts = sorted(parts_dir.glob("*.parquet"))
    parts = list(batch_parts)
    if output.exists():
        parts.insert(0, output)
    if not parts:
        return
    path_sql = ", ".join("'" + _sql_string(str(path)) + "'" for path in parts)
    temporary = output.with_suffix(".tmp.parquet")
    connection.execute(
        f"COPY (SELECT * FROM read_parquet([{path_sql}], union_by_name=true)) "
        f"TO '{_sql_string(str(temporary))}' (FORMAT PARQUET, COMPRESSION ZSTD)"
    )
    os.replace(temporary, output)
    for part in batch_parts:
        part.unlink()
    try:
        parts_dir.rmdir()
    except OSError:
        pass


def _ensure_disk_space(path: Path, minimum_gb: float) -> None:
    if minimum_gb <= 0:
        return
    free = shutil.disk_usage(path).free
    required = int(minimum_gb * 1_000_000_000)
    if free < required:
        raise RuntimeError(
            f"Only {free / 1_000_000_000:.1f} GB disk space remains; "
            f"at least {minimum_gb:g} GB is required. Free space and restart to resume."
        )


def run_streaming(args, crawl: str, selected: list[str], monitor: RuntimeMonitor,
                  limiter: BandwidthLimiter) -> None:
    """Pipeline index shards into Stage 2 while bounding disk and network use."""
    root = Path(args.runtime_dir) / crawl
    root.mkdir(parents=True, exist_ok=True)
    index_dir, candidate_dir = root / "index", root / "candidates"
    result_dir = Path(args.output) / crawl
    result_dir.mkdir(parents=True, exist_ok=True)
    previous_crawl = monitor.state.get("crawl")
    if previous_crawl and previous_crawl != crawl:
        monitor.reset_progress()
    monitor.update(crawl=crawl, total_shards=len(selected), output=str(result_dir),
                   bandwidth_mbit=args.bandwidth_mbit, phase="starting")

    work_queue: queue.Queue = queue.Queue(maxsize=2)
    producer_error: list[BaseException] = []
    stop = threading.Event()

    def produce() -> None:
        connection = _new_connection(args)
        try:
            for position, remote_path in enumerate(selected, 1):
                if stop.is_set():
                    break
                shard_id = _shard_id(remote_path)
                shard_state = monitor.state.get("shards", {}).get(shard_id, {})
                if shard_state.get("stage2_done"):
                    continue
                # `subset` is a Hive partition column in Common Crawl's object path,
                # not a physical Parquet column. Preserve it in the local path.
                local_index = index_dir / "subset=warc" / f"{shard_id}.parquet"
                candidates = candidate_dir / f"{shard_id}.parquet"
                if not shard_state.get("stage1_done") or not candidates.exists():
                    _ensure_disk_space(root, getattr(args, "min_free_gb", 0))
                    monitor.update(phase="stage1_download", current_shard=shard_id)
                    monitor.log(f"[*] Stage 1 [{position}/{len(selected)}]: lade Index-Shard {shard_id}")
                    _download_index_shard(remote_path, local_index, limiter, monitor)
                    monitor.update(phase="stage1_scan", current_shard=shard_id)
                    candidates.parent.mkdir(parents=True, exist_ok=True)
                    temporary = candidates.with_suffix(".tmp.parquet")
                    run_stage1(connection, [str(local_index)], str(temporary))
                    os.replace(temporary, candidates)
                    count = connection.execute("SELECT count(*) FROM read_parquet(?)", [str(candidates)]).fetchone()[0]
                    monitor.shard(shard_id, stage1_done=True, stage2_done=False,
                                  candidate_count=count, next_batch=0, processed_rows=0)
                    monitor.increment(stage1_shards=1)
                    monitor.log(f"[+] Stage 1: Shard {shard_id} ergab {count:,} Kandidaten")
                    try:
                        local_index.unlink()
                    except FileNotFoundError:
                        pass
                while not stop.is_set():
                    try:
                        work_queue.put((shard_id, candidates), timeout=0.5)
                        break
                    except queue.Full:
                        continue
        except BaseException as exc:
            producer_error.append(exc)
        finally:
            connection.close()
            if not stop.is_set():
                work_queue.put(None)

    producer = threading.Thread(target=produce, name="stage1-producer", daemon=True)
    producer.start()

    connection = _new_connection(args)
    writer = _new_connection(args)
    soft404_path = root / "soft404.sqlite"
    soft404 = Soft404Index(str(soft404_path), reset=not soft404_path.exists())
    fetcher = WarcFetcher(args.cache_dir, args.workers, max_record_bytes=args.max_record_bytes,
                          limiter=limiter,
                          progress=lambda size: monitor.transfer("warc_download_bytes", size))
    processed = int(monitor.state.get("stats", {}).get("candidate_count", 0))
    budget_reached = False
    try:
        while True:
            item = work_queue.get()
            if item is None:
                break
            shard_id, candidates = item
            shard_parts = result_dir / ".parts" / shard_id
            shard_state = monitor.state.get("shards", {}).get(shard_id, {})
            next_batch = int(shard_state.get("next_batch", 0))
            shard_processed = int(shard_state.get("processed_rows", 0))
            monitor.update(phase="stage2", current_shard=shard_id)
            monitor.log(f"[*] Stage 2: analysiere Shard {shard_id} ab Batch {next_batch}")
            cursor = connection.execute(
                "SELECT * FROM read_parquet(?) QUALIFY row_number() OVER (PARTITION BY "
                "warc_filename, warc_record_offset, warc_record_length ORDER BY endpoint_confidence DESC) = 1 "
                f"ORDER BY endpoint_confidence DESC, fetch_time DESC NULLS LAST OFFSET {shard_processed}",
                [str(candidates)])
            names = [column[0] for column in cursor.description]
            batch_index = next_batch
            while True:
                wanted = max(1, args.batch_size)
                if args.max_candidates:
                    remaining = args.max_candidates - processed
                    if remaining <= 0:
                        budget_reached = True
                        stop.set()
                        break
                    wanted = min(wanted, remaining)
                values = cursor.fetchmany(wanted)
                if not values:
                    break
                rows = [dict(zip(names, row_values)) for row_values in values]
                records = [(row["warc_filename"], int(row["warc_record_offset"]),
                            int(row["warc_record_length"])) for row in rows]
                _ensure_disk_space(root, getattr(args, "min_free_gb", 0))
                prepass = index_soft404_rows(rows, fetcher, soft404,
                                             max_body_bytes=args.max_body_bytes,
                                             parse_workers=args.parse_workers)
                enriched, metrics = enrich_rows(rows, fetcher,
                                                max_body_bytes=args.max_body_bytes,
                                                soft404_index=soft404,
                                                parse_workers=args.parse_workers)
                output = shard_parts / f"batch-{batch_index:06d}.parquet"
                _write_result_batch(writer, enriched, output)
                if not args.keep_warc_cache:
                    fetcher.remove_many(records)
                monitor.add_results(enriched)
                states = {"likely_vulnerable_count": 0, "confirmed_count": 0,
                          "cve_candidate_count": 0, "product_detection_count": 0}
                state_keys = {"LIKELY_VULNERABLE": "likely_vulnerable_count",
                              "CONFIRMED": "confirmed_count", "CVE_CANDIDATE": "cve_candidate_count",
                              "PRODUCT_DETECTED": "product_detection_count"}
                for result in enriched:
                    key = state_keys.get(result.get("evidence_state"))
                    if key:
                        states[key] += 1
                monitor.increment(**prepass, **metrics, **states)
                monitor.update(disk_free_bytes=shutil.disk_usage(root).free)
                processed += len(rows)
                shard_processed += len(rows)
                batch_index += 1
                monitor.shard(shard_id, next_batch=batch_index, processed_rows=shard_processed)
            if stop.is_set():
                _compact_result_shard(writer, shard_parts, result_dir / f"part-{shard_id}.parquet")
                break
            _compact_result_shard(writer, shard_parts, result_dir / f"part-{shard_id}.parquet")
            monitor.shard(shard_id, stage2_done=True)
            monitor.increment(stage2_shards=1)
            try:
                candidates.unlink()
            except FileNotFoundError:
                pass
            monitor.log(f"[+] Stage 2: Shard {shard_id} abgeschlossen")
    finally:
        stop.set()
        soft404.close()
        connection.close()
        writer.close()
        producer.join()
    if producer_error:
        raise producer_error[0]
    if budget_reached:
        monitor.update(phase="budget_reached")
        monitor.log(f"[+] Kandidatenbudget von {args.max_candidates:,} erreicht; Lauf kann spaeter fortgesetzt werden")
        return
    monitor.update(phase="complete")
    monitor.log(f"[+] Streaming-Scan abgeschlossen. Parquet-Dataset: {result_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive Common Crawl CVE candidate generator")
    parser.add_argument("-n", "--num-files", type=int, default=5)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--crawl")
    parser.add_argument("-o", "--output", default="security_candidates.parquet")
    parser.add_argument("--stage1-output", default="url_candidates.parquet")
    parser.add_argument("--candidate-parquet", help="Skip Stage 1 and enrich an existing candidate parquet")
    parser.add_argument("--stage1-only", action="store_true")
    parser.add_argument("--max-candidates", type=int, default=5000,
                        help="WARC budget; 0 means unlimited (default: 5000)")
    parser.add_argument("--cache-dir", default=".cache/warc")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--parse-workers", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=250)
    parser.add_argument("--max-record-bytes", type=int, default=8_000_000)
    parser.add_argument("--max-body-bytes", type=int, default=2_000_000)
    parser.add_argument("--soft404-db", default=".cache/soft404.sqlite")
    parser.add_argument("--no-global-soft404", action="store_true",
                        help="Disable the full-candidate similarity prepass")
    parser.add_argument("--memory", default="6GB")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--update-cves", action="store_true",
                        help="Refresh CVE.org/NVD/GHSA/vendor knowledge before scanning")
    parser.add_argument("--cve-cache-dir", default=".cache/cve")
    parser.add_argument("--stream-shards", action="store_true",
                        help="Pipeline local, resumable index shards into Stage 2")
    parser.add_argument("--bandwidth-mbit", type=float, default=0,
                        help="Shared download limit in Mbit/s; streaming mode required for Stage 1")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--dashboard-host", default="127.0.0.1")
    parser.add_argument("--dashboard-port", type=int, default=8080)
    parser.add_argument("--runtime-dir", default=".cache/stream")
    parser.add_argument("--state-file", default="scan-status.json")
    parser.add_argument("--log-file", default="scan.log")
    parser.add_argument("--keep-warc-cache", action="store_true")
    parser.add_argument("--min-free-gb", type=float, default=10,
                        help="Abort safely before free disk falls below this value")
    args = parser.parse_args()
    if duckdb is None:
        sys.exit("duckdb is required: python -m pip install -r requirements.txt")
    if args.bandwidth_mbit < 0 or args.min_free_gb < 0:
        sys.exit("--bandwidth-mbit/--min-free-gb cannot be negative")
    if (args.dashboard or args.bandwidth_mbit) and not args.stream_shards:
        sys.exit("--dashboard/--bandwidth-mbit require --stream-shards")
    if args.stream_shards and (args.candidate_parquet or args.stage1_only):
        sys.exit("--stream-shards cannot be combined with --candidate-parquet/--stage1-only")
    monitor = RuntimeMonitor(args.state_file, args.log_file) if args.stream_shards or args.dashboard else None
    dashboard = DashboardServer(monitor, args.dashboard_host, args.dashboard_port) if args.dashboard else None
    if dashboard:
        dashboard.start()
        monitor.log(f"[+] Dashboard: http://{args.dashboard_host}:{args.dashboard_port}")
    if args.update_cves:
        from src import settings
        from src.cve_importer import update_file
        from src.cve_matcher import load_rules

        print("[*] Updating CVE knowledge from vendor, CVE.org, GHSA and NVD")
        generated_rules = Path(args.cve_cache_dir) / "cve_rules.generated.json"
        update_metrics = update_file(str(ROOT / "data" / "cve_rules.json"), args.cve_cache_dir,
                                     output=str(generated_rules))
        settings.CVE_RULES[:] = load_rules(generated_rules)
        print(json.dumps(update_metrics, indent=2))

    if args.stream_shards:
        try:
            crawl = args.crawl or get_latest_crawl()
            paths = get_warc_parquet_paths(crawl)
            selected = paths if args.full else paths[:args.num_files]
            limiter = BandwidthLimiter(args.bandwidth_mbit)
            run_streaming(args, crawl, selected, monitor, limiter)
            monitor.finish()
            return
        except BaseException as exc:
            monitor.log(f"[!] Scan abgebrochen: {exc}")
            monitor.finish(str(exc))
            raise
        finally:
            if dashboard:
                dashboard.close()

    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET max_memory='{_sql_string(args.memory)}'")
    con.execute(f"SET threads={max(1, args.threads)}")
    stage1 = args.candidate_parquet or args.stage1_output
    if not args.candidate_parquet:
        crawl = args.crawl or get_latest_crawl()
        paths = get_warc_parquet_paths(crawl)
        selected = paths if args.full else paths[:args.num_files]
        print(f"[*] Stage 1: {crawl}, {len(selected)}/{len(paths)} index shards")
        run_stage1(con, selected, stage1)
    if args.stage1_only:
        print(f"[+] Stage-1 candidates: {stage1}")
        return

    limit = "" if args.max_candidates == 0 else f" LIMIT {max(1, args.max_candidates)}"
    candidate_sql = (
        f"SELECT * FROM read_parquet('{_sql_string(stage1)}') "
        "QUALIFY row_number() OVER (PARTITION BY warc_filename, warc_record_offset, warc_record_length "
        "ORDER BY endpoint_confidence DESC) = 1 "
        f"ORDER BY endpoint_confidence DESC, fetch_time DESC NULLS LAST{limit}")
    fetcher = WarcFetcher(args.cache_dir, args.workers, max_record_bytes=args.max_record_bytes)
    metrics = {"candidate_count": 0, "mime_skipped_count": 0,
               "warc_record_count": 0, "warc_failure_count": 0, "result_count": 0}
    batch_size = max(1, args.batch_size)
    soft404_index = None
    if not args.no_global_soft404:
        soft404_index = Soft404Index(args.soft404_db, reset=True)
        print("[*] Soft-404 prepass: indexing response hashes across all batches")
        prepass = {"soft404_indexed_count": 0, "soft404_index_failure_count": 0}
        cursor = con.execute(candidate_sql)
        names = [column[0] for column in cursor.description]
        while values := cursor.fetchmany(batch_size):
            rows = [dict(zip(names, row_values)) for row_values in values]
            batch_metrics = index_soft404_rows(rows, fetcher, soft404_index,
                                               max_body_bytes=args.max_body_bytes,
                                               parse_workers=args.parse_workers)
            for key in prepass:
                prepass[key] += batch_metrics[key]
        metrics.update(prepass)

    print("[*] Stage 2: streaming selected WARC records (PASSIVE_ONLY=true)")
    cursor = con.execute(candidate_sql)
    names = [column[0] for column in cursor.description]
    handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", encoding="utf-8", delete=False)
    try:
        with handle:
            while values := cursor.fetchmany(batch_size):
                rows = [dict(zip(names, row_values)) for row_values in values]
                enriched, batch_metrics = enrich_rows(
                    rows, fetcher, max_body_bytes=args.max_body_bytes, soft404_index=soft404_index,
                    parse_workers=args.parse_workers)
                for row in enriched:
                    handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
                for key, value in batch_metrics.items():
                    metrics[key] = metrics.get(key, 0) + value
        if not metrics["result_count"]:
            raise RuntimeError("Stage 2 produced no results; Stage-1 parquet remains available")
        _jsonl_to_parquet(con, handle.name, args.output)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        if soft404_index:
            soft404_index.close()
    summary = con.execute(f"SELECT evidence_state, count(*) FROM read_parquet('{_sql_string(args.output)}') GROUP BY ALL").fetchall()
    metrics.update({"product_detection_count": 0, "cve_candidate_count": 0,
                    "likely_vulnerable_count": 0, "confirmed_count": 0,
                    "false_positive_rate": None})
    metric_names = {"PRODUCT_DETECTED": "product_detection_count",
                    "CVE_CANDIDATE": "cve_candidate_count",
                    "LIKELY_VULNERABLE": "likely_vulnerable_count", "CONFIRMED": "confirmed_count"}
    metrics.update({metric_names[state]: count for state, count in summary})
    print("[+] Output:", args.output)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
