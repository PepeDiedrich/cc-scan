#!/usr/bin/env python3
"""
cc-scan: Multi-Vulnerability Scanner ueber Common Crawl Index-Daten (passiv).

- Findet automatisch den NEUESTEN vollstaendigen Common-Crawl-Index
- Scannt WAT-Index-Parquet-Dateien mit DuckDB nach Schwachstellen-Mustern
- Ergebnis: Parquet + CSV-Export der HIGH-Confidence-Treffer

Nutzung:
    python pipeline_runner.py                 # 5 Dateien des neuesten Crawls (Test)
    python pipeline_runner.py -n 50           # 50 Dateien
    python pipeline_runner.py --full          # kompletter Crawl (alle ~300 warc-Shards)
    python pipeline_runner.py --crawl CC-MAIN-2026-30 -n 10
"""
import argparse
import gzip
import json
import os
import sys
import urllib.request

import duckdb

COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
DATA_BASE = "https://data.commoncrawl.org/"
SQL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "master_scan.sql")


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "cc-scan/2.0"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def get_latest_crawl() -> str:
    """Gibt die ID des neuesten Crawls zurueck, dessen Index vollstaendig ist."""
    print("[*] Suche neuesten Common-Crawl-Index via collinfo.json ...")
    crawls = json.loads(http_get(COLLINFO_URL))
    for crawl in crawls:
        crawl_id = crawl["id"]
        paths_url = f"{DATA_BASE}crawl-data/{crawl_id}/cc-index-table.paths.gz"
        try:
            http_get(paths_url, timeout=30)
            print(f"[+] Neuester vollstaendiger Crawl: {crawl_id} ({crawl.get('name', '')})")
            return crawl_id
        except Exception:
            # Crawl laeuft evtl. noch / Index unvollstaendig -> naechstaelteren nehmen
            print(f"    [-] {crawl_id} Index noch unvollstaendig, pruefe aelteren Crawl ...")
            continue
    raise RuntimeError("Kein verwendbarer Crawl gefunden!")


def get_warc_parquet_paths(crawl_id: str) -> list:
    """Laedt die Shard-Liste und filtert nur subset=warc Parquet-Dateien."""
    paths_url = f"{DATA_BASE}crawl-data/{crawl_id}/cc-index-table.paths.gz"
    print(f"[*] Lade Shard-Liste: {paths_url}")
    raw = http_get(paths_url)
    lines = gzip.decompress(raw).decode().splitlines()
    warc_files = [
        DATA_BASE + line.strip()
        for line in lines
        if line.strip().endswith(".parquet") and "subset=warc" in line
    ]
    print(f"[+] {len(warc_files)} warc-Index-Shards gefunden")
    return warc_files


def main() -> None:
    parser = argparse.ArgumentParser(description="cc-scan Pipeline (Common Crawl Vulnerability Scanner)")
    parser.add_argument("-n", "--num-files", type=int, default=5,
                        help="Anzahl zu scannender Parquet-Shards (Default: 5 Testlauf)")
    parser.add_argument("--full", action="store_true",
                        help="Kompletten Crawl scannen (alle warc-Shards)")
    parser.add_argument("--crawl", type=str, default=None,
                        help="Crawl-ID erzwingen (z.B. CC-MAIN-2026-30). Default: automatisch neuester")
    parser.add_argument("-o", "--output", type=str, default="all_vulnerabilities_master.parquet",
                        help="Ausgabe-Parquet-Datei")
    parser.add_argument("--memory", type=str, default="14GB", help="DuckDB max_memory (Default: 6GB)")
    parser.add_argument("--threads", type=int, default=12, help="DuckDB Threads (Default: 4)")
    args = parser.parse_args()

    crawl_id = args.crawl or get_latest_crawl()
    all_files = get_warc_parquet_paths(crawl_id)

    batch = all_files if args.full else all_files[: args.num_files]
    print(f"[*] Crawl: {crawl_id} | Scanne {len(batch)} von {len(all_files)} Shards ...")

    with open(SQL_FILE, "r") as f:
        sql_template = f.read()

    if "__PARQUET_PATHS__" not in sql_template:
        print("[!] FEHLER: Platzhalter __PARQUET_PATHS__ fehlt in master_scan.sql")
        sys.exit(1)

    formatted_paths = ", ".join(f"'{p}'" for p in batch)
    final_sql = sql_template.replace("__PARQUET_PATHS__", formatted_paths)
    final_sql = final_sql.replace("all_vulnerabilities_master.parquet", args.output)

    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    con.execute("SET preserve_insertion_order = false;")
    con.execute(f"SET max_memory = '{args.memory}';")
    con.execute(f"SET threads = {args.threads};")

    print("[*] Starte DuckDB-Scan (das kann je nach Shard-Anzahl dauern) ...")
    con.execute(final_sql)

    # Zusammenfassung ausgeben
    print("\n[+] Scan abgeschlossen! Ergebnisse in:", args.output)
    summary = con.execute(f"""
        SELECT vulnerability_class, confidence, COUNT(*) AS treffer
        FROM read_parquet('{args.output}')
        GROUP BY ALL ORDER BY treffer DESC
    """).fetchall()
    print("\n=== Treffer nach Klasse ===")
    for row in summary:
        print(f"  {row[0]:<55} {row[1]:<7} {row[2]}")

    high = con.execute(f"""
        SELECT COUNT(*) FROM read_parquet('{args.output}') WHERE confidence = 'HIGH'
    """).fetchone()[0]
    print(f"\n=== {high} HIGH-Confidence-Treffer (zuerst pruefen!) ===")

    # HIGH-Confidence als CSV exportieren (fuer direkte Nachverifikation mit nuclei)
    csv_out = args.output.replace(".parquet", "_HIGH.csv")
    con.execute(f"""
        COPY (SELECT url_host_registered_domain, url_host_name, url, vulnerability_class, nuclei_tags
              FROM read_parquet('{args.output}') WHERE confidence = 'HIGH'
              ORDER BY vulnerability_class)
        TO '{csv_out}' (HEADER, DELIMITER ',')
    """)
    print(f"[+] HIGH-Confidence-Export: {csv_out}")

    # Takeover-Kandidaten separat (Hostliste fuer DNS-Verifikation mit subzy/nuclei)
    takeover_out = args.output.replace(".parquet", "_takeover_hosts.txt")
    con.execute(f"""
        COPY (SELECT DISTINCT url_host_name FROM read_parquet('{args.output}')
              WHERE vulnerability_class LIKE 'TAKEOVER_%' ORDER BY url_host_name)
        TO '{takeover_out}' (HEADER, DELIMITER ',')
    """)
    print(f"[+] Takeover-Hosts fuer DNS-Verifikation: {takeover_out}")


if __name__ == "__main__":
    main()
