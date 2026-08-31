# cc-scan: passive Common-Crawl evidence pipeline

`cc-scan` erzeugt nachvollziehbare Security- und CVE-Kandidaten aus dem Common-Crawl-URL-Index und den zugehörigen archivierten HTTP-Responses. Es ist kein Exploit-Scanner. Der Standardmodus ist immer `PASSIVE_ONLY=true`; es gibt keinen Code zum Verwenden gefundener Secrets, Beanspruchen fremder Provider-Ressourcen oder aktiven Testen von Internet-Systemen.

## Architektur

```text
URL-Index-Parquet (Milliarden Zeilen)
  -> Stage 1: Status-/URL-Prefilter, Normalisierung, Produkt-Hinweise
  -> Candidate Parquet
  -> Stage 2: deduplizierte HTTP Range Requests auf WARC Records + Cache
  -> HTTP-Parser: Header, Redirect, Cookie-Namen, Body, HTML/JS/JSON/XML
  -> Produkt- und Versions-Evidenz, Soft-404/SPA, Secrets (nur Typen)
  -> externe CVE-Regeln + Konfiguration/Protokoll + Confidence
  -> finales Evidence Parquet
```

Stage 1 optimiert Recall. Die erlaubten Statuscodes umfassen 200, 201, 204, Redirects, Client-/Auth-/Methodenfehler einschließlich 405 sowie relevante 5xx. Ein Status ist nur Evidenz. `url_path` und `url_query` bleiben getrennt; `normalized_url` verliert die Query nicht. Stage 2 streamt begrenzte Batches, lädt ausschließlich selektierte WARC-Records per `offset + length`, dedupliziert sie, verarbeitet sie parallel, cached sie lokal, begrenzt Record-/Body-Größe und überspringt eindeutige Bild-/Audio-/Video-/Font-MIME-Typen. Gzip, Deflate, HTTP-Chunking und Brotli werden mit Dekompressionslimits verarbeitet.

## Evidenzzustände und Confidence

- `PRODUCT_DETECTED`: Produkt/Endpoint beobachtet; kein belastbarer CVE-Match.
- `CVE_CANDIDATE`: Produkt durch Response-Evidenz bestätigt, HTTP-Endpoint/Voraussetzung passt, Version fehlt oder ist nicht belastbar.
- `LIKELY_VULNERABLE`: normalisierte Version erscheint im betroffenen Bereich. Backport-/Patchstatus bleibt unbekannt.
- `CONFIRMED`: nur ein eindeutiger Nachweis in der archivierten Response selbst, derzeit z. B. tatsächlich enthaltener Secret-Inhalt. Ein URL- oder Versionsmatch kann diesen Zustand nie erzeugen.

`overall_confidence` ist die feste gewichtete Summe:

```text
0.30 product + 0.20 version + 0.15 endpoint + 0.10 configuration
+ 0.15 CVE match + 0.05 response quality + 0.05 freshness
```

Fehlende Evidenz trägt 0 bei; die Gewichte werden nicht neu normiert. Dadurch wird Unsicherheit sichtbar und fehlende Konfiguration nicht künstlich kompensiert. Die Einzelwerte bleiben im Ergebnis erhalten. Response-Confidence sinkt bei Soft-404, SPA-Fallback, generischen WAF-/Login- und CDN-Fehlerseiten. Freshness ist 1.0 bis 30 Tage, sinkt moderat bis Tag 90 und danach exponentiell bis zu einem historischen Mindestwert von 0.1. Nichts wird wegen Alters hart entfernt.

## Produktnachweis, CVE-Nachweis und Grenzen

Ein Pfad wie `/geoserver/wms` trägt nur 0.30 Produktgewicht. Erst Response-Marker können das Produkt bestätigen. Ein CVE wird aus [data/cve_rules.json](data/cve_rules.json) zugemischt; Nicht-HTTP-Protokolle wie OpenWire oder SMTP werden von Common Crawl ausdrücklich nicht zum CVE-Kandidaten hochgestuft. Versionsvergleiche zerlegen numerische und textuelle Komponenten statt String-Sortierung zu verwenden.

Common Crawl ist historisch, unvollständig und GET-zentriert. Es sieht keine heutigen DNS-/Patchzustände, interne Konfiguration, Paket-Backports oder andere Protokolle. Eine zum Crawl-Zeitpunkt betroffen erscheinende Version ist daher `VERSION_APPEARS_AFFECTED`, nicht automatisch verwundbar. Vendor-Patches auf unveränderter Versionsnummer sind insbesondere bei GeoServer/Distributionen möglich.

Soft-404 und SPA-Erkennung verwendet einen diskgestützten Prepass über die komplette ausgewählte Kandidatenmenge. Der SQLite-Index vergleicht hostweit und batchübergreifend Body-Hash, normalisierten Hash, Titel, Root-Dokument und Textmarker. Gibt es keinen archivierten Vergleichspfad, bleibt die Aussage entsprechend schwächer. Secret-Inhalte werden nie gespeichert; `evidence_json` enthält nur Typ, Vorhandensein und Anzahl. Cookie-Werte werden ebenfalls verworfen.

Takeover-Signale sind von DNS-Evidenz getrennt. `src/dns_evidence.py` akzeptiert eine bereits erhobene CNAME-Kette und erzeugt höchstens `TAKEOVER_HINT`. Direkte Provider-Hosts werden abgewiesen. Es findet keine Ressourcenübernahme statt.

## Regeln pflegen

- Response-Marker: [data/product_fingerprints.json](data/product_fingerprints.json)
- CVE-Wissensbasis: [data/cve_rules.json](data/cve_rules.json)
- Migration/Audit alter Regeln: [docs/RULE_MIGRATION.md](docs/RULE_MIGRATION.md)

Vendor Advisories sind beim Aktualisieren der Regeln vorrangig. NVD/CVE.org, CISA KEV und GHSA können ergänzen; Versionsgrenzen werden nicht geraten. Regeln ohne normalisierte Grenzen können maximal Kandidaten erzeugen. `suggested_validation_tags` sind lediglich Metadaten für eine später autorisierte Validierung, kein Vulnerability-Beweis.

Der Updater lädt konfigurierte Vendor-Advisories sowie CVE.org-CNA-, GHSA- und NVD-Daten, cached Antworten, normalisiert CPE-/SemVer-Bereiche und priorisiert `Vendor > CVE.org > GHSA > NVD`. Handkuratierte Vendor-Grenzen werden nicht überschrieben:

```bash
.venv/bin/python update_cves.py
```

`NVD_API_KEY` und `GITHUB_TOKEN` sind optional und erhöhen lediglich die API-Limits. Beim automatischen Update eines Scans wird eine generierte Regeldatei unter `.cache/cve/` verwendet, damit die kuratierte Quelldatei unverändert bleibt.
Ohne `GITHUB_TOKEN` verwendet der Updater vorhandene GHSA-Cacheeinträge, startet aber keine neuen
GHSA-API-Abfragen, da das anonyme Stundenkontingent kleiner als der Regelsatz ist und oft mit anderen
Prozessen geteilt wird. Mit Token prüft er das verbleibende Kontingent, reserviert einen Request und
begrenzt die Parallelität auf zwei. Fehlendes Kontingent wird als übersprungene Quelle gemeldet, statt
zu Beginn einen Burst aus Rate-Limit-Fehlern zu erzeugen.

## Ausführen

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# Stage 1 und höchstens 5.000 WARC-Records in Stage 2
.venv/bin/python pipeline_runner.py -n 5

# Nur High-Recall URL-Kandidaten
.venv/bin/python pipeline_runner.py -n 5 --stage1-only

# Vorhandenes Candidate-Parquet anreichern
.venv/bin/python pipeline_runner.py --candidate-parquet url_candidates.parquet \
  --max-candidates 20000 --workers 16

# Gesamten neuesten Crawl mit automatisch ermittelter Systemkapazität scannen
./start-full.sh

# Streaming-Profil: i5-6600, etwa 300 GB Speicher, insgesamt 20 Mbit/s
./start-300gb.sh
```

## Streaming-Modus und Web-Dashboard

`start-300gb.sh` ist für vier CPU-Kerne und begrenzten Plattenspeicher ausgelegt. Es lädt immer nur
einen vollständigen Index-Shard lokal, erzeugt dessen Kandidaten und gibt ihn sofort für Stage 2 frei.
Während Stage 2 WARC-Records verarbeitet, lädt Stage 1 bereits den nächsten Shard. Index- und
WARC-Downloads teilen sich einen gemeinsamen Token-Bucket von insgesamt 20 Mbit/s.

Der lokale Index-Shard wird nach dem Filtern gelöscht. WARC-Dateien bleiben nur für Soft-404-Prepass
und Analyse desselben Batches im Cache und werden danach ebenfalls gelöscht. Ergebnisse landen
shardweise unter `security_results/<crawl-id>/`, Zwischenstand und Log in `scan-status.json` und
`scan.log`. Ein abgebrochener Lauf wird mit demselben Befehl anhand abgeschlossener Shards und Batches
fortgesetzt.

Für einen bewusst vollständigen Neustart ab Shard 0 werden nur die Laufdaten des gewählten Crawls,
der WARC-Cache sowie Status und Log verworfen:

```bash
./start-300gb.sh --fresh-start
```

Das 300-GB-Profil bindet das Dashboard ausschließlich an die aktuelle Tailscale-IPv4-Adresse des
Rechners (zum Beispiel `http://100.x.y.z:8080`). Damit ist es aus dem Tailnet erreichbar, soweit die
Tailscale-ACL Port 8080 erlaubt, aber nicht zusätzlich über das LAN-Interface veröffentlicht. Die
konkrete URL wird beim Start ausgegeben. Das Dashboard zeigt Phase, Shards, Kandidaten,
Ergebniszustände, aktuelle und übertragene Daten, freien Speicher, letzte Funde und Logs.
Ohne Tailscale kann der normale Runner weiterhin lokal gestartet oder ein SSH-Tunnel verwendet werden:

```bash
ssh -L 8080:127.0.0.1:8080 user@scan-machine
```

Nach Ende des Scans kann der gespeicherte Stand erneut angezeigt werden:

```bash
.venv/bin/python dashboard_server.py
```

Alle Ergebnisteile lassen sich gemeinsam abfragen:

```sql
SELECT * FROM read_parquet('security_results/*/*.parquet', union_by_name=true);
```

Die harte Bandbreitenbegrenzung erfordert, dass Stage 1 über den Streaming-Downloader läuft. Dadurch
werden die kompletten Index-Shards übertragen. Beim Crawl `CC-MAIN-2026-34` sind das rund 181 GB statt
etwa 80 GB projizierter Spalten über DuckDB-HTTP-Range-Requests. Zusammen mit geschätzt rund 220 GB
WARC-Daten sind etwa 400 GB Traffic plausibel. Bei 20 Mbit/s sind allein dafür mindestens 45 Stunden
nötig; Millionen kleiner Range-Requests können den realen Lauf auf mehrere Tage verlängern. Der lokale
Spitzenbedarf bleibt dagegen begrenzt: ein Index-Shard, höchstens ein WARC-Batch, Kandidatenteile,
Soft-404-Index und finale Ergebnisse. `--keep-warc-cache` sollte auf einer 300-GB-Maschine nicht
verwendet werden.

Auf dem aktuell geprüften System setzt `start-full.sh` 12 DuckDB-/Parser-Threads, 36 parallele WARC-Downloads und Batches von 288 Records. Das RAM-Budget ist das kleinere von 75 % des Gesamtspeichers und dem aktuell verfügbaren Speicher abzüglich 3 GiB Reserve; dadurch werden laufende Anwendungen berücksichtigt. Die Werte werden bei jedem Start neu berechnet. Mit `--max-record-bytes`, `--max-body-bytes`, `--batch-size`, `--cache-dir`, `--workers`, `--parse-workers`, `--memory` und `--threads` lassen sich Ressourcenbudgets überschreiben. Kandidaten werden nach Endpoint-Confidence und Aktualität priorisiert. `--max-candidates 0` hebt das Stage-2-Budget bewusst auf.

Die RTX 4060 Ti wird absichtlich nicht verwendet. Der dominante Aufwand besteht aus Netzwerk-I/O, DuckDB-Parquet-Scan, vielen kleinen Dekompressionen und Python-RegEx/Parsing. DuckDBs GPU-Community-Erweiterung beschleunigt ausgewählte Aggregationen, nicht diese Operatorenkette; CPU-/RAM-/I/O-Tuning ist hier wirksamer.

## Tests und Messwerte

```bash
python -m unittest discover -v
```

Der Runner meldet `candidate_count`, deduplizierte `warc_record_count`, Soft-404-Index-/MIME-/Fetch-Metriken, Resultate und Counts je Evidenzzustand. Der Testkorpus deckt die geforderten Positiv-/Negativfälle, Brotli, den batchübergreifenden Index und CVE-Quellnormalisierung ab. Das ist kein belastbarer Internet-FPR-Benchmark. Dafür muss ein manuell gelabeltes, zeitlich und produktseitig stratifiziertes Parquet ergänzt werden.

## Verifizierte Designquellen

- [Common Crawl URL Index schema](https://commoncrawl.org/blog/url-index)
- [Apache ActiveMQ advisory zu CVE-2023-46604](https://activemq.apache.org/news/cve-2023-46604)
- [GeoServer-Hinweise zu CVE-2024-36401 und verfügbaren Patches](https://geoserver.org/vulnerability/2024/09/12/cve-2024-36401.html)
- [Palo Alto Networks Advisory zu CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [NVD Vulnerability API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE Services und CVE JSON 5](https://www.cve.org/allresources/cveservices)
- [GitHub Global Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [DuckDB GPU Community Extension](https://duckdb.org/community_extensions/extensions/gpudb)
