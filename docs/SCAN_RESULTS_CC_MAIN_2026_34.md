# Auswertung: CC-MAIN-2026-34

## Kurzfazit

Der passive Lauf über Common-Crawl-Responses lieferte 782.932 Evidenzzeilen
aus 300 Parquet-Teilen. Davon sind 4.160 Zeilen als
`LIKELY_VULNERABLE` und 692 als `CONFIRMED` klassifiziert. Das sind
archivierte Beobachtungen, keine Aussage über den heutigen Zustand der
jeweiligen Systeme. Es wurde keine aktive Validierung durchgeführt.

Die höchste Priorität für eine spätere, ausdrücklich autorisierte
Validierung haben die kritisch bewerteten CVE-Kandidaten mit ausreichender
Response-Evidenz. Ein Kontakt zu betroffenen Betreibern oder eine
Veröffentlichung von Hostnamen/Secret-Inhalten ist nicht Bestandteil dieses
Reports.

## Datenbasis und Grenzen

- Crawl: `CC-MAIN-2026-34`
- Eingelesene Ergebnisdateien: 300 (`security_results/CC-MAIN-2026-34/*.parquet`)
- Beobachtungszeitraum der archivierten Responses: 7. bis 20. August 2026
- Eindeutige normalisierte URLs: 774.565
- Eindeutige registrierte Domains: 139.389
- Crawl-Alter beim Abruf: 7 bis 23 Tage
- Mittlere Gesamt-Confidence: 0,338

Common Crawl ist historisch und GET-zentriert. Ein Produkt-, Versions- oder
Pfadtreffer beweist weder die heutige Erreichbarkeit noch Patchstatus,
Konfiguration oder Besitzverhältnisse. Insbesondere können Distributionen
Backports mit unveränderter Versionsnummer enthalten. Die Statusnamen des
Pipelineschemas sind daher als Evidenzklassen, nicht als Live-Befunde zu
lesen.

## Evidenzklassen

| Evidenzklasse | Zeilen | Anteil |
| --- | ---: | ---: |
| `PRODUCT_DETECTED` | 778.080 | 99,38 % |
| `LIKELY_VULNERABLE` | 4.160 | 0,53 % |
| `CONFIRMED` | 692 | 0,09 % |
| **Gesamt** | **782.932** | **100,00 %** |

`PRODUCT_DETECTED` überwiegt erwartungsgemäß: die Pipeline erkennt damit
Produkte, Endpoints oder Dateipfade, ohne daraus einen CVE-Befund abzuleiten.
Die `CONFIRMED`-Einträge bezeichnen eine eindeutige Evidenz in der archivierten
Response selbst; sie sind ebenfalls keine aktuelle externe Bestätigung.

## Verteilung der Beobachtungen

| Kategorie | Zeilen |
| --- | ---: |
| Beobachteter Produkt- oder Endpoint-Hinweis | 539.577 |
| Beobachteter Exposition-Endpoint | 157.079 |
| Beobachteter Pfad zu potenziell sensibler Datei | 85.011 |
| Öffentliches Quellartefakt | 573 |
| Verwundbar wirkende Client-Komponente | 314 |
| Archivierter Secret-Inhaltsnachweis | 309 |
| Client-Komponente ohne Vulnerability-Match | 69 |

Bei den 692 `CONFIRMED`-Zeilen entfallen 309 auf archivierte
Secret-Inhaltsnachweise, 234 auf Produkt-/Endpoint-Evidenz und 149 auf
Exposition-Endpoint-Evidenz. Secret-Werte selbst werden nicht gespeichert
oder in diesem Report wiedergegeben.

## CVE-Kandidaten mit höchster Häufigkeit

Die folgenden Werte beziehen sich ausschließlich auf `LIKELY_VULNERABLE`.
Die Domainanzahl ist nach registrierter Domain dedupliziert; mehrere URLs
können daher zu derselben Domain gehören.

| CVE | Schweregrad in der Regelbasis | Zeilen | Domains | mittlere Confidence |
| --- | --- | ---: | ---: | ---: |
| CVE-2023-29357 | kritisch | 2.630 | 169 | 0,750 |
| CVE-2023-42793 | kritisch | 445 | 44 | 0,701 |
| CVE-2023-38000 | mittel | 425 | 15 | 0,707 |
| CVE-2020-11022 | nicht hinterlegt | 350 | 223 | 0,665 |
| CVE-2023-7028 | kritisch | 204 | 16 | 0,755 |
| CVE-2024-23897 | kritisch | 71 | 26 | 0,672 |
| CVE-2021-43798 | hoch | 24 | 2 | 0,750 |

Alle sieben kritischen Regel-IDs ergeben 3.358 Beobachtungen. Aufgrund der
archivierten Quelle und möglicher Versions-/Backport-Effekte ist dies eine
Priorisierung für Review, kein
Nachweis einer verwertbaren oder noch bestehenden Schwachstelle.

## Ergänzender High-Export

Die bereits versionierte Datei
[`all_vulnerabilities_master_HIGH.csv`](../all_vulnerabilities_master_HIGH.csv)
enthält 16 Zeilen aus einem separaten, tagbasierten High-Export:

| Klasse | Zeilen |
| --- | ---: |
| Datenbank- oder Backup-Exposition | 4 |
| Ivanti EPMM CVE-2023-35082 | 4 |
| Jupyter-Terminal ohne Authentisierung | 5 |
| Git-Repository-Exposition | 1 |
| Terraform-/Postman-Key-Exposition | 1 |
| WebLogic CVE-2020-14882 | 1 |

Dieser Export hat eine andere Klassifikation als das Parquet-Dataset und
sollte nicht mit dessen Evidenzklassen oder Zeilenzahlen zusammengezählt
werden.

## Empfohlene nächste Schritte

1. Die kritisch bewerteten Kandidaten zunächst nach Zeitstempel, Confidence,
   Produktnachweis und möglichem Backport priorisieren.
2. Vor jeder Live-Prüfung eine ausdrückliche Autorisierung und einen klaren
   Scope einholen; ohne diese nur passiv auswerten.
3. Bei autorisiertem Scope zuerst Fehlklassifikationen durch Soft-404-,
   Login- und generische Fehlerseiten ausschließen.
4. Bestätigte Secret-Hinweise über einen verantwortungsvollen, privaten
   Disclosure-Prozess behandeln; keine Werte oder betroffenen Hosts in Issues
   oder öffentlichen Reports veröffentlichen.
