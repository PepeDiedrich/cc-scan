# Audit und Migration der alten Regeln

Alle alten CVE-Zuordnungen verwendeten nur Pfad/Host/Status. Keine war passiv bereits ein bestätigter CVE-Nachweis. `Version?` und `Konfig.?` bezeichnen, ob diese Evidenz zusätzlich nötig ist. „teilweise“ heißt: Common Crawl kann Produkt, HTTP-Endpoint und manchmal Version erkennen, aber nicht alle Exploit-Voraussetzungen.

| Alte Regel | Produkt | bisherige CVE/Aussage | beobachtetes Signal | Protokoll | Version? | Konfig.? | passiv? | neue Klassifizierung |
|---|---|---|---|---|---:|---:|---|---|
| `/app/rest/...` | TeamCity | CVE-2024-27198 RCE | REST-Endpoint | HTTP | ja | ja | teilweise | PRODUCT_HINT; nach Response höchstens CVE_CANDIDATE |
| `/geoserver/(wms\|wfs\|ows)` | GeoServer | CVE-2024-36401 RCE | OGC-Endpoint | HTTP | ja | ja/Backport | teilweise | PRODUCT_HINT; Versionsmatch = LIKELY_VULNERABLE |
| `/jolokia/...`, `:8161/admin` | Jolokia/ActiveMQ | CVE-2023-46604 RCE | HTTP-Management | **OpenWire** | ja | ja | nein | PRODUCT_HINT; kein HTTP-CVE-Kandidat |
| `/api/v1/totp...` | Ivanti Connect Secure | CVE-2023-46805 / CVE-2024-21887 | HTTP-API | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| `setupadministrator`, `/template/custom` | Confluence | CVE-2023-22527; Tag auch 22515 | Setup-/Template-Pfad | HTTP | ja | ja | teilweise | PRODUCT_HINT; keine Gleichsetzung mehrerer CVEs |
| `/mgmt/tm/util/bash`, `/mgmt/shared/authn/login` | F5 BIG-IP | CVE-2022-1388 | iControl REST | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| Tomcat Manager | Tomcat | generische WAR-Upload-RCE | Adminoberfläche | HTTP | ja | Auth/Schreibrecht | teilweise | PRODUCT_DETECTED / EXPOSURE_ENDPOINT_OBSERVED |
| JBoss Console/Invoker | JBoss | generische unauth RCE | Admin-/Invoker-Pfad | HTTP/RMI | ja | Auth/Deployment | gering | PRODUCT_DETECTED |
| Jenkins Script Console | Jenkins | generische RCE | Adminpfad | HTTP | ja | Auth/Berechtigung | teilweise | PRODUCT_DETECTED |
| WebLogic Console/WLS-WSAT | WebLogic | CVE-2020-14882 | Konsole/WSAT-Pfad | HTTP/SOAP | ja | ja | teilweise | PRODUCT_HINT |
| `/solr/...` | Solr | CVE-2019-17558 | Solr Admin/Config | HTTP | ja | Velocity-Konfig. | teilweise | PRODUCT_HINT |
| `eval-stdin.php` | PHPUnit | CVE-2017-9841 | spezifische Datei | HTTP | ja | Datei web-erreichbar | teilweise | ENDPOINT_HINT; Body muss PHPUnit bestätigen |
| `/_ignition/...` | Laravel Ignition | CVE-2021-3129 | Debug-Endpoint | HTTP | ja | Debug-Modus | teilweise | PRODUCT_HINT |
| Autodiscover/EWS/ECP | Exchange | ProxyLogon/ProxyShell-Sammellabel | normale Exchange-Endpunkte | HTTP | ja | mehrere Voraussetzungen | gering | PRODUCT_DETECTED; Sammel-CVE entfernt |
| `vropspluginui` | vCenter | CVE-2021-21972 | Plugin-Endpoint | HTTP | ja | Plugin vorhanden | teilweise | PRODUCT_HINT |
| `/remote/fgt_lang`, `/sslvpn` | FortiOS | CVE-2024-21762 | SSL-VPN-Oberfläche | HTTP | ja | SSL VPN | teilweise | PRODUCT_HINT |
| `/global-protect/...` | PAN-OS | CVE-2024-3400 | GlobalProtect-Seite | HTTP | ja, branch/hotfix | Gateway/Portal | teilweise | PRODUCT_HINT; Config-Confidence separat |
| `/cacti/...` | Cacti | CVE-2022-46169 | Login/Agent-Pfad | HTTP | ja | Authorization-Pfad | teilweise | PRODUCT_HINT |
| `/cfide/...` | ColdFusion | CVE-2023-26360 | Admin-/Komponentenpfad | HTTP | ja | Update-Level | teilweise | PRODUCT_HINT |
| `/service/soap` | Zimbra | CVE-2024-45519 | SOAP-Endpoint | **SMTP/postjournal** | ja | postjournal aktiv | nein | PRODUCT_HINT; kein CVE-Kandidat |
| `/goanywhere/...` | GoAnywhere | CVE-2023-0669 | Admin/API-Pfad | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| MOVEit API/Machine | MOVEit | CVE-2023-34362 | Produktendpoint | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| `/webinterface/...` | CrushFTP | CVE-2025-31161 | Weboberfläche | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| `/mifs/`, `/rs/api/v2` | Ivanti EPMM | CVE-2023-35082 | API-Pfad | HTTP | ja | ja | teilweise | PRODUCT_HINT |
| MinIO bootstrap verify | MinIO | CVE-2023-28432 Credential Leak | spezifischer Endpoint | HTTP | ja | distributed mode | gut nur mit Body | PRODUCT_HINT; erst Body kann Disclosure bestätigen |
| Nacos API | Nacos | generische unauth RCE | Produkt-API | HTTP | ja | Auth-Konfig. | teilweise | PRODUCT_DETECTED; unspezifisches RCE-Label entfernt |
| APISIX Admin/API | APISIX | CVE-2022-24112 | Admin-API | HTTP | ja | Default/weak key | teilweise | PRODUCT_HINT |
| Elasticsearch/CouchDB/etcd APIs | mehrere | unauth Exposure | normale API | HTTP | nein | Auth/ACL | teilweise | PRODUCT_DETECTED; Exposure nur bei Body/Auth-Evidenz |
| Jupyter Terminal | Jupyter | unauth RCE | Terminal-Pfad | HTTP/WebSocket | ja | Auth/Token | teilweise | PRODUCT_DETECTED |
| Selenium Grid | Selenium | unauth RCE | Hub-Endpoint | HTTP/WebDriver | ja | Auth/Netzgrenze | teilweise | PRODUCT_DETECTED |
| Druid API | Druid | CVE-2021-25646 | Cluster-API | HTTP | ja | JavaScript aktiviert | teilweise | PRODUCT_HINT |
| `/sdk/weblanguage` | Hikvision | CVE-2021-36260 | Geräteendpoint | HTTP | Firmware | ja | teilweise | PRODUCT_HINT |
| `/api/v1/validate/code` | Langflow | CVE-2025-3248 | Endpoint, oft GET=405 | HTTP | ja | Endpoint exponiert | teilweise | PRODUCT_HINT; 405 bleibt erhalten |
| Openfire Setup-JSP | Openfire | CVE-2023-32315 | Setup-Endpoint | HTTP | ja | Setup-Kontext | teilweise | PRODUCT_HINT; zuvor durch Prefilter faktisch unerreichbar |
| OAuth IdP/LogonPoint | Citrix Gateway | Tag CVE-2023-4966 | Gateway/Login | HTTP | ja | Gateway-Konfig. | gering | PRODUCT_HINT; kein Leak-Nachweis |
| AI/ML-API-Sammelregex | diverse | „unauth RCE“ | normale APIs | HTTP | je Produkt | Auth/Deployment | gering | PRODUCT_DETECTED; Sammel-RCE entfernt |
| Actuator/Admin/Monitoring/API-Schema | diverse | Exposure | Endpoint | HTTP | meist nein | Auth/Response | teilweise | EXPOSURE_ENDPOINT_OBSERVED, nicht Exposure bestätigt |
| `.env`, Git, Keys, CMS Config | Datei/Metadaten | Secret Leak | Dateipfad | HTTP | nein | echter Inhalt | gut mit Body | SECRET_FILE_PATH_OBSERVED oder SECRET_CONTENT_OBSERVED |
| SQL/Dump/Backup | Datei | DB-/Backup-Leak | Dateiname | HTTP | nein | echter Dateiinhalt | teilweise | SECRET_FILE_PATH_OBSERVED; keine Leak-Behauptung nur aus Namen |
| Source Maps/Debug/API schema | Komponente | Exposure | Dateipfad | HTTP | nein | echter Inhalt | gut mit Body | EXPOSURE_ENDPOINT_OBSERVED |
| Polyfill/BootCDN Host | Client-Asset | Supply-Chain-Aussage | Host/URL | HTTP | zeitabhängig | ausgelieferter Body/Zeit | gering | CLIENT_COMPONENT_PRESENT; kein pauschales „malicious“ |
| PDF.js Versionspfad | PDF.js | CVE-2024-4367 | Client-Datei | HTTP | ja | Renderpfad/isEvalSupported | teilweise | VULNERABLE_CLIENT_COMPONENT_PRESENT |
| jQuery Versionspfad | jQuery | CVE-2020-11022 | Client-Datei | HTTP | ja | betroffene DOM-Nutzung | teilweise | VULNERABLE_CLIENT_COMPONENT_PRESENT |
| jQuery UI | jQuery UI | CVE-2021-41182 | Client-Datei | HTTP | ja | betroffene Nutzung | teilweise | CLIENT_COMPONENT_PRESENT bis Regel importiert |
| Angular/Lodash/Bootstrap/DOMPurify/Editor | Client-Libs | generische XSS/PP | Client-Datei | HTTP | ja | betroffene API/Nutzung | teilweise | CLIENT_COMPONENT_PRESENT; generische Exploitlabels entfernt |
| `404 + direkter Provider-Host` | Provider-Asset | Takeover | Status+Providerhost | HTTP/DNS | nein | CNAME/unclaimed | nein | kein Treffer |
| Custom Domain + CNAME + Provider-Fingerprint | Provider-Service | Takeover | HTTP + gelieferte DNS-Evidenz | HTTP/DNS | nein | dangling target | teilweise | TAKEOVER_HINT, nie Übernahme |

Die alten `HIGH/MEDIUM/LOW`-Regeln und `nuclei_tags` sind nicht migriert worden, weil sie Pfadspezifität mit Beweiskraft verwechselten. Tags heißen nun `suggested_validation_tags`; alle Confidence-Werte entstehen aus einzeln gespeicherter Evidenz. Regeln mit fehlenden autoritativen Versionsgrenzen bleiben absichtlich ohne Range und können nicht `LIKELY_VULNERABLE` erzeugen.
