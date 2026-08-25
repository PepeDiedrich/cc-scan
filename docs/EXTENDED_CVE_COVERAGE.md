# Extended CVE coverage

The rules added from the August 2026 audit are passive evidence rules. A product marker plus a
matching HTTP endpoint can produce `CVE_CANDIDATE`; only a detected version inside an official range
can produce `LIKELY_VULNERABLE`. Neither state proves present-day exploitability, configuration,
backport status, or reachability.

All requested identifiers are represented in `data/cve_rules.json`. The HTTP-passive set covers:

- Jenkins, GitLab, Confluence, TeamCity, PHP-CGI, Spring Framework and Spring Cloud Config;
- OFBiz, Elasticsearch, Nacos, Grafana, Solr, Check Point, FortiOS and Ivanti Sentry;
- WP Automatic, WordPress, Gutenberg, Roundcube, cPanel, WS_FTP and Workspace ONE Access;
- Citrix Gateway, Struts, HugeGraph, Aegon Life, aiohttp and Tomcat;
- Adobe Commerce, ColdFusion, Joomla, CouchDB, ShareFile, ScreenConnect, Cisco ASA/FTD,
  Exchange and SharePoint;
- Underscore.js, npm `ini`, Axios and node-semver.

Four requested identifiers are retained as non-passive audit rules and are never promoted by the
HTTP matcher:

| CVE | Actual product | Why Common Crawl cannot assess it |
|---|---|---|
| CVE-2023-43660 | Warpgate | Requires SSH public-key authentication state. |
| CVE-2024-37085 | VMware ESXi | Requires Active Directory group state and permissions. |
| CVE-2021-44228 | Apache Log4j | A web fingerprint cannot establish loaded `log4j-core`, runtime configuration, or logged attacker input. |
| CVE-2023-38606 | Apple operating systems | Local-application/kernel issue; it is not a SonicWall HTTP CVE. |

## Corrected source-list mappings

- CVE-2023-31418 is Elasticsearch uncontrolled resource consumption, not Nacos.
- CVE-2023-38000 is WordPress Core/Gutenberg stored XSS, not Elementor Pro RCE.
- CVE-2024-27954 is WP Automatic path traversal/SSRF, not Backup Migration RCE.
- CVE-2023-43660 is Warpgate SSH authentication bypass, not Roundcube.
- CVE-2024-36599 is an Aegon Life application XSS, not Ray/Anyscale.
- CVE-2023-38606 is an Apple operating-system issue, not SonicWall.
- CVE-2020-7788 affects the npm package `ini`, not Lodash.

Several CVSS values in the source list also differed from CNA values. The rule metadata uses a CNA
score when the CNA record publishes one and otherwise omits the numeric score rather than guessing.
