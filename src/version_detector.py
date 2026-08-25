from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs

from .response_parser import ParsedResponse


@dataclass(frozen=True)
class DetectedVersion:
    product: str
    raw_version: str
    normalized_version: str
    version_source: str
    version_confidence: float


BODY_PATTERNS = {
    "GeoServer": [r"GeoServer(?: version)?[ /:v-]*(\d+(?:\.\d+){1,3}(?:[-._][0-9A-Za-z]+)?)"],
    "Apache Tomcat": [r"Apache Tomcat[/ ](\d+(?:\.\d+){1,3})", r"Apache-Coyote/(\d+(?:\.\d+){1,3})"],
    "Grafana": [r"Grafana(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?)"],
    "jQuery": [r"jQuery(?: JavaScript Library)? v?(\d+(?:\.\d+){1,3})"],
    "PDF.js": [r"(?:pdfjsVersion|PDF\.js)[\s=:v'\"]+(\d+(?:\.\d+){1,3})"],
    "Langflow": [r"Langflow(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Jenkins": [r"Jenkins(?: ver\.| version|/| v)?[ :=-]*(\d+(?:\.\d+){1,3})",
                r"x-jenkins:\s*(\d+(?:\.\d+){1,3})"],
    "GitLab": [r"GitLab(?: Community Edition| Enterprise Edition| CE| EE)?[ /v-]*(\d+(?:\.\d+){1,3})",
               r"gitlabVersion[\"']?\s*[:=]\s*[\"'](\d+(?:\.\d+){1,3})"],
    "Atlassian Confluence": [r"ajs-version-number[\"'][^>]*content=[\"'](\d+(?:\.\d+){1,3})",
                              r"Confluence(?: version)?[ /v:-]*(\d+(?:\.\d+){1,3})"],
    "JetBrains TeamCity": [r"TeamCity(?: Professional| Enterprise)?(?: Version| version|/| v)?[ :=-]*(\d{4}\.\d+(?:\.\d+)?)"],
    "PHP": [r"PHP/(\d+(?:\.\d+){1,3})"],
    "Spring Framework": [r"Spring Framework(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Spring Cloud Config": [r"Spring Cloud Config(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3}(?:\.RELEASE)?)"],
    "Apache OFBiz": [r"Apache OFBiz(?: Release| version|/| v)?[ :=-]*(\d+(?:\.\d+){1,3})"],
    "Elasticsearch": [r"\"number\"\s*:\s*\"(\d+(?:\.\d+){1,3})\"",
                      r"Elasticsearch(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Nacos": [r"Nacos(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Apache Solr": [r"(?:solr-spec-version|Solr(?: Specification Version)?)[\"' :=/v-]+(\d+(?:\.\d+){1,3})"],
    "Fortinet FortiOS": [r"FortiOS(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Ivanti Sentry": [r"(?:MobileIron|Ivanti) Sentry(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "WordPress Automatic": [r"(?:wp-automatic|WordPress Automatic)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "WordPress": [r"generator[\"'][^>]*content=[\"']WordPress\s+(\d+(?:\.\d+){1,3})"],
    "Gutenberg": [r"Gutenberg(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Roundcube Webmail": [r"Roundcube Webmail(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "cPanel": [r"cPanel(?: & WHM)?(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,4})"],
    "VMware ESXi": [r"VMware ESXi(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "WS_FTP Server": [r"WS_FTP Server(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "VMware Workspace ONE Access": [r"(?:Workspace ONE Access|Identity Manager)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Citrix NetScaler Gateway": [r"(?:NetScaler|Citrix Gateway)(?: ADC)?(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3}(?:-[\w.]+)?)"],
    "Apache Struts": [r"Apache Struts(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Apache HugeGraph": [r"HugeGraph(?:-Server)?(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Aegon Life": [r"Aegon Life(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "aiohttp": [r"aiohttp/(\d+(?:\.\d+){1,3})"],
    "Adobe Commerce": [r"(?:Adobe Commerce|Magento)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3}(?:-p\d+)?)"],
    "Adobe ColdFusion": [r"ColdFusion(?: Server)?(?: v|/| version[=: ]+)(20\d{2}(?:\.\d+)?)"],
    "Joomla": [r"generator[\"'][^>]*content=[\"']Joomla!?\s*(\d+(?:\.\d+){1,3})"],
    "Apache CouchDB": [r"\"version\"\s*:\s*\"(\d+(?:\.\d+){1,3})\""],
    "Citrix ShareFile": [r"(?:ShareFile|StorageZones Controller)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "ConnectWise ScreenConnect": [r"(?:ScreenConnect|ConnectWise Control)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Microsoft Exchange": [r"x-owa-version:\s*(\d+(?:\.\d+){2,4})",
                           r"Exchange Server(?: v|/| version[=: ]+)(\d+(?:\.\d+){2,4})"],
    "Microsoft SharePoint": [r"microsoftsharepointteamservices:\s*(\d+(?:\.\d+){2,4})"],
    "Underscore.js": [r"(?:Underscore(?:\.js)?|_\.VERSION)(?: v|/| version|\s*=)?[\"' :=-]*(\d+(?:\.\d+){1,3}(?:-\d+)?)"],
    "ini": [r"(?:npm )?ini(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
    "Axios": [r"(?:axios(?:\.VERSION)?)(?: v|/|\s*=)?[\"' :=-]*(\d+(?:\.\d+){1,3})"],
    "Semver": [r"(?:node-semver|SemVer)(?: v|/| version[=: ]+)(\d+(?:\.\d+){1,3})"],
}


PATH_PATTERNS = {
    "jQuery": [r"jquery(?:@|[-_/])v?(\d+(?:\.\d+){1,3})"],
    "PDF.js": [r"pdf(?:\.min)?(?:@|[-_/])v?(\d+(?:\.\d+){1,3})"],
    "Apache Log4j": [r"log4j-core[-_/]v?(\d+(?:\.\d+){1,3})"],
    "Underscore.js": [r"underscore(?:\.min)?[-_/]v?(\d+(?:\.\d+){1,3}(?:-\d+)?)"],
    "Axios": [r"axios(?:\.min)?[-_/]v?(\d+(?:\.\d+){1,3})"],
    "Semver": [r"(?:node-)?semver(?:\.min)?[-_/]v?(\d+(?:\.\d+){1,3})"],
    "ini": [r"(?:^|/)ini(?:\.min)?[-_/]v?(\d+(?:\.\d+){1,3})"],
}


def normalize_version(raw: str) -> str:
    value = raw.strip().lstrip("vV").replace("_", ".")
    return re.sub(r"[^0-9A-Za-z.+-].*$", "", value)


def detect_version(product: str, path: str, query: str, response: ParsedResponse) -> DetectedVersion | None:
    for pattern in BODY_PATTERNS.get(product, []):
        match = re.search(pattern, response.text, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "response_body", 0.95)
    header_text = " ".join(f"{k}: {response.headers.get(k, '')}" for k in (
        "server", "x-powered-by", "x-grafana-version", "x-jenkins", "x-teamcity-node-id",
        "x-gitlab-meta", "x-elastic-product", "x-owa-version", "x-feserver",
        "microsoftsharepointteamservices"))
    for pattern in BODY_PATTERNS.get(product, []):
        match = re.search(pattern, header_text, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "response_header", 0.90)
    for key in ("ver", "version", "v"):
        for raw in parse_qs(query, keep_blank_values=True).get(key, []):
            if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?", raw, re.I):
                return DetectedVersion(product, raw, normalize_version(raw), "url_query", 0.72)
    for pattern in PATH_PATTERNS.get(product, []):
        match = re.search(pattern, path, re.I)
        if match:
            raw = match.group(1)
            return DetectedVersion(product, raw, normalize_version(raw), "url_path", 0.75)
    return None


def version_key(version: str) -> tuple:
    """Natural product-version ordering; handles suffixes without string sorting."""
    parts = re.findall(r"\d+|[A-Za-z]+", version.replace("~", "-"))
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts)


def compare_versions(left: str, right: str) -> int:
    a, b = version_key(left), version_key(right)
    width = max(len(a), len(b))
    pad = (0, 0)
    a, b = a + (pad,) * (width - len(a)), b + (pad,) * (width - len(b))
    return (a > b) - (a < b)
