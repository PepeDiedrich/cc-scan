from __future__ import annotations

import gzip
import hashlib
import html
import io
import re
import zlib
from dataclasses import dataclass, field
from email.parser import BytesHeaderParser
from email.policy import default

try:
    import brotli
except ImportError:  # pragma: no cover - CLI dependency guard reports this
    brotli = None


TEXT_MIMES = ("text/", "json", "xml", "javascript", "ecmascript", "xhtml")


@dataclass
class ParsedResponse:
    status: int | None
    headers: dict[str, str]
    cookies: list[str]
    body: bytes
    text: str
    title: str | None
    meta_generator: str | None
    response_sha256: str
    normalized_body_hash: str
    body_length: int
    truncated: bool = False
    artifacts: dict[str, list[str]] = field(default_factory=dict)


def _split_headers(data: bytes) -> tuple[bytes, bytes]:
    for marker in (b"\r\n\r\n", b"\n\n"):
        pos = data.find(marker)
        if pos >= 0:
            return data[:pos], data[pos + len(marker):]
    return data, b""


def _decode_body(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type, re.I)
    encodings = [match.group(1)] if match else []
    for encoding in encodings + ["utf-8", "latin-1"]:
        try:
            return body.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return body.decode("utf-8", "replace")


def normalize_body(text: str) -> str:
    text = re.sub(r"(?is)<script\b[^>]*>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style\b[^>]*>.*?</style>", " ", text)
    text = re.sub(r"\b[0-9a-f]{16,}\b", "<token>", text, flags=re.I)
    text = re.sub(r"\b\d{4}-\d\d?-\d\d?[T ][\d:.+-Z]+", "<date>", text)
    text = re.sub(r"\s+", " ", html.unescape(text)).strip().lower()
    return text


def _dechunk(body: bytes) -> bytes:
    output = bytearray()
    position = 0
    while position < len(body):
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            return body
        try:
            size = int(body[position:line_end].split(b";", 1)[0], 16)
        except ValueError:
            return body
        position = line_end + 2
        if size == 0:
            return bytes(output)
        output.extend(body[position:position + size])
        position += size + 2
    return bytes(output)


def _gunzip_limited(data: bytes, limit: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        return stream.read(limit)


def _brotli_limited(data: bytes, limit: int) -> bytes:
    if brotli is None:
        raise RuntimeError("Brotli response found but the brotli package is not installed")
    try:
        decoder = brotli.Decompressor()
        output = bytearray()
        for position in range(0, len(data), 64 * 1024):
            output.extend(decoder.process(data[position:position + 64 * 1024]))
            if len(output) > limit:
                return bytes(output[:limit])
        return bytes(output)
    except Exception as exc:  # brotli implementations expose different error classes
        raise RuntimeError("invalid Brotli response") from exc


def parse_warc_record(raw: bytes, max_body_bytes: int = 2_000_000) -> ParsedResponse:
    try:
        if raw[:2] == b"\x1f\x8b":
            raw = _gunzip_limited(raw, max_body_bytes + 1_000_000)
    except (gzip.BadGzipFile, EOFError):
        pass
    _, payload = _split_headers(raw)  # WARC headers
    http_head, body = _split_headers(payload)
    lines = http_head.splitlines()
    status = None
    if lines:
        m = re.match(rb"HTTP/\S+\s+(\d{3})", lines[0])
        status = int(m.group(1)) if m else None
    header_blob = b"\r\n".join(lines[1:]) + b"\r\n\r\n"
    parsed = BytesHeaderParser(policy=default).parsebytes(header_blob)
    headers: dict[str, str] = {}
    for name in parsed.keys():
        if name.lower() != "set-cookie":
            headers[name.lower()] = ", ".join(parsed.get_all(name, []))
    cookies = []
    for value in parsed.get_all("set-cookie", []):
        cookie_name = value.split("=", 1)[0].strip()
        if cookie_name:
            cookies.append(cookie_name)  # values may be credentials; never persist them
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    encoding = headers.get("content-encoding", "").lower()
    decoding_error = False
    try:
        if "gzip" in encoding:
            body = _gunzip_limited(body, max_body_bytes + 1)
        elif "br" in {item.strip() for item in encoding.split(",")}:
            body = _brotli_limited(body, max_body_bytes + 1)
        elif "deflate" in encoding:
            body = zlib.decompressobj().decompress(body, max_body_bytes + 1)
    except (gzip.BadGzipFile, EOFError, RuntimeError, zlib.error):
        decoding_error = True
    truncated = len(body) > max_body_bytes
    body = body[:max_body_bytes]
    content_type = headers.get("content-type", "")
    textual = not content_type or any(part in content_type.lower() for part in TEXT_MIMES)
    text = _decode_body(body, content_type) if textual and not decoding_error else ""
    title_m = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    gen_m = re.search(r"(?is)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", text)
    artifacts = {
        "script_src": re.findall(r"(?is)<script[^>]+src=[\"']([^\"']+)", text)[:100],
        "source_mapping_url": re.findall(r"(?im)sourceMappingURL\s*=\s*([^\s*]+)", text)[:20],
        "product_version_fields": ["=".join(item) for item in re.findall(
            r'(?i)[\"\']?(product|productName|apiVersion|buildVersion|version|build)[\"\']?\s*[:=]\s*[\"\']?([0-9A-Za-z_.+ -]{1,80})',
            text)[:50]],
        "capabilities": re.findall(r"(?is)<(?:wms:|wfs:)?(?:Capability|Capabilities)\b[^>]*", text)[:20],
        "content_decoding_error": [encoding] if decoding_error else [],
    }
    normalized = normalize_body(text)
    return ParsedResponse(
        status=status, headers=headers, cookies=cookies, body=body, text=text,
        title=re.sub(r"\s+", " ", html.unescape(title_m.group(1))).strip()[:500] if title_m else None,
        meta_generator=gen_m.group(1).strip()[:500] if gen_m else None,
        response_sha256=hashlib.sha256(body).hexdigest(),
        normalized_body_hash=hashlib.sha256(normalized.encode()).hexdigest(),
        body_length=len(body), truncated=truncated, artifacts=artifacts,
    )
