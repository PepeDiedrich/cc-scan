from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request
import io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .runtime import BandwidthLimiter, copy_limited


DATA_BASE = "https://data.commoncrawl.org/"


class WarcFetcher:
    def __init__(self, cache_dir: str = ".cache/warc", workers: int = 8,
                 timeout: int = 45, retries: int = 3, max_record_bytes: int = 8_000_000,
                 limiter: BandwidthLimiter | None = None, progress=None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.workers, self.timeout, self.retries = workers, timeout, retries
        self.max_record_bytes = max_record_bytes
        self.limiter, self.progress = limiter, progress

    @staticmethod
    def record_key(filename: str, offset: int, length: int) -> str:
        return hashlib.sha256(f"{filename}:{offset}:{length}".encode()).hexdigest()

    def fetch(self, filename: str, offset: int, length: int) -> bytes:
        if length <= 0 or length > self.max_record_bytes:
            raise ValueError(f"WARC record length outside limit: {length}")
        cached = self.cache_dir / (self.record_key(filename, offset, length) + ".warc.gz")
        if cached.exists():
            return cached.read_bytes()
        url = filename if filename.startswith("http") else DATA_BASE + filename.lstrip("/")
        request = urllib.request.Request(url, headers={
            "Range": f"bytes={offset}-{offset + length - 1}",
            "User-Agent": "cc-scan/3.0 passive research",
        })
        last_error = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    if response.status not in (200, 206):
                        raise IOError(f"unexpected HTTP {response.status}")
                    buffer = io.BytesIO()
                    copy_limited(response, buffer, self.limiter, self.max_record_bytes + 1,
                                 progress=self.progress)
                    data = buffer.getvalue()
                    if len(data) > self.max_record_bytes:
                        raise ValueError("WARC record exceeds configured maximum")
                    tmp = cached.with_suffix(f".tmp.{os.getpid()}")
                    tmp.write_bytes(data)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, cached)
                    return data
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
                if attempt + 1 < self.retries:
                    time.sleep(0.5 * (2 ** attempt))
        raise IOError(f"WARC range request failed for {filename}: {last_error}")

    def fetch_many(self, records: list[tuple[str, int, int]]) -> dict[tuple[str, int, int], bytes | Exception]:
        unique = list(dict.fromkeys(records))
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self.fetch, *record): record for record in unique}
            result = {}
            for future, record in futures.items():
                try:
                    result[record] = future.result()
                except Exception as exc:  # retain per-record failures for reporting
                    result[record] = exc
            return result

    def remove_many(self, records: list[tuple[str, int, int]]) -> None:
        for filename, offset, length in set(records):
            path = self.cache_dir / (self.record_key(filename, offset, length) + ".warc.gz")
            try:
                path.unlink()
            except FileNotFoundError:
                pass
