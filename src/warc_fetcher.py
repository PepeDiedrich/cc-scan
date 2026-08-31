from __future__ import annotations

import hashlib
import os
import time
import urllib.error
import urllib.request
import io
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .runtime import BandwidthLimiter, copy_limited


DATA_BASE = "https://data.commoncrawl.org/"


class WarcFetchError(IOError):
    def __init__(self, category: str, filename: str, cause: BaseException):
        super().__init__(f"{category}: {filename}: {cause}")
        self.category = category


class WarcFetcher:
    def __init__(self, cache_dir: str = ".cache/warc", workers: int = 8,
                 timeout: int = 45, retries: int = 3, max_record_bytes: int = 8_000_000,
                 limiter: BandwidthLimiter | None = None, progress=None,
                 cooldown_seconds: int = 120):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.workers, self.timeout, self.retries = workers, timeout, retries
        self.max_record_bytes = max_record_bytes
        self.limiter, self.progress = limiter, progress
        self.cooldown_seconds = max(1, cooldown_seconds)
        self._cooldown_until = 0.0
        self._cooldown_lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="warc-fetch")

    def _wait_for_cooldown(self) -> None:
        while True:
            with self._cooldown_lock:
                remaining = self._cooldown_until - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(remaining, 1.0))

    def _start_cooldown(self) -> None:
        with self._cooldown_lock:
            self._cooldown_until = max(self._cooldown_until,
                                       time.monotonic() + self.cooldown_seconds)

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
            self._wait_for_cooldown()
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
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code in (403, 429):
                    self._start_cooldown()
                    category = f"http_{exc.code}"
                    break
                category = f"http_{exc.code}"
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
                category = "network"
            if attempt + 1 < self.retries:
                time.sleep(0.5 * (2 ** attempt))
        raise WarcFetchError(category, filename, last_error)

    def fetch_many(self, records: list[tuple[str, int, int]]) -> dict[tuple[str, int, int], bytes | Exception]:
        unique = list(dict.fromkeys(records))
        futures = {self.pool.submit(self.fetch, *record): record for record in unique}
        result = {}
        for future, record in futures.items():
            try:
                result[record] = future.result()
            except Exception as exc:  # retain per-record failures for reporting
                result[record] = exc
        return result

    def close(self) -> None:
        self.pool.shutdown(wait=True)

    def remove_many(self, records: list[tuple[str, int, int]]) -> None:
        for filename, offset, length in set(records):
            path = self.cache_dir / (self.record_key(filename, offset, length) + ".warc.gz")
            try:
                path.unlink()
            except FileNotFoundError:
                pass
