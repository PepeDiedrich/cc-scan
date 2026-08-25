from __future__ import annotations

import sqlite3
from pathlib import Path

from .response_parser import ParsedResponse


class Soft404Index:
    """Disk-backed response similarity index spanning every Stage-2 batch."""

    def __init__(self, path: str, reset: bool = True):
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(db_path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("""
          CREATE TABLE IF NOT EXISTS responses (
            record_key TEXT PRIMARY KEY, host TEXT NOT NULL, path TEXT NOT NULL,
            body_hash TEXT NOT NULL, title TEXT, body_length INTEGER NOT NULL)
        """)
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS responses_host_hash ON responses(host, body_hash)")
        if reset:
            self.connection.execute("DELETE FROM responses")
            self.connection.commit()

    def add(self, record_key: str, host: str, path: str, response: ParsedResponse) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, ?, ?)",
            (record_key, host, path, response.normalized_body_hash,
             response.title, response.body_length))

    def commit(self) -> None:
        self.connection.commit()

    def context(self, host: str, path: str, body_hash: str) -> dict[str, int | bool]:
        count, has_root = self.connection.execute("""
          SELECT count(DISTINCT CASE WHEN path <> ? THEN path END),
                 coalesce(max(CASE WHEN path IN ('/', '/index.html') AND path <> ? THEN 1 ELSE 0 END), 0)
          FROM responses WHERE host = ? AND body_hash = ?
        """, (path, path, host, body_hash)).fetchone()
        return {"same_hash_path_count": int(count), "same_hash_has_root": bool(has_root)}

    def count(self) -> int:
        return self.connection.execute("SELECT count(*) FROM responses").fetchone()[0]

    def close(self) -> None:
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
