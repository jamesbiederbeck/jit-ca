"""Opt-in raw HTTP body capture to <state>/captures (unredacted unless configured otherwise)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Callable

from .config import CaptureConfig
from .events import EventLog


class BodyCapture:
    """Write request/response bodies to private files; failures never break request handling.

    Files are 0600 in a 0700 directory, named ``<utc-timestamp>_<seq>_<host>_<direction>_<sha12>.bin``
    (host is a validated DNS name, never raw request data), and the oldest are evicted past max_files.
    """

    def __init__(self, directory: Path, config: CaptureConfig, redact: Callable[[object], object]):
        self.directory = directory
        self.config = config
        self._redact = redact
        self._lock = threading.Lock()
        self._sequence = 0
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)

    def save(self, log: EventLog, direction: str, hostname: str, body: bytes) -> dict | None:
        if not body:
            return None
        try:
            data = body
            if self.config.redact:
                try:
                    data = json.dumps(self._redact(json.loads(body)), ensure_ascii=False).encode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    return {"skipped": "non-JSON body not captured when capture.redact is true"}
            truncated = len(data) > self.config.max_body_bytes
            data = data[:self.config.max_body_bytes]
            digest = hashlib.sha256(body).hexdigest()[:12]
            with self._lock:
                self._sequence += 1
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                name = f"{stamp}_{self._sequence:06d}_{hostname[:60]}_{direction}_{digest}.bin"
                descriptor = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                self._evict()
            return {"file": name, "bytes": len(data), "truncated": truncated,
                    "redacted": self.config.redact}
        except OSError as exc:
            log.emit("capture_error", hostname=hostname, direction=direction, error=str(exc))
            return None

    def _evict(self) -> None:
        names = sorted(entry.name for entry in os.scandir(self.directory) if entry.name.endswith(".bin"))
        for stale in names[:max(0, len(names) - self.config.max_files)]:
            try:
                (self.directory / stale).unlink()
            except FileNotFoundError:
                pass
