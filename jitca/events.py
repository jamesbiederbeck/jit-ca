from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import threading


class EventLog:
    """Queue observations without disk I/O in network or certificate workers."""

    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._closed = False
        self._error: Exception | None = None
        self._queue: queue.Queue[dict | None] = queue.Queue()
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        self._stream = os.fdopen(descriptor, "a", buffering=1)
        self.thread = threading.Thread(target=self._work, name="jitca-event-log", daemon=True)
        try:
            self.thread.start()
        except BaseException:
            self._stream.close()
            raise

    def emit(self, event: str, **details) -> None:
        record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, **details}
        with self._lock:
            if self._closed:
                raise RuntimeError("event log is closed")
            self._queue.put_nowait(record)

    def _write(self, record: dict) -> None:
        self._stream.write(json.dumps(record, default=str) + "\n")

    def _work(self) -> None:
        try:
            while True:
                record = self._queue.get()
                try:
                    if record is None:
                        return
                    if self._error is None:
                        try:
                            self._write(record)
                        except Exception as exc:
                            # Keep draining so a failed writer cannot strand shutdown.
                            self._error = exc
                finally:
                    self._queue.task_done()
        finally:
            try:
                self._stream.close()
            except Exception as exc:
                self._error = self._error or exc

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._queue.put_nowait(None)
        self.thread.join()
        if self._error is not None:
            raise OSError("event log writer failed") from self._error
