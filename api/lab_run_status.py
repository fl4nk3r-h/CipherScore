"""Atomic, process-shared status records for Lab sweeps."""
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path
from typing import Any


def read_status(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def update_status(path: Path, **changes: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        status = read_status(path) or {}
        status.update(changes)
        status["updated_at"] = time.time()
        temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(status))
        temp.replace(path)
        return status
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
