"""POST /captures (mvp.md §5): upload PCAP (multipart), returns capture_id.

Uploaded file names are never used as paths: files are stored under
data/uploads/<sha256>.pcapng (repo.md §7). 500 MB cap (mvp.md §13).
"""
from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from api import db
from api.settings import settings

router = APIRouter(tags=["captures"])

_CHUNK = 1024 * 1024


@router.post("/captures")
async def upload_capture(file: UploadFile) -> dict:
    max_bytes = settings.max_upload_mb * 1024 * 1024
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.data_dir / "uploads"
    dest.mkdir(parents=True, exist_ok=True)

    tmp = dest / f".{uuid.uuid4().hex}.tmp"
    sha, size, ok = await run_in_threadpool(_stream_to_file, file, tmp, max_bytes)
    if not ok:
        tmp.unlink(missing_ok=True)
        raise HTTPException(413, f"upload exceeds {settings.max_upload_mb} MB cap")

    def _finalize() -> tuple[str, str, int]:
        final = dest / f"{sha.hexdigest()}.pcapng"
        tmp.replace(final)
        return str(final), sha.hexdigest(), size

    final, sha_hex, size = await run_in_threadpool(_finalize)

    capture_id = f"cap_{uuid.uuid4().hex[:8]}"

    def _insert() -> None:
        conn = db.connect()            # same-thread connection + use
        try:
            conn.execute(
                "INSERT INTO capture (id, path, bytes, sha256) VALUES (?, ?, ?, ?)",
                (capture_id, final, size, sha_hex))
            conn.commit()
        finally:
            conn.close()

    await run_in_threadpool(_insert)
    return {"capture_id": capture_id, "bytes": size, "sha256": sha_hex}


def _stream_to_file(file: UploadFile, tmp, max_bytes: int):
    """Stream the upload into tmp; returns (sha, size, ok). Blocking — runs in
    the threadpool."""
    sha = hashlib.sha256()
    size = 0
    with open(tmp, "wb") as fh:
        while True:
            chunk = file.file.read(_CHUNK)      # sync read of the spooled file
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                return sha, size, False
            sha.update(chunk)
            fh.write(chunk)
    return sha, size, True
