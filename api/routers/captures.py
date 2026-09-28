"""POST /captures (mvp.md §5): upload PCAP (multipart), returns capture_id.

Uploaded file names are never used as paths: files are stored under
data/uploads/<sha256>.pcapng (repo.md §7). 500 MB cap (mvp.md §13).
"""
from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, HTTPException, UploadFile

from api import db
from api.settings import settings

router = APIRouter(tags=["captures"])


@router.post("/captures")
async def upload_capture(file: UploadFile) -> dict:
    max_bytes = settings.max_upload_mb * 1024 * 1024
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    dest = settings.data_dir / "uploads"
    dest.mkdir(parents=True, exist_ok=True)

    sha = hashlib.sha256()
    size = 0
    tmp = dest / f".{uuid.uuid4().hex}.tmp"
    with open(tmp, "wb") as fh:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, f"upload exceeds {settings.max_upload_mb} MB cap")
            sha.update(chunk)
            fh.write(chunk)

    final = dest / f"{sha.hexdigest()}.pcapng"
    tmp.replace(final)

    capture_id = f"cap_{uuid.uuid4().hex[:8]}"
    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO capture (id, path, bytes, sha256) VALUES (?, ?, ?, ?)",
            (capture_id, str(final), size, sha.hexdigest()))
        conn.commit()
    finally:
        conn.close()
    return {"capture_id": capture_id, "bytes": size, "sha256": sha.hexdigest()}
