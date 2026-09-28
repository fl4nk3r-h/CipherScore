"""GET /analyses/{id}/reports/{executive|technical}.pdf (mvp.md §5)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from analyzer import config

router = APIRouter(prefix="/analyses", tags=["reports"])


@router.get("/{analysis_id}/reports/{kind}.pdf")
def get_report(analysis_id: str, kind: str):
    if kind not in ("executive", "technical"):
        raise HTTPException(404, "unknown report kind")
    path = config.REPORTS_DIR / analysis_id / f"{kind}.pdf"
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    return FileResponse(path, media_type="application/pdf", filename=f"{kind}.pdf")
