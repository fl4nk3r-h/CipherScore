"""GET /analyses/{id}/reports/{executive|technical}.pdf, report.json,
findings.csv (mvp.md §5).

Routes answer HEAD as well as GET: the web client probes report availability
with HEAD (web/lib/api.ts headExists), and FastAPI's method-specific decorators
do not auto-register HEAD the way Starlette's Route does.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from analyzer import config

router = APIRouter(prefix="/analyses", tags=["reports"])

# filename -> (media type, download name) for every artifact the pipeline
# renders into data/reports/<analysis_id>/ (analyzer/report/render.py, export.py).
_ARTIFACTS: dict[str, tuple[str, str]] = {
    "executive.pdf": ("application/pdf", "executive.pdf"),
    "technical.pdf": ("application/pdf", "technical.pdf"),
    "report.json": ("application/json", "report.json"),
    "findings.csv": ("text/csv", "findings.csv"),
}


@router.api_route("/{analysis_id}/reports/{filename}", methods=["GET", "HEAD"])
def get_report(analysis_id: str, filename: str):
    media_type, download_name = _ARTIFACTS.get(filename, ("", ""))
    if not media_type:
        raise HTTPException(404, "unknown report kind")
    path = config.REPORTS_DIR / analysis_id / filename
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    return FileResponse(path, media_type=media_type, filename=download_name)
