"""GET /healthz, /version (repo.md §7): health + model versions."""
from __future__ import annotations

import json

from fastapi import APIRouter

from analyzer import __version__
from analyzer import config
from analyzer.infer import loader

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/version")
def version() -> dict:
    registry = {}
    path = config.MODELS_DIR / "registry.json"
    if path.exists():
        registry = json.loads(path.read_text())
    return {"api": __version__, "models": registry}
