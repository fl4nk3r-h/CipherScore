"""FastAPI app (repo.md §7): factory, CORS, routers, lifespan (load models).

Base URL: http://localhost:8000/api/v1 (mvp.md §5). The API contains no
analysis logic: every router calls analyzer.pipeline or a repository.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from analyzer import config
from analyzer.infer import loader
from api import db
from api.routers import analyses, captures, health, lab, live, reports, threats

TASKS = ("mode", "cipher", "integ", "pfs", "dh_group", "traffic",
         "beaconing", "dga", "dns_tunneling", "encrypted_malware")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Apply schema so a fresh data dir serves uploads/analyses out of the box.
    db.migrate()
    # Preload model versions so analyses never pay cold-load latency.
    for task in TASKS:
        loader.load_task(task, str(config.MODELS_DIR))
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="CipherScope MVP API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CS_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3100,http://127.0.0.1:3100").split(","),
        allow_methods=["*"],
        allow_headers=["*"],
    )
    for router in (captures.router, analyses.router, reports.router,
                   lab.router, live.router, threats.router, health.router):
        app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
_ = Path  # keep import for settings paths
