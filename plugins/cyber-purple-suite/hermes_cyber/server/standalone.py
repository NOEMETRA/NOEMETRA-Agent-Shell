"""Standalone FastAPI app runner for NOEMETRA Cyber Purple Suite web UI."""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from hermes_cyber.server.api import router as cyber_router

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="NOEMETRA Cyber Purple Suite", version="1.0.0")
    app.include_router(cyber_router, prefix="/api/plugins/cyber-purple-suite")

    @app.get("/", response_class=HTMLResponse)
    async def serve_index():
        index_file = _STATIC_DIR / "index.html"
        if index_file.exists():
            return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>NOEMETRA Cyber Purple Suite</h1>")

    return app


app = create_app()
