"""Standalone FastAPI application and server runner for Hermes Voice Assistant.

Mounts:
- /api/plugins/voice-document-assistant/ (Plugin REST API)
- / and /voice-document (Static GUI Web App)
"""

from __future__ import annotations

import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from hermes_voice.server.api import router as plugin_router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Hermes Voice Assistant API & GUI",
    version="1.0.0",
    description="Deterministic multi-agent voice document assistant",
)

# Enable CORS restricted to localhost/127.0.0.1 origins only to prevent cross-origin attacks
ALLOWED_ORIGINS = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# Mount plugin API router at official Hermes endpoint prefix
app.include_router(plugin_router, prefix="/api/plugins/voice-document-assistant")

# Static files path
STATIC_DIR = Path(__file__).parent / "static"


@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/voice-document", methods=["GET", "HEAD"])
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Hermes Voice API online"}


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run server via Uvicorn."""
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run()
