"""Standalone FastAPI application and server runner for Hermes Voice Assistant.

Mounts:
- /api/plugins/voice-document-assistant/ (Plugin REST API)
- / and /voice-document (Static GUI Web App)
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Response
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

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "testserver"}


def is_allowed_loopback_host(host_header: str) -> bool:
    """Validate whether the Host header belongs to an explicitly allowed loopback interface (DNS rebinding guard)."""
    if not host_header or not host_header.strip():
        return False
    h = host_header.strip()
    if h.startswith("["):
        closing = h.find("]")
        if closing != -1:
            h = h[1:closing]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h.lower() in ALLOWED_LOOPBACK_HOSTS


def is_loopback_host(url_or_origin: str) -> bool:
    """Validate whether an origin or referer URL belongs to a local loopback interface."""
    if not url_or_origin or url_or_origin.strip().lower() in ("null", "none"):
        return False
    try:
        parsed = urlparse(url_or_origin)
        if not parsed.netloc and not parsed.scheme:
            parsed = urlparse(f"http://{url_or_origin}")
        hostname = (parsed.hostname or "").lower()
        return hostname in ALLOWED_LOOPBACK_HOSTS
    except Exception:
        return False


@app.middleware("http")
async def csrf_and_origin_protection(request: Request, call_next):
    """Prevent DNS rebinding attacks and cross-origin state mutations on unauthenticated standalone endpoints."""
    # 1. Reject requests whose Host is not an explicitly allowed loopback host, including for GET requests (DNS Rebinding Guard)
    host_header = request.headers.get("host") or ""
    if not is_allowed_loopback_host(host_header):
        return Response(content="Untrusted Host header forbidden (DNS rebinding protection)", status_code=403)

    # 2. Prevent cross-origin state mutations
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").lower()

        if origin is not None:
            if not is_loopback_host(origin):
                return Response(content="Untrusted origin forbidden", status_code=403)
        elif referer is not None:
            if not is_loopback_host(referer):
                return Response(content="Untrusted referer forbidden", status_code=403)

        if sec_fetch_site == "cross-site":
            if not (origin and is_loopback_host(origin)):
                return Response(content="Cross-origin request forbidden", status_code=403)

    return await call_next(request)


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
