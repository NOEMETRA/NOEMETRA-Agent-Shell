"""Standalone FastAPI application and server runner for Hermes Voice Assistant.

Mounts:
- /api/plugins/voice-document-assistant/ (Plugin REST API)
- / and /voice-document (Static GUI Web App)
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from hermes_voice.server.api import router as plugin_router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Hermes Voice Assistant API & GUI",
    version="1.0.0",
    description="Deterministic multi-agent voice document assistant",
)

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "testserver", "testclient"}


def is_loopback_address(host_or_ip: str) -> bool:
    """Validate whether an address or hostname refers strictly to a local loopback interface."""
    if not host_or_ip or not host_or_ip.strip():
        return False
    h = host_or_ip.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h and not h.startswith("["):
        parts = h.split(":")
        if len(parts) == 2:
            h = parts[0]
    if h in ALLOWED_LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback
    except ValueError:
        return False


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
    return is_loopback_address(h)


def is_loopback_host(url_or_origin: str) -> bool:
    """Validate whether an origin or referer URL belongs to a local loopback interface."""
    if not url_or_origin or url_or_origin.strip().lower() in ("null", "none"):
        return False
    try:
        parsed = urlparse(url_or_origin)
        if not parsed.netloc and not parsed.scheme:
            parsed = urlparse(f"http://{url_or_origin}")
        hostname = (parsed.hostname or "").lower()
        return is_loopback_address(hostname)
    except Exception:
        return False


def _normalize_netloc(host: str, scheme: str = "http") -> str:
    """Normalize host[:port] into a canonical lowercase netloc with explicit port."""
    h = (host or "").strip().lower()
    if not h:
        return ""
    default_port = "443" if scheme == "https" else "80"
    if h.startswith("["):
        closing = h.find("]")
        if closing == -1:
            return ""
        hostname = h[: closing + 1]
        rest = h[closing + 1 :]
        port = rest[1:] if rest.startswith(":") and rest[1:] else default_port
    elif h.count(":") == 1:
        hostname, port = h.split(":", 1)
        port = port or default_port
    else:
        hostname, port = h, default_port
    return f"{hostname}:{port}"


def is_same_origin(url_or_origin: str, host_header: str) -> bool:
    """True only when the Origin/Referer exactly matches the standalone server's own serving origin."""
    if not url_or_origin or url_or_origin.strip().lower() in ("null", "none"):
        return False
    try:
        parsed = urlparse(url_or_origin.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        origin_netloc = _normalize_netloc(parsed.netloc.rsplit("@", 1)[-1], parsed.scheme)
        server_netloc = _normalize_netloc(host_header, parsed.scheme)
        return bool(origin_netloc) and origin_netloc == server_netloc
    except Exception:
        return False


@app.middleware("http")
async def csrf_and_origin_protection(request: Request, call_next):
    """Prevent DNS rebinding and restrict the unauthenticated API to the standalone server's own origin.

    Any other web application served on a different localhost port is a different origin and must not
    be able to read private document data or mutate playback state (AGENTS.md:22-24).
    """
    # 0. Reject requests from non-loopback peer client addresses to prevent remote access (AGENTS.md:22-24)
    client_host = request.client.host if request.client else ""
    if client_host and not is_loopback_address(client_host):
        return Response(content="Forbidden: remote client access not permitted", status_code=403)

    # 1. Reject requests whose Host is not an explicitly allowed loopback host, including for GET requests (DNS Rebinding Guard)
    host_header = request.headers.get("host") or ""
    if not is_allowed_loopback_host(host_header):
        return Response(content="Untrusted Host header forbidden (DNS rebinding protection)", status_code=403)

    # 2. Same-origin enforcement for every API request (reads included) and every mutating request
    is_api = request.url.path.startswith("/api/")
    if is_api or request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()

        if origin is not None:
            if not is_same_origin(origin, host_header):
                return Response(content="Untrusted origin forbidden", status_code=403)
        elif referer is not None:
            if not is_same_origin(referer, host_header):
                return Response(content="Untrusted referer forbidden", status_code=403)

        # Browsers send Sec-Fetch-Site on every request: only same-origin pages or direct user navigation are allowed
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none"):
            return Response(content="Cross-origin request forbidden", status_code=403)

    return await call_next(request)


# No CORSMiddleware: the bundled GUI is served from the same origin, so cross-origin reads stay blocked by the browser.

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
    """Run server via Uvicorn strictly restricted to loopback host."""
    if not is_loopback_address(host):
        raise ValueError(
            f"The standalone voice server can only bind to loopback addresses (127.0.0.1, ::1, localhost) "
            f"to prevent exposing unauthenticated document APIs to remote clients. Received host: {host!r}."
        )
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run()
