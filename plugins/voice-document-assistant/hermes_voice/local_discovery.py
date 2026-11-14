"""Cross-platform discovery for local LLM runtimes and GGUF/Unsloth model files.

Works on any workstation without machine-specific paths by combining:
- Loopback runtime probing (`127.0.0.1`) for Ollama, LM Studio, llama.cpp/llama-server, Jan, KoboldCpp, vLLM.
- Standard OS / environment directories (HuggingFace cache, LM Studio, Jan, llama.cpp, Hermes local_runtime).
- User-configured local directories persisted in the active voice profile.
- On-demand `llama-server` spawning for standalone GGUF files (e.g. Unsloth dynamic quants).
"""

from __future__ import annotations

import atexit
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_SPLIT_PART_RE = re.compile(r"-(\d{5})-of-(\d{5})\.gguf$", re.IGNORECASE)
_QUANT_IN_NAME_RE = re.compile(
    r"(?:^|[._-])((?:UD-)?(?:IQ\d_[A-Z0-9_]+|Q\d+_K(?:_[MSL01]+)?|Q\d+_[01]|BF16|F16|F32|MXFP4|NVFP4))(?:[._-]|$)",
    re.IGNORECASE,
)

_NON_CHAT_GGUF_ARCHS = frozenset({
    "flux", "sdxl", "sd3", "qwen_image", "wan", "gemma4-assistant", "bert", "nomic-bert", "whisper", "clip",
})
_NON_CHAT_GGUF_NAME_MARKERS = (
    "mmproj", "mtp-", "whisper", "nomic-embed", "bge-", "-embed", "flux-", "qwen-image", "sdxl", ".partial",
)
_GGUF_META_CACHE: Dict[str, Tuple[int, int, str, str]] = {}

_DEFAULT_LOCAL_RUNTIME_SPECS: Tuple[Dict[str, str], ...] = (
    {"id": "lmstudio", "label": "LM Studio", "base_url": "http://127.0.0.1:1234/v1"},
    {"id": "llamacpp", "label": "llama.cpp / llama-server", "base_url": "http://127.0.0.1:8080/v1"},
    {"id": "unsloth_studio", "label": "Unsloth Studio", "base_url": "http://127.0.0.1:8888/v1"},
    {"id": "jan", "label": "Jan Local", "base_url": "http://127.0.0.1:1337/v1"},
    {"id": "koboldcpp", "label": "KoboldCpp", "base_url": "http://127.0.0.1:5001/v1"},
    {"id": "vllm", "label": "vLLM / LocalAI", "base_url": "http://127.0.0.1:8000/v1"},
)

LOCAL_RUNTIME_DEFAULT_URLS: Dict[str, str] = {
    spec["id"]: spec["base_url"] for spec in _DEFAULT_LOCAL_RUNTIME_SPECS
}


def format_bytes_label(nbytes: int) -> str:
    """Return human-readable binary size string (e.g. '8.4 GB')."""
    if nbytes <= 0:
        return "0 B"
    val = float(nbytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if val < 1024.0 or unit == "TB":
            return f"{val:.1f} {unit}" if unit in ("GB", "TB") else f"{val:.0f} {unit}"
        val /= 1024.0
    return f"{nbytes} B"


def _split_env_paths(raw: Optional[str]) -> List[Path]:
    if not raw or not str(raw).strip():
        return []
    out: List[Path] = []
    for chunk in str(raw).split(os.pathsep):
        cleaned = chunk.strip().strip('"').strip("'")
        if cleaned:
            out.append(Path(cleaned).expanduser())
    return out


def get_model_scan_dirs(
    extra_dirs: Optional[Iterable[UnionPath]] = None,
    *,
    include_missing: bool = False,
) -> List[Path]:
    """Resolve cross-platform candidate directories that may hold GGUF/Unsloth models."""
    candidates: List[Path] = []

    if extra_dirs:
        for item in extra_dirs:
            raw = str(item or "").strip()
            if raw:
                candidates.append(Path(raw).expanduser())

    for env_name in ("HERMES_LOCAL_MODELS_DIR", "UNSLOTH_MODELS_DIR", "LM_STUDIO_MODELS_PATH", "LLAMACPP_MODELS_DIR"):
        candidates.extend(_split_env_paths(os.environ.get(env_name)))

    hf_hub = os.environ.get("HF_HUB_CACHE", "").strip()
    if hf_hub:
        candidates.extend(_split_env_paths(hf_hub))
    elif os.environ.get("HF_HOME", "").strip():
        for hf_root in _split_env_paths(os.environ.get("HF_HOME")):
            candidates.append(hf_root / "hub")

    home = Path.home()
    candidates.extend([
        home / ".cache" / "huggingface" / "hub",
        home / ".lmstudio" / "models",
        home / ".cache" / "llama.cpp",
        home / "jan" / "models",
        home / ".local" / "share" / "llama.cpp",
        home / "models",
    ])

    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if local_appdata:
        candidates.append(Path(local_appdata) / "LM-Studio" / "models")
        candidates.append(Path(local_appdata) / "Jan" / "data" / "models")

    with suppress(Exception):
        from hermes_cli.local_runtime.bootstrap import models_dir as hermes_models_dir

        mdir = hermes_models_dir()
        if mdir:
            candidates.append(Path(mdir))

    deduped: List[Path] = []
    seen = set()
    for p in candidates:
        try:
            resolved = p.resolve()
        except Exception:
            resolved = p
        key = str(resolved).lower() if os.name == "nt" else str(resolved)
        if key in seen:
            continue
        seen.add(key)
        if include_missing or resolved.is_dir():
            deduped.append(resolved)
    return deduped


def _infer_model_source(file_path: Path) -> str:
    lowered = str(file_path).lower()
    if "unsloth" in lowered:
        return "unsloth"
    if ".lmstudio" in lowered or "lm-studio" in lowered or "lm studio" in lowered:
        return "lmstudio"
    if "huggingface" in lowered or f"{os.sep}hub{os.sep}" in lowered:
        return "huggingface"
    if f"{os.sep}jan{os.sep}" in lowered:
        return "jan"
    if ".hermes" in lowered or "runtimes" in lowered:
        return "hermes"
    return "custom"


def _infer_quant_from_name(name: str) -> str:
    m = _QUANT_IN_NAME_RE.search(name)
    return m.group(1) if m else ""


def _read_gguf_meta_safe(path: Path) -> Tuple[str, str]:
    """Read (architecture, friendly_name) from GGUF header with stat caching."""
    cache_key = str(path)
    try:
        st = path.stat()
        cached = _GGUF_META_CACHE.get(cache_key)
        if cached and cached[0] == st.st_size and cached[1] == st.st_mtime_ns:
            return cached[2], cached[3]
    except OSError:
        st = None

    arch = ""
    friendly = ""
    try:
        from hermes_cli.local_runtime.gguf import read_gguf_header

        hdr = read_gguf_header(path)
        meta = hdr.metadata or {}
        arch = str(meta.get("general.architecture") or "").strip()
        friendly = str(meta.get("general.name") or "").strip()
    except Exception:
        pass

    if st is not None:
        _GGUF_META_CACHE[cache_key] = (st.st_size, st.st_mtime_ns, arch, friendly)
    return arch, friendly


def _is_non_chat_gguf(primary_path: Path, arch: str) -> bool:
    """Filter out diffusion, draft/MTP sidecars, embedding, and audio-only GGUF files."""
    if arch and arch.strip().lower() in _NON_CHAT_GGUF_ARCHS:
        return True
    low_name = primary_path.name.lower()
    return any(tok in low_name for tok in _NON_CHAT_GGUF_NAME_MARKERS)


def _iter_gguf_files(root: Path, max_depth: int = 5) -> List[Path]:
    """Bounded recursive walk looking for .gguf files inside *root*."""
    found: List[Path] = []
    if not root.is_dir():
        return found
    root_depth = len(root.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            cur = Path(dirpath)
            depth = len(cur.parts) - root_depth
            # Prune helper/hidden dirs and stop deeper recursion at max_depth
            dirnames[:] = [
                d for d in dirnames
                if not d.startswith(".") and d.lower() not in ("assets", "__pycache__", "node_modules", ".git")
            ]
            if depth >= max_depth:
                dirnames[:] = []
            for fname in filenames:
                low = fname.lower()
                if not low.endswith(".gguf"):
                    continue
                if low.startswith("mmproj") or ".partial" in low or low.endswith(".tmp"):
                    continue
                found.append(cur / fname)
    except OSError as exc:
        logger.debug("Impossibile scansionare la cartella %s: %s", root, exc)
    return found


def scan_local_gguf_models(
    extra_dirs: Optional[Iterable[UnionPath]] = None,
    *,
    max_depth: int = 5,
    max_models: int = 120,
) -> List[Dict[str, Any]]:
    """Discover chat/VLM GGUF models (including Unsloth quants) across standard & custom directories."""
    scan_dirs = get_model_scan_dirs(extra_dirs=extra_dirs, include_missing=False)
    grouped_splits: Dict[str, List[Tuple[int, Path]]] = {}
    standalone_files: List[Path] = []
    seen_paths = set()

    for root in scan_dirs:
        for fpath in _iter_gguf_files(root, max_depth=max_depth):
            try:
                resolved = fpath.resolve()
            except Exception:
                resolved = fpath
            key = str(resolved).lower() if os.name == "nt" else str(resolved)
            if key in seen_paths:
                continue
            seen_paths.add(key)

            # Preserve the original symlink/snapshot path so HF blob hashes do not hide split filenames
            split_m = _SPLIT_PART_RE.search(fpath.name)
            if split_m:
                part_idx = int(split_m.group(1))
                stem_base = _SPLIT_PART_RE.sub("", str(fpath))
                grouped_splits.setdefault(stem_base, []).append((part_idx, fpath))
            else:
                standalone_files.append(fpath)

    entries: List[Dict[str, Any]] = []

    def _build_entry(primary_path: Path, total_bytes: int, display_stem: str) -> Optional[Dict[str, Any]]:
        arch, friendly = _read_gguf_meta_safe(primary_path)
        if _is_non_chat_gguf(primary_path, arch):
            return None
        quant = _infer_quant_from_name(display_stem)
        source = _infer_model_source(primary_path)
        label_name = display_stem
        # Include parent folder hint for generic names inside HF/Unsloth snapshot folders
        parent_name = primary_path.parent.name
        if parent_name and parent_name.lower() not in ("models", "blobs", "snapshots") and len(parent_name) < 48:
            if source == "unsloth" and "unsloth" not in label_name.lower():
                label_name = f"Unsloth/{label_name}"
        return {
            "id": str(primary_path),
            "model_id": display_stem,
            "name": friendly or label_name,
            "file_name": primary_path.name,
            "path": str(primary_path),
            "size_bytes": total_bytes,
            "size_label": format_bytes_label(total_bytes),
            "source": source,
            "architecture": arch,
            "quant": quant,
            "provider": "gguf",
        }

    for _, parts in sorted(grouped_splits.items()):
        parts.sort(key=lambda item: item[0])
        primary = parts[0][1]
        total_bytes = 0
        for _, p in parts:
            with suppress(OSError):
                total_bytes += p.stat().st_size
        display_stem = _SPLIT_PART_RE.sub("", primary.name)
        built = _build_entry(primary, total_bytes, display_stem)
        if built is not None:
            entries.append(built)

    for fpath in standalone_files:
        total_bytes = 0
        with suppress(OSError):
            total_bytes = fpath.stat().st_size
        built = _build_entry(fpath, total_bytes, fpath.stem)
        if built is not None:
            entries.append(built)

    # Prefer Unsloth models first, then larger/clear names alphabetically
    entries.sort(key=lambda e: (0 if e["source"] == "unsloth" else 1, e["name"].lower()))
    return entries[:max_models]


def _is_loopback_port_open(base_url: str, timeout_s: float = 0.08) -> bool:
    """Fast TCP loopback pre-check to skip closed ports in ~1ms instead of waiting on OS SYN retries."""
    try:
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if host.lower() not in ("127.0.0.1", "localhost", "::1"):
            return True
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connect_host = "127.0.0.1" if host.lower() in ("localhost", "127.0.0.1") else host
        family = socket.AF_INET6 if ":" in connect_host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_s)
            return sock.connect_ex((connect_host, port)) == 0
    except Exception:
        return True


def _probe_openai_compat_models(
    runtime_id: str,
    label: str,
    base_url: str,
    api_key: str = "",
    timeout_s: float = 0.45,
) -> Dict[str, Any]:
    clean_base = base_url.rstrip("/")
    models_url = f"{clean_base}/models" if clean_base.endswith("/v1") else f"{clean_base}/v1/models"
    headers: Dict[str, str] = {"Accept": "application/json"}
    if api_key and api_key != "local":
        headers["Authorization"] = f"Bearer {api_key}"

    result: Dict[str, Any] = {
        "id": runtime_id,
        "label": label,
        "url": clean_base,
        "status": "offline",
        "models": [],
        "is_local": True,
    }
    if not _is_loopback_port_open(clean_base, timeout_s=min(0.08, timeout_s)):
        return result
    try:
        resp = requests.get(models_url, headers=headers, timeout=timeout_s)
        if resp.status_code == 200:
            payload = resp.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            raw_items = []
            if isinstance(data, list):
                raw_items = data
            elif isinstance(payload, dict) and isinstance(payload.get("models"), list):
                raw_items = payload["models"]
            models: List[str] = []
            for item in raw_items:
                if isinstance(item, dict):
                    mid = str(item.get("id") or item.get("name") or item.get("model") or "").strip()
                elif isinstance(item, str):
                    mid = item.strip()
                else:
                    mid = ""
                if mid and mid not in models:
                    models.append(mid)
            result["status"] = "online"
            result["models"] = models
    except Exception:
        pass
    return result


def _read_lmstudio_dynamic_urls() -> List[str]:
    """Read active LM Studio local HTTP server ports (e.g. dynamic bionic port)."""
    urls: List[str] = []
    home = Path.home()
    candidates = [
        home / ".lmstudio" / "apps" / "bionic" / ".internal" / "http-server.json",
        home / ".lmstudio" / ".internal" / "http-server.json",
    ]
    for cfg_path in candidates:
        if not cfg_path.is_file():
            continue
        with suppress(Exception):
            import json
            payload = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            port = int(payload.get("port") or 0) if isinstance(payload, dict) else 0
            host = str(payload.get("host") or "127.0.0.1").strip() or "127.0.0.1"
            if port > 0 and host.lower() in ("127.0.0.1", "localhost", "::1"):
                u = f"http://127.0.0.1:{port}/v1"
                if u not in urls:
                    urls.append(u)
    return urls


def discover_local_servers(
    *,
    custom_endpoints: Optional[List[Dict[str, str]]] = None,
    timeout_s: float = 0.45,
) -> Dict[str, Dict[str, Any]]:
    """Probe loopback OpenAI-compatible local AI runtimes concurrently."""
    targets: List[Tuple[str, str, str, str]] = []
    seen_urls = set()

    # 1. Check Hermes managed llama-server if currently running
    with suppress(Exception):
        from hermes_cli.local_runtime.endpoint import resolve_llamacpp_endpoint

        ep = resolve_llamacpp_endpoint(wait_for_boot_s=0.0)
        if isinstance(ep, dict) and ep.get("base_url"):
            u = str(ep["base_url"]).strip().rstrip("/")
            targets.append(("llamacpp", "llama.cpp (Hermes)", u, str(ep.get("api_key") or "")))
            seen_urls.add(u)

    # 2. Custom endpoints provided by router config (only loopback)
    if custom_endpoints:
        for item in custom_endpoints:
            rid = str(item.get("id") or "custom").strip().lower()
            lbl = str(item.get("label") or rid).strip()
            url = str(item.get("base_url") or "").strip().rstrip("/")
            key = str(item.get("api_key") or "")
            if url and url not in seen_urls:
                targets.append((rid, lbl, url, key))
                seen_urls.add(url)

    # 3. Dynamic LM Studio ports reported by local LM Studio state
    for lms_url in _read_lmstudio_dynamic_urls():
        if lms_url not in seen_urls:
            targets.append(("lmstudio", "LM Studio", lms_url, ""))
            seen_urls.add(lms_url)

    # 4. Standard local runtime ports
    for spec in _DEFAULT_LOCAL_RUNTIME_SPECS:
        u = spec["base_url"].rstrip("/")
        if u not in seen_urls:
            targets.append((spec["id"], spec["label"], u, ""))
            seen_urls.add(u)

    discovered: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
        futures = [
            pool.submit(_probe_openai_compat_models, rid, lbl, url, key, timeout_s)
            for rid, lbl, url, key in targets
        ]
        for fut in futures:
            with suppress(Exception):
                res = fut.result()
                rid = res["id"]
                # Keep online entry if multiple ports map to same runtime id (e.g. managed llamacpp + 8080, LM Studio dynamic)
                if rid not in discovered or res["status"] == "online":
                    discovered[rid] = res
    return discovered


def find_llama_server_binary() -> Optional[Path]:
    """Locate an installed llama-server executable on the current machine (cross-platform)."""
    env_bin = os.environ.get("LLAMA_SERVER_BIN", "").strip().strip('"')
    if env_bin:
        p = Path(env_bin).expanduser()
        if p.is_file():
            return p

    with suppress(Exception):
        from hermes_cli.local_runtime.binaries import installed_engine

        eng = installed_engine("auto")
        if eng and eng.binary and Path(eng.binary).is_file():
            return Path(eng.binary)

    for candidate in ("llama-server", "llama-server.exe"):
        resolved = shutil.which(candidate)
        if resolved:
            return Path(resolved)

    # Well-known Unsloth, Hermes, LM Studio, Jan, Homebrew, and Ollama install locations
    exe_names = ("llama-server.exe", "llama-server") if os.name == "nt" else ("llama-server",)
    home = Path.home()
    local_app = Path(os.environ["LOCALAPPDATA"]) if os.environ.get("LOCALAPPDATA") else None

    direct_candidates: List[Path] = []
    for exe in exe_names:
        direct_candidates.extend([
            home / ".unsloth" / "llama.cpp" / "build" / "bin" / "Release" / exe,
            home / ".unsloth" / "llama.cpp" / "build" / "bin" / exe,
            home / ".hermes" / "bin" / exe,
            home / ".local" / "bin" / exe,
        ])
        if local_app:
            direct_candidates.extend([
                local_app / "hermes" / "bin" / exe,
                local_app / "Programs" / "Ollama" / "lib" / "ollama" / exe,
            ])
        if os.name != "nt":
            direct_candidates.extend([
                Path("/opt/homebrew/bin") / exe,
                Path("/usr/local/bin") / exe,
                Path("/usr/lib/ollama") / exe,
            ])

    for cand in direct_candidates:
        with suppress(OSError):
            if cand.is_file():
                return cand

    # Shallow bounded search inside ~/.hermes/runtimes, ~/.unsloth, ~/.lmstudio
    search_roots = [
        home / ".unsloth" / "llama.cpp",
        home / ".hermes" / "runtimes",
        home / ".lmstudio",
    ]
    if local_app:
        search_roots.extend([
            local_app / "hermes" / "runtimes",
            local_app / "LM-Studio",
            local_app / "Jan",
        ])
    for sroot in search_roots:
        if not sroot.is_dir():
            continue
        for exe in exe_names:
            with suppress(OSError):
                for hit in sroot.rglob(exe):
                    if hit.is_file():
                        return hit

    return None


def _pick_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class LocalGGUFRunner:
    """Manages an on-demand llama-server subprocess for arbitrary local GGUF files (e.g. Unsloth)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._active_path: str = ""
        self._base_url: str = ""
        self._model_id: str = ""
        atexit.register(self.stop)

    @property
    def active_path(self) -> str:
        return self._active_path

    @property
    def base_url(self) -> str:
        return self._base_url

    def ensure_running(self, gguf_path: UnionPath, *, startup_timeout_s: float = 90.0) -> Tuple[str, str]:
        """Start (or reuse) a local llama-server serving *gguf_path*.

        Returns ``(openai_compatible_base_url, served_model_id)``.
        """
        target = Path(str(gguf_path)).expanduser()
        if not target.is_file():
            raise FileNotFoundError(
                f"File modello GGUF non trovato su disco: '{target}'. "
                "Verifica che la cartella o il file siano accessibili."
            )
        # Preserve symlink snapshot paths (e.g. HF cache) so llama-server finds split shards
        resolved_str = os.path.abspath(str(target))

        with self._lock:
            if (
                self._proc is not None
                and self._proc.poll() is None
                and self._active_path == resolved_str
                and self._base_url
            ):
                return self._base_url, self._model_id or target.stem

            self._stop_unlocked()

            binary = find_llama_server_binary()
            if binary is None:
                raise RuntimeError(
                    f"Impossibile avviare direttamente '{target.name}': nessun eseguibile 'llama-server' "
                    "trovato su questo PC. Installa il runtime llama.cpp di Hermes oppure carica il file "
                    "GGUF in LM Studio / Ollama locale."
                )

            port = _pick_free_loopback_port()
            cmd = [
                str(binary),
                "-m",
                resolved_str,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-ui",
                "--jinja",
                "-c",
                "8192",
            ]
            creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(binary.parent),
                creationflags=creationflags,
            )
            self._active_path = resolved_str
            self._base_url = f"http://127.0.0.1:{port}/v1"
            self._model_id = target.stem

            health_url = f"http://127.0.0.1:{port}/health"
            deadline = time.monotonic() + startup_timeout_s
            while time.monotonic() < deadline:
                if self._proc.poll() is not None:
                    rc = self._proc.returncode
                    self._stop_unlocked()
                    raise RuntimeError(
                        f"llama-server terminato prematuramente (codice {rc}) caricando '{target.name}'."
                    )
                with suppress(Exception):
                    r = requests.get(health_url, timeout=1.5)
                    if r.status_code == 200:
                        models_info = _probe_openai_compat_models("llamacpp", "llama-server", self._base_url, timeout_s=1.5)
                        if models_info.get("models"):
                            self._model_id = models_info["models"][0]
                        logger.info("llama-server avviato per GGUF '%s' su %s", target.name, self._base_url)
                        return self._base_url, self._model_id
                time.sleep(0.5)

            self._stop_unlocked()
            raise TimeoutError(
                f"Timeout ({int(startup_timeout_s)}s) durante il caricamento di '{target.name}' con llama-server."
            )

    def _stop_unlocked(self) -> None:
        if self._proc is not None:
            with suppress(Exception):
                if self._proc.poll() is None:
                    self._proc.terminate()
                    self._proc.wait(timeout=4.0)
            with suppress(Exception):
                if self._proc.poll() is None:
                    self._proc.kill()
        self._proc = None
        self._active_path = ""
        self._base_url = ""
        self._model_id = ""

    def stop(self) -> None:
        with self._lock:
            self._stop_unlocked()


UnionPath = os.PathLike[str] | str
