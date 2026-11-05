"""NOEMETRA Agent Shell Dashboard / Desktop plugin API backend mount.

Mounted by gateway at /api/plugins/voice-document-assistant/
reusing the persistent singleton hermes_voice engine.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_DIR = str(Path(__file__).resolve().parent.parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

try:
    from hermes_voice.server.api import router
except (ImportError, ModuleNotFoundError) as err:
    import logging
    from fastapi import APIRouter
    _missing_err_msg = str(err)
    logging.getLogger("hermes.plugins.voice").warning("Dipendenze del plugin voice non ancora installate: %s", _missing_err_msg)
    router = APIRouter()
    @router.get("/status")
    async def _missing_deps():
        return {
            "error": "missing_dependencies",
            "detail": f"Dipendenze Python mancanti ({_missing_err_msg}). Eseguire: hermes plugins install voice-document-assistant",
        }

__all__ = ["router"]

