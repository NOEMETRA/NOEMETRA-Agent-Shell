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
            "state": "error",
            "detail": (
                f"Dipendenze Python del plugin vocale non trovate ({_missing_err_msg}). "
                "Per completare l'installazione, eseguire: 'hermes pm install --extra voice-document-assistant' "
                "(oppure 'hermes pm repair'), quindi riavviare l'applicazione desktop o il gateway Hermes."
            ),
            "repair_command": "hermes pm install --extra voice-document-assistant",
            "restart_required": True,
        }

    @router.get("/library")
    async def _missing_deps_library():
        return {"documents": [], "error": "missing_dependencies"}

    @router.get("/models")
    async def _missing_deps_models():
        return {"error": "missing_dependencies", "default_provider": "ollama", "models": []}

__all__ = ["router"]

