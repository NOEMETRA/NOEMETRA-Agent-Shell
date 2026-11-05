"""FastAPI REST router for Hermes Voice Document Assistant.

Exposes endpoints mounted under /api/plugins/voice-document-assistant/
providing state persistence, document library, audio playback,
synchronized text highlighting data, and multi-agent question answering.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from hermes_voice.models import GroundedAnswer, LibraryEntry, PlayerStatusResponse, ReadingBookmark
from hermes_voice.server.state import get_assistant

logger = logging.getLogger(__name__)

router = APIRouter()


def _sanitize_filename(name: str) -> str:
    """Sanitize filename to prevent directory traversal and special character exploits."""
    base = Path(name).name
    cleaned = re.sub(r"[^\w\.-]", "_", base)
    if not cleaned.lower().endswith(".pdf"):
        cleaned += ".pdf"
    return cleaned


class SelectDocRequest(BaseModel):
    doc_id: str


class SeekRequest(BaseModel):
    sentence_index: Optional[int] = None
    page_number: Optional[int] = None


class ConfigRequest(BaseModel):
    tts_model: Optional[str] = None
    speed: Optional[float] = None
    allow_remote: Optional[bool] = None


class AskRequest(BaseModel):
    question: str


class PrivacyRequest(BaseModel):
    allow_remote: bool


@router.get("/status", response_model=PlayerStatusResponse)
async def get_status():
    """Return complete live state snapshot for GUI."""
    assistant = get_assistant()
    return assistant.get_full_status()


@router.get("/library")
async def list_library():
    """Return list of documents in the persistent library."""
    assistant = get_assistant()
    docs = assistant.get_library()
    return {"documents": [d.model_dump() for d in docs]}


@router.post("/select_document")
async def select_document(req: SelectDocRequest):
    """Switch active document from library."""
    assistant = get_assistant()
    try:
        bm = await asyncio.to_thread(assistant.select_document, req.doc_id)
        return {
            "status": "success",
            "bookmark": bm.model_dump(),
            "document": assistant.current_document.model_dump() if assistant.current_document else None,
        }
    except Exception as e:
        logger.error(f"Errore selezione documento {req.doc_id}: {e}")
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/upload")
async def upload_document(request: Request):
    """Upload or register a PDF document into library and set as active.
    Supports both application/json and multipart/form-data.
    Validates PDF format, prevents directory traversal, and ensures collision-free storage.
    """
    assistant = get_assistant()
    upload_dir = (Path.home() / ".hermes" / "uploaded_pdfs").resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)

    target_path: Optional[Path] = None
    content_type = request.headers.get("content-type", "").lower()

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "filename"):
            raw_filename = uploaded_file.filename or "uploaded.pdf"
            clean_name = _sanitize_filename(raw_filename)
            content = await uploaded_file.read()
            if not content.startswith(b"%PDF-"):
                raise HTTPException(status_code=400, detail="Il file caricato non contiene un'intestazione PDF valida (%PDF-).")
            content_hash = hashlib.sha256(content).hexdigest()[:12]
            dest_file = (upload_dir / f"{content_hash}_{clean_name}").resolve()
            if not str(dest_file).startswith(str(upload_dir)):
                raise HTTPException(status_code=400, detail="Destinazione non consentita.")
            dest_file.write_bytes(content)
            target_path = dest_file
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}

        file_path = body.get("file_path")
        content_base64 = body.get("content_base64")
        raw_filename = body.get("filename") or "document.pdf"

        if file_path:
            p = Path(file_path).resolve()
            if p.exists() and p.is_file():
                if not p.name.lower().endswith(".pdf"):
                    raise HTTPException(status_code=400, detail="Il file deve avere estensione .pdf.")
                target_path = p
        elif content_base64:
            clean_name = _sanitize_filename(raw_filename)
            try:
                data = base64.b64decode(content_base64)
            except Exception:
                raise HTTPException(status_code=400, detail="Payload base64 non decodificabile.")
            if not data.startswith(b"%PDF-"):
                raise HTTPException(status_code=400, detail="Il payload base64 non contiene un'intestazione PDF valida (%PDF-).")
            content_hash = hashlib.sha256(data).hexdigest()[:12]
            dest_file = (upload_dir / f"{content_hash}_{clean_name}").resolve()
            if not str(dest_file).startswith(str(upload_dir)):
                raise HTTPException(status_code=400, detail="Destinazione non consentita.")
            dest_file.write_bytes(data)
            target_path = dest_file

    if not target_path or not target_path.exists():
        raise HTTPException(status_code=400, detail="Nessun file o percorso PDF valido fornito.")

    try:
        bm = await asyncio.to_thread(assistant.load_document, target_path, resume_bookmark=True)
        doc = assistant.current_document
        return {
            "status": "success",
            "bookmark": bm.model_dump(),
            "document": doc.model_dump() if doc else None,
        }
    except Exception as e:
        logger.error(f"Errore estrazione PDF da {target_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Errore caricamento PDF: {e}")


@router.get("/document/{doc_id}")
async def get_document(doc_id: str):
    """Return full document data including text and sentence bounding boxes without changing active document or playback."""
    assistant = get_assistant()
    doc = await asyncio.to_thread(assistant.get_document_by_id, doc_id)
    if doc:
        return doc.model_dump()

    raise HTTPException(status_code=404, detail=f"Documento ID '{doc_id}' non trovato.")


@router.post("/playback/play")
async def play_playback():
    """Start audio playback."""
    assistant = get_assistant()
    try:
        bm = assistant.play()
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore play: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/pause")
async def pause_playback():
    """Pause audio playback and save exact bookmark."""
    assistant = get_assistant()
    bm = assistant.pause()
    return {"status": "success", "bookmark": bm.model_dump()}


@router.post("/playback/resume")
async def resume_playback():
    """Resume playback from exact point."""
    assistant = get_assistant()
    try:
        bm = assistant.resume()
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore resume: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/stop")
async def stop_playback():
    """Stop audio playback."""
    assistant = get_assistant()
    bm = assistant.stop()
    return {"status": "success", "bookmark": bm.model_dump()}


@router.post("/playback/seek")
async def seek_playback(req: SeekRequest):
    """Seek to specific page or sentence."""
    assistant = get_assistant()
    try:
        if req.sentence_index is not None:
            bm = assistant.seek_sentence(req.sentence_index)
        elif req.page_number is not None:
            bm = assistant.seek_page(req.page_number)
        else:
            raise ValueError("Specificare 'sentence_index' oppure 'page_number'.")
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore seek: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/config")
async def configure_playback(req: ConfigRequest):
    """Update TTS model, playback speed, or privacy settings."""
    assistant = get_assistant()
    if req.tts_model:
        await asyncio.to_thread(assistant.set_tts_model, req.tts_model)
    if req.speed is not None:
        assistant.set_speed(req.speed)
    if req.allow_remote is not None:
        assistant.set_allow_remote(req.allow_remote)

    return {
        "status": "success",
        "tts_model": assistant.tts.language,
        "speed": assistant.player.speed,
        "allow_remote": assistant.router.allow_remote,
    }


@router.post("/ask")
async def ask_question(req: AskRequest):
    """Ask question to document using Bibliotecario, Analista, and Verificatore.
    Dispatched off the event loop via asyncio.to_thread and pinned to active document context.
    """
    assistant = get_assistant()
    if not assistant.current_document:
        raise HTTPException(status_code=400, detail="Nessun documento attivo. Caricare un PDF prima di interrogare gli agenti.")

    target_doc_id = assistant.current_document.doc_id
    try:
        grounded_answer = await asyncio.to_thread(assistant.ask, req.question, target_doc_id)
        return grounded_answer.model_dump()
    except Exception as e:
        logger.error(f"Errore durante l'interrogazione della Triade: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/models")
async def get_models():
    """Return local and remote model provider statuses."""
    assistant = get_assistant()
    return assistant.router.get_providers_status()


@router.post("/config/privacy")
async def set_privacy(req: PrivacyRequest):
    """Explicitly toggle remote provider authorization."""
    assistant = get_assistant()
    assistant.set_allow_remote(req.allow_remote)
    return {"status": "success", "allow_remote": assistant.router.allow_remote}
