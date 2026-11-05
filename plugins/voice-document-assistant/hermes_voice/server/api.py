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
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from hermes_voice.models import GroundedAnswer, LibraryEntry, PlayerStatusResponse, ReadingBookmark
from hermes_voice.profile import PROFILE_ID_RE, resolve_voice_profile_dir, validate_path_profile_ownership
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


def _resolve_profile_home(prof_name: str) -> Path:
    try:
        from hermes_cli.profiles import get_profile_dir
        return get_profile_dir(prof_name).resolve()
    except Exception:
        if prof_name == "default":
            return (Path.home() / ".hermes").resolve()
        return (Path.home() / ".hermes" / "profiles" / prof_name).resolve()


def _resolve_authorized_context(request: Request) -> Tuple[str, Optional[Path]]:
    """Resolve the profile name and authorized home directory bound to this request's gateway scope.

    Strictly enforces AGENTS.md:13 profile isolation:
    - If a native HTTP principal grant is present on request.state:
      - If it points to a standard profile under profiles/, the profile name is extracted.
      - If it points to a custom HERMES_HOME, the authorized home directory is preserved directly
        as the storage identity so that custom-home sessions do not collide with or resolve under profiles/.
    - If a context-local hermes_home_override is active:
      - If under profiles/, bound to that profile name.
      - Else, preserved as the authorized custom home directory.
    - If an explicit X-Hermes-Profile header or ?profile= query is provided:
      - It must match the authorized profile (or the basename of the authorized custom home if matching).
      - Cross-profile switching on a scoped session returns HTTP 403 Forbidden.
    """
    grant = getattr(request.state, "native_http_principal", None)
    bound_profile: Optional[str] = None
    authorized_home: Optional[Path] = None

    if isinstance(grant, dict) and grant.get("profile_id"):
        prof_id = str(grant["profile_id"]).strip()
        p = Path(prof_id)
        if p.is_absolute() or "\\" in prof_id or "/" in prof_id or p.exists():
            resolved = p.resolve()
            authorized_home = resolved
            try:
                from hermes_cli.profiles import _get_default_hermes_home, _get_profiles_root
                default_h = _get_default_hermes_home().resolve()
                prof_root = _get_profiles_root().resolve()
                if resolved == default_h:
                    bound_profile = "default"
                elif resolved.parent == prof_root and PROFILE_ID_RE.match(resolved.name.lower()):
                    bound_profile = resolved.name.lower()
                elif resolved.is_relative_to(prof_root):
                    rel = resolved.relative_to(prof_root)
                    bound_profile = rel.parts[0].lower() if rel.parts else "default"
                else:
                    bound_profile = None
            except Exception:
                bound_profile = None
        elif PROFILE_ID_RE.match(prof_id.lower()):
            bound_profile = prof_id.lower()
            try:
                from hermes_cli.profiles import get_profile_dir
                authorized_home = get_profile_dir(bound_profile).resolve()
            except Exception:
                pass

    if not authorized_home and not bound_profile:
        try:
            from hermes_constants import get_hermes_home_override
            home_override = get_hermes_home_override()
            if home_override:
                resolved = Path(home_override).resolve()
                authorized_home = resolved
                try:
                    from hermes_cli.profiles import _get_default_hermes_home, _get_profiles_root
                    default_h = _get_default_hermes_home().resolve()
                    prof_root = _get_profiles_root().resolve()
                    if resolved == default_h:
                        bound_profile = "default"
                    elif resolved.parent == prof_root and PROFILE_ID_RE.match(resolved.name.lower()):
                        bound_profile = resolved.name.lower()
                    elif resolved.is_relative_to(prof_root):
                        rel = resolved.relative_to(prof_root)
                        bound_profile = rel.parts[0].lower() if rel.parts else "default"
                    else:
                        bound_profile = None
                except Exception:
                    bound_profile = None
        except Exception:
            pass

    # If still unbound, anchor strictly to the gateway server's process-level home (AGENTS.md:13)
    if not authorized_home and not bound_profile:
        try:
            from hermes_cli.profiles import current_profile_name, get_profile_dir
            srv_prof = current_profile_name()
            if srv_prof:
                bound_profile = srv_prof
                authorized_home = get_profile_dir(srv_prof).resolve()
        except Exception:
            pass

    if not authorized_home and not bound_profile:
        try:
            from hermes_cli.profiles import _get_default_hermes_home
            authorized_home = _get_default_hermes_home().resolve()
            bound_profile = "default"
        except Exception:
            authorized_home = Path.home() / ".hermes"
            bound_profile = "default"

    untrusted_profile = request.headers.get("X-Hermes-Profile") or request.query_params.get("profile") or None
    if untrusted_profile:
        untrusted_profile = untrusted_profile.strip().lower()
        if not PROFILE_ID_RE.match(untrusted_profile):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid profile name {untrusted_profile!r}: must match ^[a-z0-9][a-z0-9_-]{{0,63}}$",
            )

        # Strictly reject profile selection that does not match authorized scope
        is_authorized = False
        if bound_profile and untrusted_profile == bound_profile.lower():
            is_authorized = True
        elif authorized_home:
            untrusted_home = _resolve_profile_home(untrusted_profile)
            if untrusted_home and untrusted_home == authorized_home.resolve():
                is_authorized = True

        if not is_authorized:
            expected = bound_profile or (authorized_home.name if authorized_home else "default")
            logger.warning(
                "Cross-profile access attempt blocked: caller requested %r but authorized scope is %r",
                untrusted_profile,
                expected,
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: request profile {untrusted_profile!r} does not match authorized scope {expected!r}",
            )

    resolved_profile = bound_profile or (authorized_home.name if authorized_home else "default")
    return resolved_profile, authorized_home


def _resolve_authorized_profile(request: Request) -> str:
    prof, _ = _resolve_authorized_context(request)
    return prof


def _req_profile(request: Request) -> str:
    return _resolve_authorized_profile(request)


def _req_assistant(request: Request) -> HermesVoiceAssistant:
    profile_name, authorized_home = _resolve_authorized_context(request)
    try:
        return get_assistant(profile=profile_name, home_dir=authorized_home)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


class SelectDocRequest(BaseModel):
    doc_id: str


class SeekRequest(BaseModel):
    sentence_index: Optional[int] = None
    page_number: Optional[int] = None


class PlaybackAckRequest(BaseModel):
    sentence_index: int
    event: str = "started"  # "started" | "ended" | "progress"
    offset_seconds: Optional[float] = None


class ConfigRequest(BaseModel):
    tts_model: Optional[str] = None
    speed: Optional[float] = None
    allow_remote: Optional[bool] = None
    llm_model: Optional[str] = None


class AskRequest(BaseModel):
    question: str


class PrivacyRequest(BaseModel):
    allow_remote: bool


@router.get("/status", response_model=PlayerStatusResponse)
async def get_status(request: Request):
    """Return complete live state snapshot for GUI."""
    assistant = _req_assistant(request)
    return assistant.get_full_status()


@router.get("/library")
async def list_library(request: Request):
    """Return list of documents in the persistent library."""
    assistant = _req_assistant(request)
    docs = assistant.get_library()
    return {"documents": [d.model_dump() for d in docs]}


@router.post("/select_document")
async def select_document(req: SelectDocRequest, request: Request):
    """Switch active document from library."""
    assistant = _req_assistant(request)
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
    profile_name, authorized_home = _resolve_authorized_context(request)
    try:
        assistant = get_assistant(profile=profile_name, home_dir=authorized_home)
        upload_dir = (resolve_voice_profile_dir(profile=profile_name, home_dir=authorized_home) / "uploaded_pdfs").resolve()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
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
            # Enforce AGENTS.md:13 profile isolation: validate path ownership against authorized vs foreign profile homes
            try:
                validate_path_profile_ownership(p, profile=profile_name, home_dir=authorized_home)
            except PermissionError as e:
                logger.warning(
                    "Cross-profile file path rejected in upload: %s (caller is %r at %s)",
                    e,
                    profile_name,
                    authorized_home,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied: {e}",
                )

            if p.exists() and p.is_file():
                if not p.name.lower().endswith(".pdf"):
                    raise HTTPException(status_code=400, detail="Il file deve avere estensione .pdf.")
                target_path = p
            else:
                raise HTTPException(status_code=404, detail=f"File PDF non trovato al percorso specificato: '{file_path}'.")
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
async def get_document(doc_id: str, request: Request):
    """Return full document data including text and sentence bounding boxes without changing active document or playback."""
    assistant = _req_assistant(request)
    doc = await asyncio.to_thread(assistant.get_document_by_id, doc_id)
    if doc:
        return doc.model_dump()

    raise HTTPException(status_code=404, detail=f"Documento ID '{doc_id}' non trovato.")


@router.post("/playback/play")
async def play_playback(request: Request):
    """Start audio playback."""
    assistant = _req_assistant(request)
    client_playback = None
    try:
        body = await request.json()
        if isinstance(body, dict):
            out = body.get("output")
            if out == "client":
                client_playback = True
            elif out == "server":
                client_playback = False
    except Exception:
        pass

    if client_playback is None:
        q_out = request.query_params.get("output")
        if q_out == "client":
            client_playback = True
        elif q_out == "server":
            client_playback = False

    try:
        bm = await asyncio.to_thread(assistant.play, client_playback=client_playback)
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore play: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/pause")
async def pause_playback(request: Request):
    """Pause audio playback and save exact bookmark."""
    assistant = _req_assistant(request)
    try:
        bm = await asyncio.to_thread(assistant.pause)
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore pause: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/resume")
async def resume_playback(request: Request):
    """Resume playback from exact point."""
    assistant = _req_assistant(request)
    client_playback = None
    try:
        body = await request.json()
        if isinstance(body, dict):
            out = body.get("output")
            if out == "client":
                client_playback = True
            elif out == "server":
                client_playback = False
    except Exception:
        pass

    if client_playback is None:
        q_out = request.query_params.get("output")
        if q_out == "client":
            client_playback = True
        elif q_out == "server":
            client_playback = False

    try:
        bm = await asyncio.to_thread(assistant.resume, client_playback=client_playback)
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore resume: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/stop")
async def stop_playback(request: Request):
    """Stop audio playback."""
    assistant = _req_assistant(request)
    try:
        bm = await asyncio.to_thread(assistant.stop)
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore stop: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/seek")
async def seek_playback(req: SeekRequest, request: Request):
    """Seek to specific page or sentence."""
    assistant = _req_assistant(request)
    try:
        if req.sentence_index is not None:
            bm = await asyncio.to_thread(assistant.seek_sentence, req.sentence_index)
        elif req.page_number is not None:
            bm = await asyncio.to_thread(assistant.seek_page, req.page_number)
        else:
            raise ValueError("Specificare 'sentence_index' oppure 'page_number'.")
        return {"status": "success", "bookmark": bm.model_dump()}
    except Exception as e:
        logger.error(f"Errore seek: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/playback/ack")
async def ack_playback(req: PlaybackAckRequest, request: Request):
    """Client playback acknowledgement to synchronize server-side bookmarks and sentence transitions."""
    assistant = _req_assistant(request)
    assistant.player.handle_client_ack(
        sentence_index=req.sentence_index,
        event=req.event,
        offset_seconds=req.offset_seconds,
    )
    return {"status": "success", "bookmark": assistant.player.get_bookmark().model_dump()}


@router.get("/audio/sentence/{sentence_idx}")
async def get_sentence_audio(sentence_idx: int, request: Request):
    """Deliver generated audio for sentence to the desktop client for local playback."""
    assistant = _req_assistant(request)
    # When a client fetches sentence audio via HTTP, ensure client playback is active to avoid double output
    assistant.player.client_playback = True
    wav_bytes = await asyncio.to_thread(assistant.player.get_sentence_audio_wav, sentence_idx)
    if not wav_bytes:
        raise HTTPException(status_code=404, detail="Audio non disponibile per la frase richiesta.")

    # Return base64 JSON when queried with ?format=json or accept: application/json
    fmt = request.query_params.get("format", "").lower()
    accept = request.headers.get("accept", "").lower()
    if fmt == "json" or ("application/json" in accept and "audio/wav" not in accept):
        b64_audio = base64.b64encode(wav_bytes).decode("ascii")
        return {
            "status": "success",
            "sentence_index": sentence_idx,
            "format": "wav",
            "audio_base64": b64_audio,
        }

    return Response(content=wav_bytes, media_type="audio/wav")


@router.post("/playback/config")
async def configure_playback(req: ConfigRequest, request: Request):
    """Update TTS model, playback speed, LLM model, or privacy settings."""
    assistant = _req_assistant(request)
    if req.tts_model:
        await asyncio.to_thread(assistant.set_tts_model, req.tts_model)
    if req.speed is not None:
        assistant.set_speed(req.speed)
    if req.allow_remote is not None:
        assistant.set_allow_remote(req.allow_remote)
    if req.llm_model:
        assistant.router.set_model(req.llm_model)

    return {
        "status": "success",
        "tts_model": assistant.tts.language,
        "speed": assistant.player.speed,
        "allow_remote": assistant.router.allow_remote,
        "llm_model": assistant.router.ollama_model,
    }


@router.post("/ask")
async def ask_question(req: AskRequest, request: Request):
    """Ask question to document using Bibliotecario, Analista, and Verificatore.
    Dispatched off the event loop via asyncio.to_thread and pinned to active document context.
    """
    assistant = _req_assistant(request)
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
async def get_models(request: Request):
    """Return local and remote model provider statuses."""
    assistant = _req_assistant(request)
    return assistant.router.get_providers_status()


@router.post("/config/privacy")
async def set_privacy(req: PrivacyRequest, request: Request):
    """Explicitly toggle remote provider authorization."""
    assistant = _req_assistant(request)
    assistant.set_allow_remote(req.allow_remote)
    return {"status": "success", "allow_remote": assistant.router.allow_remote}
