"""Unified orchestrator for the Hermes Voice Document Assistant.

Combines:
- DocumentExtractor (PyMuPDF with explicit OCR boundary)
- PocketTTSEngine (Kyutai Labs Pocket TTS with model selection)
- DocumentPlayer (Audio playback & bookmark state with robust lifecycle)
- ModelRouter (Local-first Ollama / Codex / APIs with strict privacy consent)
- Agent Triad (Bibliotecario, Analista, Verificatore)
- Persistent Library Management across restarts
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from hermes_voice.agents.analyst import AnalystAgent
from hermes_voice.agents.librarian import LibrarianAgent
from hermes_voice.agents.verifier import VerifierAgent
from hermes_voice.extractor import DocumentExtractor
from hermes_voice.models import (
    AgentStatusInfo,
    ExtractedDocument,
    GroundedAnswer,
    LibraryEntry,
    PlayerState,
    PlayerStatusResponse,
    ReadingBookmark,
    SentenceSpan,
)
from hermes_voice.model_router import ModelRouter
from hermes_voice.player import DocumentPlayer
from hermes_voice.profile import resolve_voice_profile_dir
from hermes_voice.tts_engine import PocketTTSEngine

logger = logging.getLogger(__name__)


class HermesVoiceAssistant:
    """The central multi-agent voice document assistant."""

    def __init__(
        self,
        tts_engine: Optional[PocketTTSEngine] = None,
        model_router: Optional[ModelRouter] = None,
        bookmark_path: Optional[Union[str, Path]] = None,
        library_path: Optional[Union[str, Path]] = None,
        cache_dir: Optional[Union[str, Path]] = None,
        virtual_playback: bool = False,
        on_sentence_change: Optional[Callable[[SentenceSpan], None]] = None,
        profile: Optional[str] = None,
    ):
        prof_dir = resolve_voice_profile_dir(profile)
        self.profile = profile

        self.library_path = Path(library_path or prof_dir / "voice_library.json")
        self.library_path.parent.mkdir(parents=True, exist_ok=True)

        bm_path = Path(bookmark_path or prof_dir / "reading_state.json")
        c_dir = Path(cache_dir or prof_dir / "audio_cache")

        self.tts = tts_engine or PocketTTSEngine(cache_dir=c_dir, lazy_load=True)
        self.router = model_router or ModelRouter()
        self.extractor = DocumentExtractor()

        self.player = DocumentPlayer(
            tts_engine=self.tts,
            bookmark_path=bm_path,
            virtual_playback=virtual_playback,
            on_sentence_change=on_sentence_change,
        )

        self.librarian = LibrarianAgent()
        self.analyst = AnalystAgent(router=self.router)
        self.verifier = VerifierAgent()

        self.current_document: Optional[ExtractedDocument] = None
        self._agents_status = AgentStatusInfo(
            librarian="ready",
            analyst="ready",
            verifier="ready",
            detail="Tutti gli agenti operativi in modalità locale",
        )
        self._last_answer: Optional[GroundedAnswer] = None

        # Cache of extracted documents keyed by doc_id
        self._doc_cache: Dict[str, ExtractedDocument] = {}
        self._activation_lock = threading.Lock()
        self._init_library()

    def _init_library(self) -> None:
        """Load library catalog and restore last active document if available."""
        if self.library_path.exists():
            try:
                data = json.loads(self.library_path.read_text(encoding="utf-8"))
                entries = [LibraryEntry(**e) for e in data.get("documents", [])]
                last_doc_id = data.get("last_active_doc_id")
                if last_doc_id and entries:
                    target_entry = next((e for e in entries if e.doc_id == last_doc_id), entries[0])
                    if Path(target_entry.file_path).exists():
                        self.load_document(target_entry.file_path, resume_bookmark=True)
            except Exception as e:
                logger.warning(f"Errore caricamento catalogo biblioteca da {self.library_path}: {e}")

    def _save_library_catalog(self, last_active_id: Optional[str] = None) -> None:
        """Save document catalog to disk."""
        entries: List[LibraryEntry] = []
        if self.library_path.exists():
            try:
                data = json.loads(self.library_path.read_text(encoding="utf-8"))
                entries = [LibraryEntry(**e) for e in data.get("documents", [])]
            except Exception:
                entries = []

        if self.current_document:
            existing = next((e for e in entries if e.doc_id == self.current_document.doc_id), None)
            now_iso = datetime.now().isoformat()
            if existing:
                existing.last_opened_at = now_iso
                existing.file_path = self.current_document.file_path
                existing.total_pages = self.current_document.total_pages
                existing.total_sentences = len(self.current_document.all_sentences)
            else:
                entries.append(
                    LibraryEntry(
                        doc_id=self.current_document.doc_id,
                        file_path=self.current_document.file_path,
                        title=self.current_document.title,
                        total_pages=self.current_document.total_pages,
                        total_sentences=len(self.current_document.all_sentences),
                        created_at=now_iso,
                        last_opened_at=now_iso,
                    )
                )

        payload = {
            "last_active_doc_id": last_active_id or (self.current_document.doc_id if self.current_document else None),
            "documents": [e.model_dump() for e in entries],
        }
        try:
            self.library_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Impossibile salvare la biblioteca su {self.library_path}: {e}")

    def get_library(self) -> List[LibraryEntry]:
        """Return list of all registered documents in library."""
        if not self.library_path.exists():
            return []
        try:
            data = json.loads(self.library_path.read_text(encoding="utf-8"))
            return [LibraryEntry(**e) for e in data.get("documents", [])]
        except Exception:
            return []

    def load_document(self, file_path: Union[str, Path], resume_bookmark: bool = True) -> ReadingBookmark:
        """Extract PDF document and set up player and agents atomically."""
        with self._activation_lock:
            logger.info(f"Caricamento documento da '{file_path}'...")
            doc = self.extractor.extract(file_path)
            self.current_document = doc
            self._doc_cache[doc.doc_id] = doc

            # Update agents
            self.librarian.set_document(doc)
            self.verifier.set_document(doc)
            self._agents_status.librarian = "ready"
            self._agents_status.analyst = "ready"
            self._agents_status.verifier = "ready"
            self._agents_status.detail = f"Documento '{doc.title}' indicizzato ({doc.total_pages} pagine)"

            # Update player
            bookmark = self.player.load_document(doc, resume_from_bookmark=resume_bookmark)
            self._save_library_catalog(doc.doc_id)

            logger.info(
                f"Documento '{doc.title}' caricato: {doc.total_pages} pagine, "
                f"{len(doc.all_sentences)} frasi estratte."
            )
            return bookmark

    def get_document_by_id(self, doc_id: str) -> Optional[ExtractedDocument]:
        """Retrieve document data without altering current active player or document state."""
        if self.current_document and self.current_document.doc_id == doc_id:
            return self.current_document
        if doc_id in self._doc_cache:
            return self._doc_cache[doc_id]
        library = self.get_library()
        entry = next((e for e in library if e.doc_id == doc_id), None)
        if entry and Path(entry.file_path).exists():
            doc = self.extractor.extract(entry.file_path)
            self._doc_cache[doc.doc_id] = doc
            return doc
        return None

    def select_document(self, doc_id: str) -> ReadingBookmark:
        """Switch active document by doc_id from library catalog."""
        if self.current_document and self.current_document.doc_id == doc_id:
            return self.player.get_bookmark()

        if doc_id in self._doc_cache:
            doc = self._doc_cache[doc_id]
            return self.load_document(doc.file_path, resume_bookmark=True)

        library = self.get_library()
        entry = next((e for e in library if e.doc_id == doc_id), None)
        if not entry:
            raise FileNotFoundError(f"Documento ID '{doc_id}' non presente nella biblioteca.")

        return self.load_document(entry.file_path, resume_bookmark=True)

    def play(self) -> ReadingBookmark:
        """Start or resume deterministic audio reading."""
        return self.player.play()

    def pause(self) -> ReadingBookmark:
        """Pause audio reading and record exact position."""
        return self.player.pause()

    def resume(self) -> ReadingBookmark:
        """Resume audio reading from exact position."""
        return self.player.resume()

    def stop(self) -> ReadingBookmark:
        """Stop playback."""
        return self.player.stop()

    def seek_page(self, page_number: int) -> ReadingBookmark:
        """Jump to specific page."""
        return self.player.seek_to_page(page_number)

    def seek_sentence(self, sentence_index: int) -> ReadingBookmark:
        """Jump to specific sentence."""
        return self.player.seek_to_sentence(sentence_index)

    def set_tts_model(self, model_name: str) -> None:
        """Switch Pocket TTS model ('italian' or 'italian_24l') safely."""
        was_playing = (self.player.state == PlayerState.PLAYING)
        if was_playing:
            self.player.pause()
        self.tts.set_model(model_name)
        if was_playing:
            self.player.play()

    def set_speed(self, speed: float) -> None:
        """Set playback speed multiplier."""
        self.player.set_speed(speed)

    def set_allow_remote(self, allowed: bool) -> None:
        """Update explicit user authorization for remote network transmission."""
        self.router.set_allow_remote(allowed)

    def get_status(self) -> ReadingBookmark:
        """Return current reading bookmark."""
        return self.player.get_bookmark()

    def get_full_status(self) -> PlayerStatusResponse:
        """Return complete live state snapshot for GUI."""
        bm = self.player.get_bookmark()
        doc_title = self.current_document.title if self.current_document else ""
        total_pages = self.current_document.total_pages if self.current_document else 0

        return PlayerStatusResponse(
            state=bm.state,
            doc_id=bm.doc_id,
            doc_title=doc_title,
            file_path=bm.file_path,
            current_page=bm.current_page,
            total_pages=total_pages,
            current_sentence_index=bm.current_sentence_index,
            total_sentences=bm.total_sentences,
            current_sentence_text=bm.current_sentence_text,
            audio_seconds_offset=bm.audio_seconds_offset,
            tts_model=self.tts.language,
            speed=self.player.speed,
            allow_remote=self.router.allow_remote,
            agents=self._agents_status,
            last_answer=self._last_answer,
        )

    def ask(self, question: str, doc_id: Optional[str] = None) -> GroundedAnswer:
        """Execute full multi-agent question answering flow with verification,
        pinned to the document context to prevent cross-document races.
        """
        doc = None
        if doc_id and doc_id in self._doc_cache:
            doc = self._doc_cache[doc_id]
        if not doc:
            doc = self.current_document
        if not doc:
            raise ValueError("Nessun documento caricato. Utilizzare load_document() prima di formulare domande.")

        logger.info(f"Domanda ricevuta per documento '{doc.title}': '{question}'")

        # Request-local retrieval and verification agents bound to target doc to eliminate cross-document races
        librarian = LibrarianAgent(doc)
        verifier = VerifierAgent(doc)

        # Step 1: Bibliotecario retrieves relevant evidence
        self._agents_status.librarian = "searching"
        self._agents_status.detail = "Bibliotecario: ricerca estratti pertinenti..."
        excerpts = librarian.search(question, top_k=3)
        self._agents_status.librarian = "ready"
        logger.info(f"Bibliotecario ha individuato {len(excerpts)} estratti pertinenti.")

        # Step 2: Analista formulates answer with citations
        self._agents_status.analyst = "generating"
        self._agents_status.detail = "Analista: formulazione risposta grounded..."
        grounded_answer = self.analyst.answer_question(question, excerpts)
        self._agents_status.analyst = "ready"
        logger.info(f"Analista ha generato la risposta con {len(grounded_answer.citations)} citazioni.")

        # Step 3: Verificatore validates citations against source text
        self._agents_status.verifier = "verifying"
        self._agents_status.detail = "Verificatore: controllo fedeltà citazioni..."
        verification = verifier.verify(grounded_answer)

        if verification.is_valid:
            self._agents_status.verifier = "valid"
            self._agents_status.detail = f"Verifica completata: {verification.notes}"
        else:
            self._agents_status.verifier = "invalid"
            self._agents_status.detail = f"Attenzione: {verification.notes}"

        logger.info(
            f"Verificatore: stato={'CONFERMATO' if verification.is_valid else 'ANOMALIA'}, "
            f"accuratezza={verification.citation_match_score * 100:.0f}%"
        )

        # Associate result with current document only if document did not switch mid-flight
        if self.current_document and self.current_document.doc_id == doc.doc_id:
            self._last_answer = grounded_answer
        return grounded_answer
