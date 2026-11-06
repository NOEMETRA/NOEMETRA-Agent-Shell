"""Data models for Hermes Voice Document Assistant."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PlayerState(str, Enum):
    IDLE = "idle"
    PLAYING = "playing"
    PAUSED = "paused"
    STOPPED = "stopped"
    FINISHED = "finished"


class SentenceSpan(BaseModel):
    """Verbatim sentence extracted from document with exact location."""
    sentence_index: int = Field(description="Global sequential sentence index (0-based)")
    page_number: int = Field(description="Document page number (1-based)")
    paragraph_index: int = Field(default=0, description="Paragraph index on page (0-based)")
    text: str = Field(description="Verbatim sentence text without alteration")
    char_start: int = Field(default=0, description="Start character offset in page text")
    char_end: int = Field(default=0, description="End character offset in page text")
    bbox: Optional[List[float]] = Field(default=None, description="Bounding box [x0, y0, x1, y1]")


class DocumentPage(BaseModel):
    """Page extracted from PDF."""
    page_number: int = Field(description="Page number (1-based)")
    text: str = Field(description="Raw text of the page")
    sentences: List[SentenceSpan] = Field(default_factory=list)
    is_scanned: bool = Field(default=False, description="Whether page consists mostly of images requiring OCR")
    ocr_applied: bool = Field(default=False, description="Whether OCR was used to extract text")


class ExtractedDocument(BaseModel):
    """Complete document representation."""
    doc_id: str = Field(description="Unique document identifier")
    file_path: str = Field(description="Original file path")
    title: str = Field(default="Senza Titolo")
    total_pages: int = Field(default=0)
    pages: List[DocumentPage] = Field(default_factory=list)
    all_sentences: List[SentenceSpan] = Field(default_factory=list)
    has_scanned_pages: bool = Field(default=False, description="Whether any page needed or used OCR")

    def get_sentence(self, index: int) -> Optional[SentenceSpan]:
        if 0 <= index < len(self.all_sentences):
            return self.all_sentences[index]
        return None

    def get_page(self, page_num: int) -> Optional[DocumentPage]:
        for p in self.pages:
            if p.page_number == page_num:
                return p
        return None


class LibraryEntry(BaseModel):
    """Persistent catalog item in the PDF library."""
    doc_id: str
    file_path: str
    title: str
    total_pages: int
    total_sentences: int
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    last_opened_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ReadingBookmark(BaseModel):
    """Persistent playback state and bookmark."""
    doc_id: str
    file_path: str
    current_sentence_index: int = 0
    current_page: int = 1
    current_sentence_text: str = ""
    audio_sample_offset: int = 0
    audio_seconds_offset: float = 0.0
    state: PlayerState = PlayerState.IDLE
    total_sentences: int = 0
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class Citation(BaseModel):
    """Verifiable page citation."""
    page_number: int
    verbatim_quote: str
    sentence_index: Optional[int] = None
    confidence: float = 1.0


class VerificationResult(BaseModel):
    """Result from Verifier agent."""
    is_valid: bool
    citation_match_score: float = 1.0  # 0.0 to 1.0
    unsupported_claims: List[str] = Field(default_factory=list)
    verified_quotes: List[str] = Field(default_factory=list)
    notes: str = ""


class GroundedAnswer(BaseModel):
    """Response to user question with evidence and page citations."""
    question: str
    answer: str
    citations: List[Citation] = Field(default_factory=list)
    verification: Optional[VerificationResult] = None
    model_used: str = "ollama/gemma4:12b"
    latency_seconds: float = 0.0


class AgentStatusInfo(BaseModel):
    """Real activity status of the three agents."""
    librarian: str = "idle"  # "idle" | "searching" | "ready" | "error"
    analyst: str = "idle"    # "idle" | "generating" | "ready" | "error"
    verifier: str = "idle"   # "idle" | "verifying" | "valid" | "invalid" | "error"
    detail: Optional[str] = None


class PlayerStatusResponse(BaseModel):
    """Complete backend status response for GUI updates."""
    state: PlayerState = PlayerState.IDLE
    doc_id: str = ""
    doc_title: str = ""
    file_path: str = ""
    current_page: int = 1
    total_pages: int = 0
    current_sentence_index: int = 0
    total_sentences: int = 0
    current_sentence_text: str = ""
    audio_seconds_offset: float = 0.0
    tts_model: str = "italian"  # "italian" | "italian_24l"
    speed: float = 1.0
    client_playback: bool = False
    allow_remote: bool = False
    agents: AgentStatusInfo = Field(default_factory=AgentStatusInfo)
    last_answer: Optional[GroundedAnswer] = None
