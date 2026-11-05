"""Bibliotecario (Librarian) Agent.

Responsibilities:
- Ingestion and indexing of PDF documents.
- Structure extraction (pages, paragraphs, sentences).
- Context-aware retrieval of verbatim excerpts based on user queries.
- Reading progress tracking and bookmark coordination.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from hermes_voice.models import DocumentPage, ExtractedDocument, SentenceSpan


class RetrievedExcerpt:
    """Document excerpt retrieved by the Librarian."""

    def __init__(
        self,
        page_number: int,
        paragraph_index: int,
        text: str,
        score: float,
        sentences: List[SentenceSpan],
    ):
        self.page_number = page_number
        self.paragraph_index = paragraph_index
        self.text = text
        self.score = score
        self.sentences = sentences

    def __repr__(self) -> str:
        return f"<Excerpt Pag.{self.page_number} score={self.score:.2f}: {self.text[:40]}...>"


class LibrarianAgent:
    """Agent in charge of document indexing and retrieval."""

    def __init__(self, document: Optional[ExtractedDocument] = None):
        self.document = document

    def set_document(self, document: ExtractedDocument) -> None:
        self.document = document

    def search(self, query: str, top_k: int = 3) -> List[RetrievedExcerpt]:
        """Retrieve most relevant verbatim passages matching query with page numbers."""
        if not self.document:
            return []

        query_terms = self._tokenize(query)
        if not query_terms:
            return []

        scored_excerpts: List[RetrievedExcerpt] = []

        # Group sentences by page and paragraph for coherent excerpts
        for page in self.document.pages:
            paragraphs: dict[int, List[SentenceSpan]] = {}
            for sent in page.sentences:
                paragraphs.setdefault(sent.paragraph_index, []).append(sent)

            for para_idx, sents in paragraphs.items():
                para_text = " ".join(s.text for s in sents)
                score = self._compute_relevance(query_terms, para_text)
                if score > 0:
                    scored_excerpts.append(
                        RetrievedExcerpt(
                            page_number=page.page_number,
                            paragraph_index=para_idx,
                            text=para_text,
                            score=score,
                            sentences=sents,
                        )
                    )

        scored_excerpts.sort(key=lambda x: x.score, reverse=True)
        return scored_excerpts[:top_k]

    def get_page_context(self, page_number: int) -> Optional[str]:
        """Return full text for a given page."""
        if not self.document:
            return None
        page = self.document.get_page(page_number)
        return page.text if page else None

    def _tokenize(self, text: str) -> set[str]:
        words = re.findall(r'\b[a-zA-ZàèéìòùÀÈÉÌÒÙ0-9_-]{3,}\b', text.lower())
        stopwords = {
            "per", "con", "tra", "fra", "delle", "della", "dello", "degli",
            "quale", "quali", "come", "cosa", "dove", "sono", "viene", "hanno"
        }
        return {w for w in words if w not in stopwords}

    def _compute_relevance(self, query_terms: set[str], text: str) -> float:
        text_lower = text.lower()
        score = 0.0
        for term in query_terms:
            if term in text_lower:
                # Frequency weighting
                count = text_lower.count(term)
                score += 1.0 + (count - 1) * 0.3
        return score
