"""Verificatore (Verifier) Agent.

Responsibilities:
- Strictly validate citations in the Analyst's answer against the original verbatim document text.
- Verify that every cited page exists and actually contains the quoted text.
- Reject answers with missing citations, invalid page numbers, or ungrounded claims.
- Never approve hallucinations or LLM runtime errors.
"""

from __future__ import annotations

import re
from typing import List, Optional

from hermes_voice.models import ExtractedDocument, GroundedAnswer, VerificationResult


class VerifierAgent:
    """Agent in charge of citation and factual grounding verification."""

    def __init__(self, document: Optional[ExtractedDocument] = None):
        self.document = document

    def set_document(self, document: ExtractedDocument) -> None:
        self.document = document

    def verify(self, grounded_answer: GroundedAnswer) -> VerificationResult:
        """Verify citations and textual support against original document."""
        if not self.document:
            result = VerificationResult(
                is_valid=False,
                citation_match_score=0.0,
                unsupported_claims=["Nessun documento caricato per la verifica."],
                notes="Verifica fallita: nessun documento attivo nel sistema.",
            )
            grounded_answer.verification = result
            return result

        answer_text = (grounded_answer.answer or "").strip()

        # Check for model runtime error or empty answer
        if not answer_text or answer_text.startswith("Errore") or "[Errore]" in answer_text:
            result = VerificationResult(
                is_valid=False,
                citation_match_score=0.0,
                unsupported_claims=["La risposta indica un errore del modello o è vuota."],
                notes="Verifica fallita: la risposta dell'Analista non è valida o è un messaggio di errore.",
            )
            grounded_answer.verification = result
            return result

        citations = grounded_answer.citations
        # Factual claims require citations. An answer without citations is ungrounded.
        if not citations:
            result = VerificationResult(
                is_valid=False,
                citation_match_score=0.0,
                unsupported_claims=["Nessuna citazione formale fornita a supporto della risposta."],
                notes="Verifica fallita: la risposta non contiene riferimenti verificabili [Pagina X].",
            )
            grounded_answer.verification = result
            return result

        verified_quotes: List[str] = []
        unsupported_claims: List[str] = []
        matched_citations = 0

        # Check for substantive sentences that lack any page citation
        sentence_spans = [
            s.strip() for s in re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!|\n)\s+', answer_text) if s.strip()
        ]
        framing_prefixes = (
            "in base al documento", "in base al testo", "dal documento", "secondo il testo",
            "in riferimento a", "ecco la risposta", "in sintesi", "per riassumere",
            "sulla base del", "in base a", "come indicato",
        )
        # Collect text from cited pages for grounding check
        all_cited_text = " ".join(
            self._normalize_text(self.document.get_page(c.page_number).text)
            for c in citations
            if self.document.get_page(c.page_number)
        )
        if not all_cited_text:
            all_cited_text = " ".join(
                self._normalize_text(p.text) for p in self.document.pages
            )

        for s in sentence_spans:
            if not re.search(r'\[Pagina\s*\d+\]', s, re.IGNORECASE):
                cleaned_span = self._normalize_text(s)
                is_framing = (
                    s.strip().endswith(":")
                    or bool(re.match(r'^(?:\d+[\.\)]|[-•*])\s+', s.strip()))
                    or any(cleaned_span.startswith(self._normalize_text(prefix)) for prefix in framing_prefixes)
                )
                substantive_words = [w for w in cleaned_span.split() if len(w) > 3]
                if not is_framing and len(substantive_words) >= 4:
                    present_words = [w for w in substantive_words if w in all_cited_text]
                    grounded_ratio = len(present_words) / len(substantive_words) if substantive_words else 1.0
                    if grounded_ratio < 0.6:
                        unsupported_claims.append(
                            f"Affermazione nel testo priva di citazione o riscontro della fonte: '{s}'"
                        )

        for cit in citations:
            page = self.document.get_page(cit.page_number)
            if not page:
                unsupported_claims.append(
                    f"Pagina {cit.page_number} inesistente nel documento (totale pagine: {self.document.total_pages})."
                )
                continue

            page_text_clean = self._normalize_text(page.text)

            # Check if verbatim_quote or a substantial portion of it exists on page
            if not cit.verbatim_quote or not cit.verbatim_quote.strip():
                unsupported_claims.append(
                    f"Citazione a Pagina {cit.page_number} priva di testo letterale di riscontro."
                )
                continue

            quote_snippet = self._normalize_text(cit.verbatim_quote.strip("...").strip())

            # Split into significant words (ignore tiny stop words for matching)
            words = [w for w in quote_snippet.split() if len(w) > 2]
            if not words:
                unsupported_claims.append(
                    f"Citazione a Pagina {cit.page_number} contiene solo stop-words non verificabili."
                )
                continue

            # Check for exact substring match first
            if quote_snippet in page_text_clean:
                matched_citations += 1
                verified_quotes.append(f"Pagina {cit.page_number}: riscontro letterale esatto trovato.")
            else:
                # Substring / full quote check: verify that the substantive claim words are grounded on the page
                present_words = [w for w in words if w in page_text_clean]
                ratio = len(present_words) / len(words)

                # Split quote into sub-clauses to detect fabricated conclusions or claims appended to real phrases
                sub_clauses = [
                    c.strip()
                    for c in re.split(
                        r'[,;\.\n]|(?:\b(?:ma|però|tuttavia|quindi|inoltre|invece|sebbene|benché)\b)',
                        cit.verbatim_quote,
                        flags=re.IGNORECASE,
                    )
                    if c.strip()
                ]
                unsupported_subclause = None
                for clause in sub_clauses:
                    clause_words = [w for w in self._normalize_text(clause).split() if len(w) > 2]
                    if len(clause_words) >= 3:
                        clause_match_count = sum(1 for w in clause_words if w in page_text_clean)
                        if clause_match_count / len(clause_words) < 0.5:
                            unsupported_subclause = clause
                            break

                if unsupported_subclause:
                    unsupported_claims.append(
                        f"La citazione a Pagina {cit.page_number} contiene l'affermazione non riscontrata nel testo: '{unsupported_subclause}'."
                    )
                elif ratio >= 0.85:
                    matched_citations += 1
                    verified_quotes.append(
                        f"Pagina {cit.page_number}: concetti chiave confermati ({len(present_words)}/{len(words)} parole)."
                    )
                else:
                    unsupported_claims.append(
                        f"La pagina {cit.page_number} non contiene il testo citato: '{cit.verbatim_quote[:80]}'."
                    )

        total_citations = len(citations)
        score = matched_citations / total_citations if total_citations > 0 else 0.0

        # Strict validity: ALL citations must be verified and NO unsupported claims
        is_valid = (len(unsupported_claims) == 0) and (score == 1.0) and (matched_citations > 0)

        result = VerificationResult(
            is_valid=is_valid,
            citation_match_score=round(score, 2),
            unsupported_claims=unsupported_claims,
            verified_quotes=verified_quotes,
            notes=(
                f"Verifica completata con successo: tutte le {matched_citations} citazioni sono confermate nel documento."
                if is_valid
                else f"Anomalia riscontrata: {len(unsupported_claims)} citazioni non supportate o pagine non corrispondenti."
            ),
        )

        grounded_answer.verification = result
        return result

    def _normalize_text(self, text: str) -> str:
        """Normalize punctuation and whitespace for robust comparison."""
        t = text.lower()
        t = re.sub(r'[\.,;:\'\"\!\?\(\)\[\]\{\}\-\—\–]', ' ', t)
        return " ".join(t.split())
