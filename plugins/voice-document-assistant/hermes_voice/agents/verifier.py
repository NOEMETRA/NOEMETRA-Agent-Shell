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
                # Substring check: take n-grams of 4 consecutive words from quote
                found_ngram = False
                if len(words) >= 4:
                    for i in range(len(words) - 3):
                        ngram = " ".join(words[i:i+4])
                        if ngram in page_text_clean:
                            found_ngram = True
                            matched_citations += 1
                            verified_quotes.append(f"Pagina {cit.page_number}: riscontro confermato su '{ngram}'.")
                            break

                if not found_ngram:
                    # Require at least 80% of significant words to appear in page
                    present_words = [w for w in words if w in page_text_clean]
                    ratio = len(present_words) / len(words)
                    if ratio >= 0.8:
                        matched_citations += 1
                        verified_quotes.append(f"Pagina {cit.page_number}: concetti chiave confermati ({len(present_words)}/{len(words)} parole).")
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
