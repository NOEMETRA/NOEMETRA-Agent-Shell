"""Verificatore (Verifier) Agent.

Responsibilities:
- Strictly validate citations in the Analyst's answer against the original verbatim document text.
- Verify that every cited page exists and actually contains both any quoted text and the full surrounding claim.
- Reject answers with missing citations, invalid page numbers, or ungrounded claims.
- Never approve hallucinations or LLM runtime errors.
"""

from __future__ import annotations

import re
from typing import List, Optional

from hermes_voice.models import ExtractedDocument, GroundedAnswer, VerificationResult

NEUTRAL_DISCOURSE_WORDS = frozenset({
    # Function words / articles / prepositions / auxiliaries / pronouns (>2 chars)
    "del", "dello", "della", "dei", "degli", "delle", "nel", "nello", "nella",
    "nei", "negli", "nelle", "sul", "sullo", "sulla", "sui", "sugli", "sulle",
    "dal", "dallo", "dalla", "dai", "dagli", "dalle", "col", "con", "per", "tra",
    "fra", "una", "uno", "gli", "che", "chi", "cui", "più", "anche", "solo",
    "sono", "sia", "stato", "stata", "stati", "state", "essere", "avere", "hanno",
    "questo", "questa", "questi", "queste", "quello", "quella", "quelli", "quelle",
    "suo", "sua", "suoi", "sue", "loro", "ogni", "tutti", "tutte", "tutto",
    "come", "dove", "quando", "quale", "quali", "quanto", "così", "cioè", "ossia",
    "ovvero", "infatti", "quindi", "dunque", "inoltre", "invece", "però", "tuttavia",
    "ecco", "circa", "oltre", "verso", "entro", "mediante", "tramite", "attraverso",
    # Pure meta-document reporting / framing / structural verbs & nouns
    "documento", "documentale", "testo", "pagina", "pagine", "capitolo", "paragrafo",
    "sezione", "estratto", "estratti", "fonte", "fonti", "secondo", "base", "basata",
    "basato", "fornito", "forniti", "fornite", "allegato", "allegati", "riferimento",
    "merito", "punto", "punti", "parte", "parti", "modo", "seguente", "seguenti",
    "afferma", "riporta", "riportato", "indica", "indicato", "specifica", "specificato",
    "descrive", "descritto", "mostra", "evidenzia", "spiega", "sottolinea", "conferma",
    "confermano", "confermato", "dimostra", "dimostrano", "dimostrato",
    "cita", "citato", "citando", "menziona", "definisce", "definito",
    "prevede", "adotta", "utilizza", "impiega", "presenta", "contiene", "riguarda",
    "compongono", "composto", "composta", "comprende", "comprendono", "costituiscono",
    "costituito", "formano", "formato", "include", "includono", "rappresenta",
    "sintesi", "riassumendo", "conclusione", "risposta",
})

_SUBCLAUSE_SPLIT_RE = re.compile(
    r'[,;:\.\n"“”«»\—\–]|(?:\b(?:ma|però|tuttavia|quindi|inoltre|invece|sebbene|benché|mentre)\b)',
    flags=re.IGNORECASE,
)


class VerifierAgent:
    """Agent in charge of citation and factual grounding verification."""

    def __init__(self, document: Optional[ExtractedDocument] = None):
        self.document = document

    def set_document(self, document: ExtractedDocument) -> None:
        self.document = document

    def _content_words(self, text: str) -> List[str]:
        """Extract substantive content words excluding short tokens and neutral discourse framing."""
        return [
            w for w in self._normalize_text(text).split()
            if len(w) > 2 and w not in NEUTRAL_DISCOURSE_WORDS
        ]

    def _verify_claim_on_page(
        self,
        claim_text: str,
        page_text_clean: str,
        page_number: int,
        allow_pure_framing: bool = False,
    ) -> tuple[bool, str]:
        """Validate a claim (including both any verbatim quotes and surrounding assertions) against page text.

        Returns (is_ok, detail_message).
        """
        raw = (claim_text or "").strip().strip("...").strip()
        if not raw:
            return False, f"Citazione a Pagina {page_number} priva di testo letterale di riscontro."

        quote_snippet = self._normalize_text(raw)
        words = [w for w in quote_snippet.split() if len(w) > 2]
        if not words:
            if allow_pure_framing:
                return True, ""
            return False, f"Citazione a Pagina {page_number} contiene solo stop-words non verificabili."

        # 1. Check whether the claim embeds explicit quotation marks alongside surrounding prose
        quoted_matches = [
            q.strip()
            for q in re.findall(r'["“«]([^"”»\n]{4,})["”»]', raw)
            if q.strip()
        ]
        if quoted_matches:
            # 1a. Every quoted span must match on the cited page
            for q_span in quoted_matches:
                q_norm = self._normalize_text(q_span.strip("...").strip())
                if not q_norm:
                    continue
                if q_norm not in page_text_clean:
                    q_words = [w for w in q_norm.split() if len(w) > 2]
                    if q_words:
                        q_present = sum(1 for w in q_words if w in page_text_clean)
                        if q_present / len(q_words) < 0.85:
                            return (
                                False,
                                f"La pagina {page_number} non contiene la citazione tra virgolette: '{q_span[:80]}'.",
                            )

            # 1b. Verify the unquoted residual assertion so a genuine quote never masks a fabricated claim
            unquoted_residual = re.sub(r'["“«][^"”»\n]+["”»]', " ; ", raw)
            res_content_words = self._content_words(unquoted_residual)
            if len(res_content_words) >= 2:
                res_matches = sum(1 for w in res_content_words if w in page_text_clean)
                if res_matches / len(res_content_words) < 0.6:
                    cleaned_res = re.sub(r"\s*;\s*", " ", unquoted_residual).strip(" ;:.,-")
                    return (
                        False,
                        f"La citazione a Pagina {page_number} accompagna un'affermazione non supportata dal testo: '{cleaned_res[:80]}'.",
                    )

            for clause in (c.strip() for c in _SUBCLAUSE_SPLIT_RE.split(unquoted_residual) if c.strip()):
                c_words = self._content_words(clause)
                if len(c_words) >= 2:
                    c_matches = sum(1 for w in c_words if w in page_text_clean)
                    if (len(c_words) == 2 and c_matches == 0) or (
                        len(c_words) >= 3 and c_matches / len(c_words) < 0.6
                    ):
                        return (
                            False,
                            f"La citazione a Pagina {page_number} contiene l'affermazione non riscontrata nel testo: '{clause}'.",
                        )

            return True, f"Pagina {page_number}: citazione e affermazione contestuale confermate."

        # 2. Exact normalized substring match on page
        if quote_snippet in page_text_clean:
            return True, f"Pagina {page_number}: riscontro letterale esatto trovato."

        # 3. Paraphrased / composite claim check: validate sub-clauses and substantive word coverage
        content_words = self._content_words(raw)
        if not content_words:
            if allow_pure_framing:
                return True, ""
            return False, f"Citazione a Pagina {page_number} priva di contenuto fattuale verificabile."

        sub_clauses = [c.strip() for c in _SUBCLAUSE_SPLIT_RE.split(raw) if c.strip()]
        for clause in sub_clauses:
            clause_words = self._content_words(clause)
            if len(clause_words) >= 3:
                clause_match_count = sum(1 for w in clause_words if w in page_text_clean)
                if clause_match_count / len(clause_words) < 0.5:
                    return (
                        False,
                        f"La citazione a Pagina {page_number} contiene l'affermazione non riscontrata nel testo: '{clause}'.",
                    )
            elif len(clause_words) == 2:
                clause_match_count = sum(1 for w in clause_words if w in page_text_clean)
                if clause_match_count == 0:
                    return (
                        False,
                        f"La citazione a Pagina {page_number} contiene l'affermazione non riscontrata nel testo: '{clause}'.",
                    )

        present_words = [w for w in content_words if w in page_text_clean]
        ratio = len(present_words) / len(content_words)
        if ratio >= 0.85:
            return (
                True,
                f"Pagina {page_number}: concetti chiave confermati ({len(present_words)}/{len(content_words)} parole).",
            )

        return False, f"La pagina {page_number} non contiene il testo citato: '{raw[:80]}'."

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

        # Check all sentences in answer_text (both uncited sentences and full cited claims)
        sentence_spans = [
            s.strip() for s in re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!|\n)\s+', answer_text) if s.strip()
        ]
        framing_prefixes = (
            "in base al documento", "in base al testo", "dal documento", "secondo il testo",
            "in riferimento a", "ecco la risposta", "in sintesi", "per riassumere",
            "sulla base del", "in base a", "come indicato",
        )
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
            page_matches = list(re.finditer(r'\[Pagina\s*(\d+)\]', s, re.IGNORECASE))
            if not page_matches:
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
            else:
                # Validate the full cited sentence (including any unquoted assertions surrounding a quote)
                cited_page_nums = [int(m.group(1)) for m in page_matches]
                valid_pages_for_sent = [
                    self.document.get_page(pn) for pn in cited_page_nums if self.document.get_page(pn)
                ]
                if valid_pages_for_sent:
                    sent_pages_clean = " ".join(self._normalize_text(p.text) for p in valid_pages_for_sent)
                    sent_claim = re.sub(r'\[Pagina\s*\d+\]', '', s, flags=re.IGNORECASE).strip()
                    sent_claim = re.sub(r'^(?:\d+[\.\)]|[-•*]+)\s*', '', sent_claim).strip()
                    if sent_claim:
                        ok, msg = self._verify_claim_on_page(
                            sent_claim,
                            sent_pages_clean,
                            cited_page_nums[0],
                            allow_pure_framing=True,
                        )
                        if not ok and msg not in unsupported_claims:
                            unsupported_claims.append(msg)

        for cit in citations:
            page = self.document.get_page(cit.page_number)
            if not page:
                unsupported_claims.append(
                    f"Pagina {cit.page_number} inesistente nel documento (totale pagine: {self.document.total_pages})."
                )
                continue

            page_text_clean = self._normalize_text(page.text)
            ok, msg = self._verify_claim_on_page(
                cit.verbatim_quote,
                page_text_clean,
                cit.page_number,
                allow_pure_framing=False,
            )
            if ok:
                matched_citations += 1
                verified_quotes.append(msg)
            else:
                if msg not in unsupported_claims:
                    unsupported_claims.append(msg)

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
        """Normalize punctuation, markdown markers, and whitespace for robust comparison."""
        t = text.lower()
        t = re.sub(r'[\.,;:\'\"“”«»\!\?\(\)\[\]\{\}\-\—\–\*\_\#\`•]', ' ', t)
        return " ".join(t.split())
