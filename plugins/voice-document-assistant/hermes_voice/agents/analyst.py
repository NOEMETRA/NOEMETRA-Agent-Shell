"""Analista (Analyst) Agent.

Responsibilities:
- Synthesize answers strictly based on evidence retrieved by the Librarian.
- Include explicit, verifiable page citations [Pagina X].
- Disclose absence of information if not grounded in document excerpts.
"""

from __future__ import annotations

import logging
import re
import time
from typing import List, Optional

from hermes_voice.agents.librarian import RetrievedExcerpt
from hermes_voice.models import Citation, GroundedAnswer
from hermes_voice.model_router import ModelRouter

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Sei l'Agente Analista di Hermes Voice Research.
Il tuo compito è rispondere alle domande dell'utente ESCLUSIVAMENTE sulla base degli estratti documentali forniti dal Bibliotecario.

REGOLE VINCOLANTI:
1. Basati SOLO sui fatti presenti negli estratti allegati.
2. CITA SEMPRE il numero di pagina esatto nel formato [Pagina X] per ogni affermazione principale.
3. Se possibile, includi brevi citazioni letterali tra virgolette ("...").
4. Se gli estratti non contengono informazioni sufficienti per rispondere, dichiara chiaramente: "Il documento non contiene informazioni sufficienti su questo punto."
5. NON inventare numeri, pagine, date o concetti non presenti nel testo.
6. Rispondi in italiano in modo chiaro, sintetico e professionale.
"""


class AnalystAgent:
    """Agent in charge of evidence-based document question answering."""

    def __init__(self, router: Optional[ModelRouter] = None):
        self.router = router or ModelRouter()

    def answer_question(
        self,
        question: str,
        excerpts: List[RetrievedExcerpt],
    ) -> GroundedAnswer:
        """Formulate grounded answer using retrieved excerpts."""
        t0 = time.perf_counter()

        if not excerpts:
            return GroundedAnswer(
                question=question,
                answer="Nessun estratto pertinente trovato nel documento per questa domanda.",
                citations=[],
                model_used=self.router.ollama_model,
                latency_seconds=round(time.perf_counter() - t0, 3),
            )

        # Build prompt with labeled excerpts and page numbers
        context_parts = []
        for i, exc in enumerate(excerpts, 1):
            context_parts.append(
                f"--- ESTRATTO {i} (Pagina {exc.page_number}) ---\n{exc.text}\n"
            )
        context_text = "\n".join(context_parts)

        user_prompt = (
            f"ESTRATTI DOCUMENTALI:\n{context_text}\n\n"
            f"DOMANDA DELL'UTENTE:\n{question}\n\n"
            "Fornisci una risposta accurata basata sugli estratti, indicando esplicitamente [Pagina X]."
        )

        is_error = False
        try:
            raw_answer = self.router.generate(
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT,
                temperature=0.1,  # Low temperature for deterministic grounding
                max_tokens=400,
            )
        except Exception as e:
            logger.error(f"Errore generazione LLM nell'Analista: {e}")
            raw_answer = f"Errore durante l'elaborazione della risposta con il modello: {e}"
            is_error = True

        elapsed = time.perf_counter() - t0

        # Extract citations [Pagina X] only if not an error
        if is_error:
            citations = []
        else:
            citations = self._extract_citations(raw_answer, excerpts)

        return GroundedAnswer(
            question=question,
            answer=raw_answer,
            citations=citations,
            model_used=self.router.ollama_model,
            latency_seconds=round(elapsed, 3),
        )

    def _extract_citations(
        self,
        answer_text: str,
        excerpts: List[RetrievedExcerpt],
    ) -> List[Citation]:
        """Parse [Pagina X] references and extract every cited claim from the answer.

        Strict constraint: Do not deduplicate by page. Every distinct cited statement
        must be retained so VerifierAgent can independently verify each claim.
        """
        citations: List[Citation] = []
        seen_claim_keys = set()

        # Split answer into sentence blocks to associate each citation with its specific claim
        sentence_spans = [
            s.strip() for s in re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?|\!|\n)\s+', answer_text) if s.strip()
        ]

        for s in sentence_spans:
            matches = list(re.finditer(r'\[Pagina\s*(\d+)\]', s, re.IGNORECASE))
            if not matches:
                continue

            # Check for explicit quotation marks inside this claim first
            quoted = re.findall(r'["«\']([^"»\']{8,})["»\']', s)
            if quoted:
                claim_text = quoted[0].strip()
            else:
                # Strip the citation marker from the claim sentence
                claim_text = re.sub(r'\[Pagina\s*\d+\]', '', s, flags=re.IGNORECASE).strip()

            if not claim_text:
                continue

            for match in matches:
                page_num = int(match.group(1))
                claim_key = (page_num, claim_text.lower())
                if claim_key in seen_claim_keys:
                    continue
                seen_claim_keys.add(claim_key)

                citations.append(
                    Citation(
                        page_number=page_num,
                        verbatim_quote=claim_text,
                        confidence=1.0,
                    )
                )

        # Fallback if citations matched in raw answer but were not captured by sentence splitting
        if not citations:
            matches = list(re.finditer(r'\[Pagina\s*(\d+)\]', answer_text, re.IGNORECASE))
            for match in matches:
                page_num = int(match.group(1))
                claim_text = re.sub(r'\[Pagina\s*\d+\]', '', answer_text, flags=re.IGNORECASE).strip()
                citations.append(
                    Citation(
                        page_number=page_num,
                        verbatim_quote=claim_text,
                        confidence=1.0,
                    )
                )

        # Do NOT fabricate evidence for uncited answers: preserve empty citations list
        # so that VerifierAgent properly flags ungrounded answers.
        return citations
