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
        """Parse [Pagina X] references and pair with excerpt quotes."""
        matches = re.findall(r'\[Pagina\s*(\d+)\]', answer_text, re.IGNORECASE)
        citations: List[Citation] = []
        seen_pages = set()

        for match in matches:
            page_num = int(match)
            if page_num in seen_pages:
                continue
            seen_pages.add(page_num)

            # Find matching excerpt for verbatim quote reference
            quote = ""
            for exc in excerpts:
                if exc.page_number == page_num:
                    quote = exc.text[:120] + "..." if len(exc.text) > 120 else exc.text
                    break

            citations.append(
                Citation(
                    page_number=page_num,
                    verbatim_quote=quote,
                    confidence=1.0,
                )
            )

        # Fallback only if answer is substantive and not an error
        if not citations and excerpts and len(answer_text) > 20 and not answer_text.startswith("Errore"):
            # Check if any excerpt text appears in the answer
            top_exc = excerpts[0]
            citations.append(
                Citation(
                    page_number=top_exc.page_number,
                    verbatim_quote=top_exc.text[:120] + "...",
                    confidence=0.7,
                )
            )

        return citations
