"""Tests for agent triad: Librarian, Analyst, Verifier with explicit negative test cases."""

import tempfile
from pathlib import Path
import pytest

from hermes_voice.agents.analyst import AnalystAgent
from hermes_voice.agents.librarian import LibrarianAgent
from hermes_voice.agents.verifier import VerifierAgent
from hermes_voice.extractor import DocumentExtractor, create_sample_italian_pdf
from hermes_voice.models import Citation, GroundedAnswer


def test_librarian_search():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)

        librarian = LibrarianAgent(doc)
        results = librarian.search("Pocket TTS Kyutai Labs", top_k=2)

        assert len(results) > 0
        top = results[0]
        assert top.page_number in (1, 2)
        assert "pocket tts" in top.text.lower()


def test_verifier_citation_validation():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)

        verifier = VerifierAgent(doc)

        # Valid citation on Page 2
        valid_answer = GroundedAnswer(
            question="Qual è la velocità del modello italiano distillato?",
            answer="Il modello italiano raggiunge 2.6 volte il tempo reale su CPU [Pagina 2].",
            citations=[
                Citation(
                    page_number=2,
                    verbatim_quote="raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU",
                )
            ],
        )

        res_valid = verifier.verify(valid_answer)
        assert res_valid.is_valid is True
        assert res_valid.citation_match_score == 1.0
        assert len(res_valid.unsupported_claims) == 0


def test_verifier_negative_hallucinated_page():
    """Negative test: citation points to non-existent page."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        invalid_answer = GroundedAnswer(
            question="Qual è la velocità?",
            answer="Il modello raggiunge 2.6 volte il tempo reale [Pagina 99].",
            citations=[
                Citation(
                    page_number=99,
                    verbatim_quote="2.6 volte il tempo reale",
                )
            ],
        )

        res_invalid = verifier.verify(invalid_answer)
        assert res_invalid.is_valid is False
        assert len(res_invalid.unsupported_claims) > 0
        assert "Pagina 99 inesistente" in res_invalid.unsupported_claims[0]


def test_verifier_negative_hallucinated_quote():
    """Negative test: citation references real page but quote does not exist on that page."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        hallucinated_answer = GroundedAnswer(
            question="Che tipo di memoria ha il sistema?",
            answer="Il sistema adotta memorie quantistiche superconduttrici [Pagina 1].",
            citations=[
                Citation(
                    page_number=1,
                    verbatim_quote="memorie quantistiche superconduttrici operanti a zero kelvin",
                )
            ],
        )

        res = verifier.verify(hallucinated_answer)
        assert res.is_valid is False
        assert len(res.unsupported_claims) > 0
        assert any("non contiene il testo citato" in c or "non riscontrata nel testo" in c for c in res.unsupported_claims)


def test_verifier_negative_model_error():
    """Negative test: Analyst encountered a model error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        error_answer = GroundedAnswer(
            question="Qualcosa?",
            answer="Errore durante l'elaborazione della risposta con il modello: Ollama connection refused",
            citations=[],
        )

        res = verifier.verify(error_answer)
        assert res.is_valid is False
        assert "La risposta indica un errore del modello" in res.unsupported_claims[0]


def test_verifier_negative_empty_citations():
    """Negative test: Answer has claims but no citations provided."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        uncited_answer = GroundedAnswer(
            question="Qualcosa?",
            answer="Il processore è un Intel Core Ultra 7 ma non dico da dove l'ho letto.",
            citations=[],
        )

        res = verifier.verify(uncited_answer)
        assert res.is_valid is False
        assert "Nessuna citazione formale fornita" in res.unsupported_claims[0]


def test_verifier_rejects_unsupported_conclusion_appended_to_real_ngram():
    """Verify that a fabricated claim appended to a real 4-word phrase is rejected by the verifier."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        # "raggiunge una velocità di generazione" is real on page 2, but "ma produce allucinazioni quantistiche" is completely fabricated
        poisoned_answer = GroundedAnswer(
            question="Qual è la velocità?",
            answer="Il modello raggiunge una velocità di generazione ma produce allucinazioni quantistiche [Pagina 2].",
            citations=[
                Citation(
                    page_number=2,
                    verbatim_quote="raggiunge una velocità di generazione ma produce allucinazioni quantistiche",
                )
            ],
        )

        res = verifier.verify(poisoned_answer)
        assert res.is_valid is False
        assert len(res.unsupported_claims) > 0
        assert any("affermazione non riscontrata" in c or "non contiene il testo citato" in c for c in res.unsupported_claims)

