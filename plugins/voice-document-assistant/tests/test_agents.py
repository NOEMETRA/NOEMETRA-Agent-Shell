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


def test_analyst_extracts_all_claims_without_page_deduplication():
    """Verify that multiple claims citing the same page are all extracted rather than deduplicated."""
    analyst = AnalystAgent()
    answer_text = (
        "Il modello italiano Pocket TTS è compatto [Pagina 1]. "
        "Inoltre supporta la modulazione del tono e della velocità [Pagina 1]."
    )
    citations = analyst._extract_citations(answer_text, excerpts=[])
    assert len(citations) == 2
    assert citations[0].page_number == 1
    assert "compatto" in citations[0].verbatim_quote.lower()
    assert citations[1].page_number == 1
    assert "modulazione" in citations[1].verbatim_quote.lower()


def test_verifier_rejects_answer_with_uncited_substantive_claim():
    """Verify that an answer containing an uncited substantive claim is marked invalid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        # First sentence has valid citation, second sentence has an uncited fabricated claim
        mixed_answer = GroundedAnswer(
            question="Cosa dice il documento?",
            answer=(
                "Il modello raggiunge una velocità pari a 2.6 volte il tempo reale su CPU [Pagina 2]. "
                "Tuttavia il server richiede 512 gigabyte di memoria RAM e raffreddamento ad azoto liquido."
            ),
            citations=[
                Citation(
                    page_number=2,
                    verbatim_quote="raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU",
                )
            ],
        )

        res = verifier.verify(mixed_answer)
        assert res.is_valid is False
        assert len(res.unsupported_claims) > 0
        assert any("priva di citazione" in c for c in res.unsupported_claims)


def test_verifier_validates_multiple_claims_on_same_page():
    """Verify that multiple valid citations referencing the same page are all verified."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)
        verifier = VerifierAgent(doc)

        multi_answer = GroundedAnswer(
            question="Dettagli modello",
            answer=(
                "La sintesi vocale è affidata a Pocket TTS [Pagina 1]. "
                "L'assistente documentale opera su sistemi Windows 11 [Pagina 1]."
            ),
            citations=[
                Citation(
                    page_number=1,
                    verbatim_quote="Pocket TTS",
                ),
                Citation(
                    page_number=1,
                    verbatim_quote="sistemi Windows 11",
                ),
            ],
        )

        res = verifier.verify(multi_answer)
        assert res.is_valid is True
        assert res.citation_match_score == 1.0
        assert len(res.unsupported_claims) == 0


def test_analyst_and_verifier_reject_unsupported_claim_paired_with_real_quote():
    """Verify that an unsupported assertion paired with a real verbatim quote in the same cited sentence is rejected (P1)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        analyst = AnalystAgent()
        verifier = VerifierAgent(doc)

        # 1. Fabricated Italian claim paired with a real quote from Page 2
        poisoned_it = (
            'L\'amministratore delegato ha sottratto fondi societari: '
            '"raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU" [Pagina 2].'
        )
        cits_it = analyst._extract_citations(poisoned_it, excerpts=[])
        # Both full claim and inner quote must be retained
        assert len(cits_it) == 2
        assert any("sottratto fondi" in c.verbatim_quote.lower() for c in cits_it)
        assert any(
            c.verbatim_quote == "raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU"
            for c in cits_it
        )

        ans_it = GroundedAnswer(question="Cosa emerge?", answer=poisoned_it, citations=cits_it)
        res_it = verifier.verify(ans_it)
        assert res_it.is_valid is False
        assert len(res_it.unsupported_claims) > 0

        # 2. English / colon-prefixed fabricated assertion paired with a real quote
        poisoned_en = (
            'The CEO stole funds: "raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU" [Pagina 2].'
        )
        cits_en = analyst._extract_citations(poisoned_en, excerpts=[])
        res_en = verifier.verify(GroundedAnswer(question="What?", answer=poisoned_en, citations=cits_en))
        assert res_en.is_valid is False
        assert len(res_en.unsupported_claims) > 0

        # 3. Direct GroundedAnswer passing only the quote in citations still fails sentence-level verification
        direct_bypass = GroundedAnswer(
            question="What?",
            answer=poisoned_en,
            citations=[
                Citation(
                    page_number=2,
                    verbatim_quote="raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU",
                )
            ],
        )
        res_direct = verifier.verify(direct_bypass)
        assert res_direct.is_valid is False
        assert len(res_direct.unsupported_claims) > 0


def test_analyst_and_verifier_accept_grounded_claim_paired_with_real_quote():
    """Verify that a grounded assertion accompanied by a genuine verbatim quote passes verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)
        doc = DocumentExtractor().extract(pdf_path)

        analyst = AnalystAgent()
        verifier = VerifierAgent(doc)

        grounded_text = (
            'In base al documento, la configurazione hardware di riferimento prevede un '
            '"processore Intel Core Ultra 7 con 16 gigabyte di memoria RAM" [Pagina 1].'
        )
        cits = analyst._extract_citations(grounded_text, excerpts=[])
        assert len(cits) == 2

        ans = GroundedAnswer(question="Qual è la configurazione hardware?", answer=grounded_text, citations=cits)
        res = verifier.verify(ans)
        assert res.is_valid is True
        assert res.citation_match_score == 1.0
        assert len(res.unsupported_claims) == 0


