"""Tests for document extraction and sentence segmentation."""

import tempfile
from pathlib import Path
import pytest
from hermes_voice.extractor import DocumentExtractor, create_sample_italian_pdf


def test_extractor_sample_pdf():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "test.pdf"
        create_sample_italian_pdf(pdf_path)

        extractor = DocumentExtractor()
        doc = extractor.extract(pdf_path)

        assert doc.total_pages == 3
        assert len(doc.pages) == 3
        assert len(doc.all_sentences) > 0

        # Verify page 1 content
        p1 = doc.get_page(1)
        assert p1 is not None
        assert "Hermes Voice" in p1.text
        assert "Intel Core Ultra 7" in p1.text

        # Verify sentence indexing is contiguous
        for idx, sent in enumerate(doc.all_sentences):
            assert sent.sentence_index == idx
            assert sent.page_number in (1, 2, 3)
            assert len(sent.text) > 0
            # Ensure no newlines remain inside sentence
            assert "\n" not in sent.text


def test_extractor_abbreviations():
    extractor = DocumentExtractor()
    text = "Il dott. Rossi ha incontrato il prof. Bianchi all'art. 5 del codice civile."
    sentences = extractor._split_into_sentences(text)
    # Should not split on "dott.", "prof.", "art."
    assert len(sentences) == 1
    assert "dott. Rossi" in sentences[0]


def test_extractor_preserves_trailing_text_without_terminal_punctuation():
    """Verify text after the last sentence delimiter is preserved for TTS and retrieval (P1)."""
    import pymupdf

    extractor = DocumentExtractor()

    # 1. Complete sentence followed by trailing clause without terminal punctuation
    mixed = "Prima frase completa. Avvertenza importante senza punto finale"
    assert extractor._split_into_sentences(mixed) == [
        "Prima frase completa.",
        "Avvertenza importante senza punto finale",
    ]

    # 2. Abbreviation followed by trailing text without terminal punctuation
    abbrev_tail = "Gentile Dott. Mario Rossi"
    assert extractor._split_into_sentences(abbrev_tail) == ["Gentile Dott. Mario Rossi"]

    # 3. Quoted exclamation followed by closing punctuation and unpunctuated tail
    quoted = 'Disse "Attenzione!". Nota operativa urgente'
    assert extractor._split_into_sentences(quoted) == [
        'Disse "Attenzione!".',
        "Nota operativa urgente",
    ]

    # 4. End-to-end PDF block extraction preserves trailing unpunctuated text in all_sentences
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "trailing.pdf"
        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Introduzione regolarmente punteggiata. Clausola finale critica")
        doc.save(str(pdf_path))
        doc.close()

        extracted = extractor.extract(pdf_path)
        texts = [s.text for s in extracted.all_sentences]
        assert texts == [
            "Introduzione regolarmente punteggiata.",
            "Clausola finale critica",
        ]


def test_extractor_preserves_technical_numbering_and_abbreviations():
    extractor = DocumentExtractor()

    numbered = "1. Configurazione di rete. 2. Verifica finale."
    assert extractor._split_into_sentences(numbered) == [
        "1. Configurazione di rete.",
        "2. Verifica finale.",
    ]

    nested = "1.2.3. Sottocapitolo tecnico con P1=10 e client/server."
    assert extractor._split_into_sentences(nested) == [
        "1.2.3. Sottocapitolo tecnico con P1=10 e client/server.",
    ]

    article = "Art. 1. Oggetto e Fig. 2 versione v2.6."
    assert extractor._split_into_sentences(article) == [
        "Art. 1. Oggetto e Fig. 2 versione v2.6.",
    ]


def test_extractor_splits_all_caps_heading_before_body_text():
    import pymupdf

    extractor = DocumentExtractor()
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "headings.pdf"
        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((72, 72), "1. INTRODUZIONE\nIl sistema usa REST API dal 13/11/2026.")
        doc.save(str(pdf_path))
        doc.close()

        extracted = extractor.extract(pdf_path)
        texts = [s.text for s in extracted.all_sentences]
        assert texts == [
            "1. INTRODUZIONE",
            "Il sistema usa REST API dal 13/11/2026.",
        ]


def test_extractor_tags_repeated_headers_and_footers_verbatim():
    import pymupdf

    extractor = DocumentExtractor()
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = Path(tmpdir) / "multipage_headers.pdf"
        doc = pymupdf.open()
        for page_num, body in [(1, "Contenuto prima pagina reale."), (2, "Contenuto seconda pagina reale.")]:
            page = doc.new_page()
            page.insert_text((50, 40), "HORIZON / TOPNETWORK - CONFRONTO TECNICO")
            page.insert_text((50, 120), body)
            page.insert_text((50, 800), f"9 novembre 2026 - Documento | Pagina {page_num}")
        doc.save(str(pdf_path))
        doc.close()

        extracted = extractor.extract(pdf_path)
        p1_flags = [(s.text, s.is_header_footer) for s in extracted.pages[0].sentences]
        p2_flags = [(s.text, s.is_header_footer) for s in extracted.pages[1].sentences]
        assert p1_flags == [
            ("HORIZON / TOPNETWORK - CONFRONTO TECNICO", True),
            ("Contenuto prima pagina reale.", False),
            ("9 novembre 2026 - Documento | Pagina 1", True),
        ]
        assert p2_flags == [
            ("HORIZON / TOPNETWORK - CONFRONTO TECNICO", True),
            ("Contenuto seconda pagina reale.", False),
            ("9 novembre 2026 - Documento | Pagina 2", True),
        ]

