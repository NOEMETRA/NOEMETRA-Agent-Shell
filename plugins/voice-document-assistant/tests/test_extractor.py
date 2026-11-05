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
