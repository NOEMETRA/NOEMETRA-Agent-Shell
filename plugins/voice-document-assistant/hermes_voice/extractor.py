"""Deterministic PDF document extractor using PyMuPDF.

Strict constraint: Verbatim preservation of original text.
No LLM rewriting or alteration is performed during extraction.
Explicit OCR boundary: Scanned pages and image-based PDFs are detected,
and OCR is applied when Tesseract is available, or flagged with explicit diagnostic notice.
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple
import pymupdf

from hermes_voice.models import DocumentPage, ExtractedDocument, SentenceSpan

logger = logging.getLogger(__name__)

# Common Italian abbreviations that should not trigger sentence boundary splits
ITALIAN_ABBREVIATIONS = {
    "dott", "dott.ssa", "prof", "prof.ssa", "avv", "ing", "sig", "sig.ra",
    "art", "artt", "p", "pp", "pag", "pagg", "es", "ecc", "vol", "cap",
    "n", "sez", "all", "rif", "lett", "comma", "c.d", "c.p", "c.c", "v"
}


class DocumentExtractor:
    """Extracts text deterministically from PDF documents."""

    def __init__(self, ocr_language: str = "ita"):
        self.ocr_language = ocr_language
        # Regex for Italian sentence splitting preserving delimiters, decimals (e.g. 2.6), and closing quotes
        self._sentence_regex = re.compile(
            r'.+?[\.!?]+[\'"”»\)\]]*(?:[\.!?]+[\'"”»\)\]]*)*(?:\s+|$)',
            re.UNICODE,
        )

    def extract(self, file_path: str | Path) -> ExtractedDocument:
        """Extract all pages and segment into verbatim sentences."""
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Documento non trovato: {path}")

        # Compute deterministic doc_id from file hash
        file_bytes = path.read_bytes()
        doc_id = hashlib.sha256(file_bytes).hexdigest()[:16]

        doc = pymupdf.open(str(path))
        title = doc.metadata.get("title") or path.stem

        pages: List[DocumentPage] = []
        all_sentences: List[SentenceSpan] = []
        global_sent_idx = 0
        has_scanned = False

        for page_idx in range(len(doc)):
            page_num = page_idx + 1
            page = doc[page_idx]

            # Extract structured blocks: (x0, y0, x1, y1, text, block_no, block_type)
            # block_type 0 is text
            blocks = page.get_text("blocks")
            page_text_parts = []
            page_sentences: List[SentenceSpan] = []

            para_idx = 0
            char_cursor = 0

            for block in blocks:
                if len(block) < 5 or block[6] != 0:
                    continue  # skip non-text blocks (images)

                block_text = block[4].strip()
                if not block_text:
                    continue

                # Clean line breaks within paragraph (de-hyphenation)
                cleaned_block = self._clean_paragraph_text(block_text)
                if not cleaned_block:
                    continue

                bbox = [round(block[0], 2), round(block[1], 2), round(block[2], 2), round(block[3], 2)]

                # Segment block into sentences
                sentences = self._split_into_sentences(cleaned_block)
                for sent_text in sentences:
                    sent_text_clean = sent_text.strip()
                    if not sent_text_clean:
                        continue

                    start_char = char_cursor
                    end_char = start_char + len(sent_text_clean)
                    char_cursor = end_char + 1

                    span = SentenceSpan(
                        sentence_index=global_sent_idx,
                        page_number=page_num,
                        paragraph_index=para_idx,
                        text=sent_text_clean,
                        char_start=start_char,
                        char_end=end_char,
                        bbox=bbox,
                    )
                    page_sentences.append(span)
                    all_sentences.append(span)
                    global_sent_idx += 1

                page_text_parts.append(cleaned_block)
                para_idx += 1

            full_page_text = "\n\n".join(page_text_parts)

            # Check for scanned page: minimal extracted text and presence of images
            images = page.get_images()
            is_scanned = False
            ocr_applied = False

            if len(full_page_text.strip()) < 40 and len(images) > 0:
                is_scanned = True
                has_scanned = True
                logger.info(f"Pagina {page_num}: rilevata pagina scansionata/immagine ({len(images)} immagini). Tentativo OCR...")
                ocr_text = self._try_ocr(page)
                if ocr_text:
                    ocr_applied = True
                    # Remove previously extracted partial sentences for this page to prevent duplicates
                    prev_count = len(page_sentences)
                    if prev_count > 0:
                        all_sentences = all_sentences[:-prev_count]
                        global_sent_idx -= prev_count
                        page_sentences.clear()

                    full_page_text = ocr_text
                    cleaned_ocr = self._clean_paragraph_text(ocr_text)
                    ocr_sentences = self._split_into_sentences(cleaned_ocr)
                    for sent_text in ocr_sentences:
                        sent_text_clean = sent_text.strip()
                        if not sent_text_clean:
                            continue
                        span = SentenceSpan(
                            sentence_index=global_sent_idx,
                            page_number=page_num,
                            paragraph_index=0,
                            text=sent_text_clean,
                            char_start=0,
                            char_end=len(sent_text_clean),
                            bbox=None,
                        )
                        page_sentences.append(span)
                        all_sentences.append(span)
                        global_sent_idx += 1
                else:
                    logger.warning(
                        f"Pagina {page_num}: OCR non disponibile su questo sistema (Tesseract/Tessdata assente). "
                        "I caratteri grafici scansionati non possono essere estratti testualmente."
                    )

            doc_page = DocumentPage(
                page_number=page_num,
                text=full_page_text,
                sentences=page_sentences,
                is_scanned=is_scanned,
                ocr_applied=ocr_applied,
            )
            pages.append(doc_page)

        doc.close()

        return ExtractedDocument(
            doc_id=doc_id,
            file_path=str(path),
            title=title,
            total_pages=len(pages),
            pages=pages,
            all_sentences=all_sentences,
            has_scanned_pages=has_scanned,
        )

    def _try_ocr(self, page: pymupdf.Page) -> Optional[str]:
        """Attempt OCR on a page using PyMuPDF and Tesseract if installed."""
        try:
            tp = page.get_textpage_ocr(language=self.ocr_language)
            text = tp.extractText()
            return text.strip() if text and text.strip() else None
        except Exception as e:
            logger.debug(f"OCR fallito o Tesseract non configurato: {e}")
            return None

    def _clean_paragraph_text(self, text: str) -> str:
        """Preserve words while joining broken lines and hyphenations."""
        # Fix hyphenation: 'parola-\ncomposta' -> 'parolacomposta'
        text = re.sub(r'(\w+)-\s*\n\s*(\w+)', r'\1\2', text)
        # Replace remaining single newlines with spaces
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return " ".join(lines)

    def _split_into_sentences(self, text: str) -> List[str]:
        """Split text into sentences while respecting Italian abbreviations and preserving trailing text."""
        raw_chunks: List[str] = []
        cursor = 0

        for match in self._sentence_regex.finditer(text):
            if match.start() > cursor:
                gap = text[cursor:match.start()]
                if gap.strip():
                    if raw_chunks and not any(ch.isalnum() for ch in gap):
                        raw_chunks[-1] += gap
                    else:
                        raw_chunks.append(gap)
            raw_chunks.append(match.group(0))
            cursor = match.end()

        if cursor < len(text):
            tail = text[cursor:]
            if tail.strip():
                if raw_chunks and not any(ch.isalnum() for ch in tail):
                    raw_chunks[-1] += tail
                else:
                    raw_chunks.append(tail)

        if not raw_chunks:
            return [text.strip()] if text.strip() else []

        merged_sentences: List[str] = []
        current = ""

        for chunk in raw_chunks:
            if not current:
                current = chunk
            else:
                # Check if previous chunk ended on an abbreviation
                words = current.strip().split()
                last_word = words[-1].lower().rstrip(".!?,;:") if words else ""
                if "'" in last_word:
                    last_word = last_word.split("'")[-1]

                if last_word in ITALIAN_ABBREVIATIONS:
                    current += chunk
                else:
                    merged_sentences.append(current.strip())
                    current = chunk

        if current.strip():
            merged_sentences.append(current.strip())

        return merged_sentences


def create_sample_italian_pdf(output_path: str | Path) -> Path:
    """Helper to generate a real, high-quality Italian test PDF with multiple pages."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    doc = pymupdf.open()

    # Page 1: Introduzione e Architettura
    p1 = doc.new_page(width=595, height=842)
    p1.insert_text(
        pymupdf.Point(50, 60),
        "SISTEMI MULTI-AGENTE PER L'ANALISI DOCUMENTALE VOCALE",
        fontsize=16,
        fontname="helv",
    )
    p1.insert_text(
        pymupdf.Point(50, 100),
        "Capitolo 1: Architettura di Sistema e Obiettivi",
        fontsize=13,
        fontname="helv",
    )
    p1_body = (
        "L'assistente documentale Hermes Voice è progettato per operare in ambienti ad alta "
        "affidabilità su sistemi Windows 11. Il principio cardine del sistema è la separazione "
        "netta tra la lettura deterministica del documento e le capacità di interrogazione "
        "analitica. Nessun modello linguistico è autorizzato a parafrasare o riscrivere il "
        "testo originale durante la sessione di ascolto.\n\n"
        "La configurazione hardware di riferimento prevede un processore Intel Core Ultra 7 "
        "con 16 gigabyte di memoria RAM e grafica integrata. In questa prima iterazione, la "
        "sintesi vocale è affidata a Pocket TTS sviluppato da Kyutai Labs, con la voce Giovanni "
        "configurata sia per il modello standard italiano che per la variante avanzata a ventiquattro livelli."
    )
    p1.insert_textbox(pymupdf.Rect(50, 120, 545, 400), p1_body, fontsize=11, fontname="helv")

    # Page 2: Modelli e Valutazione Prestazioni
    p2 = doc.new_page(width=595, height=842)
    p2.insert_text(
        pymupdf.Point(50, 60),
        "Capitolo 2: Prestazioni della Sintesi Vocale e Routing LLM",
        fontsize=14,
        fontname="helv",
    )
    p2_body = (
        "I benchmark eseguiti localmente hanno dimostrato che il modello italiano distillato di Pocket TTS "
        "raggiunge una velocità di generazione pari a 2.6 volte il tempo reale su CPU, con un tempo medio "
        "per passo di generazione di 27 millisecondi. Al contrario, il modello non distillato a 24 livelli "
        "opera a 0.54 volte il tempo reale, richiedendo 138 millisecondi per passo.\n\n"
        "Per quanto concerne l'interrogazione del contenuto, il router dei modelli indirizza le "
        "richieste in via predefinita a un'istanza locale di Ollama equipaggiata con il modello gemma4 da 12B. "
        "Questa scelta garantisce la totale riservatezza dei dati aziendali ed esclude l'invio "
        "non autorizzato di informazioni riservate verso server esterni o provider remoti."
    )
    p2.insert_textbox(pymupdf.Rect(50, 100, 545, 400), p2_body, fontsize=11, fontname="helv")

    # Page 3: Triade di Agenti e Criterio di Successo
    p3 = doc.new_page(width=595, height=842)
    p3.insert_text(
        pymupdf.Point(50, 60),
        "Capitolo 3: La Triade di Agenti e Criteri di Accettazione",
        fontsize=14,
        fontname="helv",
    )
    p3_body = (
        "La gestione dell'interazione è articolata in tre ruoli complementari: il Bibliotecario, "
        "l'Analista e il Verificatore. Il Bibliotecario indicizza i paragrafi ed estrae i frammenti "
        "pertinenti con i relativi numeri di pagina. L'Analista formula le risposte formulando "
        "citazioni esplicite. Infine, il Verificatore controlla la fedeltà delle risposte rispetto "
        "al testo sorgente ed elimina ogni possibile allucinazione.\n\n"
        "Il criterio di successo vincolante prevede che l'utente possa avviare la riproduzione, "
        "interromperla a proprio piacimento, formulare una domanda ottenendo riscontri verificabili "
        "con numero di pagina esatto, e riprendere la lettura dal punto preciso in cui era stata sospesa."
    )
    p3.insert_textbox(pymupdf.Rect(50, 100, 545, 400), p3_body, fontsize=11, fontname="helv")

    doc.save(str(path))
    doc.close()
    return path
