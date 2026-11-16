"""Deterministic Pocket TTS synthesis engine with Italian models and voice Giovanni.

Strict constraint: Extracted document text remains 100% verbatim across storage and UI.
Deterministic, zero-LLM Italian speech normalization is applied solely at synthesis time
so technical schemas (numbering, symbols, operators, slashes) are spoken clearly.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
import numpy as np
import soundfile as sf

from hermes_voice.profile import ensure_voice_dir, resolve_voice_profile_dir

logger = logging.getLogger(__name__)

_ITALIAN_ABBREV_EXPANSIONS: Dict[str, str] = {
    "art": "Articolo",
    "artt": "Articoli",
    "sez": "Sezione",
    "cap": "Capitolo",
    "par": "Paragrafo",
    "fig": "Figura",
    "tab": "Tabella",
    "pag": "Pagina",
    "pagg": "Pagine",
    "cod": "Codice",
    "rev": "Revisione",
    "ver": "Versione",
    "rif": "Riferimento",
    "all": "Allegato",
    "es": "Esempio",
    "ecc": "Eccetera",
    "n": "numero",
}

_ABBREV_RE = re.compile(
    r"\b(" + "|".join(_ITALIAN_ABBREV_EXPANSIONS.keys()) + r")\.(?=\s|$|[0-9])",
    re.IGNORECASE,
)

_OPERATOR_REPLACEMENTS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<=>|<->"), " equivale a "),
    (re.compile(r"->|→"), " verso "),
    (re.compile(r"=>|⇒"), " implica "),
    (re.compile(r"<=|≤"), " minore o uguale a "),
    (re.compile(r">=|≥"), " maggiore o uguale a "),
    (re.compile(r"!=|<>|≠"), " diverso da "),
    (re.compile(r"=="), " uguale a "),
    (re.compile(r":="), " assegnato a "),
    (re.compile(r"="), " uguale a "),
    (re.compile(r"<"), " minore di "),
    (re.compile(r">"), " maggiore di "),
    (re.compile(r"±"), " più o meno "),
    (re.compile(r"×"), " per "),
    (re.compile(r"÷"), " diviso "),
    (re.compile(r"≈|~"), " circa "),
    (re.compile(r"%"), " percento "),
    (re.compile(r"&"), " e "),
    (re.compile(r"@"), " chiocciola "),
    (re.compile(r"\s*\+\s*"), " più "),
)

_EN_OPERATOR_REPLACEMENTS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<=>|<->"), " is equivalent to "),
    (re.compile(r"->|→"), " to "),
    (re.compile(r"=>|⇒"), " implies "),
    (re.compile(r"<=|≤"), " less than or equal to "),
    (re.compile(r">=|≥"), " greater than or equal to "),
    (re.compile(r"!=|<>|≠"), " not equal to "),
    (re.compile(r"=="), " equals "),
    (re.compile(r":="), " assigned to "),
    (re.compile(r"="), " equals "),
    (re.compile(r"<"), " less than "),
    (re.compile(r">"), " greater than "),
    (re.compile(r"±"), " plus or minus "),
    (re.compile(r"×"), " times "),
    (re.compile(r"÷"), " divided by "),
    (re.compile(r"≈|~"), " approximately "),
    (re.compile(r"%"), " percent "),
    (re.compile(r"&"), " and "),
    (re.compile(r"@"), " at "),
    (re.compile(r"\s*\+\s*"), " plus "),
)


_ROMAN_SECTION_NUMERALS: Dict[str, str] = {
    "ii": "2",
    "iii": "3",
    "iv": "4",
    "v": "5",
    "vi": "6",
    "vii": "7",
    "viii": "8",
    "ix": "9",
    "x": "10",
    "xi": "11",
    "xii": "12",
}

_SECTION_NOUNS_PATTERN = (
    r"Articolo|Articoli|Sezione|Capitolo|Parte|Paragrafo|Figura|Tabella|Pagina|Pagine|"
    r"Codice|Revisione|Versione|Riferimento|Allegato|Titolo|Comma|numero"
)


def _expand_dotted_sequence(dotted: str) -> str:
    return " punto ".join(dotted.strip(".").split("."))


_ITALIAN_MONTHS: Dict[int, str] = {
    1: "gennaio",
    2: "febbraio",
    3: "marzo",
    4: "aprile",
    5: "maggio",
    6: "giugno",
    7: "luglio",
    8: "agosto",
    9: "settembre",
    10: "ottobre",
    11: "novembre",
    12: "dicembre",
}

_ENGLISH_MONTHS: Dict[int, str] = {
    1: "January",
    2: "February",
    3: "March",
    4: "April",
    5: "May",
    6: "June",
    7: "July",
    8: "August",
    9: "September",
    10: "October",
    11: "November",
    12: "December",
}

_MONTH_NAME_TO_NUM: Dict[str, int] = {
    # Italian full & abbreviated
    "gennaio": 1, "gen": 1,
    "febbraio": 2, "feb": 2,
    "marzo": 3, "mar": 3,
    "aprile": 4, "apr": 4,
    "maggio": 5, "mag": 5,
    "giugno": 6, "giu": 6,
    "luglio": 7, "lug": 7,
    "agosto": 8, "ago": 8,
    "settembre": 9, "sett": 9, "set": 9,
    "ottobre": 10, "ott": 10,
    "novembre": 11, "nov": 11,
    "dicembre": 12, "dic": 12,
    # English full & abbreviated
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sept": 9, "sep": 9,
    "october": 10, "oct": 10,
    "november": 11,
    "december": 12, "dec": 12,
}

_MONTH_TOKEN_PATTERN = "|".join(sorted(_MONTH_NAME_TO_NUM.keys(), key=len, reverse=True))
_DATE_CONTEXT_RE_PREFIX = r"(?:del|dal|al|data|rev\.?|scad\.?|il|di|in|on|from|since|dated|until|before|after)"

_ACRONYM_WHITELIST = {
    "AI", "AOI", "API", "ASCII", "BIOS", "CAD", "CAP", "CF", "CNR", "CPU", "CRS",
    "CSV", "DAC", "DB", "DC", "AC", "DHCP", "DIN", "DNS", "DOM", "DRAM", "DVD",
    "EEPROM", "EPSG", "EU", "FAQ", "FTP", "GB", "GEOJSON", "GEOTIFF", "GPIO",
    "GPS", "GPU", "GUI", "HD", "HDMI", "HMI", "HTML", "HTTP", "HTTPS", "ID", "IDE",
    "IEC", "IMAP", "IP", "ISO", "IT", "IVA", "JSON", "KB", "LAN", "LCD", "LED",
    "LLM", "LUT", "MAC", "MB", "MIDI", "MIME", "MQTT", "NFC", "NODATA", "NTP",
    "OCR", "OK", "ONLUS", "OPENAPI", "OS", "PC", "PCB", "PDF", "PEC", "PIN", "PLC",
    "PNG", "POP", "PUK", "PWM", "QR", "RAM", "REST", "RF", "RFID", "RGB", "ROM",
    "RPC", "RS", "RSS", "RTC", "SAS", "SDK", "SEO", "SFTP", "SIM", "SIP", "SMTP",
    "SNC", "SNMP", "SPA", "SPID", "SQL", "SRAM", "SRL", "SSD", "SSH", "SSL", "TCP",
    "TIFF", "TLS", "TTS", "UART", "UDP", "UI", "UML", "UPS", "URI", "URL", "USB",
    "UTF", "UUID", "UX", "VAT", "VLAN", "VM", "VPN", "VR", "WAN", "WEBHOOK",
    "WLAN", "WKT", "XML", "YAML",
}

_ITALIAN_SHORT_UPPER_WORDS = {
    "A", "AD", "AGLI", "AI", "AL", "ALL", "ALLA", "ALLE", "ALLO", "CHE", "CHI",
    "CI", "COI", "COL", "CON", "CUI", "DA", "DAI", "DAL", "DEI", "DEL", "DI",
    "E", "ED", "FRA", "GLI", "HA", "HO", "I", "IL", "IN", "LA", "LE", "LI", "LO",
    "MA", "MI", "NE", "NEI", "NEL", "NO", "NON", "O", "PER", "PIU", "PIÙ", "SE",
    "SI", "SU", "SUI", "SUL", "TI", "TRA", "UN", "VI",
}

_VOWELS = frozenset("AEIOUÀÈÉÌÒÙ")


_SHORT_UPPER_WORDS = _ITALIAN_SHORT_UPPER_WORDS | {
    "AN", "AND", "AS", "AT", "BY", "FOR", "FROM", "IN", "INTO", "IS",
    "OF", "ON", "OR", "THE", "TO", "WITH",
}


def _is_preserved_acronym(word: str, *, all_caps_line: bool) -> bool:
    if all_caps_line and word in _SHORT_UPPER_WORDS:
        return False
    if word in _ACRONYM_WHITELIST:
        return True
    if 2 <= len(word) <= 4 and not any(ch in _VOWELS for ch in word):
        return True
    return False


def _normalize_all_caps_titles(text: str) -> str:
    """Convert ALL-CAPS titles/headings to natural Sentence Case so Pocket TTS avoids spelling."""
    alpha_chars = [ch for ch in text if ch.isalpha()]
    if len(alpha_chars) < 2:
        return text

    all_caps_line = not any(ch.islower() for ch in alpha_chars)
    tokens = re.findall(r"[A-Za-zÀ-Úà-ú]+|[^A-Za-zÀ-Úà-ú]+", text)

    if all_caps_line:
        capitalized_first = False
        out: list[str] = []
        for tok in tokens:
            if tok.isalpha() and tok.isupper():
                if _is_preserved_acronym(tok, all_caps_line=True):
                    out.append(tok)
                    capitalized_first = True
                elif not capitalized_first:
                    out.append(tok.capitalize())
                    capitalized_first = True
                else:
                    out.append(tok.lower())
            else:
                out.append(tok)
        return "".join(out)

    # Mixed-case text that embeds uppercase headings/blocks (e.g. "Art. 1. OGGETTO DEL CONTRATTO")
    converted_flags = [False] * len(tokens)
    for idx, tok in enumerate(tokens):
        if (
            tok.isalpha()
            and tok.isupper()
            and len(tok) >= 4
            and any(ch in _VOWELS for ch in tok)
            and tok not in _ACRONYM_WHITELIST
        ):
            converted_flags[idx] = True

    if not any(converted_flags):
        return text

    # Also lowercase short uppercase Italian function words adjacent to converted uppercase words
    for idx, tok in enumerate(tokens):
        if tok.isalpha() and tok.isupper() and tok in _ITALIAN_SHORT_UPPER_WORDS:
            left_conv = any(converted_flags[j] for j in range(max(0, idx - 2), idx))
            right_conv = any(converted_flags[j] for j in range(idx + 1, min(len(tokens), idx + 3)))
            if left_conv or right_conv:
                converted_flags[idx] = True

    out_mixed: list[str] = []
    seen_converted = False
    for idx, tok in enumerate(tokens):
        if converted_flags[idx]:
            if not seen_converted and (idx == 0 or not any(c.isalpha() for c in "".join(tokens[:idx]))):
                out_mixed.append(tok.capitalize())
            else:
                out_mixed.append(tok.lower())
            seen_converted = True
        else:
            out_mixed.append(tok)
    return "".join(out_mixed)


_IT_UNITS = (
    "zero", "uno", "due", "tre", "quattro", "cinque", "sei", "sette", "otto", "nove",
    "dieci", "undici", "dodici", "tredici", "quattordici", "quindici", "sedici",
    "diciassette", "diciotto", "diciannove",
)

_IT_TENS = (
    "", "", "venti", "trenta", "quaranta", "cinquanta",
    "sessanta", "settanta", "ottanta", "novanta",
)


def _int_to_italian(n: int) -> str:
    """Convert non-negative integer (0..999_999_999) into natural Italian words."""
    if n < 20:
        return _IT_UNITS[n]
    if n < 100:
        tens, rem = divmod(n, 10)
        base = _IT_TENS[tens]
        if rem == 0:
            return base
        if rem in (1, 8):
            base = base[:-1]
        unit_word = "tré" if rem == 3 else _IT_UNITS[rem]
        return base + unit_word
    if n < 1000:
        hundreds, rem = divmod(n, 100)
        prefix = "cento" if hundreds == 1 else f"{_IT_UNITS[hundreds]}cento"
        return prefix if rem == 0 else prefix + _int_to_italian(rem)
    if n < 1_000_000:
        thousands, rem = divmod(n, 1000)
        prefix = "mille" if thousands == 1 else f"{_int_to_italian(thousands)}mila"
        return prefix if rem == 0 else prefix + _int_to_italian(rem)
    millions, rem = divmod(n, 1_000_000)
    prefix = "un milione" if millions == 1 else f"{_int_to_italian(millions)} milioni"
    return prefix if rem == 0 else f"{prefix} {_int_to_italian(rem)}"


def _digits_token_to_italian(token: str) -> str:
    """Convert an unsigned digit string into Italian words, keeping leading zeros explicit."""
    if len(token) > 1 and token.startswith("0"):
        leading_zeros = len(token) - len(token.lstrip("0"))
        zero_words = ["zero"] * leading_zeros
        rest = token.lstrip("0")
        if not rest:
            return " ".join(zero_words)
        return " ".join(zero_words + [_digits_token_to_italian(rest)])
    if len(token) >= 8 and not token.endswith("000000"):
        return " ".join(_IT_UNITS[int(ch)] for ch in token)
    value = int(token)
    if value >= 1_000_000_000:
        return " ".join(_IT_UNITS[int(ch)] for ch in token)
    return _int_to_italian(value)


_EN_UNITS = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
    "seventeen", "eighteen", "nineteen",
)

_EN_TENS = (
    "", "", "twenty", "thirty", "forty", "fifty",
    "sixty", "seventy", "eighty", "ninety",
)

_EN_ORDINALS_1_TO_31: Dict[int, str] = {
    1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth",
    6: "sixth", 7: "seventh", 8: "eighth", 9: "ninth", 10: "tenth",
    11: "eleventh", 12: "twelfth", 13: "thirteenth", 14: "fourteenth", 15: "fifteenth",
    16: "sixteenth", 17: "seventeenth", 18: "eighteenth", 19: "nineteenth", 20: "twentieth",
    21: "twenty-first", 22: "twenty-second", 23: "twenty-third", 24: "twenty-fourth",
    25: "twenty-fifth", 26: "twenty-sixth", 27: "twenty-seventh", 28: "twenty-eighth",
    29: "twenty-ninth", 30: "thirtieth", 31: "thirty-first",
}

_IT_STRONG_DETECT_WORDS = frozenset({
    "il", "lo", "la", "gli", "le", "uno", "una", "del", "dello", "della",
    "dei", "degli", "delle", "al", "allo", "alla", "ai", "agli", "alle",
    "dal", "dallo", "dalla", "dai", "dagli", "dalle", "nel", "nello", "nella",
    "nei", "negli", "nelle", "sul", "sullo", "sulla", "sui", "sugli", "sulle",
    "che", "chi", "cui", "tra", "fra", "come", "quando", "dove", "mentre",
    "quindi", "anche", "sono", "stato", "stata", "stati", "state", "essere",
    "avere", "questo", "questa", "questi", "queste", "quello", "quella",
    "tutto", "tutti", "molto", "non", "articolo", "sezione", "capitolo",
    "pagina", "allegato", "versione", "documento", "contratto", "sistema",
    "valido", "solo", "testo", "normale", "senza", "simboli", "configurazione",
    "lettura", "scrittura", "tolleranza", "fattore", "valore", "pari", "euro",
    "confronto", "relazione", "introduzione", "oggetto", "norme", "architettura",
    "manuale", "tecnico", "installazione", "revisione", "frase", "prova",
    "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio",
    "agosto", "settembre", "ottobre", "novembre", "dicembre",
})

_EN_STRONG_DETECT_WORDS = frozenset({
    "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
    "been", "have", "has", "had", "will", "would", "can", "could", "should",
    "must", "might", "which", "who", "what", "when", "where", "how", "not",
    "but", "into", "about", "between", "through", "during", "before", "after",
    "above", "below", "under", "your", "our", "they", "their", "its", "his",
    "her", "you", "we", "these", "those", "such", "only", "same", "than",
    "then", "also", "very", "just", "each", "every", "both", "few", "more",
    "most", "other", "some", "shall", "signed", "agreement", "please", "hello",
    "welcome", "thank", "thanks",
    "january", "february", "march", "april", "june", "july", "august",
    "september", "october", "november", "december",
})

_EN_MEDIUM_DETECT_WORDS = frozenset({
    "is", "of", "to", "by", "on", "as", "at", "an", "or", "it", "be",
    "guide", "overview", "summary", "introduction", "privacy", "policy",
    "terms", "service", "conditions", "release", "notes", "changelog",
    "requirements", "installation", "configuration", "setup", "usage",
    "reference", "troubleshooting", "appendix", "copyright", "rights",
    "reserved", "chapter", "section", "page", "version", "document",
    "contract", "meeting", "report", "getting", "started", "discount",
    "updated", "expired", "expires", "within", "days", "customer", "system",
})


def _int_to_english(n: int) -> str:
    """Convert non-negative integer (0..999_999_999) into natural English words."""
    if n < 20:
        return _EN_UNITS[n]
    if n < 100:
        tens, rem = divmod(n, 10)
        return _EN_TENS[tens] if rem == 0 else f"{_EN_TENS[tens]}-{_EN_UNITS[rem]}"
    if n < 1000:
        hundreds, rem = divmod(n, 100)
        prefix = f"{_EN_UNITS[hundreds]} hundred"
        return prefix if rem == 0 else f"{prefix} {_int_to_english(rem)}"
    if n < 1_000_000:
        thousands, rem = divmod(n, 1000)
        prefix = f"{_int_to_english(thousands)} thousand"
        return prefix if rem == 0 else f"{prefix} {_int_to_english(rem)}"
    millions, rem = divmod(n, 1_000_000)
    prefix = f"{_int_to_english(millions)} million"
    return prefix if rem == 0 else f"{prefix} {_int_to_english(rem)}"


def _english_ordinal(n: int) -> str:
    if n in _EN_ORDINALS_1_TO_31:
        return _EN_ORDINALS_1_TO_31[n]
    base = _int_to_english(n)
    if base.endswith("y"):
        return base[:-1] + "ieth"
    if base.endswith("ve"):
        return base[:-2] + "fth"
    if base.endswith("e") and not base.endswith("ee"):
        return base[:-1] + "th"
    if base.endswith("t"):
        return base + "h"
    return base + "th"


def _english_year_words(year_str: str) -> str:
    year = int(year_str)
    if len(year_str) == 2:
        return _int_to_english(year)
    if 2000 <= year <= 2009:
        return _int_to_english(year)
    if 2010 <= year <= 2099:
        hi, lo = divmod(year, 100)
        return f"{_int_to_english(hi)} {_int_to_english(lo)}"
    if 1900 <= year <= 1999:
        hi, lo = divmod(year, 100)
        if lo == 0:
            return f"{_int_to_english(hi)} hundred"
        if lo < 10:
            return f"{_int_to_english(hi)} oh {_int_to_english(lo)}"
        return f"{_int_to_english(hi)} {_int_to_english(lo)}"
    return _int_to_english(year)


def _digits_token_to_english(token: str) -> str:
    """Convert an unsigned digit string into English words."""
    if len(token) > 1 and token.startswith("0"):
        return " ".join(_EN_UNITS[int(ch)] for ch in token)
    if len(token) == 4 and (1900 <= int(token) <= 2099):
        return _english_year_words(token)
    if len(token) >= 8 and not token.endswith("000000"):
        return " ".join(_EN_UNITS[int(ch)] for ch in token)
    value = int(token)
    if value >= 1_000_000_000:
        return " ".join(_EN_UNITS[int(ch)] for ch in token)
    return _int_to_english(value)


def _normalize_numbers_for_english_tts(text: str) -> str:
    """Verbalize English thousands, ordinals, and standalone numbers."""
    # Collapse English thousands commas ("1,000,000" -> "1000000")
    s = re.sub(
        r"\b(\d{1,3}(?:,\d{3})+)\b",
        lambda m: m.group(1).replace(",", ""),
        text,
    )
    # Generic English ordinals: "1st", "2nd", "3rd", "16th" -> "first", "sixteenth"
    s = re.sub(
        r"\b(\d+)(?:st|nd|rd|th)\b",
        lambda m: _english_ordinal(int(m.group(1))),
        s,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\b\d+\b", lambda m: _digits_token_to_english(m.group(0)), s)


def _score_text_languages(text: str) -> Tuple[float, float]:
    """Return (it_score, en_score) for deterministic language identification."""
    if not text or not text.strip():
        return 0.0, 0.0

    it_score = 0.0
    en_score = 0.0

    # Italian diacritics are strong Italian indicators
    it_accents = len(re.findall(r"[àèéìòùÀÈÉÌÒÙ]", text))
    it_score += min(it_accents, 3) * 2.5

    # Italian elided articles/prepositions: l', dell', nell', sull', all', dall', un'
    it_elisions = len(re.findall(r"\b(?:l|un|all|dell|nell|sull|dall|c|quest|quell)['’][a-zA-ZàèéìòùÀÈÉÌÒÙ]", text, flags=re.IGNORECASE))
    it_score += min(it_elisions, 3) * 2.0

    # English contractions: 're, 've, 'll, 'd, n't, it's/that's/what's/there's/here's
    en_contr = len(re.findall(r"\b[a-zA-Z]+(?:'re|'ve|'ll|'d|n't)\b|\b(?:it|that|what|who|there|here|let)'s\b", text, flags=re.IGNORECASE))
    en_score += min(en_contr, 3) * 2.5

    words = re.findall(r"[A-Za-zÀ-Úà-ú]{2,}", text.lower())
    for w in words:
        if w in _IT_STRONG_DETECT_WORDS:
            it_score += 2.0
        elif w in _EN_STRONG_DETECT_WORDS:
            en_score += 2.0
        elif w in _EN_MEDIUM_DETECT_WORDS:
            en_score += 1.0
        elif w.endswith("zione") or w.endswith("zioni") or w.endswith("mente"):
            it_score += 1.5
        elif w.endswith("ing") and len(w) >= 5:
            en_score += 1.0

    return it_score, en_score


def detect_speech_language(text: str, default: str = "it") -> str:
    """Detect whether *text* is English ('en') or Italian ('it') deterministically."""
    it_score, en_score = _score_text_languages(text)
    if default == "en":
        return "it" if (it_score >= 2.0 and it_score > en_score) else "en"
    return "en" if (en_score >= 2.0 and en_score > it_score) else "it"


def _split_bilingual_segments(text: str, default_lang: str = "it") -> list[Tuple[str, str]]:
    """Split text into contiguous ('it'|'en', chunk) segments at clause/sentence boundaries."""
    cleaned = (text or "").strip()
    if not cleaned:
        return []

    whole_lang = detect_speech_language(cleaned, default=default_lang)
    # Candidate splits on sentence terminators (ignoring decimals and month/title abbrevs) or colons/semicolons/parentheses
    parts = re.split(
        r"(?<=[!?;])\s+|(?<=[A-Za-zÀ-Úà-ú\)])\s*:\s+(?=[A-Za-z\"'(])|(?<=[a-zàèéìòù\)])\.\s+(?=[A-Z\"'])|(?<=\d{4})\.\s+(?=[A-Z\"'])|\s+(?=\([^()]{12,}\))|(?<=\))\s+",
        cleaned,
    )
    if len(parts) <= 1:
        return [(whole_lang, cleaned)]

    raw_segments: list[Tuple[str, str]] = []
    for part in parts:
        frag = part.strip()
        if not frag:
            continue
        it_s, en_s = _score_text_languages(frag)
        alpha_words = re.findall(r"[A-Za-zÀ-Úà-ú]{2,}", frag)
        if len(alpha_words) >= 3 and en_s >= 3.0 and it_s == 0.0:
            seg_lang = "en"
        elif len(alpha_words) >= 3 and it_s >= 3.0 and en_s == 0.0:
            seg_lang = "it"
        elif len(alpha_words) >= 4 and en_s > it_s + 1.5:
            seg_lang = "en"
        elif len(alpha_words) >= 4 and it_s > en_s + 1.5:
            seg_lang = "it"
        else:
            seg_lang = raw_segments[-1][0] if raw_segments else whole_lang

        if raw_segments and raw_segments[-1][0] == seg_lang:
            raw_segments[-1] = (seg_lang, f"{raw_segments[-1][1]} {frag}")
        else:
            raw_segments.append((seg_lang, frag))

    return raw_segments or [(whole_lang, cleaned)]


def _normalize_numbers_for_tts(text: str) -> str:
    """Verbalize Italian thousands and standalone numbers so Pocket TTS avoids digit byte tokens."""
    # Collapse Italian thousands dots ("1.000.000" -> "1000000") before digit conversion
    s = re.sub(
        r"\b(\d{1,3}(?:\.\d{3})+)\b",
        lambda m: m.group(1).replace(".", ""),
        text,
    )
    # "1 gennaio" -> "primo gennaio" for prose dates already written with month names
    month_names_re = "|".join(_ITALIAN_MONTHS.values())
    s = re.sub(rf"\b1\s+({month_names_re})\b", r"primo \1", s, flags=re.IGNORECASE)
    return re.sub(r"\b\d+\b", lambda m: _digits_token_to_italian(m.group(0)), s)


def _format_spoken_date(day: int, month: int, year_str: Optional[str], target_lang: str = "it") -> Optional[str]:
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return None
    if target_lang == "en":
        month_name = _ENGLISH_MONTHS[month]
        day_word = _english_ordinal(day)
        if year_str:
            return f"{month_name} {day_word}, {_english_year_words(year_str)}"
        return f"{month_name} {day_word}"
    day_str = "primo" if day == 1 else str(day)
    if year_str:
        return f"{day_str} {_ITALIAN_MONTHS[month]} {year_str}"
    return f"{day_str} {_ITALIAN_MONTHS[month]}"


def _format_italian_date(day: int, month: int, year_str: str) -> Optional[str]:
    return _format_spoken_date(day, month, year_str, target_lang="it")


def _format_spoken_time(hour: int, minute: int, target_lang: str = "it") -> str:
    if target_lang == "en":
        if minute == 0:
            return f"{_int_to_english(hour)} o'clock"
        if minute < 10:
            return f"{_int_to_english(hour)} oh {_int_to_english(minute)}"
        return f"{_int_to_english(hour)} {_int_to_english(minute)}"
    return f"ore {hour}" if minute == 0 else f"ore {hour} e {minute:02d}" if minute < 10 else f"ore {hour} e {minute}"


def _normalize_dates(text: str, target_lang: str = "it") -> str:
    """Convert numeric and textual dates (IT, EN, ISO, US unambiguous, ranges, MM/YYYY) cleanly."""
    s = text

    # 1. ISO timestamps YYYY-MM-DDTHH:MM(:SS)?(Z|+HH:MM)?
    def _iso_ts_repl(m: re.Match[str]) -> str:
        year_s, month_s, day_s, hh_s, mm_s = m.group(1), m.group(3), m.group(4), m.group(5), m.group(6)
        formatted = _format_spoken_date(int(day_s), int(month_s), year_s, target_lang=target_lang)
        if formatted is None:
            return m.group(0)
        hh, mm = int(hh_s), int(mm_s)
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            return m.group(0)
        time_spoken = _format_spoken_time(hh, mm, target_lang=target_lang)
        joiner = " at " if target_lang == "en" else ", "
        return f"{formatted}{joiner}{time_spoken}"

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)((?:19|20)\d{2})([/.-])(0?[1-9]|1[0-2])\2(0?[1-9]|[12]\d|3[01])[Tt]([01]\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?(?:[Zz]|[+-][01]\d:?[0-5]\d)?\b",
        _iso_ts_repl,
        s,
    )

    # 2. Compact date ranges: DD-DD/MM/YYYY or DD–DD/MM/YYYY (e.g. "12-15/11/2026")
    def _range_repl(m: re.Match[str]) -> str:
        d1, d2, mon, yr = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
        if not (1 <= d1 <= 31 and 1 <= d2 <= 31 and 1 <= mon <= 12):
            return m.group(0)
        if target_lang == "en":
            return f"{_ENGLISH_MONTHS[mon]} {_english_ordinal(d1)} to {_english_ordinal(d2)}, {_english_year_words(yr)}"
        d1_s = "primo" if d1 == 1 else str(d1)
        d2_s = "primo" if d2 == 1 else str(d2)
        return f"dal {d1_s} al {d2_s} {_ITALIAN_MONTHS[mon]} {yr}"

    s = re.sub(
        r"(?<![\d/-])(0?[1-9]|[12]\d|3[01])\s*[-–—]\s*(0?[1-9]|[12]\d|3[01])\s*/\s*(0?[1-9]|1[0-2])\s*/\s*((?:19|20)\d{2})(?!\d)",
        _range_repl,
        s,
    )

    # 3. ISO YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD
    def _iso_repl(m: re.Match[str]) -> str:
        formatted = _format_spoken_date(int(m.group(4)), int(m.group(3)), m.group(1), target_lang=target_lang)
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)((?:19|20)\d{2})([/.-])(0?[1-9]|1[0-2])\2(0?[1-9]|[12]\d|3[01])(?![\d])(?![./-]\w)",
        _iso_repl,
        s,
    )

    # 4. 4-digit year slash/dash/dot dates: handles DD/MM/YYYY, US unambiguous MM/DD/YYYY (day 13..31),
    #    spaced slashes ("16 / 11 / 2026"), and Italian ordinal "1°/05/2026".
    def _slash4_repl(m: re.Match[str]) -> str:
        first = int(m.group(1))
        has_deg = bool(m.group(2))
        sep = m.group(3).strip()
        second = int(m.group(4))
        year_s = m.group(5)
        if has_deg:
            day, month = first, second
        elif 1 <= first <= 12 and 13 <= second <= 31 and sep in ("/", "-"):
            # Unambiguously MM/DD/YYYY (e.g. 11/16/2026)
            month, day = first, second
        elif target_lang == "en" and sep == "/" and 1 <= first <= 12 and 1 <= second <= 12:
            # In English prose, slash dates default to US MM/DD/YYYY
            month, day = first, second
        else:
            day, month = first, second
        formatted = _format_spoken_date(day, month, year_s, target_lang=target_lang)
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0?[1-9]|[12]\d|3[01])([°º])?(\s*/\s*|[.-])(0?[1-9]|[12]\d|3[01])(?:\3|\s*/\s*|[-.])((?:19|20)\d{2})(?![\d])(?![./-]\w)",
        _slash4_repl,
        s,
    )

    # 5. Short 2-digit year dates: DD/MM/YY, DD-MM-YY, DD.MM.YY (plus unambiguous MM/DD/YY)
    def _slash2_repl(m: re.Match[str]) -> str:
        first = int(m.group(1))
        sep = m.group(2)
        second = int(m.group(3))
        year_s = m.group(4)
        if 1 <= first <= 12 and 13 <= second <= 31 and sep in ("/", "-"):
            month, day = first, second
        elif target_lang == "en" and sep == "/" and 1 <= first <= 12 and 1 <= second <= 12:
            month, day = first, second
        else:
            day, month = first, second
        formatted = _format_spoken_date(day, month, year_s, target_lang=target_lang)
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0?[1-9]|[12]\d|3[01])([/.-])(0?[1-9]|[12]\d|3[01])\2(\d{2})(?![\d])(?![./-]\w)",
        _slash2_repl,
        s,
    )

    # 6. Month/Year: MM/YYYY or MM-YYYY (2-digit month) and contextual single-digit M/YYYY (e.g. "Data 3/2026")
    def _month_year_fmt(month_num: int, yr: str) -> str:
        if target_lang == "en":
            return f"{_ENGLISH_MONTHS[month_num]} {_english_year_words(yr)}"
        return f"{_ITALIAN_MONTHS[month_num]} {yr}"

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0[1-9]|1[0-2])[/\-]((?:19[7-9]\d|20\d{2}))(?![\d])(?![./-]\w)",
        lambda m: _month_year_fmt(int(m.group(1)), m.group(2)),
        s,
    )
    s = re.sub(
        rf"\b({_DATE_CONTEXT_RE_PREFIX})\s+(0?[1-9]|1[0-2])[/\-]((?:19[7-9]\d|20\d{{2}}))(?![\d])(?![./-]\w)",
        lambda m: f"{m.group(1)} {_month_year_fmt(int(m.group(2)), m.group(3))}",
        s,
        flags=re.IGNORECASE,
    )

    # 7. Textual dates with full or abbreviated IT/EN month names (safe against false positives like "1 set of" or "5 may help")
    _AMBIGUOUS_LOWER_MONTHS = {"set", "may", "mar", "ago"}
    _FULL_SAFE_MONTHS = {
        "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio",
        "agosto", "settembre", "ottobre", "novembre", "dicembre",
        "january", "february", "march", "april", "june", "july", "august",
        "september", "october", "november", "december",
    }

    def _is_valid_month_match(raw_tok: str, has_dot: bool, has_year: bool, has_ordinal: bool) -> bool:
        low = raw_tok.lower()
        if low in _FULL_SAFE_MONTHS:
            return True
        if raw_tok == "May" or raw_tok == "March":
            return True
        if low in _AMBIGUOUS_LOWER_MONTHS:
            return has_dot or has_year or has_ordinal
        # Other abbreviations (gen, feb, nov, oct, dec, ...) accept dot, year, or ordinal, or unambiguous titlecase + day
        return has_dot or has_year or has_ordinal or raw_tok[:1].isupper()

    def _day_month_repl(m: re.Match[str]) -> str:
        day = int(m.group(1))
        has_ord = bool(m.group(2))
        raw_mon = m.group(3)
        has_dot = bool(m.group(4))
        year_s = m.group(5)
        if not _is_valid_month_match(raw_mon, has_dot, bool(year_s), has_ord):
            return m.group(0)
        month_num = _MONTH_NAME_TO_NUM.get(raw_mon.lower())
        if not month_num:
            return m.group(0)
        formatted = _format_spoken_date(day, month_num, year_s, target_lang=target_lang)
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        rf"\b(0?[1-9]|[12]\d|3[01])\s*([°º]|st|nd|rd|th)?\s+({_MONTH_TOKEN_PATTERN})(\.)?(?:\s+((?:19|20)\d{{2}}))?\b",
        _day_month_repl,
        s,
        flags=re.IGNORECASE,
    )

    #    - "November 16, 2026", "Nov. 16th, 2026", "November 16th"
    def _month_day_repl(m: re.Match[str]) -> str:
        # Guard against "primo febbraio 25" or "15 marzo 25" (number after month is 2-digit year, not a day)
        prefix = m.string[max(0, m.start() - 12):m.start()]
        if re.search(r"(?:\bprimo|\b\d{1,2})\s+$", prefix, flags=re.IGNORECASE):
            return m.group(0)
        raw_mon = m.group(1)
        has_dot = bool(m.group(2))
        day = int(m.group(3))
        has_ord = bool(m.group(4))
        year_s = m.group(5)
        if not _is_valid_month_match(raw_mon, has_dot, bool(year_s), has_ord):
            return m.group(0)
        month_num = _MONTH_NAME_TO_NUM.get(raw_mon.lower())
        if not month_num:
            return m.group(0)
        formatted = _format_spoken_date(day, month_num, year_s, target_lang=target_lang)
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        rf"\b({_MONTH_TOKEN_PATTERN})(\.)?\s+(0?[1-9]|[12]\d|3[01])([°º]|st|nd|rd|th)?(?:\s*,?\s+((?:19|20)\d{{2}}))?\b",
        _month_day_repl,
        s,
        flags=re.IGNORECASE,
    )

    #    - "Nov. 2026", "nov. 2026", "gennaio 2026"
    def _month_only_year_repl(m: re.Match[str]) -> str:
        raw_mon = m.group(1)
        has_dot = bool(m.group(2))
        if not _is_valid_month_match(raw_mon, has_dot, True, False):
            return m.group(0)
        month_num = _MONTH_NAME_TO_NUM.get(raw_mon.lower())
        if not month_num:
            return m.group(0)
        return _month_year_fmt(month_num, m.group(3))

    s = re.sub(
        rf"\b({_MONTH_TOKEN_PATTERN})(\.)?\s+((?:19|20)\d{{2}})\b",
        _month_only_year_repl,
        s,
        flags=re.IGNORECASE,
    )

    # 8. Remaining Italian ordinals "1° ..." / "1º ..." (avoiding temperatures °C/°F)
    s = re.sub(r"\b1\s*[°º](?!\s*[CFcf]\b)", "primo ", s)
    s = re.sub(r"\b([2-9]|[12]\d|3[01])\s*º\b", r"\1", s)
    return s


def clean_markdown_for_speech(text: str) -> str:
    """Strip Markdown formatting and inline citation tags so Analyst replies sound natural when spoken."""
    if not text or not text.strip():
        return ""
    s = str(text)
    # Remove inline page citation tags like [Pagina 3] or [Pag. 3]
    s = re.sub(r"\[Pag(?:ina)?\.?\s*\d+\]", "", s, flags=re.IGNORECASE)
    # Replace Markdown links [label](url) with label
    s = re.sub(r"\[([^\]]+)\]\(https?://[^)\s]+\)", r"\1", s)
    # Strip fenced code block markers
    s = re.sub(r"```[a-zA-Z0-9_-]*", " ", s)
    # Strip inline code backticks and emphasis markers
    s = re.sub(r"[`*_~]+", "", s)
    # Clean per-line headings, blockquotes, list bullets, and table pipes
    cleaned_lines: list[str] = []
    for raw_line in s.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?$", line):
            continue
        if re.match(r"^[-=]{3,}$", line):
            continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^>+\s*", "", line)
        line = re.sub(r"^(?:[-*•▪◦‣])\s+", "", line)
        if "|" in line:
            line = ", ".join(c.strip() for c in line.strip("|").split("|") if c.strip())
        if line:
            line = re.sub(r"\s+([.,!?;:])", r"\1", line)
            if line[-1] not in ".!?:,;":
                line += "."
            cleaned_lines.append(line)
    return " ".join(cleaned_lines).strip()


def _expand_dotted_sequence_lang(dotted: str, target_lang: str) -> str:
    word = "point" if target_lang == "en" else "punto"
    return f" {word} ".join(dotted.strip(".").split("."))


def normalize_text_for_tts(text: str, language: Optional[str] = None) -> str:
    """Deterministically normalize technical text for Pocket TTS pronunciation (IT & EN).

    When *language* is None or ``'auto'``, automatically detects Italian vs English prose
    so English sentences/documents keep English connectives, dates, units, and numbers
    while Italian sentences preserve all Italian technical expansions.
    Returns ``""`` when no speakable alphanumeric characters remain.
    """
    if not text or not text.strip():
        return ""

    s = text.strip()
    raw_lang = (language or "auto").strip().lower()
    if raw_lang in ("en", "english"):
        target_lang = "en"
    elif raw_lang in ("it", "italian", "italian_24l"):
        target_lang = "it"
    else:
        target_lang = detect_speech_language(s, default="it")

    # Strip decorative bullets (comma pause when separating inline header items) and ASCII dividers
    s = re.sub(r"(?<=\S)\s*[•▪◦‣∙●■□►▸✔✓➢➤|¦]+\s*(?=\S)", ", ", s)
    s = re.sub(r"[•▪◦‣∙●■□►▸✔✓➢➤|¦]+", " ", s)
    s = re.sub(r"(?:---+|===+|___|~~~+|\*{2,})", ", ", s)

    # Normalize ALL-CAPS titles/headings before inserting lowercase date/number words
    s = _normalize_all_caps_titles(s)

    # Normalize dates BEFORE leading multi-dot numbering so "13.11.2026 - Verbale" is parsed as a date!
    s = _normalize_dates(s, target_lang=target_lang)

    # Leading parenthesized list markers like "(1) Item" or "(a) Item"
    s = re.sub(r"^\s*\((\d{1,3}|[A-Za-z])\)\s+", r"\1, ", s)

    # Leading multi-level section numbers: "1.2.3 Title" or "1.2. Title"
    s = re.sub(
        r"^\s*(\d+(?:\.\d+)+)\.?\s+",
        lambda m: f"{_expand_dotted_sequence_lang(m.group(1), target_lang)}, ",
        s,
    )

    # Leading single-level paragraph/list markers: "1. Configuration" or "a. Item"
    s = re.sub(r"^\s*(\d{1,3}|[A-Za-z])\.\s+", r"\1, ", s)

    if target_lang == "en":
        # Expand English technical/section abbreviations safely
        s = re.sub(r"\b(?:Art|Art\.)\s+", "Article ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bSec\.\s+", "Section ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bCh\.\s+", "Chapter ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bFig\.\s+", "Figure ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bRev\.\s+", "Revision ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bNo\.\s+", "Number ", s, flags=re.IGNORECASE)
        s = re.sub(r"\bvs\.(?=\s|$)", "versus", s, flags=re.IGNORECASE)
        s = re.sub(r"\be\.g\.", "for example", s, flags=re.IGNORECASE)
        s = re.sub(r"\bi\.e\.", "that is", s, flags=re.IGNORECASE)
        s = re.sub(r"\betc\.", "etcetera", s, flags=re.IGNORECASE)
    else:
        # Expand common Italian technical abbreviations ("Art.", "Fig.", "Par.", ...)
        s = _ABBREV_RE.sub(lambda m: _ITALIAN_ABBREV_EXPANSIONS[m.group(1).lower()], s)

        # Heading number right after expanded section nouns ("Articolo 1. Oggetto" -> "Articolo 1, Oggetto")
        s = re.sub(
            rf"\b({_SECTION_NOUNS_PATTERN})\s+(\d+(?:\.\d+)*)\.\s+",
            lambda m: f"{m.group(1)} {_expand_dotted_sequence(m.group(2))}, ",
            s,
        )

        # Roman numerals after section nouns ("Capitolo IV" -> "Capitolo 4")
        s = re.sub(
            rf"\b({_SECTION_NOUNS_PATTERN})\s+(XII|XI|IX|VIII|VII|VI|IV|III|II|X|V)\b",
            lambda m: f"{m.group(1)} {_ROMAN_SECTION_NUMERALS[m.group(2).lower()]}",
            s,
            flags=re.IGNORECASE,
        )

        # Dotted revision/section numbers after section nouns ("Revisione 1.2" -> "Revisione 1 punto 2")
        s = re.sub(
            rf"\b({_SECTION_NOUNS_PATTERN})\s+(\d+(?:\.\d+)+)\b",
            lambda m: f"{m.group(1)} {_expand_dotted_sequence(m.group(2))}",
            s,
        )

    # Version numbers like "v2.6" or "v1.2.3" (avoiding "version version 2..." if preceded by "version ")
    s = re.sub(
        r"(?<!\bversion\s)\b[vV](\d+(?:\.\d+)+)\b",
        lambda m: (
            f"version {_expand_dotted_sequence_lang(m.group(1), 'en')}"
            if target_lang == "en"
            else f"v {_expand_dotted_sequence(m.group(1))}"
        ),
        s,
    )
    s = re.sub(
        r"\bversion\s+[vV](\d+(?:\.\d+)+)\b",
        lambda m: f"version {_expand_dotted_sequence_lang(m.group(1), target_lang)}",
        s,
        flags=re.IGNORECASE,
    )

    # Multi-dot numeric identifiers (2+ dots, excluding thousands like 1.000.000)
    def _replace_multidot(match: re.Match[str]) -> str:
        token = match.group(0)
        parts = token.split(".")
        if len(parts[0]) <= 3 and all(len(p) == 3 for p in parts[1:]):
            return token
        return _expand_dotted_sequence_lang(token, target_lang)

    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){2,}\b", _replace_multidot, s)

    # Decimals written with dot ("0.125" or "2.6")
    dec_word = "point" if target_lang == "en" else "virgola"
    s = re.sub(r"\b0\.(\d+)\b", lambda m: f"0 {dec_word} {m.group(1)}", s)
    s = re.sub(r"(?<!\.)\b(\d+)\.(\d{1,2})\b(?!\.)", lambda m: f"{m.group(1)} {dec_word} {m.group(2)}", s)

    # URLs and slashes ("client/server" -> "client slash server" or "client barra server")
    slash_word = " slash " if target_lang == "en" else " barra "
    s = re.sub(r"://", " ", s)
    s = re.sub(r"/{1,2}", slash_word, s)

    # Split boundaries between letters and digits (preserving English ordinals 1st/2nd/3rd/16th!)
    if target_lang == "en":
        s = re.sub(r"(?<=[A-Za-zÀ-Úà-ú])(?=\d)|(?<=\d)(?!(?:st|nd|rd|th)\b)(?=[A-Za-zÀ-Úà-ú])", " ", s, flags=re.IGNORECASE)
    else:
        s = re.sub(r"(?<=[A-Za-zÀ-Úà-ú])(?=\d)|(?<=\d)(?=[A-Za-zÀ-Úà-ú])", " ", s)
    s = re.sub(r"\b([A-Za-z]+)-(\d+)\b", r"\1 \2", s)

    # Degrees / temperatures
    if target_lang == "en":
        s = re.sub(r"(\d+)\s*°\s*[Cc]\b", r"\1 degrees Celsius", s)
        s = re.sub(r"(\d+)\s*°\s*[Ff]\b", r"\1 degrees Fahrenheit", s)
        s = re.sub(r"(\d+)\s*°", r"\1 degrees", s)
    else:
        s = re.sub(r"(\d+)\s*°\s*[Cc]\b", r"\1 gradi Celsius", s)
        s = re.sub(r"(\d+)\s*°\s*[Ff]\b", r"\1 gradi Fahrenheit", s)
        s = re.sub(r"(\d+)\s*°", r"\1 gradi", s)

    # Operators and symbolic comparisons
    op_table = _EN_OPERATOR_REPLACEMENTS if target_lang == "en" else _OPERATOR_REPLACEMENTS
    for pattern, replacement in op_table:
        s = pattern.sub(replacement, s)

    # Multiplication asterisk between operands vs stray asterisk
    mul_word = " times " if target_lang == "en" else " per "
    s = re.sub(r"(?<=\w|\))\s*\*\s*(?=\w|\()", mul_word, s)
    s = s.replace("*", " ")

    # Negative numbers preceded by whitespace, start, or delimiter
    minus_word = "minus" if target_lang == "en" else "meno"
    s = re.sub(r"(?:(?<=^)|(?<=[\s,:(]))-(\d+)", lambda m: f" {minus_word} {m.group(1)}", s)

    # En-dash / em-dash (even unspaced like "JSON–TIFF"), spaced ASCII hyphens, and glued colons
    s = re.sub(r"\s*[–—]+\s*", ", ", s)
    s = re.sub(r"\s+-\s+", ", ", s)
    s = re.sub(r"(?<=[A-Za-z]):(?=[A-Za-z0-9])", ": ", s)

    # Replace underscores and brackets with spaces so adjacent words never glue together
    s = re.sub(r"[_()\[\]{}]", " ", s)

    # Verbalize standalone digits in the target language
    if target_lang == "en":
        s = _normalize_numbers_for_english_tts(s)
    else:
        s = _normalize_numbers_for_tts(s)

    # Collapse whitespace and tidy punctuation spacing
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\s+([,.;:!?])", r"\1", s)
    s = re.sub(r"(?:,\s*){2,}", ", ", s)

    if not any(ch.isalnum() for ch in s):
        return ""
    return s


_DEFAULT_VOICE_FOR_MODEL: Dict[str, str] = {
    "italian": "giovanni",
    "italian_24l": "giovanni",
    "english": "alba",
}


class PocketTTSEngine:
    """Wrapper around Kyutai Labs Pocket TTS supporting Italian, English, and auto IT/EN synthesis."""

    def __init__(
        self,
        language: str = "italian",
        voice: str = "giovanni",
        cache_dir: Optional[Union[str, Path]] = None,
        quantize: bool = False,
        lazy_load: bool = True,
        auto_switch_english: bool = True,
    ):
        self.language = language
        self.voice = voice
        self._explicit_voice = voice != "giovanni"
        self.quantize = quantize
        self._lazy_load = lazy_load
        self.auto_switch_english = auto_switch_english
        self.cache_dir = Path(cache_dir or resolve_voice_profile_dir() / "audio_cache")
        ensure_voice_dir(self.cache_dir)
        self._lock = threading.Lock()

        self._model = None
        self._voice_state = None
        self._sample_rate: int = 24000
        self._model_pool: Dict[Tuple[str, str], Tuple[object, object, int]] = {}

        if not lazy_load:
            with self._lock:
                self._ensure_loaded()

    def _primary_model_spec(self, language: Optional[str] = None) -> Tuple[str, str]:
        """Resolve canonical Pocket TTS (model_language, voice) pair for configured *language*."""
        mode = (language or self.language or "italian").strip().lower()
        if mode == "auto":
            base_lang = "italian"
        elif mode == "auto_24l":
            base_lang = "italian_24l"
        elif mode in ("en", "english"):
            base_lang = "english"
        else:
            base_lang = mode

        if base_lang == "english":
            target_voice = self.voice if (self._explicit_voice and self.voice != "giovanni") else _DEFAULT_VOICE_FOR_MODEL["english"]
        else:
            target_voice = self.voice or _DEFAULT_VOICE_FOR_MODEL.get(base_lang, "giovanni")
        return base_lang, target_voice

    def set_model(self, language: str) -> None:
        """Switch TTS mode ('italian', 'italian_24l', 'english', 'auto', 'auto_24l') thread-safely."""
        with self._lock:
            was_loaded = self._model is not None and self._voice_state is not None
            if language == self.language and was_loaded:
                return
            logger.info(f"Cambiamento modello Pocket TTS: '{self.language}' -> '{language}'")
            prev_base_lang, _ = self._primary_model_spec(self.language)
            self.language = language
            new_base_lang, new_voice = self._primary_model_spec(language)
            if not self._explicit_voice:
                self.voice = new_voice

            # Keep cached secondary model if matching; otherwise reset primary pointers cleanly
            cached = self._model_pool.get((new_base_lang, new_voice))
            if cached is not None:
                self._model, self._voice_state, self._sample_rate = cached
            elif new_base_lang != prev_base_lang:
                self._model = None
                self._voice_state = None
                if was_loaded or not self._lazy_load:
                    self._ensure_loaded()

    def set_voice(self, voice: str) -> None:
        """Switch voice (e.g. 'giovanni', 'alba') thread-safely."""
        with self._lock:
            self._explicit_voice = True
            if voice == self.voice and self._voice_state is not None:
                return
            if self._model is not None:
                logger.info(f"Aggiornamento voce a '{voice}'...")
                new_voice_state = self._model.get_state_for_audio_prompt(voice)
                self.voice = voice
                self._voice_state = new_voice_state
                base_lang, _ = self._primary_model_spec(self.language)
                self._model_pool[(base_lang, voice)] = (self._model, self._voice_state, self._sample_rate)
            else:
                self.voice = voice

    def _load_model_entry(self, target_lang: str, target_voice: str, *, is_primary: bool) -> Tuple[object, object, int]:
        """Load and cache *(model, voice_state, sample_rate)* for *(target_lang, target_voice)*."""
        cached = self._model_pool.get((target_lang, target_voice))
        if cached is not None:
            return cached

        from pocket_tts import TTSModel

        try:
            logger.info(f"Caricamento Pocket TTS: lingua='{target_lang}', quantize={self.quantize}...")
            t0 = time.perf_counter()
            loaded_model = TTSModel.load_model(
                language=target_lang,
                quantize=self.quantize,
            )
            loaded_model.to("cpu")
            load_time = time.perf_counter() - t0
            logger.info(f"Modello Pocket TTS caricato in {load_time:.2f}s")

            sample_rate = self._sample_rate
            if hasattr(loaded_model, "config") and hasattr(loaded_model.config, "mimi"):
                sample_rate = loaded_model.config.mimi.sample_rate

            logger.info(f"Preparazione condizionamento vocale per '{target_voice}'...")
            loaded_voice_state = loaded_model.get_state_for_audio_prompt(target_voice)

            entry = (loaded_model, loaded_voice_state, sample_rate)
            self._model_pool[(target_lang, target_voice)] = entry
            if is_primary:
                self._model = loaded_model
                self._voice_state = loaded_voice_state
                self._sample_rate = sample_rate
            return entry
        except Exception:
            if is_primary:
                self._model = None
                self._voice_state = None
            raise

    def _ensure_loaded(self) -> None:
        """Load primary model and compute conditioning state for chosen voice atomically."""
        if self._model is not None and self._voice_state is not None:
            return
        base_lang, target_voice = self._primary_model_spec(self.language)
        self._load_model_entry(base_lang, target_voice, is_primary=True)

    @property
    def sample_rate(self) -> int:
        if self._model is not None and hasattr(self._model, "config"):
            return self._model.config.mimi.sample_rate
        return self._sample_rate

    def _synthesize_segment(
        self,
        spoken_text: str,
        eff_model_lang: str,
        eff_voice: str,
        *,
        use_cache: bool,
        allow_fallback_to_primary: bool,
    ) -> Tuple[np.ndarray, int]:
        """Synthesize one already-normalized text segment for *(eff_model_lang, eff_voice)*."""
        primary_lang, primary_voice = self._primary_model_spec(self.language)
        is_primary = (eff_model_lang == primary_lang and eff_voice == primary_voice)

        cache_key = hashlib.sha256(
            f"{eff_model_lang}_{eff_voice}_{self.quantize}_tts_v5_{spoken_text}".encode("utf-8")
        ).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.wav"

        if use_cache and cache_file.exists():
            data, sr = sf.read(str(cache_file), dtype="float32")
            if data.ndim > 1:
                data = data[:, 0]
            return data, sr

        with self._lock:
            if is_primary:
                self._ensure_loaded()
                model, voice_state, sr = self._model, self._voice_state, self.sample_rate
            else:
                try:
                    model, voice_state, sr = self._load_model_entry(
                        eff_model_lang, eff_voice, is_primary=False
                    )
                except Exception as exc:
                    if not allow_fallback_to_primary:
                        raise
                    logger.warning(
                        "Impossibile caricare modello Pocket TTS '%s' (%s); fallback al modello primario '%s'.",
                        eff_model_lang, exc, primary_lang,
                    )
                    self._ensure_loaded()
                    model, voice_state, sr = self._model, self._voice_state, self.sample_rate

            import torch

            audio_tensor = model.generate_audio(
                model_state=voice_state,
                text_to_generate=spoken_text,
                copy_state=True,
            )

        if isinstance(audio_tensor, torch.Tensor):
            audio_np = audio_tensor.detach().cpu().numpy()
        else:
            audio_np = np.asarray(audio_tensor)

        audio_np = audio_np.squeeze().astype(np.float32)

        if use_cache:
            try:
                ensure_voice_dir(self.cache_dir)
                sf.write(str(cache_file), audio_np, sr)
            except Exception as e:
                logger.warning(f"Impossibile scrivere la cache audio su {cache_file}: {e}")

        return audio_np, sr

    def synthesize(self, text: str, use_cache: bool = True) -> Tuple[np.ndarray, int]:
        """Synthesize text to audio array (float32, 1D), routing Italian/English segments and normalizing dates."""
        clean_text = text.strip()
        if not clean_text:
            return np.zeros(int(self.sample_rate * 0.1), dtype=np.float32), self.sample_rate

        mode = (self.language or "italian").strip().lower()
        primary_lang, primary_voice = self._primary_model_spec(mode)
        it_model_name = "italian_24l" if mode in ("italian_24l", "auto_24l") else "italian"
        it_voice = self.voice if self._explicit_voice else _DEFAULT_VOICE_FOR_MODEL[it_model_name]
        en_voice = self.voice if (self._explicit_voice and primary_lang == "english") else _DEFAULT_VOICE_FOR_MODEL["english"]

        if mode in ("en", "english"):
            segments = [("en", clean_text)]
        elif mode in ("auto", "auto_24l") or self.auto_switch_english:
            segments = _split_bilingual_segments(clean_text, default_lang="it")
        else:
            segments = [("it", clean_text)]

        normalized_segments: list[Tuple[str, str]] = []
        for seg_lang, seg_raw in segments:
            spoken = normalize_text_for_tts(seg_raw, language=seg_lang)
            if not spoken:
                continue
            if normalized_segments and normalized_segments[-1][0] == seg_lang:
                prev_lang, prev_txt = normalized_segments[-1]
                normalized_segments[-1] = (prev_lang, f"{prev_txt} {spoken}")
            else:
                normalized_segments.append((seg_lang, spoken))

        if not normalized_segments:
            return np.zeros(int(self.sample_rate * 0.1), dtype=np.float32), self.sample_rate

        chunks: list[np.ndarray] = []
        out_sr = self.sample_rate
        for idx, (seg_lang, spoken_text) in enumerate(normalized_segments):
            if seg_lang == "en":
                eff_lang = "english"
                eff_voice = en_voice
                allow_fb = (mode not in ("en", "english"))
            else:
                eff_lang = it_model_name
                eff_voice = it_voice
                allow_fb = False

            seg_audio, seg_sr = self._synthesize_segment(
                spoken_text,
                eff_lang,
                eff_voice,
                use_cache=use_cache,
                allow_fallback_to_primary=allow_fb,
            )
            out_sr = seg_sr
            if idx > 0:
                chunks.append(np.zeros(int(out_sr * 0.06), dtype=np.float32))
            chunks.append(np.atleast_1d(seg_audio).astype(np.float32))

        if len(chunks) == 1:
            return chunks[0], out_sr
        return np.concatenate(chunks), out_sr

    def benchmark(
        self,
        test_text: str = "Questo è un test prestazionale della sintesi vocale italiana.",
        runs: int = 1,
    ) -> Dict[str, Union[float, str, int]]:
        """Run reproducible benchmark measuring latency, RTF and memory."""
        with self._lock:
            self._ensure_loaded()
        import psutil

        process = psutil.Process()
        mem_before_mb = process.memory_info().rss / (1024 * 1024)

        t_start = time.perf_counter()
        audio_arr, sr = self.synthesize(test_text, use_cache=False)
        total_time = time.perf_counter() - t_start

        mem_after_mb = process.memory_info().rss / (1024 * 1024)
        audio_duration_sec = len(audio_arr) / sr

        # Real-time factor (RTF): compute_time / audio_duration
        # Speedup: audio_duration / compute_time (e.g. 2.6x real time)
        rtf = total_time / max(audio_duration_sec, 0.001)
        speedup = audio_duration_sec / max(total_time, 0.001)

        return {
            "model_language": self.language,
            "voice": self.voice,
            "quantized": self.quantize,
            "sample_rate": sr,
            "audio_duration_sec": round(audio_duration_sec, 3),
            "generation_time_sec": round(total_time, 3),
            "rtf": round(rtf, 3),
            "speedup_factor": round(speedup, 2),
            "ram_before_mb": round(mem_before_mb, 1),
            "ram_after_mb": round(mem_after_mb, 1),
            "ram_delta_mb": round(mem_after_mb - mem_before_mb, 1),
            "is_realtime_capable": speedup >= 1.0,
        }
