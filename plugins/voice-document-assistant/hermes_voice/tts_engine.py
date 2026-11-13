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


def _is_preserved_acronym(word: str, *, all_caps_line: bool) -> bool:
    if all_caps_line and word in _ITALIAN_SHORT_UPPER_WORDS:
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


def _format_italian_date(day: int, month: int, year_str: str) -> Optional[str]:
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return None
    day_str = "primo" if day == 1 else str(day)
    return f"{day_str} {_ITALIAN_MONTHS[month]} {year_str}"


def _normalize_dates(text: str) -> str:
    """Convert numeric dates (DD/MM/YYYY, DD.MM.YYYY, DD-MM-YYYY, YYYY-MM-DD, MM/YYYY) to Italian."""
    # ISO YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD (allowing trailing sentence punctuation like '.')
    def _iso_repl(m: re.Match[str]) -> str:
        formatted = _format_italian_date(int(m.group(4)), int(m.group(3)), m.group(1))
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)((?:19|20)\d{2})([/.-])(0?[1-9]|1[0-2])\2(0?[1-9]|[12]\d|3[01])(?![\d])(?![./-]\w)",
        _iso_repl,
        text,
    )

    # European DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY
    def _dmy4_repl(m: re.Match[str]) -> str:
        formatted = _format_italian_date(int(m.group(1)), int(m.group(3)), m.group(4))
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0?[1-9]|[12]\d|3[01])([/.-])(0?[1-9]|1[0-2])\2((?:19|20)\d{2})(?![\d])(?![./-]\w)",
        _dmy4_repl,
        s,
    )

    # Short European DD/MM/YY, DD-MM-YY, DD.MM.YY (2-digit year)
    def _dmy2_repl(m: re.Match[str]) -> str:
        formatted = _format_italian_date(int(m.group(1)), int(m.group(3)), m.group(4))
        return formatted if formatted is not None else m.group(0)

    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0?[1-9]|[12]\d|3[01])([/.-])(0?[1-9]|1[0-2])\2(\d{2})(?![\d])(?![./-]\w)",
        _dmy2_repl,
        s,
    )

    # Month/Year MM/YYYY (two-digit month to avoid ratios like 1/2000)
    s = re.sub(
        r"(?<![\d/-])(?<!\d\.)(0[1-9]|1[0-2])/((?:19[7-9]\d|20\d{2}))(?![\d])(?![./-]\w)",
        lambda m: f"{_ITALIAN_MONTHS[int(m.group(1))]} {m.group(2)}",
        s,
    )
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


def normalize_text_for_tts(text: str) -> str:
    """Deterministically normalize technical Italian text for Pocket TTS pronunciation.

    Preserves standard prose unchanged while making list/section numbering,
    ALL-CAPS titles, numeric dates, alphanumeric parameter codes (e.g. ``P1=10``),
    operators, decimals, and slashes (``/`` -> ``barra``) pronounceable without LLM rewriting.
    Returns ``""`` when no speakable alphanumeric characters remain.
    """
    if not text or not text.strip():
        return ""

    s = text.strip()

    # Strip decorative bullets (comma pause when separating inline header items) and ASCII dividers
    s = re.sub(r"(?<=\S)\s*[•▪◦‣∙●■□►▸✔✓➢➤|¦]+\s*(?=\S)", ", ", s)
    s = re.sub(r"[•▪◦‣∙●■□►▸✔✓➢➤|¦]+", " ", s)
    s = re.sub(r"(?:---+|===+|___|~~~+|\*{2,})", ", ", s)

    # Leading parenthesized list markers like "(1) Voce" or "(a) Voce"
    s = re.sub(r"^\s*\((\d{1,3}|[A-Za-z])\)\s+", r"\1, ", s)

    # Leading multi-level section numbers: "1.2.3 Titolo" or "1.2. Titolo"
    s = re.sub(
        r"^\s*(\d+(?:\.\d+)+)\.?\s+",
        lambda m: f"{_expand_dotted_sequence(m.group(1))}, ",
        s,
    )

    # Leading single-level paragraph/list markers: "1. Configurazione" or "a. Voce"
    s = re.sub(r"^\s*(\d{1,3}|[A-Za-z])\.\s+", r"\1, ", s)

    # Normalize ALL-CAPS titles/headings before inserting lowercase words or expanding dates
    s = _normalize_all_caps_titles(s)

    # Convert numeric dates into spoken Italian before dot/slash/dash expansions
    s = _normalize_dates(s)

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

    # Version numbers like "v2.6" or "v1.2.3" -> "v 2 punto 6"
    s = re.sub(
        r"\b[vV](\d+(?:\.\d+)+)\b",
        lambda m: f"v {_expand_dotted_sequence(m.group(1))}",
        s,
    )

    # Multi-dot numeric identifiers (2+ dots, excluding Italian thousands like 1.000.000)
    def _replace_multidot(match: re.Match[str]) -> str:
        token = match.group(0)
        parts = token.split(".")
        if len(parts[0]) <= 3 and all(len(p) == 3 for p in parts[1:]):
            return token
        return _expand_dotted_sequence(token)

    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){2,}\b", _replace_multidot, s)

    # Decimals written with dot ("0.125" or "2.6") -> "virgola"
    s = re.sub(r"\b0\.(\d+)\b", r"0 virgola \1", s)
    s = re.sub(r"(?<!\.)\b(\d+)\.(\d{1,2})\b(?!\.)", r"\1 virgola \2", s)

    # URLs and slashes ("client/server" -> "client barra server")
    s = re.sub(r"://", " ", s)
    s = re.sub(r"/{1,2}", " barra ", s)

    # Split boundaries between letters and digits so identifiers ("Q03", "res60") read cleanly
    s = re.sub(r"(?<=[A-Za-zÀ-Úà-ú])(?=\d)|(?<=\d)(?=[A-Za-zÀ-Úà-ú])", " ", s)
    s = re.sub(r"\b([A-Za-z]+)-(\d+)\b", r"\1 \2", s)

    # Degrees / temperatures
    s = re.sub(r"(\d+)\s*°\s*[Cc]\b", r"\1 gradi Celsius", s)
    s = re.sub(r"(\d+)\s*°\s*[Ff]\b", r"\1 gradi Fahrenheit", s)
    s = re.sub(r"(\d+)\s*°", r"\1 gradi", s)

    # Operators and symbolic comparisons
    for pattern, replacement in _OPERATOR_REPLACEMENTS:
        s = pattern.sub(replacement, s)

    # Multiplication asterisk between operands vs stray asterisk
    s = re.sub(r"(?<=\w|\))\s*\*\s*(?=\w|\()", " per ", s)
    s = s.replace("*", " ")

    # Negative numbers preceded by whitespace, start, or delimiter (after operators are expanded)
    s = re.sub(r"(?:(?<=^)|(?<=[\s,:(]))-(\d+)", r" meno \1", s)

    # En-dash / em-dash (even unspaced like "JSON–TIFF"), spaced ASCII hyphens, and glued colons
    s = re.sub(r"\s*[–—]+\s*", ", ", s)
    s = re.sub(r"\s+-\s+", ", ", s)
    s = re.sub(r"(?<=[A-Za-z]):(?=[A-Za-z0-9])", ": ", s)

    # Replace underscores and brackets with spaces so adjacent words never glue together
    s = re.sub(r"[_()\[\]{}]", " ", s)

    # Verbalize standalone digits into Italian words so Pocket TTS avoids byte-token spelling
    s = _normalize_numbers_for_tts(s)

    # Collapse whitespace and tidy punctuation spacing
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"\s+([,.;:!?])", r"\1", s)
    s = re.sub(r"(?:,\s*){2,}", ", ", s)

    if not any(ch.isalnum() for ch in s):
        return ""
    return s


class PocketTTSEngine:
    """Wrapper around Kyutai Labs Pocket TTS for Italian speech synthesis."""

    def __init__(
        self,
        language: str = "italian",
        voice: str = "giovanni",
        cache_dir: Optional[Union[str, Path]] = None,
        quantize: bool = False,
        lazy_load: bool = True,
    ):
        self.language = language
        self.voice = voice
        self.quantize = quantize
        self._lazy_load = lazy_load
        self.cache_dir = Path(cache_dir or resolve_voice_profile_dir() / "audio_cache")
        ensure_voice_dir(self.cache_dir)
        self._lock = threading.Lock()

        self._model = None
        self._voice_state = None
        self._sample_rate: int = 24000

        if not lazy_load:
            with self._lock:
                self._ensure_loaded()

    def set_model(self, language: str) -> None:
        """Switch model between 'italian' and 'italian_24l' thread-safely."""
        with self._lock:
            was_loaded = self._model is not None and self._voice_state is not None
            if language == self.language and was_loaded:
                return
            logger.info(f"Cambiamento modello Pocket TTS: '{self.language}' -> '{language}'")
            self.language = language
            self._model = None
            self._voice_state = None
            if was_loaded or not self._lazy_load:
                self._ensure_loaded()

    def set_voice(self, voice: str) -> None:
        """Switch voice (e.g. 'giovanni') thread-safely."""
        with self._lock:
            if voice == self.voice and self._voice_state is not None:
                return
            if self._model is not None:
                logger.info(f"Aggiornamento voce a '{voice}'...")
                new_voice_state = self._model.get_state_for_audio_prompt(voice)
                self.voice = voice
                self._voice_state = new_voice_state
            else:
                self.voice = voice

    def _ensure_loaded(self) -> None:
        """Load model and compute conditioning state for chosen voice atomically."""
        if self._model is not None and self._voice_state is not None:
            return

        from pocket_tts import TTSModel

        try:
            logger.info(f"Caricamento Pocket TTS: lingua='{self.language}', quantize={self.quantize}...")
            t0 = time.perf_counter()
            loaded_model = TTSModel.load_model(
                language=self.language,
                quantize=self.quantize,
            )
            loaded_model.to("cpu")
            load_time = time.perf_counter() - t0
            logger.info(f"Modello Pocket TTS caricato in {load_time:.2f}s")

            # Extract sample rate from config
            sample_rate = self._sample_rate
            if hasattr(loaded_model, "config") and hasattr(loaded_model.config, "mimi"):
                sample_rate = loaded_model.config.mimi.sample_rate

            # Cache voice conditioning state before publishing _model
            logger.info(f"Preparazione condizionamento vocale per '{self.voice}'...")
            loaded_voice_state = loaded_model.get_state_for_audio_prompt(self.voice)

            self._model = loaded_model
            self._voice_state = loaded_voice_state
            self._sample_rate = sample_rate
        except Exception:
            self._model = None
            self._voice_state = None
            raise

    @property
    def sample_rate(self) -> int:
        if self._model is not None and hasattr(self._model, "config"):
            return self._model.config.mimi.sample_rate
        return self._sample_rate

    def synthesize(self, text: str, use_cache: bool = True) -> Tuple[np.ndarray, int]:
        """Synthesize Italian text to audio array (float32, 1D), applying speech normalization."""
        clean_text = text.strip()
        if not clean_text:
            return np.zeros(int(self.sample_rate * 0.1), dtype=np.float32), self.sample_rate

        spoken_text = normalize_text_for_tts(clean_text)
        if not spoken_text:
            return np.zeros(int(self.sample_rate * 0.1), dtype=np.float32), self.sample_rate

        # Cache key incorporates normalized spoken form so old raw-symbol caches are bypassed
        cache_key = hashlib.sha256(
            f"{self.language}_{self.voice}_{self.quantize}_tts_v4_{spoken_text}".encode("utf-8")
        ).hexdigest()
        cache_file = self.cache_dir / f"{cache_key}.wav"

        if use_cache and cache_file.exists():
            data, sr = sf.read(str(cache_file), dtype="float32")
            if data.ndim > 1:
                data = data[:, 0]
            return data, sr

        # Audio generation serialized under model lock
        with self._lock:
            self._ensure_loaded()

            import torch

            audio_tensor = self._model.generate_audio(
                model_state=self._voice_state,
                text_to_generate=spoken_text,
                copy_state=True,
            )

        # Convert to numpy float32 1D array
        if isinstance(audio_tensor, torch.Tensor):
            audio_np = audio_tensor.detach().cpu().numpy()
        else:
            audio_np = np.asarray(audio_tensor)

        audio_np = audio_np.squeeze().astype(np.float32)

        # Save to disk cache
        if use_cache:
            try:
                ensure_voice_dir(self.cache_dir)
                sf.write(str(cache_file), audio_np, self.sample_rate)
            except Exception as e:
                logger.warning(f"Impossibile scrivere la cache audio su {cache_file}: {e}")

        return audio_np, self.sample_rate

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
