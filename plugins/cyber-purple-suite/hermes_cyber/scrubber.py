"""Reversible Cloud Privacy Scrubber masking private IPs, credentials, tokens, and emails."""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Tuple

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{4,}\b")
_BEARER_OR_KEY_RE = re.compile(
    r"\b(?:Bearer\s+[A-Za-z0-9._~+/=-]{12,}|sk-(?:ant-|proj-|or-v1-)?[A-Za-z0-9_-]{12,}|"
    r"ghp_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b",
    re.IGNORECASE,
)
_SECRET_DQUOTED_RE = re.compile(
    r'''(?i)(['"]?(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|private_key)['"]?\s*[=:]\s*)"((?:[^"\\\r\n]|\\.){4,})"'''
)
_SECRET_SQUOTED_RE = re.compile(
    r"""(?i)(['"]?(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|private_key)['"]?\s*[=:]\s*)'((?:[^'\\\r\n]|\\.){4,})'"""
)
_SECRET_ASSIGN_RE = re.compile(
    r"""(?i)(\b(?:password|passwd|pwd|secret|api_key|apikey|token|auth_token|private_key)\s*[=:]\s*)([^\s'"`,;{}]{4,})"""
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


class PrivacyScrubber:
    """Reversible local scrubber masking internal IPs, credentials, tokens, and emails for cloud calls."""

    def __init__(self) -> None:
        self._forward: Dict[str, str] = {}
        self._reverse: Dict[str, str] = {}
        self._counters: Dict[str, int] = {"private_ips": 0, "secrets": 0, "emails": 0}

    def _token_for(self, category: str, prefix: str, original: str) -> str:
        if original in self._forward:
            return self._forward[original]
        self._counters[category] = self._counters.get(category, 0) + 1
        alias = f"<{prefix}_{self._counters[category]:02d}>"
        self._forward[original] = alias
        self._reverse[alias] = original
        return alias

    def scrub(self, text: str) -> Tuple[str, Dict[str, int]]:
        """Replace private IPs, secrets/JWTs, and emails with deterministic placeholders."""
        if not text:
            return "", dict(self._counters)

        def _repl_secret(m: re.Match[str]) -> str:
            return self._token_for("secrets", "REDACTED_SECRET", m.group(0))

        s = _JWT_RE.sub(_repl_secret, text)
        s = _BEARER_OR_KEY_RE.sub(_repl_secret, s)

        for quote_char, pattern in (('"', _SECRET_DQUOTED_RE), ("'", _SECRET_SQUOTED_RE)):
            def _repl_quoted(m: re.Match[str], q: str = quote_char) -> str:
                val = m.group(2)
                if "<REDACTED_SECRET_" in val:
                    return m.group(0)
                alias = self._token_for("secrets", "REDACTED_SECRET", val)
                return f"{m.group(1)}{q}{alias}{q}"

            s = pattern.sub(_repl_quoted, s)

        def _repl_assign(m: re.Match[str]) -> str:
            val = m.group(2)
            if "<REDACTED_SECRET_" in val:
                return m.group(0)
            alias = self._token_for("secrets", "REDACTED_SECRET", val)
            return f"{m.group(1)}{alias}"

        s = _SECRET_ASSIGN_RE.sub(_repl_assign, s)

        def _repl_email(m: re.Match[str]) -> str:
            return self._token_for("emails", "EMAIL", m.group(0))

        s = _EMAIL_RE.sub(_repl_email, s)

        def _repl_ip(m: re.Match[str]) -> str:
            raw_ip = m.group(1)
            try:
                ip_obj = ipaddress.ip_address(raw_ip)
                if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    return self._token_for("private_ips", "INT_IP", raw_ip)
            except ValueError:
                pass
            return raw_ip

        s = _IPV4_RE.sub(_repl_ip, s)
        return s, dict(self._counters)

    def unscrub(self, text: str) -> str:
        """Restore masked placeholders back to original local values inside local UI outputs."""
        if not text or not self._reverse:
            return text
        out = text
        # Replace longest tokens first to avoid partial collisions
        for alias in sorted(self._reverse.keys(), key=len, reverse=True):
            out = out.replace(alias, self._reverse[alias])
        return out

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._counters)
