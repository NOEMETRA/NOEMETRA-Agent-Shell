"""Routine DNS TXT filtering and cross-record entity/time-window correlation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from hermes_cyber.models import EvidenceRecord

_TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"
)
_HOSTILE_DNS_CONTEXT_RE = re.compile(
    r"(?i)(?:c2-sync|exfil|token_leak|dns_txt_authorized\s*=\s*false|maintenance_window\s*=\s*false|"
    r"-enc\b|-encodedcommand\b|powershell|pwsh\b|child_of\s*=|\balert\s*=)"
)
_DNS_ENTROPY_RE = re.compile(r"(?i)\bentropy\s*=\s*([0-9]+(?:\.[0-9]+)?)")
_DNS_BYTES_RE = re.compile(r"(?i)\bbytes(?:_out)?\s*=\s*([0-9]+)")
_DNS_RATE_RE = re.compile(r"(?i)\b(?:rate|qps)\s*=\s*([0-9]+(?:\.[0-9]+)?)")
_PREFIXED_ROUTINE_SUBDOMAIN_RE = re.compile(r"(?i)[A-Za-z0-9_-]+\.(?:_dmarc|_acme-challenge)\.")
_LONG_DKIM_SELECTOR_RE = re.compile(r"(?i)[A-Za-z0-9_-]{24,}\._domainkey\.")
_ROUTINE_DNS_DAEMONS = frozenset({
    "postfix",
    "sendmail",
    "exim",
    "dovecot",
    "opendkim",
    "opendmarc",
    "rspamd",
    "certbot",
    "acme.sh",
    "named",
    "unbound",
    "systemd-resolved",
    "coredns",
    "dnsmasq",
    "bind",
})


def is_routine_dns_txt_record(ev: EvidenceRecord) -> bool:
    """Return True only for low-anomaly standard DNS TXT records (SPF/DMARC/DKIM/ACME)."""
    controls = ev.entities.get("controls", [])
    if "routine_dns_txt" not in controls:
        return False
    raw = ev.raw_content
    if _HOSTILE_DNS_CONTEXT_RE.search(raw):
        return False
    if _PREFIXED_ROUTINE_SUBDOMAIN_RE.search(raw) or _LONG_DKIM_SELECTOR_RE.search(raw):
        return False
    for m in _DNS_ENTROPY_RE.finditer(raw):
        if float(m.group(1)) >= 3.5:
            return False
    for m in _DNS_BYTES_RE.finditer(raw):
        if int(m.group(1)) >= 400:
            return False
    for m in _DNS_RATE_RE.finditer(raw):
        if float(m.group(1)) >= 10.0:
            return False
    for proc in ev.entities.get("processes", []):
        norm_proc = proc.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if norm_proc.endswith(".exe"):
            norm_proc = norm_proc[:-4]
        if norm_proc and norm_proc not in _ROUTINE_DNS_DAEMONS:
            return False
    return True


def _parse_record_timestamp(ts: Optional[str]) -> Optional[Tuple[datetime, bool]]:
    """Parse ISO-8601 (is_yearless=False) or syslog month/day timestamp (is_yearless=True)."""
    if not ts:
        return None
    s = ts.strip()
    try:
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s)
        norm = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        return norm, False
    except ValueError:
        pass
    try:
        normalized = " ".join(s.split())
        # Anchor yearless syslog to leap year 2000 explicitly before strptime so Feb 29 parses cleanly without warnings
        return datetime.strptime(f"2000 {normalized}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc), True
    except ValueError:
        return None


def _timestamps_within_window(
    r_parsed: Tuple[datetime, bool],
    c_parsed: Tuple[datetime, bool],
    window_seconds: int,
) -> bool:
    """Return True when two parsed timestamps fall within `window_seconds`, allowing year rollover on syslog dates."""
    r_dt, r_yearless = r_parsed
    c_dt, c_yearless = c_parsed
    if not r_yearless and not c_yearless:
        return abs((r_dt - c_dt).total_seconds()) <= window_seconds
    fixed_dt, yl_dt = (c_dt, r_dt) if r_yearless else (r_dt, c_dt)
    for target_year in (fixed_dt.year - 1, fixed_dt.year, fixed_dt.year + 1):
        try:
            candidate_dt = yl_dt.replace(year=target_year)
        except ValueError:
            continue
        if abs((fixed_dt - candidate_dt).total_seconds()) <= window_seconds:
            return True
    return False


def is_record_correlated_with_any(
    record: EvidenceRecord,
    candidates: List[EvidenceRecord],
    all_records: Optional[List[EvidenceRecord]] = None,
    window_seconds: int = 900,
) -> bool:
    """Return True if `record` shares host/IP/user identity and time window with any candidate record."""
    if not candidates:
        return False

    bridge_pool = all_records if all_records is not None else [record, *candidates]
    ip_to_hosts: Dict[str, set[str]] = {}
    for ev in bridge_pool:
        hs = {h.lower() for h in ev.entities.get("hosts", []) if h}
        if hs:
            for ip in ev.entities.get("ips", []):
                if ip:
                    ip_to_hosts.setdefault(ip.lower(), set()).update(hs)

    def _expanded_entities(ev: EvidenceRecord) -> Tuple[set[str], set[str], set[str]]:
        hosts = {h.lower() for h in ev.entities.get("hosts", []) if h}
        ips = {ip.lower() for ip in ev.entities.get("ips", []) if ip}
        users = {u.lower() for u in ev.entities.get("users", []) if u}
        for ip in ips:
            hosts.update(ip_to_hosts.get(ip, set()))
        return hosts, ips, users

    r_hosts, r_ips, r_users = _expanded_entities(record)
    r_parsed = _parse_record_timestamp(record.timestamp)

    for cand in candidates:
        # Same single record containing multiple indicators/fields corroborates itself immediately
        if cand is record or (bool(record.evidence_id) and cand.evidence_id == record.evidence_id):
            return True
        c_hosts, c_ips, c_users = _expanded_entities(cand)
        if r_hosts and c_hosts and r_hosts.isdisjoint(c_hosts):
            continue
        if not ((r_hosts & c_hosts) or (r_ips & c_ips) or (r_users & c_users)):
            continue
        c_parsed = _parse_record_timestamp(cand.timestamp)
        if r_parsed is None or c_parsed is None:
            continue
        if not _timestamps_within_window(r_parsed, c_parsed, window_seconds):
            continue
        return True
    return False
