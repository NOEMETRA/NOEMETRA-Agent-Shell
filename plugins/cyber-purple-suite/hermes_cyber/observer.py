"""Deterministic forensic evidence ingestion and entity extraction."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.dns_correlation import (
    _TIMESTAMP_RE,
    _parse_record_timestamp,
    _timestamps_within_window,
    is_record_correlated_with_any,
    is_routine_dns_txt_record,
)
from hermes_cyber.models import ArtifactIngestionResult, EvidenceRecord
from hermes_cyber.scrubber import PrivacyScrubber, _IPV4_RE

# Forensic entity extraction regexes
_HOST_RE = re.compile(
    r"(?i)\b(?:host|cmdb_host|server|node|pod)[=:\s]+([A-Za-z0-9_.-]{2,64})\b|\b((?:srv|db|ws|web|app)-[A-Za-z0-9-]+)\b"
)
_USER_RE = re.compile(r"(?i)\b(?:user|account|svc|adm|actor|login|uid)[=:\s]+([A-Za-z0-9_.@-]{2,40})\b|\b((?:svc|adm)_[A-Za-z0-9_-]+)\b")
_PROC_RE = re.compile(
    r'(?i)\b(?:proc|parent_proc|child_of|process|cmd|exe|bin|agent)[=:\s]+"?([A-Za-z0-9_./\\-]{2,64})"?|'
    r"\b(vssadmin(?:\.exe)?|powershell(?:\.exe)?|pwsh|bash|sh|dash|curl|wget|certutil|wmic|psexec|systemd|sshd|python3?|mysqld|robocopy|restic|borgbackup|borg|veeam|wbadmin(?:\.exe)?)\b"
)
_ENDPOINT_RE = re.compile(r"(?:https?://[^\s\"'<>]+|/(?:api|v[12]|admin|export|webhook|health|login|latest)[^\s\"'<>]*)")
_SINK_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("sql_concat", re.compile(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\+|\{\s*\w+|%\s*\(|f['\"])")),
    ("ssrf_fetch", re.compile(r"(?i)\b(?:requests\.(?:get|post|request)|urllib\.request\.urlopen|fetch|curl_exec)\s*\(")),
    ("cmd_exec", re.compile(r"(?i)(?:\b(?:os\.system|subprocess\.(?:run|Popen|call)|shell=True|sh\s+-c)\b|\b(?:eval|exec)\s*\()")),
    ("deserialization", re.compile(r"(?i)\b(?:pickle\.loads|yaml\.load\(|ObjectInputStream|__reduce__|unserialize)\b")),
    ("container_priv", re.compile(r"(?i)\b(?:privileged\s*:\s*true|hostPID\s*:\s*true|0\.0\.0\.0/0|chmod\s+777|CAP_SYS_ADMIN)\b")),
)
_THREAT_KEYWORDS_RE = re.compile(
    r"(?i)\b(?:failed|unauthorized|denied|invalid|exfil|c2|beacon|malware|ransomware|encrypt|vssadmin|"
    r"shadow|injection|sqli|ssrf|169\.254\.169\.254|privileged:\s*true|eval\(|os\.system|sh\s+-c|txt\s+query|qtype=txt|"
    r"token_leak|bypass|wmi|smb|logsourceunavailable|truncated)\b"
)
_CONTROL_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("signed_binary", re.compile(r"(?i)(?:signature_verified\s*=\s*true|sha256_trusted\s*=\s*true|\bsigner\s*=)")),
    ("approved_change", re.compile(r"(?i)(?:\bchangecontrol\b|approved_job\s*=|maintenance_window\s*=\s*true)")),
    ("authorized_vlan", re.compile(r"(?i)(?:authorized_backup_vlan|ransomware_note\s*=\s*false|vss_deleted\s*=\s*false)")),
    ("secret_rotation", re.compile(r"(?i)(?:passwordpolicychange|secret\s+rotated|stale\s+secret)")),
    ("internal_poller", re.compile(r"(?i)(?:external_ingress\s*=\s*false|unique_usernames\s*=\s*1|success_after_fail\s*=\s*false|interval\s*=\s*5\.0s)")),
    ("telemetry_gap", re.compile(r"(?i)(?:logsourceunavailable|\btruncated\b|\bmissing_fields\b|status\s*=\s*ambiguous)")),
    ("parameterized_sql", re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*(?:\?|%s)\s*['\"][^;\n]*,\s*\([^)]+\)")),
    ("url_allowlist", re.compile(r"(?i)(?:validate_https[a-z0-9_]*|is_safe_url|ALLOWED_HOSTS|(?<!without\s)(?<!no\s)\ballowlist\s*\()")),
    ("redirect_disabled", re.compile(r"(?i)\ballow_redirects\s*=\s*false\b")),
    ("input_validation", re.compile(r"(?i)(?:shell\s*=\s*false|shlex\.quote|hmac_verified)")),
    ("privilege_dropped", re.compile(r"(?i)(?:privileged\s*:\s*false|allowPrivilegeEscalation\s*:\s*false|drop\s*:\s*\[?\s*['\"]ALL['\"])")),
    ("routine_dns_txt", re.compile(r"(?i)(?:\bv=spf1\b|\bv=DKIM1\b|\bv=DMARC1\b|_dmarc\.|_domainkey\.|_acme-challenge\.|google-site-verification=|ms=ms\d+|apple-domain-verification=|spf\.protection\.outlook\.com|_spf\.google\.com)")),
)


def _extract_entities(raw: str, source_type: str) -> Tuple[Optional[str], Dict[str, List[str]]]:
    ts_m = _TIMESTAMP_RE.search(raw)
    timestamp = ts_m.group(1) if ts_m else None

    ips = sorted(set(_IPV4_RE.findall(raw)))
    hosts: List[str] = []
    for m in _HOST_RE.finditer(raw):
        h = m.group(1) or m.group(2)
        if h and h not in hosts:
            hosts.append(h)

    users: List[str] = []
    for m in _USER_RE.finditer(raw):
        u = m.group(1) or m.group(2)
        if u and u not in users:
            users.append(u)

    processes: List[str] = []
    for m in _PROC_RE.finditer(raw):
        p = m.group(1) or m.group(2)
        if p and p not in processes:
            processes.append(p)

    endpoints: List[str] = []
    for ep in _ENDPOINT_RE.findall(raw):
        if ep not in endpoints:
            endpoints.append(ep)

    low_raw = raw.lower()
    is_comment_line = raw.lstrip().startswith("#")

    controls: List[str] = []
    for ctrl_name, cpat in _CONTROL_PATTERNS:
        if is_comment_line and ctrl_name in ("parameterized_sql", "url_allowlist", "input_validation"):
            continue
        if cpat.search(raw):
            controls.append(ctrl_name)

    sinks: List[str] = []
    sink_literals: List[str] = []
    for sink_name, pat in _SINK_PATTERNS:
        if (
            sink_name == "cmd_exec"
            and "shell=false" in low_raw
            and not re.search(r"(?i)(?:\b(?:os\.system|shell\s*=\s*true|sh\s+-c)\b|\b(?:eval|exec)\s*\()", raw)
        ):
            continue
        matches = [m.group(0).strip()[:64] for m in pat.finditer(raw) if m.group(0).strip()]
        if matches:
            sinks.append(sink_name)
            for lit in matches:
                if lit not in sink_literals:
                    sink_literals.append(lit)

    indicators: List[str] = []
    for kw in _THREAT_KEYWORDS_RE.findall(raw):
        low = kw.lower()
        if low not in indicators:
            indicators.append(low)

    return timestamp, {
        "ips": ips,
        "hosts": hosts,
        "users": users,
        "processes": processes,
        "endpoints": endpoints,
        "sinks": sinks,
        "sink_literals": sink_literals,
        "controls": controls,
        "indicators": indicators,
    }


def _detect_source_kind(content: str, hint: str) -> str:
    clean_hint = (hint or "auto").strip().lower()
    if clean_hint in ("log", "code", "config", "http"):
        return clean_hint
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    if any(re.search(r"\b(?:def |import |from |class |SELECT |requests\.|subprocess\.|Flask|FastAPI)\b", ln) for ln in lines):
        return "code"
    if any(re.search(r"(?:^|\s)(?:privileged\s*:|containers\s*:|apiVersion\s*:|FROM\s+\w+|RUN\s+)", ln) for ln in lines):
        return "config"
    if lines and sum(1 for ln in lines[:5] if ln.startswith("{") and ln.endswith("}")) >= max(1, len(lines[:5]) // 2):
        return "log"
    if any("HTTP/1." in ln or "HTTP/2" in ln or "GET /" in ln or "POST /" in ln for ln in lines):
        return "http"
    return "log"


class CyberObserver:
    """Deterministic zero-LLM parser turning raw logs, JSONL, code, and configs into EV-xxxx records."""

    def ingest_text(
        self,
        content: str,
        title: str = "Security Artifact",
        source_kind: str = "auto",
    ) -> ArtifactIngestionResult:
        raw_text = str(content or "")
        if not raw_text.strip():
            raise ValueError("Il contenuto dell'artefatto di sicurezza è vuoto.")

        digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        case_id = f"case-{digest[:10]}"
        detected_kind = _detect_source_kind(raw_text, source_kind)

        evidences: List[EvidenceRecord] = []
        unique_ips: set[str] = set()
        unique_hosts: set[str] = set()
        unique_users: set[str] = set()
        sinks_found: set[str] = set()
        controls_found: set[str] = set()
        seq = 0

        for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            seq += 1
            rec_type = detected_kind

            is_benign_baseline = False
            ts_from_json: Optional[str] = None
            normalized_raw = stripped
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    obj: Any = json.loads(stripped)
                    if isinstance(obj, dict):
                        ts_from_json = str(obj.get("timestamp") or obj.get("ts") or "") or None
                        is_benign_baseline = bool(obj.get("baseline") or obj.get("benign"))
                        # Keep original JSON text verbatim so UI and verifier always match exact source
                        normalized_raw = stripped
                except Exception:
                    pass
            elif stripped.startswith("[BASELINE]") or "healthcheck=200 ok" in stripped.lower() or "benign=true" in stripped.lower():
                is_benign_baseline = True

            ts_parsed, entities = _extract_entities(normalized_raw, rec_type)
            timestamp = ts_from_json or ts_parsed
            unique_ips.update(entities["ips"])
            unique_hosts.update(entities["hosts"])
            unique_users.update(entities["users"])
            sinks_found.update(entities["sinks"])
            controls_found.update(entities["controls"])

            # Tag individual records accurately in mixed artifacts
            if re.search(r"\b(?:GET|POST|PUT|DELETE)\s+/", stripped) and not stripped.startswith(("#", "def ", "import ", "from ", "@")):
                rec_type = "http"
            elif (
                any(pat.search(stripped) for _, pat in _SINK_PATTERNS[:4])
                or any(c in entities["controls"] for c in ("parameterized_sql", "url_allowlist", "input_validation"))
                or stripped.startswith(("def ", "import ", "from ", "@app."))
            ):
                rec_type = "code"
            elif any(k in stripped.lower() for k in ("privileged:", "allowprivilegeescalation", "chmod ", "cap_sys_admin")):
                rec_type = "config"

            evidences.append(
                EvidenceRecord(
                    evidence_id=f"EV-{seq:04d}",
                    source_type=rec_type,  # type: ignore[arg-type]
                    line_or_seq=line_no,
                    timestamp=timestamp,
                    raw_content=raw_line.rstrip("\r\n"),
                    entities=entities,
                    is_benign_baseline=is_benign_baseline,
                )
            )

        # Propagate nearby block-level code allowlist controls onto ssrf_fetch records within the same artifact block
        if "url_allowlist" in controls_found:
            for ev in evidences:
                if "ssrf_fetch" in ev.entities.get("sinks", []) and "url_allowlist" not in ev.entities["controls"]:
                    ev.entities["controls"].append("url_allowlist")

        return ArtifactIngestionResult(
            case_id=case_id,
            title=title,
            source_kind=detected_kind,
            sha256=digest[:16],
            total_records=len(evidences),
            evidences=evidences,
            summary_stats={
                "unique_ips": len(unique_ips),
                "unique_hosts": len(unique_hosts),
                "unique_users": len(unique_users),
                "code_sinks_count": len(sinks_found),
                "controls_detected": sorted(controls_found),
                "benign_baseline_records": sum(1 for e in evidences if e.is_benign_baseline),
            },
        )


__all__ = [
    "CyberObserver",
    "PrivacyScrubber",
    "_parse_record_timestamp",
    "_timestamps_within_window",
    "is_record_correlated_with_any",
    "is_routine_dns_txt_record",
]
