"""Extracted fixture workload, rule sets, and benign telemetry corpus for ACK Mission 2."""

from __future__ import annotations

_M2_TARGET_WORKLOAD = '''\
import json
import os
from pathlib import Path

def execute_ttp_payload(aid: str, event_record: dict) -> dict:
    up = Path(os.environ["ACK_UPPERDIR"])
    canary_val = (up / "canary_vault" / "canary.txt").read_text(encoding="utf-8").strip()
    (up / f"telemetry_{aid}.json").write_text(json.dumps([event_record]), encoding="utf-8")
    return {"canary": canary_val, "telemetry_written": f"telemetry_{aid}.json"}

def handle_request(payload: dict) -> tuple:
    try:
        res = execute_ttp_payload(str(payload["aid"]), dict(payload["event"]))
        return 200, res
    except Exception as exc:
        return 403, {"error": str(exc)}
'''

_M2_BASELINE_RULES = {
    "mode": "baseline",
    "rules": [
        {"rule_id": "naive_bash_devtcp", "engine": "python_json_rule_engine", "patterns": ["bash -i >& /dev/tcp/"], "excludes": []}
    ],
}

_M2_STRUCTURAL_RULES = {
    "mode": "structural",
    "rules": [
        {
            "rule_id": "blue_rule_memfd_exec",
            "engine": "python_json_rule_engine",
            "patterns": ["memfd_create", "/proc/self/fd/", "execveat("],
            "excludes": ["signed_package_manager=true", "benign=true"],
        },
        {
            "rule_id": "blue_lotl_lineage_obf",
            "engine": "python_json_rule_engine",
            "patterns": ["parent=python3 child=sh", "${IFS}", "LD_PRELOAD=", "base64 -d"],
            "excludes": ["pytest_worker=true", "benign=true"],
        },
        {
            "rule_id": "blue_egress_entropy_beacon",
            "engine": "python_json_rule_engine",
            "patterns": ["qtype=TXT", "beacon_jitter="],
            "min_entropy": 4.2,
            "excludes": ["ntp.ubuntu.com", "healthcheck=200 ok", "proc=postfix", "proc=certbot", "benign=true"],
        },
    ],
}

_M2_OVERBROAD_RULES = {
    "mode": "overbroad_alert_all",
    "rules": [{"rule_id": "ban_all_wildcard", "engine": "python_json_rule_engine", "patterns": [""], "excludes": []}],
}

_M2_DETECTOR_ENGINE = '''\
import json, os, sys
from pathlib import Path

def evaluate(rules_spec: dict, events: list) -> list:
    if rules_spec.get("mode") == "overbroad_alert_all":
        return [{"event_index": i, "triggered": True, "rule_ids": ["ban_all_wildcard"]} for i in range(len(events))]
    outcomes = []
    for i, ev in enumerate(events):
        line = ev.get("telemetry", "")
        low = line.lower()
        entropy = float(ev.get("entropy", 0.0))
        hits = []
        for r in rules_spec.get("rules", []):
            if any(ex.lower() in low for ex in r.get("excludes", [])):
                continue
            min_ent = r.get("min_entropy")
            pat_hit = any(p.lower() in low for p in r.get("patterns", []))
            if min_ent is not None:
                if pat_hit and entropy >= float(min_ent):
                    hits.append(r["rule_id"])
            elif pat_hit:
                hits.append(r["rule_id"])
        outcomes.append({"event_index": i, "triggered": bool(hits), "rule_ids": hits})
    return outcomes

if __name__ == "__main__":
    blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
    rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
    events_path = Path(sys.argv[1])
    events = json.loads(events_path.read_text(encoding="utf-8"))
    res = evaluate(rules, events)
    print(json.dumps(res))
'''

_M2_BENIGN_CORPUS = [
    {"telemetry": "proc=pytest cmd='python3 -m pytest -q' pytest_worker=true benign=true", "entropy": 1.8},
    {"telemetry": "proc=git cmd='git status --short' benign=true", "entropy": 1.6},
    {"telemetry": "proc=systemd cmd='systemctl status nginx.service' benign=true", "entropy": 1.7},
    {"telemetry": "proc=postfix qtype=TXT query='_dmarc.corp.example.com' benign=true", "entropy": 2.3},
    {"telemetry": "proc=certbot qtype=TXT query='_acme-challenge.app.example.com' benign=true", "entropy": 2.4},
    {"telemetry": "proc=restic signer='CN=Restic' signature_verified=true benign=true", "entropy": 2.1},
    {"telemetry": "proc=nginx GET /api/v1/health status=200 healthcheck=200 ok benign=true", "entropy": 1.4},
    {"telemetry": "proc=chronyd dns_dst=ntp.ubuntu.com qtype=A benign=true", "entropy": 1.5},
    {"telemetry": "proc=apt-get signed_package_manager=true benign=true", "entropy": 1.9},
    {"telemetry": "proc=uvicorn worker startup HTTP/1.1 ready benign=true", "entropy": 1.7},
]
