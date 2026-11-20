"""Hermes Agent tool registrations for NOEMETRA Cyber Purple Suite."""

from __future__ import annotations

import json
from typing import Any


def _get_cyber_assistant():
    from hermes_cyber.server.state import get_cyber_assistant
    return get_cyber_assistant()


def _extract_arg(args: Any, kwargs: dict, key: str, default: Any = None) -> Any:
    if isinstance(args, dict):
        if key in args:
            return args[key]
    elif args is not None and not isinstance(args, dict):
        return args
    return kwargs.get(key, default)


def cyber_analyze_scenario(args: Any = None, **kwargs) -> str:
    """Esegue la pipeline Purple Team avversaria su uno scenario cyber integrato."""
    scenario_id = str(_extract_arg(args, kwargs, "scenario_id", "scen-01-ransomware-vs-backup") or "")
    try:
        report = _get_cyber_assistant().analyze_scenario(scenario_id)
        return json.dumps(report.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def cyber_analyze_artifact(args: Any = None, **kwargs) -> str:
    """Analizza log, tracce HTTP, codice o IaC in sola lettura con Red Operator, Blue Critic e Purple Replay."""
    content = str(_extract_arg(args, kwargs, "content", "") or "")
    title = str(_extract_arg(args, kwargs, "title", "Security Artifact") or "Security Artifact")
    source_kind = str(_extract_arg(args, kwargs, "source_kind", "auto") or "auto")
    if not content.strip():
        return json.dumps({"error": "Parametro 'content' vuoto o mancante."})
    try:
        report = _get_cyber_assistant().analyze_custom(title=title, content=content, source_kind=source_kind)
        return json.dumps(report.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def cyber_run_purple_benchmark(args: Any = None, **kwargs) -> str:
    """Esegue il benchmark comparativo Single-Agent vs Multi-Agent Purple sugli scenari dialettici."""
    try:
        bench = _get_cyber_assistant().run_benchmark()
        return json.dumps(bench.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def cyber_get_status(args: Any = None, **kwargs) -> str:
    """Restituisce lo stato attuale della pipeline cyber, modelli Red/Blue configurati e ultimo caso."""
    try:
        return json.dumps(_get_cyber_assistant().get_status(), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def cyber_verify_case(args: Any = None, **kwargs) -> str:
    """Aggiunge nuove evidenze a un caso aperto o verifica una versione corretta/patchata dell'artefatto."""
    case_id = str(_extract_arg(args, kwargs, "case_id", "") or "").strip()
    content = str(_extract_arg(args, kwargs, "content", "") or "")
    mode = str(_extract_arg(args, kwargs, "mode", "verify_patch") or "verify_patch")
    if not case_id or not content.strip():
        return json.dumps({"error": "Parametri 'case_id' e 'content' obbligatori."})
    try:
        report = _get_cyber_assistant().verify_case_update(case_id=case_id, content=content, mode=mode)  # type: ignore[arg-type]
        return json.dumps(report.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def cyber_run_ack_mission(args: Any = None, **kwargs) -> str:
    """Esegue una delle 4 missioni pure Adversarial Cyber Kernel (ACK) nella DetonationChamber CoW."""
    mission_id = str(_extract_arg(args, kwargs, "mission_id", "ack-m1-exploit-patch-bypass") or "")
    mutation_rounds = int(_extract_arg(args, kwargs, "mutation_rounds", 3) or 3)
    defense_mode = str(_extract_arg(args, kwargs, "defense_mode", "structural") or "structural")
    target_config = _extract_arg(args, kwargs, "target_config_content", None)
    try:
        report = _get_cyber_assistant().run_ack_mission(
            mission_id=mission_id,
            mutation_rounds=mutation_rounds,
            defense_mode=defense_mode,
            target_config_content=str(target_config) if target_config is not None else None,
        )
        return json.dumps(report.model_dump(mode="json"), indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


TOOLS = [
    {
        "name": "cyber_analyze_scenario",
        "description": "Analizza uno scenario di sicurezza dialettico (Red kill-chain, Blue contraddizioni + Sigma/YARA, Purple Replay).",
        "handler": cyber_analyze_scenario,
        "schema": {
            "name": "cyber_analyze_scenario",
            "description": "Esegue l'analisi Purple Team avversaria su uno scenario cyber integrato.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scenario_id": {"type": "string", "description": "ID dello scenario (es. scen-01-ransomware-vs-backup)"},
                },
                "required": ["scenario_id"],
            },
        },
    },
    {
        "name": "cyber_analyze_artifact",
        "description": "Analizza un artefatto di sicurezza (log JSONL/Syslog/HTTP, codice o YAML IaC) producendo kill-chain Red, contraddizioni Blue, Sigma/YARA/patch e Purple Replay.",
        "handler": cyber_analyze_artifact,
        "schema": {
            "name": "cyber_analyze_artifact",
            "description": "Ingerisce e analizza log, configurazioni o codice con Red, Blue e Purple Verifier.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string", "description": "Contenuto testuale dell'artefatto (log, codice o config)"},
                    "source_kind": {"type": "string", "description": "auto | log | code | config | http"},
                },
                "required": ["content"],
            },
        },
    },
    {
        "name": "cyber_run_purple_benchmark",
        "description": "Esegue il benchmark comparativo Single-Agent vs Multi-Agent Purple su tutti gli scenari dialettici.",
        "handler": cyber_run_purple_benchmark,
        "schema": {
            "name": "cyber_run_purple_benchmark",
            "description": "Confronta triage lineare Single-Agent con Multi-Agent Purple Verifier.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "cyber_get_status",
        "description": "Restituisce stato della suite cyber, arena multi-modello Red/Blue e casi analizzati.",
        "handler": cyber_get_status,
        "schema": {
            "name": "cyber_get_status",
            "description": "Ottiene stato della suite Cyber Purple.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "name": "cyber_verify_case",
        "description": "Aggiorna un caso cyber aperto con nuove evidenze ('append_evidence') o verifica la versione corretta ('verify_patch').",
        "handler": cyber_verify_case,
        "schema": {
            "name": "cyber_verify_case",
            "description": "Chiude il ciclo investigativo allegando nuove evidenze o verificando una patch su un caso esistente.",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "ID del caso cyber esistente"},
                    "content": {"type": "string", "description": "Nuove righe di log o artefatto patchato"},
                    "mode": {"type": "string", "description": "verify_patch | append_evidence"},
                },
                "required": ["case_id", "content"],
            },
        },
    },
    {
        "name": "cyber_run_ack_mission",
        "description": "Esegue una delle 4 missioni Adversarial Cyber Kernel (ACK) con DetonationChamber CoW, Fog of War e Oracolo Out-of-Band.",
        "handler": cyber_run_ack_mission,
        "schema": {
            "name": "cyber_run_ack_mission",
            "description": "Avvia Exploit-to-Patch, Detection vs Evasion, Shadow Clone Hardening o Fuzz-to-Fix nell'arena ACK.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mission_id": {
                        "type": "string",
                        "description": "ack-m1-exploit-patch-bypass | ack-m2-detection-evasion-arena | ack-m3-attack-path-hardening | ack-m4-fuzz-to-fix-pipeline",
                    },
                    "mutation_rounds": {"type": "integer", "description": "Round di mutazione Red con cambio classe (1..3)"},
                    "defense_mode": {
                        "type": "string",
                        "description": "structural | naive_string_replace | naive_block_all | overbroad_alert_all",
                    },
                    "target_config_content": {
                        "type": "string",
                        "description": "Manifest/config reale opzionale clonato in lowerdir per ack-m3-attack-path-hardening",
                    },
                },
                "required": ["mission_id"],
            },
        },
    },
]


def register(ctx) -> None:
    toolset = "cyber-purple-suite"
    if hasattr(ctx, "register_tool"):
        for tool_def in TOOLS:
            try:
                ctx.register_tool(
                    name=tool_def["name"],
                    toolset=toolset,
                    schema=tool_def["schema"],
                    handler=tool_def["handler"],
                    description=tool_def["description"],
                    emoji="🛡️",
                )
            except TypeError:
                try:
                    ctx.register_tool(tool_def["name"], tool_def["handler"], tool_def["description"])
                except Exception:
                    pass
