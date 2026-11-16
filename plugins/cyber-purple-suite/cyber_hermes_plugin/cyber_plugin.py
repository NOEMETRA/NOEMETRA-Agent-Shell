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
