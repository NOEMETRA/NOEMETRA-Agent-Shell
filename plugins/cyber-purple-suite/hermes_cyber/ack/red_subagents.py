"""Independent Red Team Sub-Agent Fleet (Recon, Weaponizer, Adaptive Bypass Mutator)."""

from __future__ import annotations

import ast
import json
import struct
from typing import Any, Dict, List, Optional, Tuple

from hermes_cyber.models import AckSubAgentTrace
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json


class RedReconSubAgent:
    """Inspects target surface/parser AST strictly under Red Fog of War context."""

    def analyze_python_parser(
        self,
        source_code: str,
        target_function: str,
        red_ctx: Dict[str, Any],
        *,
        expected_kind: Optional[str] = None,
        router: Optional[ModelRouter] = None,
    ) -> Tuple[Dict[str, Any], AckSubAgentTrace]:
        tree = ast.parse(source_code)
        fn_node: Optional[ast.FunctionDef] = None
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == target_function:
                fn_node = node
                break

        explicit_kind = expected_kind if expected_kind in ("bytes", "str", "dict") else None
        input_kind = explicit_kind or "bytes"
        arg_names: List[str] = []
        sinks: List[str] = []
        recursive = False

        if fn_node is not None:
            pos_args = list(fn_node.args.posonlyargs) + list(fn_node.args.args)
            arg_names = [a.arg for a in pos_args]
            if explicit_kind is None and pos_args and pos_args[0].annotation is not None:
                ann = ast.unparse(pos_args[0].annotation).lower()
                if "dict" in ann or "mapping" in ann:
                    input_kind = "dict"
                elif "str" in ann:
                    input_kind = "str"
                elif "bytes" in ann or "bytearray" in ann:
                    input_kind = "bytes"
            elif explicit_kind is None and pos_args:
                an = pos_args[0].arg.lower()
                if "bytes" not in an and "raw" not in an:
                    input_kind = "str"

            for sub in ast.walk(fn_node):
                if isinstance(sub, ast.Subscript):
                    if "indexing" not in sinks:
                        sinks.append("indexing")
                elif isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                    if "division" not in sinks:
                        sinks.append("division")
                elif isinstance(sub, ast.Call):
                    call_txt = ast.unparse(sub.func)
                    if call_txt == target_function:
                        recursive = True
                        if "recursion" not in sinks:
                            sinks.append("recursion")
                    elif "unpack" in call_txt:
                        if "struct.unpack" not in sinks:
                            sinks.append("struct.unpack")
                        if explicit_kind is None and pos_args and pos_args[0].annotation is None:
                            input_kind = "bytes"
                    elif "decode" in call_txt:
                        if "bytes.decode" not in sinks:
                            sinks.append("bytes.decode")
                        if explicit_kind is None and pos_args and pos_args[0].annotation is None:
                            input_kind = "bytes"
                    elif "loads" in call_txt:
                        if "json.loads" not in sinks:
                            sinks.append("json.loads")
                        if explicit_kind is None and pos_args and pos_args[0].annotation is None:
                            input_kind = "str"
                    elif "split" in call_txt and explicit_kind is None and pos_args and pos_args[0].annotation is None and "struct.unpack" not in sinks:
                        input_kind = "str"

        model_used = "deterministic"
        llm_str_seeds: List[str] = []
        llm_hex_seeds: List[str] = []
        if router is not None:
            sys_prompt = (
                "You are RedReconSubAgent under strict Fog of War. "
                "You receive ONLY target signature and static AST sinks (no Blue rules). "
                "Return strict JSON with keys: hypothesis (string), extra_hex_inputs (list of hex strings), "
                "extra_str_inputs (list of strings)."
            )
            user_prompt = json.dumps({
                "red_context": red_ctx,
                "target_function": target_function,
                "arg_names": arg_names,
                "input_kind": input_kind,
                "ast_sinks": sinks,
                "recursive": recursive,
            })
            parsed, m_label, _, _ = invoke_router_json(
                router,
                system_prompt=sys_prompt,
                user_prompt=user_prompt,
                scrubber=PrivacyScrubber(),
            )
            model_used = m_label
            if isinstance(parsed, dict):
                for hx in parsed.get("extra_hex_inputs") or []:
                    if isinstance(hx, str) and len(hx) <= 2048:
                        try:
                            bytes.fromhex(hx)
                            llm_hex_seeds.append(hx)
                        except ValueError:
                            pass
                for st in parsed.get("extra_str_inputs") or []:
                    if isinstance(st, str) and len(st) <= 2048:
                        llm_str_seeds.append(st)

        recon = {
            "target_function": target_function,
            "arg_names": arg_names,
            "input_kind": input_kind,
            "sinks": sinks,
            "recursive": recursive,
            "llm_hex_seeds": llm_hex_seeds[:8],
            "llm_str_seeds": llm_str_seeds[:8],
        }
        trace = AckSubAgentTrace(
            team="RED",
            role="RedReconSubAgent",
            phase="INIT_ARENA",
            model_used=model_used,
            visible_context_keys=sorted(red_ctx.keys()),
            summary=(
                f"Analizzata firma `{target_function}({', '.join(arg_names)})` [input={input_kind}, "
                f"sinks={','.join(sinks) or 'none'}, recursive={recursive}]."
            ),
            artifacts=[],
        )
        return recon, trace


class RedWeaponizerSubAgent:
    """Synthesizes data-driven crash reproducers & fuzzing candidates for the target parser."""

    def build_fuzz_candidates(
        self,
        recon: Dict[str, Any],
        red_ctx: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], AckSubAgentTrace]:
        input_kind = str(recon.get("input_kind") or "bytes")
        candidates: List[Dict[str, Any]] = []

        if input_kind == "bytes":
            raw_samples: List[bytes] = [
                b"",
                b"\x01",
                b"\x01\x02\x03",
                b"\x00" * 4,
                b"\xff\xfe\xfd\x80\x00\xff",
                struct.pack(">HH", 1, 255) + b"A",
                struct.pack(">BHH", 1, 1, 250) + b"ABCD",
                struct.pack(">BHH", 2, 5000, 2) + b"XY",
                struct.pack(">BHH", 3, 0, 0),
                b"".join(struct.pack(">BHH", 0xFF, 1, 5 * (24 - i)) for i in range(25)),
            ]
            for i in range(12):
                raw_samples.append(struct.pack(">BHH", 1, i, 200 + i) + b"A" * 4)
                raw_samples.append(struct.pack(">HH", 65535, i) + b"\x00\xff")
            for hx in recon.get("llm_hex_seeds") or []:
                raw_samples.append(bytes.fromhex(hx))
            for idx, b in enumerate(raw_samples, start=1):
                candidates.append({"name": f"cand_{idx:02d}", "kind": "bytes", "data": b.hex()})
        elif input_kind == "dict":
            dict_samples: List[Any] = [
                {},
                {"payload": ""},
                {"count": 0, "divisor": 0},
                {"length": 999999, "data": "abc"},
                {"type": "nested", "children": None},
                "NOT_A_DICT",
            ]
            for idx, obj in enumerate(dict_samples, start=1):
                candidates.append({"name": f"cand_{idx:02d}", "kind": "json", "data": obj})
        else:
            str_samples: List[str] = [
                "",
                ":::",
                "===",
                "1/0",
                "hdr:0",
                "KEY:",
                "{unclosed",
                "[[[",
                "[" * 120 + "1" + "]" * 120,
                "A\x00B\xff",
                "9" * 4000,
                *(recon.get("llm_str_seeds") or []),
            ]
            for idx, s in enumerate(str_samples, start=1):
                candidates.append({"name": f"cand_{idx:02d}", "kind": "json", "data": s})

        trace = AckSubAgentTrace(
            team="RED",
            role="RedWeaponizerSubAgent",
            phase="RED_WEAPONIZE",
            model_used="deterministic",
            visible_context_keys=sorted(red_ctx.keys()),
            summary=f"Generati {len(candidates)} input avversari `{input_kind}` per il fuzzing & minimizzazione delta.",
            artifacts=["repro_min_crash"],
        )
        return candidates, trace


class RedBypassMutatorSubAgent:
    """Mutates attack class cleanly across rounds using FogOfWarController failed-class memory."""

    def plan_mutation_rounds(
        self,
        recon: Dict[str, Any],
        red_ctx: Dict[str, Any],
        *,
        rounds: int,
        router: Optional[ModelRouter] = None,
    ) -> Tuple[List[Tuple[str, List[Dict[str, Any]]]], AckSubAgentTrace]:
        input_kind = str(recon.get("input_kind") or "bytes")
        already_failed = set(red_ctx.get("failed_attack_classes") or [])

        if input_kind == "bytes":
            specs: List[Tuple[str, List[Dict[str, Any]]]] = [
                (
                    "CLASS_TRUNCATED_AND_EMPTY_BOUNDARY",
                    [
                        {"kind": "bytes", "data": ""},
                        {"kind": "bytes", "data": "010203"},
                        {"kind": "bytes", "data": (struct.pack(">BHH", 3, 1, 65000) + b"Z" * 3).hex()},
                    ],
                ),
                (
                    "CLASS_NUMERIC_LENGTH_OVERFLOW_OR_ZERO",
                    [
                        {"kind": "bytes", "data": (struct.pack(">BHH", 4, 65535, 4) + b"ABCD").hex()},
                        {"kind": "bytes", "data": (struct.pack(">BHH", 4, 9999, 0)).hex()},
                        {"kind": "bytes", "data": (struct.pack(">HH", 0, 0) + b"\x00\x00").hex()},
                    ],
                ),
                (
                    "CLASS_DEEP_NESTING_AND_MALFORMED_ENCODING",
                    [
                        {"kind": "bytes", "data": b"".join(struct.pack(">BHH", 0xFF, 1, 5 * (29 - i)) for i in range(30)).hex()},
                        {"kind": "bytes", "data": "fffefdfc8081"},
                    ],
                ),
            ]
        elif input_kind == "dict":
            specs = [
                ("CLASS_TRUNCATED_AND_EMPTY_BOUNDARY", [{"kind": "json", "data": {}}, {"kind": "json", "data": {"type": None}}]),
                ("CLASS_NUMERIC_LENGTH_OVERFLOW_OR_ZERO", [{"kind": "json", "data": {"count": 0, "length": 999999}}]),
                ("CLASS_DEEP_NESTING_AND_MALFORMED_ENCODING", [{"kind": "json", "data": {"nested": {"bad": [1, None]}}}]),
            ]
        else:
            specs = [
                (
                    "CLASS_TRUNCATED_AND_EMPTY_BOUNDARY",
                    [
                        {"kind": "json", "data": ""},
                        {"kind": "json", "data": ":"},
                        {"kind": "json", "data": "frame:10:abc"},
                    ],
                ),
                (
                    "CLASS_NUMERIC_LENGTH_OVERFLOW_OR_ZERO",
                    [
                        {"kind": "json", "data": "10/0"},
                        {"kind": "json", "data": "count=999999999;"},
                    ],
                ),
                (
                    "CLASS_DEEP_NESTING_AND_MALFORMED_ENCODING",
                    [
                        {"kind": "json", "data": "[" * 200 + "1" + "]" * 200},
                        {"kind": "json", "data": "{\"a\":" * 120 + "1" + "}" * 120},
                    ],
                ),
            ]

        model_used = "deterministic"
        if router is not None:
            sys_prompt = (
                "You are RedBypassMutatorSubAgent under strict Fog of War. "
                "Do NOT repeat any class in failed_attack_classes. "
                "Reply JSON: {\"extra_str_mutations\": [...], \"extra_hex_mutations\": [...]}."
            )
            parsed, m_label, _, _ = invoke_router_json(
                router,
                system_prompt=sys_prompt,
                user_prompt=json.dumps({"red_context": red_ctx, "input_kind": input_kind}),
                scrubber=PrivacyScrubber(),
            )
            model_used = m_label
            if isinstance(parsed, dict) and input_kind == "bytes":
                for hx in (parsed.get("extra_hex_mutations") or [])[:4]:
                    if isinstance(hx, str):
                        try:
                            bytes.fromhex(hx)
                            specs[0][1].append({"kind": "bytes", "data": hx})
                        except ValueError:
                            pass
            elif isinstance(parsed, dict):
                for st in (parsed.get("extra_str_mutations") or [])[:4]:
                    if isinstance(st, str):
                        specs[0][1].append({"kind": "json", "data": st})

        filtered = [s for s in specs if s[0] not in already_failed] or specs
        chosen = filtered[: max(1, min(len(filtered), rounds))]
        trace = AckSubAgentTrace(
            team="RED",
            role="RedBypassMutatorSubAgent",
            phase="RED_MUTATE_BYPASS",
            model_used=model_used,
            visible_context_keys=sorted(red_ctx.keys()),
            summary=f"Pianificati {len(chosen)} round di mutazione con cambio classe obbligatorio.",
            artifacts=[c for c, _ in chosen],
        )
        return chosen, trace


def record_red_mission_traces(
    *,
    phase_base_summary: str,
    phase_mut_summary: str,
    red_ctx: Dict[str, Any],
    attack_classes: List[str],
    router: Optional[ModelRouter] = None,
) -> List[AckSubAgentTrace]:
    """Emit structured Red sub-agent fleet traces for M1-M3 while optionally querying red_router."""
    model_used = "deterministic"
    if router is not None:
        parsed, m_label, _, _ = invoke_router_json(
            router,
            system_prompt=(
                "You are RedReconSubAgent under strict Fog of War. "
                "Summarize offensive strategy concisely in JSON: {\"strategy_note\": \"...\"}."
            ),
            user_prompt=json.dumps({"red_context": red_ctx, "planned_classes": attack_classes}),
            scrubber=PrivacyScrubber(),
        )
        model_used = m_label
        if isinstance(parsed, dict) and parsed.get("strategy_note"):
            phase_mut_summary = f"{phase_mut_summary} | LLM Red note: {str(parsed['strategy_note'])[:140]}"

    keys = sorted(red_ctx.keys())
    return [
        AckSubAgentTrace(
            team="RED",
            role="RedReconSubAgent",
            phase="INIT_ARENA",
            model_used=model_used,
            visible_context_keys=keys,
            summary=f"Mappatura superficie d'attacco `{red_ctx.get('target_endpoint', 'target')}` senza visibilità sulle difese Blue.",
            artifacts=[],
        ),
        AckSubAgentTrace(
            team="RED",
            role="RedWeaponizerSubAgent",
            phase="RED_WEAPONIZE",
            model_used="deterministic",
            visible_context_keys=keys,
            summary=phase_base_summary,
            artifacts=["baseline_poc"],
        ),
        AckSubAgentTrace(
            team="RED",
            role="RedBypassMutatorSubAgent",
            phase="RED_MUTATE_BYPASS",
            model_used=model_used,
            visible_context_keys=keys,
            summary=phase_mut_summary,
            artifacts=list(attack_classes),
        ),
    ]
