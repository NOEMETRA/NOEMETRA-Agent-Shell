"""Independent Blue Team Sub-Agent Fleet (Triage, Patch Architect, Regression Suite Generator)."""

from __future__ import annotations

import ast
import json
import textwrap
from typing import Any, Dict, List, Optional, Set, Tuple

from hermes_cyber.models import AckSubAgentTrace
from hermes_cyber.observer import PrivacyScrubber
from hermes_cyber.router_bridge import ModelRouter, invoke_router_json

_DANGEROUS_MODULES = frozenset({"subprocess", "ctypes", "socket", "shutil", "http", "urllib", "os", "importlib", "builtins", "pathlib"})
_DANGEROUS_CALL_NAMES = frozenset({
    "eval", "exec", "compile", "__import__", "system", "popen", "spawn",
    "open", "write", "writelines", "write_text", "write_bytes",
    "unlink", "remove", "rmdir", "rename", "replace", "mkdir", "makedirs",
    "chmod", "chown", "symlink", "link", "truncate",
    "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint", "input",
})


def _extract_ast_surfaces(root_node: ast.AST) -> Tuple[Set[str], Set[str], Set[str]]:
    imports: Set[str] = set()
    calls: Set[str] = set()
    dunder_attrs: Set[str] = set()
    for node in ast.walk(root_node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
            elif node.level > 0:
                imports.add(".")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            dunder_attrs.add(node.attr)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    return imports, calls, dunder_attrs


def _is_llm_patch_ast_safe(original_source: str, patched_source: str, target_function: str) -> bool:
    """Reject LLM-proposed patches that introduce imports/IO/dangerous calls or alter code outside target_function."""
    try:
        orig_tree = ast.parse(original_source)
        patch_tree = ast.parse(patched_source)
    except SyntaxError:
        return False

    def _non_target_dumps(tree: ast.Module) -> List[str]:
        return [
            ast.dump(n, include_attributes=False)
            for n in tree.body
            if not (isinstance(n, ast.FunctionDef) and n.name == target_function)
        ]

    orig_fns = [n for n in orig_tree.body if isinstance(n, ast.FunctionDef) and n.name == target_function]
    patch_fns = [n for n in patch_tree.body if isinstance(n, ast.FunctionDef) and n.name == target_function]
    if len(orig_fns) != 1 or len(patch_fns) != 1:
        return False
    orig_fn, patch_fn = orig_fns[0], patch_fns[0]
    orig_decs = [ast.dump(d, include_attributes=False) for d in orig_fn.decorator_list]
    patch_decs = [ast.dump(d, include_attributes=False) for d in patch_fn.decorator_list]
    if orig_decs != patch_decs:
        return False
    if ast.dump(orig_fn.args, include_attributes=False) != ast.dump(patch_fn.args, include_attributes=False):
        return False
    orig_ret = ast.dump(orig_fn.returns, include_attributes=False) if orig_fn.returns is not None else None
    patch_ret = ast.dump(patch_fn.returns, include_attributes=False) if patch_fn.returns is not None else None
    if orig_ret != patch_ret:
        return False
    if _non_target_dumps(orig_tree) != _non_target_dumps(patch_tree):
        return False

    # Compare target_function AST surfaces directly so dangerous ops existing in unrelated module helpers
    # cannot be newly introduced into target_function.
    orig_imports, orig_calls, orig_dunders = _extract_ast_surfaces(orig_fn)
    patch_imports, patch_calls, patch_dunders = _extract_ast_surfaces(patch_fn)
    if patch_imports - orig_imports:
        return False
    if (patch_calls - orig_calls) & _DANGEROUS_CALL_NAMES:
        return False
    if patch_dunders - orig_dunders:
        return False
    return True


def _apply_deterministic_ast_parser_hardening(
    original_source: str,
    target_function: str,
    expected_kind: str,
) -> str:
    """Wrap target_function cleanly with type/size/recursion-depth bounds and safe ValueError containment."""
    tree = ast.parse(original_source)
    fn_node: Optional[ast.FunctionDef] = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == target_function:
            fn_node = node
            break
    if fn_node is None:
        raise ValueError(f"Funzione target '{target_function}' non trovata nel modulo.")

    pos_args = list(fn_node.args.posonlyargs) + list(fn_node.args.args)
    first_arg = pos_args[0].arg if pos_args else "data"
    orig_sig_args = ast.unparse(fn_node.args)
    ret_ann = f" -> {ast.unparse(fn_node.returns)}" if fn_node.returns is not None else ""

    forward_parts: List[str] = [a.arg for a in pos_args]
    if fn_node.args.vararg is not None:
        forward_parts.append(f"*{fn_node.args.vararg.arg}")
    for ka in fn_node.args.kwonlyargs:
        forward_parts.append(f"{ka.arg}={ka.arg}")
    if fn_node.args.kwarg is not None:
        forward_parts.append(f"**{fn_node.args.kwarg.arg}")
    forward_call = ", ".join(forward_parts)

    lines = original_source.splitlines()
    dec_start = (fn_node.decorator_list[0].lineno - 1) if fn_node.decorator_list else (fn_node.lineno - 1)
    def_start = fn_node.lineno - 1
    end_idx = fn_node.end_lineno or fn_node.lineno
    orig_block_lines = lines[def_start:end_idx]

    # Strip defaults/annotations on renamed impl so default expressions evaluate ONCE on the wrapper only,
    # and keep internal recursive calls pointing at `target_function` so they traverse the depth guard.
    renamed_name = f"_noemetra_impl_{target_function}"
    impl_args = ast.arguments(
        posonlyargs=[ast.arg(arg=a.arg) for a in fn_node.args.posonlyargs],
        args=[ast.arg(arg=a.arg) for a in fn_node.args.args],
        vararg=ast.arg(arg=fn_node.args.vararg.arg) if fn_node.args.vararg else None,
        kwonlyargs=[ast.arg(arg=a.arg) for a in fn_node.args.kwonlyargs],
        kw_defaults=[None for _ in fn_node.args.kwonlyargs],
        kwarg=ast.arg(arg=fn_node.args.kwarg.arg) if fn_node.args.kwarg else None,
        defaults=[],
    )
    first_stmt_line = fn_node.body[0].lineno - 1
    if first_stmt_line > def_start:
        impl_body_lines = lines[first_stmt_line:end_idx]
    else:
        impl_body_lines = ["    " + lines[def_start][fn_node.body[0].col_offset :]]
    inner_lines = [f"def {renamed_name}({ast.unparse(impl_args)}):", *impl_body_lines]

    has_parser_crash_err = "class ParserCrashError" in original_source
    crash_types = (
        "(ParserCrashError, IndexError, KeyError, TypeError, AttributeError, ZeroDivisionError, RecursionError, OverflowError, MemoryError, UnicodeDecodeError)"
        if has_parser_crash_err
        else "(IndexError, KeyError, TypeError, AttributeError, ZeroDivisionError, RecursionError, OverflowError, MemoryError, UnicodeDecodeError)"
    )

    if expected_kind == "bytes":
        type_guard = f"if not isinstance({first_arg}, (bytes, bytearray, memoryview)): raise ValueError('Expected bytes input')"
        len_guard = f"if len({first_arg}) > 1048576: raise ValueError('Payload size exceeds safe bound')"
    elif expected_kind == "dict":
        type_guard = f"if not isinstance({first_arg}, dict): raise ValueError('Expected dict payload')"
        len_guard = "pass"
    else:
        type_guard = f"if not isinstance({first_arg}, str): raise ValueError('Expected str input')"
        len_guard = f"if len({first_arg}) > 1048576: raise ValueError('Input string exceeds safe bound')"

    helper_import = "import threading as _ack_threading\nimport struct as _ack_struct\n"
    depth_init = "_ACK_DEPTH_STATE = _ack_threading.local()\n"
    wrapper_lines = [*[lines[i] for i in range(dec_start, def_start)]]
    wrapper_code = textwrap.dedent(f"""\
    def {target_function}({orig_sig_args}){ret_ann}:
        {type_guard}
        {len_guard}
        depth = getattr(_ACK_DEPTH_STATE, "depth", 0) + 1
        if depth > 64:
            raise ValueError("Maximum parser nesting depth exceeded")
        _ACK_DEPTH_STATE.depth = depth
        try:
            return {renamed_name}({forward_call})
        except ValueError:
            raise
        except (_ack_struct.error,) + {crash_types} as exc:
            raise ValueError(f"Invalid parser input rejected safely: {{exc}}") from exc
        finally:
            _ACK_DEPTH_STATE.depth = depth - 1
    """)

    new_lines = [
        *lines[:dec_start],
        helper_import.rstrip(),
        depth_init.rstrip(),
        *inner_lines,
        "",
        *wrapper_lines,
        *wrapper_code.splitlines(),
        *lines[end_idx:],
    ]
    return "\n".join(new_lines) + "\n"


class BlueTriageSubAgent:
    """Triages reproduced crashes under strict Blue Fog of War context (no Red mutation plan)."""

    def diagnose_crash(
        self,
        blue_ctx: Dict[str, Any],
        crash_records: List[Dict[str, Any]],
        target_function: str,
    ) -> Tuple[Dict[str, Any], AckSubAgentTrace]:
        exc_types: List[str] = []
        msgs: List[str] = []
        for rec in crash_records:
            et = str(rec.get("exc_type") or "").strip()
            msg = str(rec.get("exc_msg") or "").strip()
            if et and et not in exc_types:
                exc_types.append(et)
            if msg and msg not in msgs:
                msgs.append(msg[:120])

        triage = {
            "target_function": target_function,
            "reproduced_count": len(crash_records),
            "exception_types": exc_types,
            "messages": msgs[:6],
        }
        trace = AckSubAgentTrace(
            team="BLUE",
            role="BlueTriageSubAgent",
            phase="ORACLE_BASELINE_CHECK",
            model_used="deterministic",
            visible_context_keys=sorted(blue_ctx.keys()),
            summary=(
                f"Triage Blue su `{target_function}`: riprodotti {len(crash_records)} crash "
                f"({', '.join(exc_types) or 'nessuna eccezione non gestita'})."
            ),
            artifacts=[],
        )
        return triage, trace


class BluePatchArchitectSubAgent:
    """Synthesizes structural AST-safe patches preserving valid inputs and rejecting crash boundaries."""

    def synthesize_parser_patch(
        self,
        original_source: str,
        target_function: str,
        triage: Dict[str, Any],
        blue_ctx: Dict[str, Any],
        *,
        defense_mode: str,
        is_builtin_tlv: bool,
        expected_kind: str = "bytes",
        builtin_fixed_src: str = "",
        builtin_naive_block_src: str = "",
        router: Optional[ModelRouter] = None,
    ) -> Tuple[str, str, AckSubAgentTrace]:
        if defense_mode == "naive_block_all":
            if is_builtin_tlv and builtin_naive_block_src:
                patched = builtin_naive_block_src
            else:
                patched = (
                    f"def {target_function}(*args, **kwargs):\n"
                    f"    raise ValueError('naive_block_all: parser disabled')\n"
                )
            trace = AckSubAgentTrace(
                team="BLUE",
                role="BluePatchArchitectSubAgent",
                phase="BLUE_DEFEND",
                model_used="deterministic",
                visible_context_keys=sorted(blue_ctx.keys()),
                summary="Modalità anti-cheat `naive_block_all`: tutti gli input bloccati.",
                artifacts=["patch.diff"],
            )
            return patched, "naive_block_all: rifiuta tutti gli input del parser.", trace

        model_used = "deterministic"
        if router is not None and not is_builtin_tlv:
            sys_prompt = (
                "You are BluePatchArchitectSubAgent under strict Fog of War. "
                "Fix the Python parser root-cause crashes cleanly without breaking valid inputs or adding dangerous OS/network calls. "
                "Reject malformed/oversized/truncated inputs by raising ValueError. "
                "Reply strictly JSON: {\"patched_source\": \"...\", \"summary\": \"...\"}."
            )
            user_prompt = json.dumps({
                "blue_context": blue_ctx,
                "target_function": target_function,
                "triage": triage,
                "original_source": original_source,
            })
            parsed, m_label, _, _ = invoke_router_json(
                router,
                system_prompt=sys_prompt,
                user_prompt=user_prompt,
                scrubber=PrivacyScrubber(),
            )
            if isinstance(parsed, dict) and isinstance(parsed.get("patched_source"), str):
                cand_src = parsed["patched_source"]
                if _is_llm_patch_ast_safe(original_source, cand_src, target_function):
                    summary = str(parsed.get("summary") or "structural (Blue LLM patch AST-verified)")
                    trace = AckSubAgentTrace(
                        team="BLUE",
                        role="BluePatchArchitectSubAgent",
                        phase="BLUE_DEFEND",
                        model_used=m_label,
                        visible_context_keys=sorted(blue_ctx.keys()),
                        summary=summary,
                        artifacts=["patch.diff"],
                    )
                    return cand_src, summary, trace
                model_used = f"{m_label} (fallback_ast_guard)"

        if is_builtin_tlv and builtin_fixed_src:
            patched = builtin_fixed_src
            summary = (
                "structural: validazione esplicita bounds header (`length <= remaining`), "
                "`count <= 256`, profondità max `8` con `InvalidTlvFrameError(ValueError)`."
            )
        else:
            patched = _apply_deterministic_ast_parser_hardening(original_source, target_function, expected_kind)
            summary = (
                f"structural (AST hardener): validazione tipo/dimensione, limite profondità ricorsione (64) "
                f"e contenimento sicuro {triage.get('exception_types') or ['ValueError']} su `{target_function}`."
            )

        trace = AckSubAgentTrace(
            team="BLUE",
            role="BluePatchArchitectSubAgent",
            phase="BLUE_DEFEND",
            model_used=model_used,
            visible_context_keys=sorted(blue_ctx.keys()),
            summary=summary,
            artifacts=["patch.diff"],
        )
        return patched, summary, trace


class BlueRegressionSubAgent:
    """Emits a standalone pytest regression test suite covering valid corpus + minimized crash cases."""

    def build_regression_pytest(
        self,
        *,
        target_module_name: str,
        target_function: str,
        valid_cases: List[Dict[str, Any]],
        crash_cases: List[Dict[str, Any]],
        blue_ctx: Dict[str, Any],
        target_rel_path: Optional[str] = None,
    ) -> Tuple[str, AckSubAgentTrace]:
        valid_json = json.dumps(valid_cases, indent=2)
        crash_json = json.dumps(crash_cases[:16], indent=2)
        rel_mod = target_rel_path or f"{target_module_name}.py"
        test_src = textwrap.dedent(f'''\
        """Auto-generated ACK Blue Team Regression Test Suite for `{target_module_name}.{target_function}`."""

        import importlib
        import importlib.util
        import json
        from pathlib import Path
        import sys
        import pytest

        _RUN_ROOT = Path(__file__).resolve().parents[1]
        _PATCHED_DIR = _RUN_ROOT / "patched_target"
        _REL_MOD = {rel_mod!r}
        _PATCHED_MOD = _PATCHED_DIR / _REL_MOD

        _VALID_CASES = json.loads({valid_json!r})
        _CRASH_CASES = json.loads({crash_json!r})


        def _load_target_fn():
            if not _PATCHED_MOD.is_file():
                pytest.skip("Patched target module not present in run deliverable.")
            for pdir in (str(_PATCHED_DIR), str(_PATCHED_MOD.parent)):
                if pdir not in sys.path:
                    sys.path.insert(0, pdir)
            parts = list(Path(_REL_MOD).with_suffix("").parts)
            if parts and all(p.isidentifier() for p in parts):
                mod_name = ".".join(parts)
                if len(parts) > 1:
                    importlib.invalidate_caches()
                    importlib.import_module(".".join(parts[:-1]))
                spec = importlib.util.spec_from_file_location(mod_name, str(_PATCHED_MOD))
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
            else:
                spec = importlib.util.spec_from_file_location("_ack_patched_mod", str(_PATCHED_MOD))
                mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, {target_function!r})


        def _decode_input(item):
            if item.get("kind") == "bytes":
                return bytes.fromhex(item["data"])
            return item["data"]


        def _stable_snapshot(val, _depth=0):
            if _depth > 32:
                return "<max_depth>"
            if val is None or isinstance(val, (bool, int, float, str)):
                return val
            if isinstance(val, (bytes, bytearray)):
                return {{"__bytes__": bytes(val).hex()}}
            if isinstance(val, (list, tuple)):
                return {{"__seq__": type(val).__name__, "items": [_stable_snapshot(x, _depth + 1) for x in val]}}
            if isinstance(val, dict):
                return {{"__dict__": sorted(([str(k), _stable_snapshot(v, _depth + 1)] for k, v in val.items()), key=lambda kv: kv[0])}}
            if isinstance(val, (set, frozenset)):
                items = [_stable_snapshot(x, _depth + 1) for x in val]
                return {{"__set__": type(val).__name__, "items": sorted(items, key=lambda x: json.dumps(x, sort_keys=True))}}
            if hasattr(val, "__dict__"):
                return {{"__obj__": f"{{type(val).__module__}}.{{type(val).__qualname__}}", "attrs": _stable_snapshot(vars(val), _depth + 1)}}
            import re as _re
            return {{"__type__": f"{{type(val).__module__}}.{{type(val).__qualname__}}", "repr": _re.sub(r" at 0x[0-9a-fA-F]+>", ">", repr(val))}}


        def test_valid_corpus_preserves_functionality():
            fn = _load_target_fn()
            if not _VALID_CASES:
                pytest.skip("No valid corpus items supplied.")
            for case in _VALID_CASES:
                res = fn(_decode_input(case))
                if "expected_snapshot" in case:
                    assert json.dumps(_stable_snapshot(res), sort_keys=True) == case["expected_snapshot"]
                elif "expected_repr" in case:
                    assert repr(res) == case["expected_repr"]
                if "expected_json" in case:
                    assert res == case["expected_json"]


        def test_minimized_crash_inputs_fail_safely_without_crash():
            fn = _load_target_fn()
            for case in _CRASH_CASES:
                payload = _decode_input(case)
                try:
                    fn(payload)
                except ValueError:
                    pass
        ''')
        trace = AckSubAgentTrace(
            team="BLUE",
            role="BlueRegressionSubAgent",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            model_used="deterministic",
            visible_context_keys=sorted(blue_ctx.keys()),
            summary=f"Generata regression suite pytest con {len(valid_cases)} casi validi e {min(16, len(crash_cases))} reproducer.",
            artifacts=["regression_tests/"],
        )
        return test_src, trace


def record_blue_mission_traces(
    *,
    triage_summary: str,
    patch_summary: str,
    verify_summary: str,
    blue_ctx: Dict[str, Any],
    router: Optional[ModelRouter] = None,
) -> List[AckSubAgentTrace]:
    """Emit structured Blue sub-agent fleet traces for M1-M3 while optionally querying blue_router."""
    model_used = "deterministic"
    if router is not None:
        parsed, m_label, _, _ = invoke_router_json(
            router,
            system_prompt=(
                "You are BluePatchArchitectSubAgent under strict Fog of War. "
                "Summarize structural defense rationale concisely in JSON: {\"defense_note\": \"...\"}."
            ),
            user_prompt=json.dumps({"blue_context": blue_ctx}),
            scrubber=PrivacyScrubber(),
        )
        model_used = m_label
        if isinstance(parsed, dict) and parsed.get("defense_note"):
            patch_summary = f"{patch_summary} | LLM Blue note: {str(parsed['defense_note'])[:140]}"

    keys = sorted(blue_ctx.keys())
    return [
        AckSubAgentTrace(
            team="BLUE",
            role="BlueTriageSubAgent",
            phase="ORACLE_BASELINE_CHECK",
            model_used="deterministic",
            visible_context_keys=keys,
            summary=triage_summary,
            artifacts=[],
        ),
        AckSubAgentTrace(
            team="BLUE",
            role="BluePatchArchitectSubAgent",
            phase="BLUE_DEFEND",
            model_used=model_used,
            visible_context_keys=keys,
            summary=patch_summary,
            artifacts=["patch.diff"],
        ),
        AckSubAgentTrace(
            team="BLUE",
            role="BlueRegressionSubAgent",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            model_used="deterministic",
            visible_context_keys=keys,
            summary=verify_summary,
            artifacts=["regression_tests/"],
        ),
    ]
