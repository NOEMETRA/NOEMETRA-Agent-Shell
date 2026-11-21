"""Strict default-deny AST patch safety auditor and sensitive-operation inspector for LLM patches."""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Set, Tuple

_SAFE_PATCH_ALLOWLIST = frozenset({
    # Pure builtins & safe exceptions
    "ValueError", "TypeError", "KeyError", "IndexError", "OverflowError", "ZeroDivisionError",
    "AssertionError", "RuntimeError", "RecursionError", "Exception",
    "len", "isinstance", "issubclass", "int", "float", "str", "bytes", "bytearray", "memoryview",
    "bool", "dict", "list", "tuple", "set", "frozenset", "range", "enumerate", "zip",
    "min", "max", "sum", "abs", "round", "sorted", "reversed", "all", "any",
    "chr", "ord", "hex", "bin", "oct", "slice", "iter", "next", "repr", "ascii", "divmod", "pow", "hash",
    "None", "True", "False",
    # Pure non-mutating validation/unpack methods (excludes filesystem-ambiguous names like `replace`/`remove`)
    "strip", "lstrip", "rstrip", "startswith", "endswith", "isdigit", "isalpha", "isalnum",
    "isascii", "isspace", "count", "fromhex", "unpack", "unpack_from", "calcsize",
})
_UNSAFE_ATTR_RECEIVERS = frozenset({
    "os", "sys", "subprocess", "shutil", "pathlib", "Path", "io",
    "socket", "ctypes", "importlib", "builtins",
})
_FORBIDDEN_PATCH_NAMES = frozenset({
    "eval", "exec", "compile", "__import__", "system", "popen", "spawn",
    "open", "write", "writelines", "write_text", "write_bytes",
    "read", "readlines", "read_text", "read_bytes", "recv", "sendall", "connect", "urlopen",
    "run", "check_output", "check_call", "Popen",
    "unlink", "remove", "rmdir", "rename", "replace", "mkdir", "makedirs",
    "chmod", "chown", "symlink", "link", "truncate",
    "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint", "input",
})


@dataclass
class AstPatchAuditResult:
    safe: bool
    rejection_reasons: List[str] = field(default_factory=list)
    sensitive_ops_in_original: List[str] = field(default_factory=list)
    non_allowlisted_calls_in_original: List[str] = field(default_factory=list)
    manual_review_required: bool = False


def _inspect_fn_surfaces(
    fn_node: ast.FunctionDef,
    target_function: str,
) -> Tuple[
    Set[str],
    Set[str],
    Set[str],
    Set[str],
    Set[str],
    int,
    List[str],
    List[str],
    Counter[str],
]:
    imports: Set[str] = set()
    calls: Set[str] = set()
    loaded_names: Set[str] = set()
    bound_names: Set[str] = {fn_node.name}
    attr_records: Set[str] = set()
    forbidden_nodes = 0
    sensitive_ops: Set[str] = set()
    non_allow_calls: Set[str] = set()
    non_allow_call_dumps: Counter[str] = Counter()
    allowed_calls = _SAFE_PATCH_ALLOWLIST | {target_function}

    for node in ast.walk(fn_node):
        if isinstance(node, ast.arg):
            bound_names.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound_names.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn_node:
            forbidden_nodes += 1
            sensitive_ops.add("nested_def")
        elif isinstance(node, ast.ClassDef):
            forbidden_nodes += 1
            sensitive_ops.add("nested_class")
        elif isinstance(node, ast.Lambda):
            forbidden_nodes += 1
            sensitive_ops.add("lambda")
        elif isinstance(node, ast.Global):
            forbidden_nodes += 1
            sensitive_ops.add("global_stmt")
        elif isinstance(node, ast.Nonlocal):
            forbidden_nodes += 1
            sensitive_ops.add("nonlocal_stmt")
        elif isinstance(node, ast.Delete):
            forbidden_nodes += 1
            sensitive_ops.add("delete_stmt")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.add(ast.dump(node, include_attributes=False))
            sensitive_ops.add("local_import")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in _UNSAFE_ATTR_RECEIVERS:
                forbidden_nodes += 1
                sensitive_ops.add(f"unsafe_receiver:{node.value.id}.{node.attr}")
            attr_records.add(node.attr)
            if node.attr in _FORBIDDEN_PATCH_NAMES:
                forbidden_nodes += 1
                sensitive_ops.add(f"forbidden_attr:{node.attr}")
            elif node.attr.startswith("_"):
                forbidden_nodes += 1
                sensitive_ops.add(f"private_attr:{node.attr}")
        elif isinstance(node, ast.Name):
            if node.id in _UNSAFE_ATTR_RECEIVERS:
                forbidden_nodes += 1
                sensitive_ops.add(f"unsafe_receiver_name:{node.id}")
            elif node.id in _FORBIDDEN_PATCH_NAMES:
                forbidden_nodes += 1
                sensitive_ops.add(f"forbidden_name:{node.id}")
            elif node.id.startswith("__"):
                forbidden_nodes += 1
                sensitive_ops.add(f"dunder_name:{node.id}")
            if isinstance(node.ctx, ast.Store):
                bound_names.add(node.id)
            elif isinstance(node.ctx, ast.Load):
                loaded_names.add(node.id)
        elif isinstance(node, ast.Call):
            cname: str | None = None
            is_unsafe_recv = False
            if isinstance(node.func, ast.Name):
                cname = node.func.id
                calls.add(cname)
            elif isinstance(node.func, ast.Attribute):
                cname = node.func.attr
                calls.add(cname)
                is_unsafe_recv = isinstance(node.func.value, ast.Name) and node.func.value.id in _UNSAFE_ATTR_RECEIVERS
            else:
                forbidden_nodes += 1
                sensitive_ops.add("dynamic_call")
                non_allow_call_dumps[ast.dump(node, include_attributes=False)] += 1
            if cname is not None and cname not in allowed_calls:
                non_allow_call_dumps[ast.dump(node, include_attributes=False)] += 1
                if cname not in _FORBIDDEN_PATCH_NAMES and not is_unsafe_recv and not cname.startswith("_"):
                    non_allow_calls.add(cname)

    return (
        imports,
        calls,
        loaded_names,
        bound_names,
        attr_records,
        forbidden_nodes,
        sorted(sensitive_ops),
        sorted(non_allow_calls),
        non_allow_call_dumps,
    )


def inspect_function_sensitive_ops(source: str, target_function: str) -> Tuple[List[str], List[str]]:
    """Inspect top-level target_function for pre-existing sensitive or non-allowlisted operations."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == target_function]
    if len(fns) != 1:
        return [], []
    surfaces = _inspect_fn_surfaces(fns[0], target_function)
    return surfaces[6], surfaces[7]


def audit_llm_patch_ast(
    original_source: str,
    patched_source: str,
    target_function: str,
) -> AstPatchAuditResult:
    """Strictly audit LLM-proposed patch AST, closing pre-existing sensitive call mutation bypasses."""
    try:
        orig_tree = ast.parse(original_source)
        patch_tree = ast.parse(patched_source)
    except SyntaxError as exc:
        return AstPatchAuditResult(safe=False, rejection_reasons=[f"SyntaxError: {exc}"], manual_review_required=True)

    def _non_target_dumps(tree: ast.Module) -> List[str]:
        return [
            ast.dump(n, include_attributes=False)
            for n in tree.body
            if not (isinstance(n, ast.FunctionDef) and n.name == target_function)
        ]

    orig_fns = [n for n in orig_tree.body if isinstance(n, ast.FunctionDef) and n.name == target_function]
    patch_fns = [n for n in patch_tree.body if isinstance(n, ast.FunctionDef) and n.name == target_function]
    if len(orig_fns) != 1 or len(patch_fns) != 1:
        return AstPatchAuditResult(
            safe=False,
            rejection_reasons=[f"Top-level function `{target_function}` missing or duplicated."],
            manual_review_required=True,
        )
    orig_fn, patch_fn = orig_fns[0], patch_fns[0]
    o_imp, o_calls, o_load, o_bound, o_attrs, o_forbid, o_sens, o_non_allow, o_call_dumps = _inspect_fn_surfaces(
        orig_fn, target_function
    )
    needs_review = bool(o_sens or o_non_allow)

    def _reject(reason: str) -> AstPatchAuditResult:
        return AstPatchAuditResult(
            safe=False,
            rejection_reasons=[reason],
            sensitive_ops_in_original=o_sens,
            non_allowlisted_calls_in_original=o_non_allow,
            manual_review_required=True,
        )

    orig_decs = [ast.dump(d, include_attributes=False) for d in orig_fn.decorator_list]
    patch_decs = [ast.dump(d, include_attributes=False) for d in patch_fn.decorator_list]
    if orig_decs != patch_decs:
        return _reject("Decorators of target_function were modified.")
    if ast.dump(orig_fn.args, include_attributes=False) != ast.dump(patch_fn.args, include_attributes=False):
        return _reject("Function signature arguments were modified.")
    orig_ret = ast.dump(orig_fn.returns, include_attributes=False) if orig_fn.returns is not None else None
    patch_ret = ast.dump(patch_fn.returns, include_attributes=False) if patch_fn.returns is not None else None
    if orig_ret != patch_ret:
        return _reject("Function return annotation was modified.")
    if _non_target_dumps(orig_tree) != _non_target_dumps(patch_tree):
        return _reject("Code outside target_function was modified.")

    # Close pre-existing sensitive call loophole: any pre-existing forbidden/sensitive op disables auto-LLM patching
    if o_sens or o_forbid > 0:
        return _reject(
            f"Pre-existing sensitive operations in target_function ({', '.join(o_sens)}) "
            "forbid automatic LLM patching; manual review required."
        )

    p_imp, p_calls, p_load, p_bound, p_attrs, p_forbid, p_sens, _, p_call_dumps = _inspect_fn_surfaces(
        patch_fn, target_function
    )
    if p_imp != o_imp:
        return _reject("Import statements inside target_function were altered.")
    if p_forbid > 0 or p_sens:
        return _reject(f"Forbidden AST constructs introduced: {', '.join(p_sens) or 'forbidden_nodes'}.")

    # Exact AST multiset equality on every non-allowlisted Call prevents mutating args of pre-existing custom calls
    if p_call_dumps != o_call_dumps:
        return _reject("Non-allowlisted call sites or their arguments were altered by LLM patch.")

    allowed_calls = _SAFE_PATCH_ALLOWLIST | {target_function}
    for cname in p_calls - o_calls:
        if cname not in allowed_calls:
            return _reject(f"Call `{cname}` is not in _SAFE_PATCH_ALLOWLIST.")
    for name in (p_load - p_bound) - (o_load - o_bound):
        if name.startswith("_") or name not in _SAFE_PATCH_ALLOWLIST:
            return _reject(f"Loaded identifier `{name}` is not allowlisted.")
    for attr in p_attrs - o_attrs:
        if attr.startswith("_") or attr not in _SAFE_PATCH_ALLOWLIST:
            return _reject(f"Attribute access `.{attr}` is not allowlisted.")

    return AstPatchAuditResult(
        safe=True,
        rejection_reasons=[],
        sensitive_ops_in_original=[],
        non_allowlisted_calls_in_original=o_non_allow,
        manual_review_required=needs_review,
    )


def is_llm_patch_ast_safe(original_source: str, patched_source: str, target_function: str) -> bool:
    """Boolean convenience wrapper around audit_llm_patch_ast."""
    return audit_llm_patch_ast(original_source, patched_source, target_function).safe
