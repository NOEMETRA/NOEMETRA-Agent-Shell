"""Single-document YAML load/dump compatibility with ruamel.yaml, PyYAML, and pure-stdlib fallback."""

from __future__ import annotations

import io
import json
import os
import re
from typing import Any, Dict, List, Tuple


def _yaml_safe_load_compat(text: str) -> Any:
    """Load single-document YAML preferring ruamel.yaml/PyYAML, with strict pure-stdlib fallback for Python 3.11-3.13."""
    if os.environ.get("ACK_FORCE_STDLIB_YAML") != "1":
        try:
            from ruamel.yaml import YAML  # type: ignore[import-untyped]

            return YAML(typ="safe", pure=True).load(text)
        except ImportError:
            try:
                import yaml  # type: ignore[import-untyped]

                return yaml.safe_load(text)
            except ImportError:
                pass

    def _scan_quote_end(s: str, start_idx: int) -> int:
        q = s[start_idx]
        j = start_idx + 1
        n = len(s)
        while j < n:
            if q == "'":
                if s[j] == "'":
                    if j + 1 < n and s[j + 1] == "'":
                        j += 2
                        continue
                    return j
                j += 1
            else:
                if s[j] == "\\":
                    if j + 1 >= n:
                        break
                    j += 2
                    continue
                if s[j] == '"':
                    return j
                j += 1
        raise ValueError("Unclosed quoted string in YAML")

    def _decode_quoted(vs: str) -> str:
        if len(vs) < 2 or vs[0] not in ("'", '"') or _scan_quote_end(vs, 0) != len(vs) - 1:
            raise ValueError(f"Invalid quoted YAML scalar: {vs!r}")
        inner = vs[1:-1]
        if vs[0] == "'":
            out: List[str] = []
            i = 0
            while i < len(inner):
                if inner[i] == "'":
                    if i + 1 >= len(inner) or inner[i + 1] != "'":
                        raise ValueError("Invalid unescaped quote in single-quoted YAML scalar")
                    out.append("'")
                    i += 2
                else:
                    out.append(inner[i])
                    i += 1
            return "".join(out)

        escape_map = {
            "\\": "\\",
            '"': '"',
            "/": "/",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "0": "\0",
            "a": "\a",
            "v": "\v",
            "e": "\x1b",
            " ": " ",
            "\t": "\t",
            "N": "\x85",
            "_": "\xa0",
            "L": "\u2028",
            "P": "\u2029",
        }
        out = []
        i = 0
        while i < len(inner):
            ch = inner[i]
            if ch != "\\":
                if ch == '"':
                    raise ValueError("Unescaped quote in double-quoted YAML scalar")
                out.append(ch)
                i += 1
                continue
            if i + 1 >= len(inner):
                raise ValueError("Truncated escape in double-quoted YAML scalar")
            esc = inner[i + 1]
            if esc in escape_map:
                out.append(escape_map[esc])
                i += 2
            elif esc in ("x", "u", "U"):
                hex_len = {"x": 2, "u": 4, "U": 8}[esc]
                hex_part = inner[i + 2 : i + 2 + hex_len]
                if len(hex_part) != hex_len:
                    raise ValueError(f"Truncated \\{esc} escape in YAML scalar")
                code = int(hex_part, 16)
                if code > 0x10FFFF:
                    raise ValueError(f"Unicode escape out of range in YAML scalar: \\{esc}{hex_part}")
                if esc == "u" and 0xD800 <= code <= 0xDBFF:
                    if inner[i + 6 : i + 8] != "\\u" or len(inner) < i + 12:
                        raise ValueError("Unpaired high UTF-16 surrogate in YAML scalar")
                    low = int(inner[i + 8 : i + 12], 16)
                    if not (0xDC00 <= low <= 0xDFFF):
                        raise ValueError("Invalid low UTF-16 surrogate in YAML scalar")
                    out.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                    i += 12
                elif 0xD800 <= code <= 0xDFFF:
                    raise ValueError("Unpaired UTF-16 surrogate in YAML scalar")
                else:
                    out.append(chr(code))
                    i += 2 + hex_len
            else:
                raise ValueError(f"Unsupported YAML escape sequence: \\{esc}")
        return "".join(out)

    def _split_csv_top(s: str) -> List[str]:
        items: List[str] = []
        start = 0
        depth = 0
        idx = 0
        while idx < len(s):
            ch = s[idx]
            if ch in ("'", '"'):
                idx = _scan_quote_end(s, idx) + 1
                continue
            if ch in ("[", "{"):
                depth += 1
            elif ch in ("]", "}"):
                depth -= 1
                if depth < 0:
                    raise ValueError("Unmatched closing bracket in YAML flow collection")
            elif ch == "," and depth == 0:
                items.append(s[start:idx].strip())
                start = idx + 1
            idx += 1
        if depth != 0:
            raise ValueError("Unclosed bracket in YAML flow collection")
        tail = s[start:].strip()
        if tail:
            items.append(tail)
        return items

    def _split_kv(line_s: str) -> Tuple[str, str]:
        idx = 0
        while idx < len(line_s):
            ch = line_s[idx]
            if ch in ("'", '"'):
                idx = _scan_quote_end(line_s, idx) + 1
                continue
            if ch == ":" and (idx + 1 == len(line_s) or line_s[idx + 1] in (" ", "\t")):
                k_raw = line_s[:idx].strip()
                if not k_raw:
                    raise ValueError(f"Empty YAML mapping key: {line_s!r}")
                if k_raw[0] in ("'", '"'):
                    k_raw = _decode_quoted(k_raw)
                return k_raw, line_s[idx + 1 :].strip()
            idx += 1
        raise ValueError(f"Invalid YAML mapping line: {line_s!r}")

    def _parse_scalar(val_s: str) -> Any:
        vs = val_s.strip()
        if vs.startswith("["):
            if not vs.endswith("]"):
                raise ValueError("Unclosed flow sequence in YAML")
            inner = vs[1:-1].strip()
            return [_parse_scalar(x) for x in _split_csv_top(inner)] if inner else []
        if vs.startswith("{"):
            if not vs.endswith("}"):
                raise ValueError("Unclosed flow mapping in YAML")
            inner = vs[1:-1].strip()
            out_d: Dict[str, Any] = {}
            if inner:
                for entry in _split_csv_top(inner):
                    ek, ev = _split_kv(entry)
                    if ek in out_d:
                        raise ValueError(f"Duplicate key in YAML flow mapping: {ek}")
                    out_d[ek] = _parse_scalar(ev)
            return out_d
        if vs and vs[0] in ("'", '"'):
            return _decode_quoted(vs)
        if any(ch in vs for ch in ("[", "]", "{", "}")):
            raise ValueError("Unbalanced bracket in YAML scalar")
        if vs.startswith(("!", "&", "*", "|", ">")):
            raise ValueError(f"Unsupported YAML tag/anchor/block scalar: {vs!r}")
        low_v = vs.lower()
        if low_v == "true":
            return True
        if low_v == "false":
            return False
        if low_v in ("null", "~", ""):
            return None
        if re.match(r"^-?\d+$", vs) and not (len(vs) > 1 and vs.startswith("0")):
            return int(vs)
        if re.match(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+(?:[eE][+-]?\d+))$", vs):
            return float(vs)
        return vs

    tokens: List[Tuple[int, str]] = []
    seen_content = False
    seen_start_marker = False
    doc_ended = False
    for raw_ln in text.splitlines():
        ci = 0
        cut_idx = len(raw_ln)
        while ci < len(raw_ln):
            cch = raw_ln[ci]
            if cch in ("'", '"'):
                ci = _scan_quote_end(raw_ln, ci) + 1
                continue
            if cch == "#" and (ci == 0 or raw_ln[ci - 1] in (" ", "\t")):
                cut_idx = ci
                break
            ci += 1
        clean = raw_ln[:cut_idx]
        s = clean.strip()
        if not s:
            continue
        if s == "---" or s.startswith("--- "):
            if s != "---" or seen_content or seen_start_marker or doc_ended:
                raise ValueError("Multiple YAML documents or inline document headers are not supported")
            seen_start_marker = True
            continue
        if s == "..." or s.startswith("... "):
            if s != "..." or doc_ended:
                raise ValueError("Invalid YAML document end marker")
            doc_ended = True
            continue
        if doc_ended:
            raise ValueError("Unexpected YAML content after document end marker")
        if re.match(r"^\[[A-Za-z0-9_.-]+\]$", s):
            raise ValueError("INI section header inside YAML")
        indent = len(clean) - len(clean.lstrip(" "))
        if "\t" in clean[:indent]:
            raise ValueError("Tab indentation not allowed in YAML")
        seen_content = True
        tokens.append((indent, s))

    if not tokens:
        return {}

    def _is_seq_line(s_val: str) -> bool:
        return s_val == "-" or s_val.startswith("- ")

    def _parse_node(pos: int, expected_indent: int) -> Tuple[Any, int]:
        if _is_seq_line(tokens[pos][1]):
            seq: List[Any] = []
            seq_ind = tokens[pos][0]
            while pos < len(tokens) and tokens[pos][0] == seq_ind and _is_seq_line(tokens[pos][1]):
                rest = tokens[pos][1][1:].strip()
                item_pos = pos + 1
                if not rest:
                    if item_pos < len(tokens) and tokens[item_pos][0] > seq_ind:
                        item_val, item_pos = _parse_node(item_pos, tokens[item_pos][0])
                    else:
                        item_val = None
                    seq.append(item_val)
                    pos = item_pos
                    continue
                if re.search(r":(?:\s|$)", rest):
                    fk, fv = _split_kv(rest)
                    item_dict: Dict[str, Any] = {}
                    if fv:
                        item_dict[fk] = _parse_scalar(fv)
                    elif item_pos < len(tokens) and tokens[item_pos][0] > seq_ind + 2:
                        sub_val, item_pos = _parse_node(item_pos, tokens[item_pos][0])
                        item_dict[fk] = sub_val
                    else:
                        item_dict[fk] = None
                    sibling_ind = seq_ind + 2
                    while item_pos < len(tokens) and tokens[item_pos][0] == sibling_ind and not _is_seq_line(tokens[item_pos][1]):
                        sk, sv = _split_kv(tokens[item_pos][1])
                        if sk in item_dict:
                            raise ValueError(f"Duplicate YAML mapping key: {sk}")
                        item_pos += 1
                        if sv:
                            item_dict[sk] = _parse_scalar(sv)
                        elif item_pos < len(tokens) and (
                            tokens[item_pos][0] > sibling_ind
                            or (tokens[item_pos][0] == sibling_ind and _is_seq_line(tokens[item_pos][1]))
                        ):
                            sub_val, item_pos = _parse_node(item_pos, tokens[item_pos][0])
                            item_dict[sk] = sub_val
                        else:
                            item_dict[sk] = None
                    seq.append(item_dict)
                    pos = item_pos
                    continue
                seq.append(_parse_scalar(rest))
                pos = item_pos
            return seq, pos

        mapping: Dict[str, Any] = {}
        while pos < len(tokens) and tokens[pos][0] == expected_indent and not _is_seq_line(tokens[pos][1]):
            mk, mv = _split_kv(tokens[pos][1])
            if mk in mapping:
                raise ValueError(f"Duplicate YAML mapping key: {mk}")
            pos += 1
            if mv:
                mapping[mk] = _parse_scalar(mv)
            elif pos < len(tokens) and (
                tokens[pos][0] > expected_indent
                or (tokens[pos][0] == expected_indent and _is_seq_line(tokens[pos][1]))
            ):
                sub_val, pos = _parse_node(pos, tokens[pos][0])
                mapping[mk] = sub_val
            else:
                mapping[mk] = None
        return mapping, pos

    parsed_doc, end_pos = _parse_node(0, tokens[0][0])
    if end_pos != len(tokens):
        raise ValueError("Unexpected indentation or trailing content in YAML")
    return parsed_doc


def _yaml_safe_dump_compat(data: Any) -> str:
    """Dump single-document YAML preferring ruamel.yaml/PyYAML, with type-preserving pure-stdlib fallback."""
    if os.environ.get("ACK_FORCE_STDLIB_YAML") != "1":
        try:
            from ruamel.yaml import YAML  # type: ignore[import-untyped]

            y = YAML(typ="safe", pure=True)
            y.default_flow_style = False
            y.sort_base_mapping_type_on_output = False
            buf = io.StringIO()
            y.dump(data, buf)
            return buf.getvalue()
        except ImportError:
            try:
                import yaml  # type: ignore[import-untyped]

                return str(yaml.safe_dump(data, sort_keys=False))
            except ImportError:
                pass

    _reserved_yaml_words = frozenset({
        "true", "false", "null", "yes", "no", "on", "off", "y", "n",
        "nan", "inf", "-inf", "+inf", ".nan", ".inf", "-.inf", "+.inf", "~",
    })

    def _fmt_scalar(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if (
            not s
            or s != s.strip()
            or s.lower() in _reserved_yaml_words
            or not re.match(r"^[A-Za-z_][A-Za-z0-9_./:-]*$", s)
            or ": " in s
            or s.endswith(":")
        ):
            return re.sub(
                "[\x7f-\x9f\u2028\u2029\ufeff\ufffe\uffff]",
                lambda m: f"\\u{ord(m.group(0)):04x}",
                json.dumps(s, ensure_ascii=False),
            )
        return s

    lines: List[str] = []

    def _emit(node: Any, ind: int) -> None:
        pad = " " * ind
        if isinstance(node, dict):
            if not node:
                lines.append(f"{pad}{{}}")
                return
            for k, v in node.items():
                ks = _fmt_scalar(str(k))
                if isinstance(v, dict) and v:
                    lines.append(f"{pad}{ks}:")
                    _emit(v, ind + 2)
                elif isinstance(v, list) and v:
                    lines.append(f"{pad}{ks}:")
                    _emit(v, ind + 2)
                elif isinstance(v, dict):
                    lines.append(f"{pad}{ks}: {{}}")
                elif isinstance(v, list):
                    lines.append(f"{pad}{ks}: []")
                else:
                    lines.append(f"{pad}{ks}: {_fmt_scalar(v)}")
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, dict) and item:
                    first = True
                    for k, v in item.items():
                        prefix = f"{pad}- " if first else f"{pad}  "
                        first = False
                        ks = _fmt_scalar(str(k))
                        if isinstance(v, (dict, list)) and v:
                            lines.append(f"{prefix}{ks}:")
                            _emit(v, ind + 4)
                        elif isinstance(v, dict):
                            lines.append(f"{prefix}{ks}: {{}}")
                        elif isinstance(v, list):
                            lines.append(f"{prefix}{ks}: []")
                        else:
                            lines.append(f"{prefix}{ks}: {_fmt_scalar(v)}")
                elif isinstance(item, (dict, list)) and item:
                    lines.append(f"{pad}-")
                    _emit(item, ind + 2)
                else:
                    lines.append(f"{pad}- {_fmt_scalar(item)}")

    _emit(data, 0)
    return "\n".join(lines) + "\n"
