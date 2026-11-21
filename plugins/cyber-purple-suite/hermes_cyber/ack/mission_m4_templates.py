"""Embedded lab fixtures, fuzzing harness templates, and patch scripts for ACK Mission 4."""

from __future__ import annotations

_M4_VULNERABLE_PARSER = '''\
import struct

class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if depth > 16:
        raise ParserCrashError("PARSER_RECURSION_DEPTH_CRASH: unbounded TLV recursion depth")
    out = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ParserCrashError("PARSER_TRUNCATED_HEADER_CRASH: truncated 5-byte TLV header")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        if count > 4096:
            raise ParserCrashError("PARSER_COUNT_OVERFLOW_CRASH: allocation count*stride overflow")
        if offset + length > len(data):
            raise ParserCrashError("PARSER_OOB_LENGTH_CRASH: declared length exceeds packet bounds")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''

_M4_NAIVE_BLOCK_ALL_PARSER = '''\
class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    raise ValueError("Blocked all TLV packets")
'''

_M4_STRUCTURAL_FIXED_PARSER = '''\
import struct

MAX_TLV_DEPTH = 8
MAX_ITEM_COUNT = 256

class ParserCrashError(RuntimeError):
    pass

class InvalidTlvFrameError(ValueError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if not isinstance(data, (bytes, bytearray)):
        raise InvalidTlvFrameError("Input must be bytes")
    if depth > MAX_TLV_DEPTH:
        raise InvalidTlvFrameError("TLV nesting depth exceeds safe cap")
    out = []
    offset = 0
    total = len(data)
    while offset < total:
        if offset + 5 > total:
            raise InvalidTlvFrameError("Truncated TLV header rejected safely")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        if count > MAX_ITEM_COUNT:
            raise InvalidTlvFrameError("Count ceiling exceeded")
        if length > total - offset:
            raise InvalidTlvFrameError("Declared TLV length exceeds remaining buffer")
        payload = data[offset : offset + length]
        offset += length
        if t == 0xFF:
            out.append({"type": t, "nested": parse_tlv_frame(payload, depth + 1)})
        else:
            out.append({"type": t, "count": count, "size": len(payload)})
    return out
'''

_M4_DEFAULT_VALID_CORPUS = [
    {"name": "msg1.bin", "kind": "bytes", "data": b"\x01\x00\x01\x00\x04ABCD".hex()},
    {"name": "msg2.bin", "kind": "bytes", "data": b"\xff\x00\x01\x00\x08\x02\x00\x01\x00\x03XYZ".hex()},
]

_M4_BASE_FUZZ_SCRIPT = '''\
import importlib, importlib.util, json, os, sys
from pathlib import Path

up = Path(os.environ["ACK_UPPERDIR"])
target_p = up / {target_filename!r}
for pdir in (str(up), str(target_p.parent)):
    if pdir not in sys.path:
        sys.path.insert(0, pdir)
red_dir = Path(os.environ["ACK_ARTIFACTS_RED"])
_parts = list(Path({target_filename!r}).with_suffix("").parts)
if _parts and all(p.isidentifier() for p in _parts):
    _mod_name = ".".join(_parts)
    if len(_parts) > 1:
        importlib.invalidate_caches()
        importlib.import_module(".".join(_parts[:-1]))
    spec = importlib.util.spec_from_file_location(_mod_name, str(target_p))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_mod_name] = mod
else:
    spec = importlib.util.spec_from_file_location("_ack_target_parser", str(target_p))
    mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, {fn_name!r})

def _dec(item):
    return bytes.fromhex(item["data"]) if item.get("kind") == "bytes" else item["data"]

candidates = json.loads((red_dir / "candidates_base.json").read_text(encoding="utf-8"))
crashes = []
min_case = None
min_len = None

for cand in candidates:
    raw = _dec(cand)
    try:
        fn(raw)
    except ValueError:
        pass
    except Exception as exc:
        size = len(raw) if isinstance(raw, (bytes, bytearray, str)) else len(json.dumps(raw, default=str))
        crashes.append({{"name": cand.get("name", ""), "exc_type": type(exc).__name__, "exc_msg": str(exc)[:180]}})
        if min_len is None or size < min_len:
            min_len = size
            min_case = cand

# Delta minimization step for bytes or string crashing payloads
if min_case is not None and min_case.get("kind") in ("bytes", "json"):
    cur_raw = _dec(min_case)
    if isinstance(cur_raw, (bytes, str)) and len(cur_raw) > 2:
        for cut in range(len(cur_raw), 0, -1):
            trial = cur_raw[:cut]
            try:
                fn(trial)
            except ValueError:
                break
            except Exception:
                cur_raw = trial
                continue
        min_case = (
            {{"kind": "bytes", "data": cur_raw.hex()}}
            if isinstance(cur_raw, bytes)
            else {{"kind": "json", "data": cur_raw}}
        )
        min_len = len(cur_raw)

reproduced = False
if min_case is not None:
    repro_path = red_dir / "repro_min_crash.json"
    repro_path.write_text(json.dumps(min_case), encoding="utf-8")
    if min_case.get("kind") == "bytes":
        (red_dir / "repro_min_crash.bin").write_bytes(bytes.fromhex(min_case["data"]))
    try:
        fn(_dec(min_case))
    except ValueError:
        reproduced = False
    except Exception:
        reproduced = True

(red_dir / "fuzz_base_res.json").write_text(
    json.dumps({{
        "status": "COMPLETED",
        "attempts_executed": len(candidates),
        "reproduced": reproduced,
        "crashes": crashes[:12],
        "crash": crashes[0]["exc_msg"] if crashes else "",
        "min_len": min_len or 0,
        "min_case": min_case,
    }}),
    encoding="utf-8",
)
'''

_M4_CORPUS_CHECK_SCRIPT = '''\
import importlib, importlib.util, json, os, sys
from pathlib import Path

up = Path(os.environ["ACK_UPPERDIR"])
target_p = up / {target_filename!r}
for pdir in (str(up), str(target_p.parent)):
    if pdir not in sys.path:
        sys.path.insert(0, pdir)
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
_parts = list(Path({target_filename!r}).with_suffix("").parts)
if _parts and all(p.isidentifier() for p in _parts):
    _mod_name = ".".join(_parts)
    if len(_parts) > 1:
        importlib.invalidate_caches()
        importlib.import_module(".".join(_parts[:-1]))
    spec = importlib.util.spec_from_file_location(_mod_name, str(target_p))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_mod_name] = mod
else:
    spec = importlib.util.spec_from_file_location("_ack_target_parser", str(target_p))
    mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, {fn_name!r})

def _dec(item):
    return bytes.fromhex(item["data"]) if item.get("kind") == "bytes" else item["data"]

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

valid_cases = json.loads((blue_dir / "_ack_valid_cases.json").read_text(encoding="utf-8"))
mode = {check_mode!r}
if mode == "capture_baseline":
    out = []
    for item in valid_cases:
        res = fn(_dec(item))
        out.append({{**item, "expected_snapshot": json.dumps(_stable_snapshot(res), sort_keys=True)}})
    (blue_dir / "baseline_valid_outputs.json").write_text(json.dumps(out), encoding="utf-8")
    print("BASELINE_VALID_OK")
else:
    expected = json.loads((blue_dir / "baseline_valid_outputs.json").read_text(encoding="utf-8"))
    rejected_count = 0
    mismatch_count = 0
    error_count = 0
    for item in expected:
        try:
            res = fn(_dec(item))
            if json.dumps(_stable_snapshot(res), sort_keys=True) != item["expected_snapshot"]:
                mismatch_count += 1
        except ValueError:
            rejected_count += 1
        except Exception:
            error_count += 1
    repro_ok = True
    repro_p = blue_dir / "_ack_repro_min_crash.json"
    if repro_p.is_file():
        repro = json.loads(repro_p.read_text(encoding="utf-8"))
        try:
            fn(_dec(repro))
        except ValueError:
            pass
        except Exception:
            repro_ok = False
    summary = {{
        "total_valid": len(expected),
        "rejected_count": rejected_count,
        "mismatch_count": mismatch_count,
        "error_count": error_count,
        "repro_ok": repro_ok,
        "fpr": round(rejected_count / len(expected), 4) if expected else None,
    }}
    (blue_dir / "corpus_eval_res.json").write_text(json.dumps(summary), encoding="utf-8")
    if rejected_count == 0 and mismatch_count == 0 and error_count == 0 and repro_ok:
        print("CORPUS_AND_REGRESSION_OK")
'''

_M4_APPLY_PATCH_SCRIPT = '''\
import os
from pathlib import Path

up = Path(os.environ["ACK_UPPERDIR"])
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
out_p = up / {target_filename_repr}
out_p.parent.mkdir(parents=True, exist_ok=True)
out_p.write_text({patched_parser_repr}, encoding="utf-8")
min_case = {min_case_repr}
(blue_dir / "_ack_repro_min_crash.json").write_text(min_case, encoding="utf-8")
'''

_M4_MUT_FUZZ_SCRIPT = '''\
import importlib, importlib.util, json, os, sys
from pathlib import Path

up = Path(os.environ["ACK_UPPERDIR"])
target_p = up / {target_filename!r}
for pdir in (str(up), str(target_p.parent)):
    if pdir not in sys.path:
        sys.path.insert(0, pdir)
red_dir = Path(os.environ["ACK_ARTIFACTS_RED"])
_parts = list(Path({target_filename!r}).with_suffix("").parts)
if _parts and all(p.isidentifier() for p in _parts):
    _mod_name = ".".join(_parts)
    if len(_parts) > 1:
        importlib.invalidate_caches()
        importlib.import_module(".".join(_parts[:-1]))
    spec = importlib.util.spec_from_file_location(_mod_name, str(target_p))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_mod_name] = mod
else:
    spec = importlib.util.spec_from_file_location("_ack_target_parser", str(target_p))
    mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, {fn_name!r})
pkts = json.loads((red_dir / "mut_payloads_{aid}.json").read_text(encoding="utf-8"))
crashed = False
for p in pkts:
    raw = bytes.fromhex(p["data"]) if p.get("kind") == "bytes" else p["data"]
    try:
        fn(raw)
    except ValueError:
        pass
    except Exception:
        crashed = True
(red_dir / "fuzz_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": len(pkts), "crashed": crashed}}),
    encoding="utf-8",
)
'''
