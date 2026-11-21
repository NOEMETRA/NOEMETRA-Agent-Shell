"""ACK Mission 4: Fuzz-to-Fix Pipeline (Binary TLV Protocol Parser)."""

from __future__ import annotations

from typing import List, Optional

from hermes_cyber.ack.catalog import (
    _MissionExecutionOutcome,
    _contract,
    _verify_harness_execution,
)
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.models import (
    AckMissionDescriptor,
    AckMutationRoundResult,
    AckOracleVerdictType,
    AckStateTransition,
    AckTprFprMatrix,
    ConstrainedActionContract,
    OutOfBandOracleEvidence,
)

_M4_VULNERABLE_PARSER = '''\
import struct

class ParserCrashError(RuntimeError):
    pass

def parse_tlv_frame(data: bytes, depth: int = 0) -> list:
    if depth > 16:
        raise ParserCrashError("ASAN_STACK_OVERFLOW: unbounded TLV recursion depth")
    out = []
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ParserCrashError("ASAN_OOB_READ: truncated 5-byte TLV header")
        t = data[offset]
        count, length = struct.unpack(">HH", data[offset + 1 : offset + 5])
        offset += 5
        # Bug 1: Unbounded count*stride integer overflow check absent
        if count > 4096:
            raise ParserCrashError("UBSAN_INT_OVERFLOW: allocation count*stride overflow")
        # Bug 2: Out-of-bounds read when declared length > remaining buffer
        if offset + length > len(data):
            raise ParserCrashError("ASAN_HEAP_OOB_READ: declared length exceeds packet bounds")
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


def _run_m4_fuzz_to_fix(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
) -> _MissionExecutionOutcome:
    del target_config_content
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []

    valid_pkt_1 = b"\x01\x00\x01\x00\x04ABCD"
    valid_pkt_2 = b"\xff\x00\x01\x00\x08\x02\x00\x01\x00\x03XYZ"

    chamber.seed_lowerdir({
        "tlv_parser.py": _M4_VULNERABLE_PARSER,
        "corpus/valid/msg1.bin": valid_pkt_1,
        "corpus/valid/msg2.bin": valid_pkt_2,
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata pipeline Fuzz-to-Fix `{chamber.sandbox_id}` ({chamber.isolation_backend}) con corpus valido seed (2 frame).",
        passed=True,
    ))

    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="tlv_parser.parse_tlv_frame")
    fuzzer_code = '''\
import json, os, struct, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser

seed = b"\\x01\\x00\\x01\\x00\\x04ABCD"
candidates = [seed]
for i in range(32):
    candidates.append(struct.pack(">BHH", 1, 1, 200 + i) + b"A" * 4)
    candidates.append(struct.pack(">BHH", 2, 5000 + i, 2) + b"XY")

min_crash = None
crash_msg = ""
for cand in candidates:
    try:
        tlv_parser.parse_tlv_frame(cand)
    except tlv_parser.ParserCrashError as exc:
        if min_crash is None or len(cand) < len(min_crash):
            min_crash = cand
            crash_msg = str(exc)

repro_file = Path(os.environ["ACK_ARTIFACTS_RED"]) / "repro_min_crash.bin"
if min_crash is not None:
    repro_file.write_bytes(min_crash)
    reproduced = False
    try:
        tlv_parser.parse_tlv_frame(repro_file.read_bytes())
    except tlv_parser.ParserCrashError:
        reproduced = True
else:
    reproduced = False

(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_base_res.json").write_text(
    json.dumps({
        "status": "COMPLETED",
        "attempts_executed": len(candidates),
        "reproduced": reproduced,
        "crash": crash_msg,
        "min_len": len(min_crash or b""),
    }),
    encoding="utf-8",
)
'''
    rel_base, _ = chamber.write_red_artifact("fuzz_m4_base.py", fuzzer_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m4_fuzz",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="RUN_FUZZER",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_FUZZER_OOB_LENGTH_MINIMIZED",
    )
    contracts.append(base_contract)
    rc, _, _, fs_base = chamber.run_contract(base_contract)
    base_ok, base_attempts, base_res = _verify_harness_execution(rc, chamber.artifacts_red / "fuzz_base_res.json")
    pre_breach = bool(base_ok and base_res.get("reproduced"))
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    evidences.append(OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        crash_reproduced=pre_breach,
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    ))
    base_ev = evidences[-1]
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary=f"Fuzzer deterministico ha generato PoC minimizzato (`{base_res.get('min_len', 0)}B`, `{base_res.get('crash', 'none')}`).",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Crash riproducibile al 100% pre-patch={pre_breach} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="tlv_parser.py OOB length / overflow / unbounded recursion", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_parser = _M4_NAIVE_BLOCK_ALL_PARSER
        blue_summary = "naive_block_all: rifiuta tutti i pacchetti TLV."
    else:
        patched_parser = _M4_STRUCTURAL_FIXED_PARSER
        blue_summary = (
            "structural: safe validation `InvalidTlvFrameError` su header troncati, bounds `length <= remaining`, "
            "`count <= 256`, profondità max 8 + inserimento `repro_min_crash.bin` nel corpus di regressione."
        )

    rel_blue, _ = chamber.write_blue_artifact("apply_patch_m4.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "tlv_parser.py").write_text({patched_parser!r}, encoding="utf-8")
reg_dir = up / "corpus" / "regression"
reg_dir.mkdir(parents=True, exist_ok=True)
repro_env = os.environ.get("ACK_FUZZ_REPRO_PATH")
if repro_env and Path(repro_env).exists():
    (reg_dir / "repro_min_crash.bin").write_bytes(Path(repro_env).read_bytes())
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m4_fix",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if brc == 0 else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(state="BLUE_DEFEND", actor="BLUE", summary=f"Fix parser + regression corpus applicati ({defense_mode}).", passed=(brc == 0)))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    func_rel, _ = chamber.write_blue_artifact("oracle_corpus_m4.py", '''\
import os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
sys.path.insert(0, str(up))
import tlv_parser
for f in sorted((up / "corpus" / "valid").glob("*.bin")):
    parsed = tlv_parser.parse_tlv_frame(f.read_bytes())
    assert parsed, f"Empty parse on valid corpus {f.name}"
for rf in sorted((up / "corpus" / "regression").glob("*.bin")):
    try:
        tlv_parser.parse_tlv_frame(rf.read_bytes())
    except tlv_parser.ParserCrashError as exc:
        raise AssertionError(f"Regression crash still reproduces: {exc}")
    except ValueError:
        pass
print("CORPUS_AND_REGRESSION_OK")
''')
    func_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_m4_corpus",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="EXEC_ARTIFACT",
        artifact_path=func_rel,
        entrypoint=["python3", func_rel],
        target_invariant="INV_VALID_CORPUS_AND_REGRESSION_PASS",
    )
    contracts.append(func_contract)
    frc, fout, _, ffs = chamber.run_contract(func_contract)
    func_ok = (frc == 0 and "CORPUS_AND_REGRESSION_OK" in fout)
    func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
    evidences.append(OutOfBandOracleEvidence(
        action_id=func_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=func_ok,
        fpr_value=0.0,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=func_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Verifica valid corpus + regression crash: passed={func_ok} ({func_verdict}).",
        passed=func_ok,
    ))
    if not func_ok:
        transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: parser rotto sui pacchetti validi.", passed=False))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=0.0,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_BROKEN_PARSER",
            rationale="La patch ha rigettato anche i frame TLV validi.",
        )

    fuzz_classes = [
        ("CLASS_TRUNCATED_PAYLOAD_LENGTH_UNDERFLOW", "[struct.pack('>BHH', 3, 1, 65000) + b'Z'*3, b'\\x01\\x02\\x03']"),
        ("CLASS_COUNT_STRIDE_INTEGER_OVERFLOW", "[struct.pack('>BHH', 4, 65535, 4) + b'ABCD', struct.pack('>BHH', 4, 9999, 0)]"),
        ("CLASS_DEEP_RECURSIVE_TLV_NESTING_BOMB", "[b''.join(struct.pack('>BHH', 0xFF, 1, 5*(29-i)) for i in range(30))]"),
    ]
    rounds_to_run = max(1, min(len(fuzz_classes), mutation_rounds))
    post_crashes = 0
    exec_errors = 0
    for idx in range(rounds_to_run):
        atk_class, pkts_expr = fuzz_classes[idx]
        aid = f"act_red_m4_mut_{idx + 1:02d}"
        if inject_broken_mutation and idx == 0:
            mut_body = "raise RuntimeError('Simulated broken fuzzer mutation harness')\n"
        else:
            mut_body = f'''\
import json, os, struct, sys
from pathlib import Path
sys.path.insert(0, os.environ["ACK_UPPERDIR"])
import tlv_parser
crashed = False
pkts = {pkts_expr}
for pkt in pkts:
    try:
        tlv_parser.parse_tlv_frame(pkt)
    except tlv_parser.ParserCrashError:
        crashed = True
    except ValueError:
        pass
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "fuzz_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": len(pkts), "crashed": crashed}}),
    encoding="utf-8",
)
'''
        rel_mut, _ = chamber.write_red_artifact(f"fuzz_m4_mut_{idx + 1:02d}.py", mut_body)
        m_contract = _contract(
            chamber=chamber,
            action_id=aid,
            actor="RED",
            phase="RED_MUTATE_BYPASS",
            primitive="RUN_FUZZER",
            artifact_path=rel_mut,
            entrypoint=["python3", rel_mut],
            target_invariant=desc.target_invariant,
            attack_class=atk_class,
        )
        contracts.append(m_contract)
        mrc, _, _, mfs = chamber.run_contract(m_contract)
        exec_ok, attempts_n, mut_res = _verify_harness_execution(mrc, chamber.artifacts_red / f"fuzz_{aid}.json")
        if not exec_ok:
            exec_errors += 1
            crashed = False
            m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
        else:
            crashed = bool(mut_res.get("crashed"))
            if crashed:
                post_crashes += 1
            m_verdict = "INVARIANT_BREACHED_STEALTH" if crashed else "DEFENSE_HELD_CLEAN"

        mev = OutOfBandOracleEvidence(
            action_id=aid,
            exit_code=mrc,
            fs_diff=mfs,
            crash_reproduced=crashed,
            execution_valid=exec_ok,
            attempts_executed=attempts_n,
            isolation_backend=chamber.isolation_backend,
            oracle_verdict=m_verdict,
        )
        evidences.append(mev)
        prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and crashed))
        mut_results.append(AckMutationRoundResult(
            round_index=idx + 1,
            attack_class=atk_class,
            previous_failed_classes=prev_failed,
            contract=m_contract,
            oracle_evidence=mev,
            execution_valid=exec_ok,
            attempts_executed=attempts_n,
            bypass_succeeded=crashed,
        ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Fuzzing differenziale post-patch ({rounds_to_run} classi): crash={post_crashes}, errors={exec_errors}.",
        passed=(post_crashes == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_crashes == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di fuzzing non validi (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_ZERO_CRASH_PARSER"
        rationale = "Crash riprodotto al 100% prima del fix, eliminato dopo la patch sulla root cause."
    else:
        cert_verdict = "PARSER_STILL_CRASHING"
        rationale = f"{post_crashes} mutazioni continuano a causare crash nel parser."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            true_positive_rate=evasion_res,
            false_positive_rate=0.0,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_crashes + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )
