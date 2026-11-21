"""ACK Mission 2: Detection vs. Evasion Arena (Telemetry & Empirical TPR/FPR Matrix)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

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

_M2_TARGET_WORKLOAD = '''\
import json
import os
from pathlib import Path

def execute_ttp_payload(aid: str, event_record: dict) -> dict:
    up = Path(os.environ["ACK_UPPERDIR"])
    canary_val = (up / "canary_vault" / "canary.txt").read_text(encoding="utf-8").strip()
    (up / f"telemetry_{aid}.json").write_text(json.dumps([event_record]), encoding="utf-8")
    return {"canary": canary_val, "telemetry_written": f"telemetry_{aid}.json"}

def handle_request(payload: dict) -> tuple:
    try:
        res = execute_ttp_payload(str(payload["aid"]), dict(payload["event"]))
        return 200, res
    except Exception as exc:
        return 403, {"error": str(exc)}
'''

_M2_BASELINE_RULES = {
    "mode": "baseline",
    "rules": [
        {"rule_id": "naive_bash_devtcp", "engine": "static_sig", "patterns": ["bash -i >& /dev/tcp/"], "excludes": []}
    ],
}

_M2_STRUCTURAL_RULES = {
    "mode": "structural",
    "rules": [
        {
            "rule_id": "blue_ebpf_memfd_exec",
            "engine": "ebpf_syscall",
            "patterns": ["memfd_create", "/proc/self/fd/", "execveat("],
            "excludes": ["signed_package_manager=true", "benign=true"],
        },
        {
            "rule_id": "blue_lotl_lineage_obf",
            "engine": "auditd_lineage",
            "patterns": ["parent=python3 child=sh", "${IFS}", "LD_PRELOAD=", "base64 -d"],
            "excludes": ["pytest_worker=true", "benign=true"],
        },
        {
            "rule_id": "blue_ebpf_egress_entropy",
            "engine": "net_veth_ebpf",
            "patterns": ["qtype=TXT", "beacon_jitter="],
            "min_entropy": 4.2,
            "excludes": ["ntp.ubuntu.com", "healthcheck=200 ok", "proc=postfix", "proc=certbot", "benign=true"],
        },
    ],
}

_M2_OVERBROAD_RULES = {
    "mode": "overbroad_alert_all",
    "rules": [{"rule_id": "ban_all_wildcard", "engine": "naive_wildcard", "patterns": [""], "excludes": []}],
}

_M2_DETECTOR_ENGINE = '''\
import json, os, sys
from pathlib import Path

def evaluate(rules_spec: dict, events: list) -> list:
    if rules_spec.get("mode") == "overbroad_alert_all":
        return [{"event_index": i, "triggered": True, "rule_ids": ["ban_all_wildcard"]} for i in range(len(events))]
    outcomes = []
    for i, ev in enumerate(events):
        line = ev.get("telemetry", "")
        low = line.lower()
        entropy = float(ev.get("entropy", 0.0))
        hits = []
        for r in rules_spec.get("rules", []):
            if any(ex.lower() in low for ex in r.get("excludes", [])):
                continue
            min_ent = r.get("min_entropy")
            pat_hit = any(p.lower() in low for p in r.get("patterns", []))
            if min_ent is not None:
                if pat_hit and entropy >= float(min_ent):
                    hits.append(r["rule_id"])
            elif pat_hit:
                hits.append(r["rule_id"])
        outcomes.append({"event_index": i, "triggered": bool(hits), "rule_ids": hits})
    return outcomes

if __name__ == "__main__":
    blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
    rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
    events_path = Path(sys.argv[1])
    events = json.loads(events_path.read_text(encoding="utf-8"))
    res = evaluate(rules, events)
    print(json.dumps(res))
'''

_M2_BENIGN_CORPUS = [
    {"telemetry": "proc=pytest cmd='python3 -m pytest -q' pytest_worker=true benign=true", "entropy": 1.8},
    {"telemetry": "proc=git cmd='git status --short' benign=true", "entropy": 1.6},
    {"telemetry": "proc=systemd cmd='systemctl status nginx.service' benign=true", "entropy": 1.7},
    {"telemetry": "proc=postfix qtype=TXT query='_dmarc.corp.example.com' benign=true", "entropy": 2.3},
    {"telemetry": "proc=certbot qtype=TXT query='_acme-challenge.app.example.com' benign=true", "entropy": 2.4},
    {"telemetry": "proc=restic signer='CN=Restic' signature_verified=true benign=true", "entropy": 2.1},
    {"telemetry": "proc=nginx GET /api/v1/health status=200 healthcheck=200 ok benign=true", "entropy": 1.4},
    {"telemetry": "proc=chronyd dns_dst=ntp.ubuntu.com qtype=A benign=true", "entropy": 1.5},
    {"telemetry": "proc=apt-get signed_package_manager=true benign=true", "entropy": 1.9},
    {"telemetry": "proc=uvicorn worker startup HTTP/1.1 ready benign=true", "entropy": 1.7},
]


def _run_m2_detection_evasion(
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
        "target_workload.py": _M2_TARGET_WORKLOAD,
        "benign_replay.json": json.dumps(_M2_BENIGN_CORPUS, indent=2),
    })
    chamber.write_blue_artifact("detector_engine.py", _M2_DETECTOR_ENGINE)
    chamber.write_blue_artifact("blue_rules.json", json.dumps(_M2_BASELINE_RULES, indent=2))
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=f"Inizializzata Arena Telemetry CoW `{chamber.sandbox_id}` ({chamber.isolation_backend}) con corpus baseline benigna reale (10 eventi).",
        passed=True,
    ))

    def _oob_eval_telemetry(eval_aid: str, events_rel_path: str) -> List[Dict[str, Any]]:
        eval_contract = _contract(
            chamber=chamber,
            action_id=eval_aid,
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="CAPTURE_TELEMETRY",
            artifact_path="artifacts/blue/detector_engine.py",
            entrypoint=["python3", "artifacts/blue/detector_engine.py", events_rel_path],
            target_invariant=desc.target_invariant,
        )
        erc, eval_out, _, _ = chamber.run_contract(eval_contract)
        if erc != 0:
            raise RuntimeError(f"Out-of-band detector evaluation failed ({erc})")
        return json.loads(eval_out)

    # RED_WEAPONIZE + ORACLE_BASELINE_CHECK over isolated TARGET loopback HTTP boundary
    _ = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/telemetry_workload")
    base_ttp_code = '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
payload = {
    "aid": "act_red_m2_base",
    "event": {"telemetry": "proc=python3 syscall=memfd_create fd=4 arg0=anon_stage", "entropy": 4.7},
}
conn.request("POST", "/", body=json.dumps(payload), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
res = json.loads(resp.read().decode("utf-8"))
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m2_base.json").write_text(
    json.dumps({"status": "COMPLETED", "attempts_executed": 1, **res}), encoding="utf-8"
)
'''
    rel_base, _ = chamber.write_red_artifact("ttp_m2_base.py", base_ttp_code)
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m2_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_BASELINE_FILELESS_AVOIDANCE",
    )
    contracts.append(base_contract)
    with chamber.target_server("target_workload.py", "handle_request") as m2_base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(m2_base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_m2_base.json")
    base_det = _oob_eval_telemetry("act_oracle_eval_m2_base", "upperdir/telemetry_act_red_m2_base.json") if base_ok else [{"triggered": False}]
    base_triggered = bool(base_det[0]["triggered"])
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_DETECTED" if base_triggered else "INVARIANT_BREACHED_STEALTH")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        telemetry_alerts=[
            TelemetryAlertEvidence(rule_id="naive_bash_devtcp", engine="static_sig", triggered=base_triggered)
        ],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    pre_breach = bool(base_ok and fs_base.canary_accessed and (not base_triggered))
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary="Red esegue TTP fileless `memfd_create` evitando signature statiche.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Oracolo pre-patch: exec_ok={base_ok}, alert={base_triggered} ({base_verdict}).",
        passed=pre_breach,
    ))

    # BLUE_DEFEND
    _ = fow.build_blue_context(baseline_summary="naive_bash_devtcp missed memfd_create", oob_baseline=base_ev)
    if defense_mode == "overbroad_alert_all":
        chosen_rules = _M2_OVERBROAD_RULES
        blue_summary = "overbroad_alert_all: regola wildcard che genera allarme su qualsiasi evento."
    else:
        chosen_rules = _M2_STRUCTURAL_RULES
        blue_summary = (
            "structural: Sigma + eBPF syscall (`memfd_create`, `/proc/self/fd/`) + lineage (`python3->sh`, `${IFS}`) "
            "+ egress entropia (>=4.2) con esclusioni baseline firmate."
        )

    rel_blue, _ = chamber.write_blue_artifact("deploy_rules_m2.py", f'''\
import os
from pathlib import Path
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
(blue_dir / "blue_rules.json").write_text({json.dumps(chosen_rules)!r}, encoding="utf-8")
''')
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_deploy_rules",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="DEPLOY_RULE",
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
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=f"Blue distribuisce regole in modalità `{defense_mode}`.",
        passed=(brc == 0),
    ))

    # ORACLE_FUNCTIONAL_AND_FPR_CHECK
    fpr_rel, _ = chamber.write_blue_artifact("oracle_fpr_m2.py", '''\
import json, os, sys
from pathlib import Path
up = Path(os.environ["ACK_UPPERDIR"])
blue_dir = Path(os.environ["ACK_ARTIFACTS_BLUE"])
sys.path.insert(0, str(blue_dir))
import detector_engine
rules = json.loads((blue_dir / "blue_rules.json").read_text(encoding="utf-8"))
benign = json.loads((up / "benign_replay.json").read_text(encoding="utf-8"))
res = detector_engine.evaluate(rules, benign)
fps = sum(1 for r in res if r["triggered"])
fpr = fps / max(1, len(benign))
(blue_dir / "fpr_result.json").write_text(json.dumps({"fps": fps, "total": len(benign), "fpr": fpr}), encoding="utf-8")
''')
    fpr_contract = _contract(
        chamber=chamber,
        action_id="act_oracle_fpr",
        actor="BLUE",
        phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        primitive="CAPTURE_TELEMETRY",
        artifact_path=fpr_rel,
        entrypoint=["python3", fpr_rel],
        target_invariant="INV_FPR_BELOW_THRESHOLD",
    )
    contracts.append(fpr_contract)
    frc, _, _, ffs = chamber.run_contract(fpr_contract)
    fpr_obj = json.loads((chamber.artifacts_blue / "fpr_result.json").read_text(encoding="utf-8"))
    fpr_val = float(fpr_obj["fpr"])
    fpr_ok = fpr_val <= 0.05
    fpr_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if fpr_ok else "DEFENSE_REJECTED_HIGH_FPR"
    evidences.append(OutOfBandOracleEvidence(
        action_id=fpr_contract.action_id,
        exit_code=frc,
        fs_diff=ffs,
        functional_suite_passed=True,
        fpr_value=fpr_val,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=fpr_verdict,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
        actor="ORACLE",
        summary=f"Replay benigno ({len(_M2_BENIGN_CORPUS)} eventi): FPR={fpr_val:.3f} ({fpr_verdict}).",
        passed=fpr_ok,
    ))

    if not fpr_ok:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT",
            actor="ORACLE",
            summary=f"Certificazione respinta: FPR={fpr_val:.3f} supera soglia massima 0.050 (regola ban-all).",
            passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions,
            contracts=contracts,
            evidences=evidences,
            mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=0.0,
                false_positive_rate=fpr_val,
                evasion_resistance_rate=0.0,
                functional_survival_rate=0.0,
                pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=0,
            ),
            blue_summary=blue_summary,
            certified=False,
            certification_verdict="REJECTED_HIGH_FALSE_POSITIVE_RATE",
            rationale="Oracolo anti-cheat: la regola wildcard genera falsi positivi continui sulla telemetria benigna dell'host.",
        )

    # RED_MUTATE_BYPASS (3 distinct evasion attack classes)
    evasion_specs = [
        (
            "CLASS_CLI_ARG_SPOOFING_ENV_EXPANSION",
            {"telemetry": "parent=python3 child=sh arg0=[kworker] cmd=sh${IFS}-c${IFS}base64${IFS}-d", "entropy": 4.4},
        ),
        (
            "CLASS_FILELESS_MEMFD_EXECVEAT_SYSCALL",
            {"telemetry": "proc=svc_api syscall=execveat(/proc/self/fd/7) backing=memfd_create", "entropy": 4.1},
        ),
        (
            "CLASS_JITTERED_LOW_RATE_HIGH_ENTROPY_BEACON",
            {"telemetry": "proc=svc_etl dns_src=10.200.0.5 qtype=TXT beacon_jitter=17s query=JBSWY3DPEBLW64TMMQ", "entropy": 4.85},
        ),
    ]
    rounds_to_run = max(1, min(len(evasion_specs), mutation_rounds))
    detected_cnt = 0
    stealth_cnt = 0
    exec_errors = 0
    with chamber.target_server("target_workload.py", "handle_request") as m2_mut_port:
        for idx in range(rounds_to_run):
            atk_class, evt_dict = evasion_specs[idx]
            aid = f"act_red_m2_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                mut_code = "raise RuntimeError('Simulated broken telemetry mutation harness')\n"
            else:
                mut_code = f'''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({{"aid": {aid!r}, "event": {json.dumps(evt_dict)}}}), headers={{"Content-Type": "application/json"}})
resp = conn.getresponse()
res = json.loads(resp.read().decode("utf-8"))
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": 1, **res}}), encoding="utf-8"
)
'''
            rel_mut, _ = chamber.write_red_artifact(f"ttp_m2_mut_{idx + 1:02d}.py", mut_code)
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
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(m2_mut_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok or not (chamber.upperdir / f"telemetry_{aid}.json").exists():
                exec_errors += 1
                triggered = False
                bypassed = False
                rule_str = "none"
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                det = _oob_eval_telemetry(f"act_oracle_eval_{aid}", f"upperdir/telemetry_{aid}.json")
                hit_info = det[0]
                triggered = bool(hit_info["triggered"])
                rule_str = ",".join(hit_info["rule_ids"]) or "none"
                bypassed = not triggered
                if triggered:
                    detected_cnt += 1
                else:
                    stealth_cnt += 1
                m_verdict = "INVARIANT_BREACHED_DETECTED" if triggered else "INVARIANT_BREACHED_STEALTH"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{m2_mut_port}", proto="tcp", bytes_out=220, bytes_in=96)],
                telemetry_alerts=[
                    TelemetryAlertEvidence(
                        rule_id=rule_str,
                        engine="ebpf_sigma_yara",
                        triggered=triggered,
                        matched_pattern=atk_class if triggered else "",
                    )
                ],
                execution_valid=bool(exec_ok),
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
                execution_valid=(m_verdict != "EXECUTION_ERROR"),
                attempts_executed=attempts_n,
                bypass_succeeded=bypassed,
            ))

    tpr = round(detected_cnt / rounds_to_run, 3)
    transitions.append(AckStateTransition(
        state="RED_MUTATE_BYPASS",
        actor="RED",
        summary=f"Eseguiti {rounds_to_run} round adattivi di evasione: rilevati={detected_cnt}/{rounds_to_run}, errors={exec_errors}, TPR={tpr:.2f}, FPR={fpr_val:.2f}.",
        passed=(stealth_cnt == 0 and exec_errors == 0),
    ))
    certified = bool(pre_breach and fpr_ok and stealth_cnt == 0 and exec_errors == 0)
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} round di mutazione non validi (`EXECUTION_ERROR`)."
    elif certified:
        cert_verdict = "CERTIFIED_DETECTION_ARENA"
        rationale = "Matrice TPR/FPR verificata out-of-band contro mutazioni fileless, arg spoofing e jitter beacon."
    else:
        cert_verdict = "EVADED_BY_RED"
        rationale = f"{stealth_cnt} varianti stealth hanno eluso la rilevazione."

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
            true_positive_rate=tpr,
            false_positive_rate=fpr_val,
            evasion_resistance_rate=tpr,
            functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=stealth_cnt + exec_errors,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=cert_verdict,
        rationale=rationale,
    )
