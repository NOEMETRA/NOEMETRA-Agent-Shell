"""ACK Mission 3: Attack-Path Audit & Live Hardening (Shadow Clone CoW)."""

from __future__ import annotations

import inspect
import json
from typing import Any, Dict, List, Literal, Optional

from hermes_cyber.ack.blue_subagents import (
    propose_m3_blue_hardened_manifest,
    record_blue_mission_traces,
)
from hermes_cyber.ack.catalog import (
    _MissionExecutionOutcome,
    _contract,
    _verify_harness_execution,
)
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.manifest_parser import _parse_target_host_config
from hermes_cyber.ack.manifest_patcher import _harden_manifest_text, _validate_hardened_manifest_syntax
from hermes_cyber.ack.mission_m3_templates import (
    _M3_DEFAULT_SYNTHETIC_MANIFEST,
    _build_m3_host_runtime_sim,
)
from hermes_cyber.ack.red_subagents import record_red_mission_traces
from hermes_cyber.ack.workspace import compute_unified_diff
from hermes_cyber.ack.yaml_compat import _yaml_safe_dump_compat, _yaml_safe_load_compat
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
from hermes_cyber.router_bridge import ModelRouter


def _run_m3_attack_path_hardening(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
    red_router: Optional[ModelRouter] = None,
    blue_router: Optional[ModelRouter] = None,
    **_: Any,
) -> _MissionExecutionOutcome:
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []
    _m3_not_executed = [
        "live_systemd_or_kubernetes_control_plane_apply",
        "statistically_significant_benign_fpr_corpus",
        "target_host_live_apply",
        "autonomous_shell_tool_agent_team",
    ]

    has_real_manifest = bool(target_config_content and target_config_content.strip())
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest"] = (
        "cloned_target_manifest" if has_real_manifest else "synthetic_fixture_simulation"
    )
    manifest_text = target_config_content or _M3_DEFAULT_SYNTHETIC_MANIFEST
    baseline_cfg = _parse_target_host_config(manifest_text)
    seed_files: Dict[str, bytes | str] = {
        "cloned_target_manifest.conf": manifest_text,
        "host_runtime_sim.py": _build_m3_host_runtime_sim(),
    }
    if has_real_manifest:
        init_summary = (
            f"Clonato manifest target reale (`{baseline_cfg['format']}`, valid={baseline_cfg['format_valid']}) "
            f"in `{chamber.sandbox_id}` (Shadow Clone CoW; lowerdir immutabile)."
        )
    else:
        init_summary = (
            f"Simulazione Shadow Clone CoW `{chamber.sandbox_id}` avviata su **fixture sintetica** (`systemd_ini`, "
            "nessun manifest host reale fornito; non rappresenta un audit dell'host locale)."
        )

    chamber.seed_lowerdir(seed_files)
    transitions.append(AckStateTransition(
        state="INIT_ARENA",
        actor="CONTROL_PLANE",
        summary=init_summary,
        passed=bool(baseline_cfg["format_valid"]),
    ))

    ver_tier = "workspace_target_verification" if has_real_manifest else "lab_fixture_verification"
    if not baseline_cfg["format_valid"]:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT", actor="ORACLE",
            summary=f"Manifest rifiutato: sintassi `{baseline_cfg['format']}` non valida o formato misto.", passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                metric_kind="config_hardening_verification", detector_metrics_applicable=False,
                true_positive_rate=None, false_positive_rate=None, exploit_mitigation_rate=0.0,
                fpr_measured=False, benign_corpus_size=0, attack_variants_tested=0,
                evasion_resistance_rate=0.0, functional_survival_rate=0.0,
                pre_patch_breach_confirmed=False, post_patch_breaches=0,
            ),
            blue_summary="Nessuna patch applicata: manifest non valido.",
            certified=False, certification_verdict="INVALID_MANIFEST_FORMAT",
            rationale="Il manifest fornito ha formato misto o sintassi non valida e non può essere certificato.",
            audit_scope=audit_scope, verification_tier=ver_tier,
            executed_checks=["manifest_syntax_validation"], not_executed_checks=_m3_not_executed,
        )

    red_ctx = fow.build_red_context(target_invariant=desc.target_invariant, attack_surface="http://127.0.0.1:PORT/cloned_target_manifest")
    rel_base, _ = chamber.write_red_artifact("privesc_m3_base.py", '''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
results = []
for vec in ("helper_hijack", "ambient_caps", "unix_socket_ctl"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/", body=json.dumps({"vector": vec}), headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = json.loads(resp.read().decode("utf-8"))
    results.append({"vector": vec, "status": resp.status, "out": body.get("output") or body.get("error", "")})
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_act_red_m3_base.json").write_text(
    json.dumps({"status": "COMPLETED", "attempts_executed": len(results), "results": results}),
    encoding="utf-8",
)
''')
    base_contract = _contract(
        chamber=chamber,
        action_id="act_red_m3_base",
        actor="RED",
        phase="RED_WEAPONIZE",
        primitive="EXEC_ARTIFACT",
        artifact_path=rel_base,
        entrypoint=["python3", rel_base],
        target_invariant=desc.target_invariant,
        attack_class="CLASS_BASELINE_CONFIG_ESCALATION_PROBE",
    )
    contracts.append(base_contract)
    with chamber.target_server("host_runtime_sim.py", "handle_request") as m3_base_port:
        rc, _, _, fs_base = chamber.run_contract(base_contract, extra_env={"ACK_TARGET_PORT": str(m3_base_port)})
    base_ok, base_attempts, _ = _verify_harness_execution(rc, chamber.artifacts_red / "loot_act_red_m3_base.json")
    pre_breach = bool(base_ok and fs_base.canary_accessed and fs_base.lowerdir_untouched)
    base_verdict: AckOracleVerdictType = (
        "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
    )
    base_ev = OutOfBandOracleEvidence(
        action_id=base_contract.action_id,
        exit_code=rc,
        fs_diff=fs_base,
        net_events=[NetEventEvidence(dst=f"127.0.0.1:{m3_base_port}", bytes_out=120, bytes_in=240)],
        execution_valid=base_ok,
        attempts_executed=base_attempts,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict=base_verdict,
    )
    evidences.append(base_ev)
    transitions.append(AckStateTransition(
        state="RED_WEAPONIZE",
        actor="RED",
        summary=f"Red esegue catena privesc pre-hardening su {audit_scope} contro `cloned_target_manifest.conf`.",
        passed=base_ok,
    ))
    transitions.append(AckStateTransition(
        state="ORACLE_BASELINE_CHECK",
        actor="ORACLE",
        summary=f"Esito pre-hardening ({audit_scope}): canary_accessed={fs_base.canary_accessed}, lowerdir_untouched={fs_base.lowerdir_untouched}.",
        passed=pre_breach,
    ))

    if not pre_breach:
        transitions.append(AckStateTransition(
            state="CERTIFY_REPORT", actor="ORACLE",
            summary="Nessuna catena privesc riprodotta pre-patch sul manifest fornito.", passed=False,
        ))
        return _MissionExecutionOutcome(
            transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=[],
            tpr_fpr_matrix=AckTprFprMatrix(
                metric_kind="config_hardening_verification", detector_metrics_applicable=False,
                true_positive_rate=None, false_positive_rate=None, exploit_mitigation_rate=0.0,
                fpr_measured=False, benign_corpus_size=0, attack_variants_tested=0,
                evasion_resistance_rate=0.0, functional_survival_rate=1.0,
                pre_patch_breach_confirmed=False, post_patch_breaches=0,
            ),
            blue_summary="Nessun diff necessario: il manifest clonato non esponeva vettori di escalation attivi pre-patch.",
            certified=False,
            certification_verdict="NO_BASELINE_PRIVESC_IN_CLONED_MANIFEST" if has_real_manifest else "NO_BASELINE_PRIVESC_FOUND",
            rationale="ORACLE_BASELINE_CHECK non ha rilevato escalation pre-patch: impossibile certificare un loop Exploit-to-Patch su superficie già chiusa o manifest non vulnerabile.",
            audit_scope=audit_scope, verification_tier=ver_tier,
            executed_checks=["manifest_syntax_validation", "python_manifest_policy_simulator_baseline_probe", "python_subproc_confinement_and_fs_snapshot_diff"],
            not_executed_checks=_m3_not_executed,
            subagent_traces=record_red_mission_traces(
                phase_base_summary=f"M3 probe privesc baseline completata (pre_breach=False, scope={audit_scope}).",
                phase_mut_summary="Mutazione non avviata: nessun vettore privesc attivo nel manifest baseline.",
                red_ctx=red_ctx, attack_classes=["helper_hijack", "ambient_caps", "unix_socket_ctl"], router=red_router,
            ),
        )

    blue_ctx = fow.build_blue_context(baseline_summary=json.dumps(baseline_cfg), oob_baseline=base_ev)
    llm_manifest_candidate: Optional[str] = None
    used_llm_manifest = False
    if defense_mode != "naive_block_all" and blue_router is not None:
        cand_m, _ = propose_m3_blue_hardened_manifest(manifest_text, str(baseline_cfg["format"]), blue_ctx, blue_router)
        if cand_m and _validate_hardened_manifest_syntax(cand_m, str(baseline_cfg["format"]), enforce_hardened=True):
            llm_manifest_candidate = cand_m
            used_llm_manifest = True

    if defense_mode == "naive_block_all":
        blue_summary = f"naive_block_all ({baseline_cfg['format']}): disattivato il servizio nel manifest clonato."
    elif used_llm_manifest:
        blue_summary = (
            f"structural (LLM hardened manifest {baseline_cfg['format']}): manifest proposto dal modello "
            "validato sintatticamente e applicato su `cloned_target_manifest.conf`."
        )
    else:
        blue_summary = (
            f"structural ({baseline_cfg['format']}): hardening format-preserving di `cloned_target_manifest.conf` "
            "con validazione sintattica post-patch."
        )

    yaml_load_src = inspect.getsource(_yaml_safe_load_compat)
    yaml_dump_src = inspect.getsource(_yaml_safe_dump_compat)
    parse_fn_src = inspect.getsource(_parse_target_host_config)
    harden_fn_src = inspect.getsource(_harden_manifest_text)
    apply_m3_body = (
        f"up = Path(os.environ['ACK_UPPERDIR'])\n(up / 'cloned_target_manifest.conf').write_text({llm_manifest_candidate!r}, encoding='utf-8')\n"
        if used_llm_manifest and llm_manifest_candidate is not None
        else (
            f"{yaml_load_src}\n\n{yaml_dump_src}\n\n{parse_fn_src}\n\n{harden_fn_src}\n\n"
            "up = Path(os.environ['ACK_UPPERDIR'])\n"
            "manifest_path = up / 'cloned_target_manifest.conf'\n"
            f"manifest_path.write_text(_harden_manifest_text(manifest_path.read_text(encoding='utf-8'), {defense_mode!r}), encoding='utf-8')\n"
        )
    )
    rel_blue, _ = chamber.write_blue_artifact(
        "apply_hardening_m3.py",
        (
            "import io, json, os, re\n"
            "from pathlib import Path\n"
            "from typing import Any, Dict, List, Optional, Tuple\n\n"
            f"{apply_m3_body}"
        ),
    )
    blue_contract = _contract(
        chamber=chamber,
        action_id="act_blue_m3_harden",
        actor="BLUE",
        phase="BLUE_DEFEND",
        primitive="APPLY_DIFF",
        artifact_path=rel_blue,
        entrypoint=["python3", rel_blue],
        target_invariant=desc.target_invariant,
    )
    contracts.append(blue_contract)
    brc, _, _, bfs = chamber.run_contract(blue_contract)
    manifest_modified = "cloned_target_manifest.conf" in bfs.modified
    post_manifest_text = (chamber.upperdir / "cloned_target_manifest.conf").read_text(encoding="utf-8")
    patch_diff = compute_unified_diff(manifest_text, post_manifest_text, "cloned_target_manifest.conf")

    def _m3_traces(phase_mut: str, verify_msg: str):
        return [
            *record_red_mission_traces(
                phase_base_summary=f"M3 probe privesc baseline (pre_breach={pre_breach}, scope={audit_scope}).",
                phase_mut_summary=phase_mut,
                red_ctx=red_ctx,
                attack_classes=["helper_hijack", "ambient_caps", "unix_socket_ctl"],
                router=red_router,
            ),
            *record_blue_mission_traces(
                triage_summary=f"Analisi configurazione `{baseline_cfg['format']}` per privilegi helper/capabilities/socket.",
                patch_summary=blue_summary,
                verify_summary=verify_msg,
                blue_ctx=blue_ctx,
                router=blue_router,
                patch_contributed=used_llm_manifest,
            ),
        ]
    post_cfg = _parse_target_host_config(post_manifest_text)
    post_syntax_ok = _validate_hardened_manifest_syntax(
        post_manifest_text,
        str(baseline_cfg["format"]),
        enforce_hardened=(defense_mode != "naive_block_all"),
    )
    post_manifest_hardened = bool(
        post_syntax_ok
        and post_cfg["all_containers_hardened"]
        and not post_cfg["helper_writable"]
        and not post_cfg["privileged_container"]
        and post_cfg["NoNewPrivileges"]
        and post_cfg["ProtectSystem"] == "strict"
        and not post_cfg["ambient_caps"]
        and post_cfg["socket_acl_restricted"]
    )
    evidences.append(OutOfBandOracleEvidence(
        action_id=blue_contract.action_id,
        exit_code=brc,
        fs_diff=bfs,
        isolation_backend=chamber.isolation_backend,
        oracle_verdict="DEFENSE_HELD_CLEAN" if (brc == 0 and manifest_modified and post_syntax_ok) else "EXECUTION_ERROR",
    ))
    transitions.append(AckStateTransition(
        state="BLUE_DEFEND",
        actor="BLUE",
        summary=(
            f"Hardening CoW applicato su `cloned_target_manifest.conf` ({defense_mode}, "
            f"format={baseline_cfg['format']}, valid={post_syntax_ok}, modified={manifest_modified})."
        ),
        passed=(brc == 0 and manifest_modified and post_syntax_ok),
    ))

    # Boot isolated TARGET server over hardened cloned_target_manifest.conf
    with chamber.target_server("host_runtime_sim.py", "handle_request") as m3_hard_port:
        func_rel, _ = chamber.write_blue_artifact("oracle_health_m3.py", '''\
import http.client, json, os
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({"vector": "healthcheck"}), headers={"Content-Type": "application/json"})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
assert resp.status == 200 and body.get("output") == "SERVICE_HEALTHY_200", f"Unexpected health: {resp.status} {body!r}"
print("SERVICE_HEALTHY_200", end="")
''')
        func_contract = _contract(
            chamber=chamber,
            action_id="act_oracle_m3_health",
            actor="BLUE",
            phase="ORACLE_FUNCTIONAL_AND_FPR_CHECK",
            primitive="EXEC_ARTIFACT",
            artifact_path=func_rel,
            entrypoint=["python3", func_rel],
            target_invariant="INV_SERVICE_HEALTH_SURVIVES",
        )
        contracts.append(func_contract)
        frc, fout, _, ffs = chamber.run_contract(func_contract, extra_env={"ACK_TARGET_PORT": str(m3_hard_port)})
        func_ok = (frc == 0 and "SERVICE_HEALTHY_200" in fout)
        func_verdict: AckOracleVerdictType = "DEFENSE_HELD_CLEAN" if func_ok else "DEFENSE_REJECTED_BROKEN_FUNC"
        evidences.append(OutOfBandOracleEvidence(
            action_id=func_contract.action_id, exit_code=frc, fs_diff=ffs,
            functional_suite_passed=func_ok, fpr_value=None,
            isolation_backend=chamber.isolation_backend, oracle_verdict=func_verdict,
        ))
        transitions.append(AckStateTransition(
            state="ORACLE_FUNCTIONAL_AND_FPR_CHECK", actor="ORACLE",
            summary=(
                f"Check operativo servizio post-hardening: passed={func_ok} ({func_verdict}); "
                f"format={baseline_cfg['format']} valid={post_syntax_ok}, modified={manifest_modified}, hardened={post_manifest_hardened}."
            ),
            passed=bool(func_ok and manifest_modified and post_manifest_hardened),
        ))
        if not func_ok:
            transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary="Respinto: hardening ha fermato il servizio.", passed=False))
            return _MissionExecutionOutcome(
                transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=[],
                tpr_fpr_matrix=AckTprFprMatrix(
                    metric_kind="config_hardening_verification", detector_metrics_applicable=False,
                    true_positive_rate=None, false_positive_rate=None, exploit_mitigation_rate=0.0,
                    fpr_measured=False, benign_corpus_size=0, attack_variants_tested=0,
                    evasion_resistance_rate=0.0, functional_survival_rate=0.0,
                    pre_patch_breach_confirmed=pre_breach, post_patch_breaches=0,
                ),
                blue_summary=blue_summary, certified=False, certification_verdict="REJECTED_SERVICE_OUTAGE",
                rationale="Hardening ha disabilitato il servizio invece di correggere i privilegi.",
                audit_scope=audit_scope, verification_tier=ver_tier,
                executed_checks=["manifest_syntax_validation", "python_manifest_policy_simulator_baseline_probe", "manifest_diff_and_healthcheck", "python_subproc_confinement_and_fs_snapshot_diff"],
                not_executed_checks=_m3_not_executed,
                subagent_traces=_m3_traces("Mutazione interrotta: outage servizio post-hardening.", "Healthcheck fallito: servizio non attivo."),
                patch_diff=patch_diff,
            )

        vectors = [
            ("CLASS_HELPER_SCRIPT_OVERWRITE_HIJACK", "helper_hijack"),
            ("CLASS_AMBIENT_CAPABILITY_INHERITANCE", "ambient_caps"),
            ("CLASS_UNIX_SOCKET_UNAUTHORIZED_CONTROL", "unix_socket_ctl"),
        ]
        rounds_to_run = max(1, min(len(vectors), mutation_rounds))
        post_breaches = 0
        exec_errors = 0
        for idx in range(rounds_to_run):
            atk_class, vec = vectors[idx]
            aid = f"act_red_m3_mut_{idx + 1:02d}"
            if inject_broken_mutation and idx == 0:
                mut_body = "raise RuntimeError('Simulated broken privesc mutation harness')\n"
            else:
                mut_body = f'''\
import http.client, json, os
from pathlib import Path
port = int(os.environ["ACK_TARGET_PORT"])
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
conn.request("POST", "/", body=json.dumps({{"vector": {vec!r}}}), headers={{"Content-Type": "application/json"}})
resp = conn.getresponse()
body = json.loads(resp.read().decode("utf-8"))
out = body.get("output") or f"BLOCKED({{resp.status}}): {{body.get('error', '')}}"
(Path(os.environ["ACK_ARTIFACTS_RED"]) / "loot_{aid}.json").write_text(
    json.dumps({{"status": "COMPLETED", "attempts_executed": 1, "out": out}}), encoding="utf-8"
)
'''
            rel_mut, _ = chamber.write_red_artifact(f"privesc_m3_mut_{idx + 1:02d}.py", mut_body)
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
            mrc, _, _, mfs = chamber.run_contract(m_contract, extra_env={"ACK_TARGET_PORT": str(m3_hard_port)})
            exec_ok, attempts_n, _ = _verify_harness_execution(mrc, chamber.artifacts_red / f"loot_{aid}.json")
            if not exec_ok:
                exec_errors += 1
                bypassed = False
                m_verdict: AckOracleVerdictType = "EXECUTION_ERROR"
            else:
                bypassed = mfs.canary_accessed or not mfs.lowerdir_untouched
                if bypassed:
                    post_breaches += 1
                m_verdict = "INVARIANT_BREACHED_STEALTH" if bypassed else "DEFENSE_HELD_CLEAN"

            mev = OutOfBandOracleEvidence(
                action_id=aid,
                exit_code=mrc,
                fs_diff=mfs,
                net_events=[NetEventEvidence(dst=f"127.0.0.1:{m3_hard_port}", bytes_out=96, bytes_in=96)],
                telemetry_alerts=[TelemetryAlertEvidence(rule_id="manifest_hardening_policy", engine="python_manifest_policy_simulator", triggered=bool(exec_ok and not bypassed))],
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
        summary=f"{rounds_to_run} vettori privesc su {audit_scope}: bypass={post_breaches}, errors={exec_errors}.",
        passed=(post_breaches == 0 and exec_errors == 0),
    ))
    valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
    evasion_res = round(valid_defended / rounds_to_run, 3)
    certified = bool(
        pre_breach
        and manifest_modified
        and post_manifest_hardened
        and func_ok
        and post_breaches == 0
        and exec_errors == 0
    )
    if exec_errors > 0:
        cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
        rationale = f"Certificazione negata (fail-closed): {exec_errors} mutazioni non eseguite (`EXECUTION_ERROR`)."
    elif certified and has_real_manifest:
        cert_verdict = "CERTIFIED_HARDENED_CLONED_MANIFEST"
        rationale = f"Hardening verificato in clone CoW su `cloned_target_manifest.conf` ({baseline_cfg['format']}) con sintassi valida e lowerdir immutabile."
    elif certified:
        cert_verdict = "CERTIFIED_SYNTHETIC_SHADOW_CLONE_SIMULATION"
        rationale = "Hardening certificato sulla fixture sintetica `cloned_target_manifest.conf` (systemd_ini valido; non audit host corrente)."
    elif not (manifest_modified and post_manifest_hardened):
        cert_verdict = "HARDENING_BYPASSED"
        rationale = "Hardening respinto out-of-band: `cloned_target_manifest.conf` non modificato, sintassi invalidata o vettori ancora attivi."
    else:
        cert_verdict = "HARDENING_BYPASSED"
        rationale = "Hardening aggirato dopo la patch."

    transitions.append(AckStateTransition(
        state="CERTIFY_REPORT",
        actor="ORACLE",
        summary=rationale,
        passed=certified,
    ))
    return _MissionExecutionOutcome(
        transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            metric_kind="config_hardening_verification", detector_metrics_applicable=False,
            true_positive_rate=None, false_positive_rate=None, exploit_mitigation_rate=evasion_res,
            fpr_measured=False, benign_corpus_size=0, attack_variants_tested=rounds_to_run,
            evasion_resistance_rate=evasion_res, functional_survival_rate=1.0,
            pre_patch_breach_confirmed=pre_breach, post_patch_breaches=post_breaches + exec_errors,
        ),
        blue_summary=blue_summary, certified=certified, certification_verdict=cert_verdict,
        rationale=rationale, audit_scope=audit_scope, verification_tier=ver_tier,
        executed_checks=["manifest_syntax_validation", "python_manifest_policy_simulator_baseline_probe", "manifest_diff_and_healthcheck", "privesc_vector_simulation_rounds", "python_subproc_confinement_and_fs_snapshot_diff"],
        not_executed_checks=_m3_not_executed,
        subagent_traces=_m3_traces(
            f"Testati {rounds_to_run} vettori privesc simulati (bypass={post_breaches}, errors={exec_errors}).",
            f"Hardening verificato sul simulatore: verdetto={cert_verdict}, exploit_mitigation={evasion_res:.2f}.",
        ),
        patch_diff=patch_diff,
        patch_classification="semantically_verified_patch" if certified else "none",
        patch_applicable=False,
    )
