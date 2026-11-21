"""ACK Mission 4: Fuzz-to-Fix Pipeline supporting Built-in Lab TLV Fixture and Real PC Workspace Mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from hermes_cyber.ack.blue_subagents import (
    BluePatchArchitectSubAgent,
    BlueRegressionSubAgent,
    BlueTriageSubAgent,
)
from hermes_cyber.ack.catalog import (
    _MissionExecutionOutcome,
    _contract,
    _sha256_bytes,
    _verify_harness_execution,
)
from hermes_cyber.ack.chamber import DetonationChamber
from hermes_cyber.ack.fog_of_war import FogOfWarController
from hermes_cyber.ack.mission_m4_templates import (
    _M4_APPLY_PATCH_SCRIPT,
    _M4_BASE_FUZZ_SCRIPT,
    _M4_CORPUS_CHECK_SCRIPT,
    _M4_DEFAULT_VALID_CORPUS,
    _M4_MUT_FUZZ_SCRIPT,
    _M4_NAIVE_BLOCK_ALL_PARSER,
    _M4_STRUCTURAL_FIXED_PARSER,
    _M4_VULNERABLE_PARSER,
)
from hermes_cyber.ack.red_subagents import (
    RedBypassMutatorSubAgent,
    RedReconSubAgent,
    RedWeaponizerSubAgent,
)
from hermes_cyber.ack.workspace import (
    WorkspaceStagedTarget,
    compute_unified_diff,
    stage_python_parser_workspace,
)
from hermes_cyber.models import (
    AckMissionDescriptor,
    AckMutationRoundResult,
    AckOracleVerdictType,
    AckStateTransition,
    AckSubAgentTrace,
    AckTprFprMatrix,
    AckVerificationTierType,
    AckWorkspaceModeType,
    AckWorkspaceTargetInfo,
    ConstrainedActionContract,
    OutOfBandOracleEvidence,
)
from hermes_cyber.router_bridge import ModelRouter


def _run_m4_fuzz_to_fix(
    chamber: DetonationChamber,
    desc: AckMissionDescriptor,
    fow: FogOfWarController,
    *,
    mutation_rounds: int,
    defense_mode: str,
    target_config_content: Optional[str] = None,
    inject_broken_mutation: bool = False,
    target_file_path: Optional[str] = None,
    target_function: Optional[str] = None,
    valid_corpus_dir: Optional[str] = None,
    valid_inputs: Optional[List[Any]] = None,
    workspace_mode: AckWorkspaceModeType = "isolated_copy",
    red_router: Optional[ModelRouter] = None,
    blue_router: Optional[ModelRouter] = None,
) -> _MissionExecutionOutcome:
    del target_config_content
    transitions: List[AckStateTransition] = []
    contracts: List[ConstrainedActionContract] = []
    evidences: List[OutOfBandOracleEvidence] = []
    mut_results: List[AckMutationRoundResult] = []
    traces: List[AckSubAgentTrace] = []
    exec_logs: List[Dict[str, Any]] = []
    repro_artifacts: Dict[str, bytes] = {}

    staged: Optional[WorkspaceStagedTarget] = None
    try:
        is_builtin_tlv = not bool(target_file_path and str(target_file_path).strip())
        if not is_builtin_tlv:
            staged = stage_python_parser_workspace(
                str(target_file_path),
                str(target_function or "parse"),
                valid_corpus_dir=valid_corpus_dir,
                valid_inputs=valid_inputs,
                workspace_mode=workspace_mode,
            )
            module_name = staged.module_name
            target_filename = staged.target_rel_path or staged.target_filename
            fn_name = staged.target_function
            target_source = staged.original_source
            expected_kind = staged.param_type_hint
            valid_corpus = staged.valid_corpus
            audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest", "workspace_target_file"] = "workspace_target_file"
            verification_tier: AckVerificationTierType = "workspace_target_verification"
            seed_files: Dict[str, bytes | str] = {
                target_filename: target_source,
                **staged.extra_files,
            }
            ws_info = AckWorkspaceTargetInfo(
                target_file_path=staged.target_file_path,
                target_function=fn_name,
                target_rel_path=staged.target_rel_path,
                workspace_mode=staged.workspace_mode,
                original_sha256=staged.original_sha256,
                original_untouched=True,
                valid_corpus_count=len(valid_corpus),
            )
        else:
            module_name = "tlv_parser"
            target_filename = "tlv_parser.py"
            fn_name = "parse_tlv_frame"
            target_source = _M4_VULNERABLE_PARSER
            expected_kind = "bytes"
            valid_corpus = list(_M4_DEFAULT_VALID_CORPUS)
            audit_scope = "synthetic_fixture_simulation"
            verification_tier = "lab_fixture_verification"
            seed_files = {
                target_filename: target_source,
            }
            ws_info = None

        chamber.seed_lowerdir(seed_files)
        chamber.write_blue_artifact("_ack_valid_cases.json", json.dumps(valid_corpus))

        # Capture pre-patch baseline valid outputs cleanly before attacking
        rel_cap, _ = chamber.write_blue_artifact(
            "capture_valid_m4.py",
            _M4_CORPUS_CHECK_SCRIPT.format(target_filename=target_filename, fn_name=fn_name, check_mode="capture_baseline"),
        )
        cap_c = _contract(
            chamber=chamber,
            action_id="act_oracle_m4_baseline_valid",
            actor="BLUE",
            phase="INIT_ARENA",
            primitive="EXEC_ARTIFACT",
            artifact_path=rel_cap,
            entrypoint=["python3", rel_cap],
            target_invariant=desc.target_invariant,
        )
        crc, cout, cerr, _ = chamber.run_contract(cap_c)
        exec_logs.append({"action_id": cap_c.action_id, "exit_code": crc, "stdout": cout, "stderr": cerr})
        if crc != 0:
            raise RuntimeError(f"Il corpus valido fornito fallisce già sul file pre-patch: {cerr}")

        valid_with_expected = json.loads((chamber.artifacts_blue / "baseline_valid_outputs.json").read_text(encoding="utf-8"))
        transitions.append(AckStateTransition(
            state="INIT_ARENA",
            actor="CONTROL_PLANE",
            summary=(
                f"Workspace Mode `{target_filename}.{fn_name}` ({audit_scope}, {len(valid_corpus)} casi validi) in `{chamber.sandbox_id}`."
                if not is_builtin_tlv
                else f"Lab Fixture TLV `{chamber.sandbox_id}` con {len(valid_corpus)} frame validi."
            ),
            passed=True,
        ))

        # 1. Red Sub-Agents: Recon & Weaponizer (Fog of War enforced)
        red_ctx = fow.build_red_context(
            target_invariant=desc.target_invariant,
            attack_surface=f"{module_name}.{fn_name}",
            target_signature=f"{target_filename}::{fn_name}",
            surface_hints=[audit_scope],
        )
        recon, recon_trace = RedReconSubAgent().analyze_python_parser(
            target_source, fn_name, red_ctx, expected_kind=expected_kind, router=red_router
        )
        candidates, weap_trace = RedWeaponizerSubAgent().build_fuzz_candidates(recon, red_ctx)
        traces.extend([recon_trace, weap_trace])
        chamber.write_red_artifact("candidates_base.json", json.dumps(candidates))

        rel_base, _ = chamber.write_red_artifact(
            "fuzz_m4_base.py",
            _M4_BASE_FUZZ_SCRIPT.format(target_filename=target_filename, fn_name=fn_name),
        )
        base_contract = _contract(
            chamber=chamber,
            action_id="act_red_m4_fuzz",
            actor="RED",
            phase="RED_WEAPONIZE",
            primitive="RUN_FUZZER",
            artifact_path=rel_base,
            entrypoint=["python3", rel_base],
            target_invariant=desc.target_invariant,
            attack_class="CLASS_INITIAL_CRASH_MINIMIZATION",
        )
        contracts.append(base_contract)
        rc, bout, berr, fs_base = chamber.run_contract(base_contract)
        exec_logs.append({"action_id": base_contract.action_id, "exit_code": rc, "stdout": bout, "stderr": berr})
        base_ok, base_attempts, base_res = _verify_harness_execution(rc, chamber.artifacts_red / "fuzz_base_res.json")
        pre_breach = bool(base_ok and base_res.get("reproduced"))
        base_verdict: AckOracleVerdictType = (
            "EXECUTION_ERROR" if not base_ok else ("INVARIANT_BREACHED_STEALTH" if pre_breach else "DEFENSE_HELD_CLEAN")
        )
        base_ev = OutOfBandOracleEvidence(
            action_id=base_contract.action_id,
            exit_code=rc,
            fs_diff=fs_base,
            crash_reproduced=pre_breach,
            execution_valid=base_ok,
            attempts_executed=base_attempts,
            isolation_backend=chamber.isolation_backend,
            oracle_verdict=base_verdict,
        )
        evidences.append(base_ev)
        if (chamber.artifacts_red / "repro_min_crash.json").is_file():
            repro_artifacts["repro_min_crash.json"] = (chamber.artifacts_red / "repro_min_crash.json").read_bytes()
        if (chamber.artifacts_red / "repro_min_crash.bin").is_file():
            repro_artifacts["repro_min_crash.bin"] = (chamber.artifacts_red / "repro_min_crash.bin").read_bytes()

        transitions.append(AckStateTransition(
            state="RED_WEAPONIZE",
            actor="RED",
            summary=f"RedWeaponizerSubAgent ha generato PoC minimizzato (`{base_res.get('min_len', 0)}B`, `{base_res.get('crash', 'none')}`).",
            passed=base_ok,
        ))
        transitions.append(AckStateTransition(
            state="ORACLE_BASELINE_CHECK",
            actor="ORACLE",
            summary=f"Crash riproducibile al 100% pre-patch={pre_breach} ({base_verdict}).",
            passed=pre_breach,
        ))

        crashes = list(base_res.get("crashes") or [])
        crash_cases = [base_res["min_case"]] if base_res.get("min_case") else []

        # If target parser had zero pre-patch crashes, refuse certification honestly instead of pretending to fix
        if not pre_breach:
            transitions.append(AckStateTransition(
                state="CERTIFY_REPORT",
                actor="ORACLE",
                summary="Nessun crash non gestito riprodotto pre-patch sul parser target.",
                passed=False,
            ))
            if ws_info is not None and staged is not None:
                ws_info.original_untouched = _sha256_bytes(Path(staged.target_file_path).read_bytes()) == staged.original_sha256
            return _MissionExecutionOutcome(
                transitions=transitions,
                contracts=contracts,
                evidences=evidences,
                mutation_rounds=[],
                tpr_fpr_matrix=AckTprFprMatrix(
                    true_positive_rate=0.0,
                    false_positive_rate=0.0,
                    evasion_resistance_rate=0.0,
                    functional_survival_rate=1.0,
                    pre_patch_breach_confirmed=False,
                    post_patch_breaches=0,
                    fpr_measured=bool(valid_corpus),
                    benign_corpus_size=len(valid_corpus),
                    attack_variants_tested=0,
                ),
                blue_summary="Nessuna patch applicata: i test avversari non hanno causato crash sul target.",
                certified=False,
                certification_verdict="NO_BASELINE_CRASH_REPRODUCED",
                rationale="ORACLE_BASELINE_CHECK non ha riprodotto eccezioni non gestite pre-patch sul target.",
                audit_scope=audit_scope,
                verification_tier=verification_tier,
                executed_checks=["valid_baseline_capture", "red_subagent_fuzzing", "oob_oracle_baseline_check"],
                not_executed_checks=["patch_synthesis", "red_bypass_mutation", "real_asan_ubsan_native_sanitizers"],
                subagent_traces=traces,
                execution_logs=exec_logs,
                repro_artifacts=repro_artifacts,
                workspace_target=ws_info,
            )

        # 2. Blue Sub-Agents: Triage -> Patch Architect -> Apply Diff (`BLUE_DEFEND`)
        blue_ctx = fow.build_blue_context(
            baseline_summary=f"{target_filename}::{fn_name} ({expected_kind})",
            oob_baseline=base_ev,
            repro_summary=str(base_res.get("crash") or ""),
            valid_corpus_summary=f"{len(valid_corpus)} valid baseline samples",
            traceback_excerpt=json.dumps(crashes[:3]),
        )
        triage, triage_trace = BlueTriageSubAgent().diagnose_crash(blue_ctx, crashes, fn_name)
        patched_parser, blue_summary, arch_trace = BluePatchArchitectSubAgent().synthesize_parser_patch(
            target_source,
            fn_name,
            triage,
            blue_ctx,
            defense_mode=defense_mode,
            is_builtin_tlv=is_builtin_tlv,
            expected_kind=expected_kind,
            builtin_fixed_src=_M4_STRUCTURAL_FIXED_PARSER,
            builtin_naive_block_src=_M4_NAIVE_BLOCK_ALL_PARSER,
            router=blue_router,
        )
        traces.extend([triage_trace, arch_trace])
        patch_diff = compute_unified_diff(target_source, patched_parser, target_filename)

        rel_blue, _ = chamber.write_blue_artifact(
            "apply_patch_m4.py",
            _M4_APPLY_PATCH_SCRIPT.format(
                target_filename_repr=repr(target_filename),
                patched_parser_repr=repr(patched_parser),
                min_case_repr=repr(json.dumps(base_res.get("min_case"))),
            ),
        )
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
        brc, bout2, berr2, bfs = chamber.run_contract(blue_contract)
        exec_logs.append({"action_id": blue_contract.action_id, "exit_code": brc, "stdout": bout2, "stderr": berr2})
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
            summary=f"BluePatchArchitectSubAgent ha applicato patch su copia `{target_filename}` ({defense_mode}).",
            passed=(brc == 0),
        ))

        # 3. Blue Regression Sub-Agent + `ORACLE_FUNCTIONAL_AND_FPR_CHECK`
        regression_code, reg_trace = BlueRegressionSubAgent().build_regression_pytest(
            target_module_name=module_name,
            target_function=fn_name,
            valid_cases=valid_with_expected,
            crash_cases=crash_cases,
            blue_ctx=blue_ctx,
            target_rel_path=target_filename,
        )
        traces.append(reg_trace)

        func_rel, _ = chamber.write_blue_artifact(
            "oracle_corpus_m4.py",
            _M4_CORPUS_CHECK_SCRIPT.format(target_filename=target_filename, fn_name=fn_name, check_mode="verify_patched"),
        )
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
        frc, fout, ferr, ffs = chamber.run_contract(func_contract)
        exec_logs.append({"action_id": func_contract.action_id, "exit_code": frc, "stdout": fout, "stderr": ferr})
        has_valid_evidence = bool(is_builtin_tlv or len(valid_corpus) > 0)
        eval_path = chamber.artifacts_blue / "corpus_eval_res.json"
        eval_obj: Dict[str, Any] = {}
        if eval_path.is_file():
            try:
                eval_obj = json.loads(eval_path.read_text(encoding="utf-8"))
            except Exception:
                eval_obj = {}
        total_eval = int(eval_obj.get("total_valid") or 0)
        fpr_measured = bool(valid_corpus and total_eval > 0 and eval_obj.get("fpr") is not None)
        fpr_val = float(eval_obj["fpr"]) if fpr_measured else 0.0
        rejected_n = int(eval_obj.get("rejected_count") or 0)
        mismatch_n = int(eval_obj.get("mismatch_count") or 0)
        error_n = int(eval_obj.get("error_count") or 0)
        surv_n = max(0, total_eval - rejected_n - mismatch_n - error_n) if total_eval > 0 else 0
        func_survival = round(surv_n / total_eval, 4) if total_eval > 0 else 0.0
        func_ok = bool(
            frc == 0
            and "CORPUS_AND_REGRESSION_OK" in fout
            and has_valid_evidence
            and defense_mode != "naive_block_all"
            and rejected_n == 0
            and mismatch_n == 0
            and error_n == 0
        )
        func_verdict: AckOracleVerdictType = (
            "DEFENSE_HELD_CLEAN" if func_ok else ("DEFENSE_REJECTED_HIGH_FPR" if rejected_n > 0 else "DEFENSE_REJECTED_BROKEN_FUNC")
        )
        evidences.append(OutOfBandOracleEvidence(
            action_id=func_contract.action_id, exit_code=frc, fs_diff=ffs,
            functional_suite_passed=func_ok, fpr_value=fpr_val if fpr_measured else None,
            isolation_backend=chamber.isolation_backend, oracle_verdict=func_verdict,
        ))
        transitions.append(AckStateTransition(
            state="ORACLE_FUNCTIONAL_AND_FPR_CHECK", actor="ORACLE",
            summary=f"Valid corpus ({len(valid_corpus)} casi) + regression crash: passed={func_ok} ({func_verdict}, fpr={fpr_val if fpr_measured else 'N/A'}).",
            passed=func_ok,
        ))
        if not func_ok:
            if not has_valid_evidence:
                fail_verdict = "REJECTED_NO_VALID_CORPUS"
                fail_summary = "Certificazione Workspace Mode negata: corpus valido vuoto (0 input)."
                fail_rationale = "Workspace Mode richiede almeno 1 input valido (`valid_corpus_dir` o `valid_inputs`) per verificare la preservazione funzionale prima della certificazione."
            else:
                fail_verdict = "REJECTED_BROKEN_PARSER"
                fail_summary = "Respinto: parser rotto o falsi positivi sugli input validi."
                fail_rationale = "La patch ha alterato l'output o rigettato input validi del corpus."
            transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary=fail_summary, passed=False))
            return _MissionExecutionOutcome(
                transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=[],
                tpr_fpr_matrix=AckTprFprMatrix(
                    true_positive_rate=0.0, false_positive_rate=fpr_val, evasion_resistance_rate=0.0,
                    functional_survival_rate=func_survival, pre_patch_breach_confirmed=pre_breach, post_patch_breaches=0,
                    fpr_measured=fpr_measured, benign_corpus_size=total_eval if fpr_measured else len(valid_corpus), attack_variants_tested=0,
                ),
                blue_summary=blue_summary, certified=False, certification_verdict=fail_verdict,
                rationale=fail_rationale,
                audit_scope=audit_scope, verification_tier=verification_tier,
                executed_checks=["valid_baseline_capture", "red_subagent_fuzzing", "blue_ast_patch_synthesis", "valid_corpus_functional_gate"],
                not_executed_checks=[
                    "red_bypass_mutation",
                    "real_asan_ubsan_native_sanitizers",
                    *([] if has_valid_evidence else ["user_supplied_valid_corpus_regression"]),
                ],
                subagent_traces=traces, patch_diff=patch_diff, regression_test_code=regression_code,
                execution_logs=exec_logs, repro_artifacts=repro_artifacts, workspace_target=ws_info,
            )

        # 4. Red Bypass Mutator Sub-Agent (`RED_MUTATE_BYPASS`, iterative Fog of War)
        post_crashes = 0
        exec_errors = 0
        rounds_planned, mut_trace = RedBypassMutatorSubAgent().plan_mutation_rounds(
            recon,
            fow.build_red_context(target_invariant=desc.target_invariant, attack_surface=f"{module_name}.{fn_name}"),
            rounds=mutation_rounds,
            router=red_router,
        )
        traces.append(mut_trace)
        rounds_to_run = len(rounds_planned)

        for idx, (atk_class, pkts_list) in enumerate(rounds_planned):
            aid = f"act_red_m4_mut_{idx + 1:02d}"
            chamber.write_red_artifact(f"mut_payloads_{aid}.json", json.dumps(pkts_list))
            if inject_broken_mutation and idx == 0:
                mut_body = "raise RuntimeError('Simulated broken fuzzer mutation harness')\n"
            else:
                mut_body = _M4_MUT_FUZZ_SCRIPT.format(target_filename=target_filename, fn_name=fn_name, aid=aid)
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
            mrc, mout, merr, mfs = chamber.run_contract(m_contract)
            exec_logs.append({"action_id": aid, "exit_code": mrc, "stdout": mout, "stderr": merr})
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
                round_index=idx + 1, attack_class=atk_class, previous_failed_classes=prev_failed,
                contract=m_contract, oracle_evidence=mev, execution_valid=exec_ok,
                attempts_executed=attempts_n, bypass_succeeded=crashed,
            ))

        transitions.append(AckStateTransition(
            state="RED_MUTATE_BYPASS", actor="RED",
            summary=f"Fuzzing differenziale post-patch ({rounds_to_run} classi): crash={post_crashes}, errors={exec_errors}.",
            passed=(post_crashes == 0 and exec_errors == 0),
        ))
        valid_defended = sum(1 for r in mut_results if r.execution_valid and not r.bypass_succeeded)
        evasion_res = round(valid_defended / rounds_to_run, 3)
        if ws_info is not None and staged is not None:
            ws_info.original_untouched = _sha256_bytes(Path(staged.target_file_path).read_bytes()) == staged.original_sha256

        certified = bool(pre_breach and func_ok and has_valid_evidence and post_crashes == 0 and exec_errors == 0 and defense_mode != "naive_block_all")
        if exec_errors > 0:
            cert_verdict = "REJECTED_MUTATION_EXECUTION_ERROR"
            rationale = f"Certificazione negata (fail-closed): {exec_errors} round di fuzzing non validi (`EXECUTION_ERROR`)."
        elif certified and not is_builtin_tlv:
            cert_verdict = "VERIFIED_WORKSPACE_PARSER_PATCH"
            rationale = f"Workspace `{target_filename}.{fn_name}`: crash minimizzato, patch verificata su {len(valid_corpus)} casi validi e {rounds_to_run} classi avversarie; file originale intatto."
        elif certified:
            cert_verdict = "CERTIFIED_ZERO_CRASH_PARSER"
            rationale = "Crash riprodotto pre-fix, eliminato post-patch su tutte le varianti Python testate (modalità Lab)."
        else:
            cert_verdict = "PARSER_STILL_CRASHING"
            rationale = f"{post_crashes} mutazioni continuano a causare crash nel parser."

        executed = [
            "valid_baseline_capture", "red_subagent_recon_and_weaponize", "crash_delta_minimization",
            "blue_subagent_triage_and_patch", "post_patch_valid_regression", "red_bypass_mutation_rounds",
        ]
        not_executed = ["real_asan_ubsan_native_sanitizers", "real_container_or_microvm_sandbox"]
        if staged is not None and not staged.user_supplied_corpus:
            not_executed.append("user_supplied_valid_corpus_regression")

        transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary=rationale, passed=certified))
        return _MissionExecutionOutcome(
            transitions=transitions, contracts=contracts, evidences=evidences, mutation_rounds=mut_results,
            tpr_fpr_matrix=AckTprFprMatrix(
                true_positive_rate=evasion_res, false_positive_rate=fpr_val, evasion_resistance_rate=evasion_res,
                functional_survival_rate=func_survival, pre_patch_breach_confirmed=pre_breach,
                post_patch_breaches=post_crashes + exec_errors, fpr_measured=fpr_measured,
                benign_corpus_size=total_eval if fpr_measured else len(valid_corpus), attack_variants_tested=rounds_to_run,
            ),
            blue_summary=blue_summary, certified=certified, certification_verdict=cert_verdict,
            rationale=rationale, audit_scope=audit_scope, verification_tier=verification_tier,
            executed_checks=executed, not_executed_checks=not_executed, subagent_traces=traces,
            patch_diff=patch_diff, regression_test_code=regression_code,
            execution_logs=exec_logs, repro_artifacts=repro_artifacts, workspace_target=ws_info,
        )
    finally:
        if staged is not None:
            staged.cleanup_staged_worktree()
