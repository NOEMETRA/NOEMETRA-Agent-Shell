"""Honest 3-tier classification and shared outcome builders for ACK Mission 4."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from hermes_cyber.ack.catalog import _MissionExecutionOutcome
from hermes_cyber.models import (
    AckMutationRoundResult,
    AckStateTransition,
    AckSubAgentTrace,
    AckTprFprMatrix,
    AckVerificationTierType,
    AckWorkspaceTargetInfo,
    ConstrainedActionContract,
    OutOfBandOracleEvidence,
)


def classify_m4_outcome(
    *,
    patch_origin: str,
    defense_mode: str,
    is_builtin_tlv: bool,
    pre_breach: bool,
    func_ok: bool,
    post_crashes: int,
    exec_errors: int,
    rounds_to_run: int,
    semantic_checked: int,
    semantic_passed: int,
    target_filename: str,
    fn_name: str,
    total_valid: int,
    patch_meta: dict,
) -> dict:
    """Apply honest 3-tier classification distinguishing exception containment from verified root fixes."""
    sens_ops = list(patch_meta.get("sensitive_ops_in_original") or [])
    llm_rej = list(patch_meta.get("llm_rejection_reasons") or [])
    non_allow = list(patch_meta.get("non_allowlisted_calls_in_original") or [])
    reasons: List[str] = []

    if sens_ops:
        reasons.append(f"Operazioni sensibili preesistenti in `{fn_name}` ({', '.join(sens_ops)}): revisione manuale obbligatoria.")
    if llm_rej:
        reasons.append(f"Patch LLM rifiutata dal gate AST: {'; '.join(llm_rej)}.")

    if exec_errors > 0:
        return {
            "certified": False,
            "patch_applicable": False,
            "patch_classification": "none",
            "cert_verdict": "REJECTED_MUTATION_EXECUTION_ERROR",
            "rationale": f"Certificazione negata (fail-closed): {exec_errors} round di fuzzing non validi (`EXECUTION_ERROR`).",
            "manual_review_required": True,
            "manual_review_reasons": reasons or ["Errore esecuzione harness mutazione."],
        }

    if not (pre_breach and func_ok and post_crashes == 0 and defense_mode != "naive_block_all"):
        return {
            "certified": False,
            "patch_applicable": False,
            "patch_classification": "none",
            "cert_verdict": "PARSER_STILL_CRASHING",
            "rationale": f"{post_crashes} mutazioni continuano a causare crash nel parser.",
            "manual_review_required": True,
            "manual_review_reasons": reasons or ["Il parser presenta ancora crash residui."],
        }

    if is_builtin_tlv and patch_origin == "builtin_structural_fix":
        sem_ok = semantic_checked > 0 and semantic_passed == semantic_checked
        return {
            "certified": sem_ok,
            "patch_applicable": False,
            "patch_classification": "semantically_verified_patch" if sem_ok else "root_cause_patch_unverified_semantics",
            "cert_verdict": "CERTIFIED_ZERO_CRASH_PARSER" if sem_ok else "PATCHED_WORKSPACE_UNVERIFIED_SEMANTICS",
            "rationale": (
                "Crash riprodotto pre-fix, eliminato post-patch su tutte le varianti Python "
                f"e {semantic_passed}/{semantic_checked} asserzioni semantiche TLV verificate (modalità Lab)."
            ),
            "manual_review_required": not sem_ok,
            "manual_review_reasons": reasons,
        }

    if patch_origin == "deterministic_exception_wrapper":
        reasons.insert(
            0,
            "Patch tramite wrapper deterministico di contenimento eccezioni (-> ValueError): "
            "protezione attiva contro crash, ma la causa logica interna del parser richiede revisione manuale.",
        )
        if semantic_checked == 0:
            reasons.append("Nessuna asserzione semantica esterna (<stem>.expected.json o AckSemanticTestCase) fornita.")
        return {
            "certified": False,
            "patch_applicable": not is_builtin_tlv,
            "patch_classification": "exception_containment_only",
            "cert_verdict": "CONTAINED_WORKSPACE_PARSER_EXCEPTIONS",
            "rationale": (
                f"Workspace `{target_filename}.{fn_name}`: eccezioni contenute in ValueError su {total_valid} input validi "
                f"e {rounds_to_run} classi fuzz, ma solo exception containment senza patch semantica root-cause."
            ),
            "manual_review_required": True,
            "manual_review_reasons": reasons,
        }

    if patch_origin == "llm_ast_audited_patch" and (semantic_checked == 0 or semantic_passed < semantic_checked):
        reasons.append(
            "Patch root-cause AST-verificata ma priva di asserzioni semantiche esterne superate "
            "(<stem>.expected.json o AckSemanticTestCase): confrontato solo snapshot pre/post patch."
        )
        return {
            "certified": False,
            "patch_applicable": True,
            "patch_classification": "root_cause_patch_unverified_semantics",
            "cert_verdict": "PATCHED_WORKSPACE_UNVERIFIED_SEMANTICS",
            "rationale": (
                f"Workspace `{target_filename}.{fn_name}`: patch strutturale AST-verificata e {rounds_to_run} classi fuzz contenute, "
                "ma assenza di asserzioni semantiche esterne per certificazione completa."
            ),
            "manual_review_required": True,
            "manual_review_reasons": reasons,
        }

    if non_allow:
        reasons.append(
            f"Chiamate non-allowlisted invariate in AST presenti nel target ({', '.join(non_allow)}): "
            "verificare manualmente il flusso dati."
        )
    return {
        "certified": True,
        "patch_applicable": True,
        "patch_classification": "semantically_verified_patch",
        "cert_verdict": "VERIFIED_WORKSPACE_PARSER_PATCH",
        "rationale": (
            f"Workspace `{target_filename}.{fn_name}`: patch root-cause AST-verificata, {semantic_passed}/{semantic_checked} "
            f"asserzioni semantiche superate su {total_valid} casi validi e {rounds_to_run} classi avversarie; file originale intatto."
        ),
        "manual_review_required": bool(sens_ops or non_allow),
        "manual_review_reasons": reasons,
    }


def build_m4_early_failure_outcome(
    *,
    transitions: List[AckStateTransition],
    contracts: List[ConstrainedActionContract],
    evidences: List[OutOfBandOracleEvidence],
    traces: List[AckSubAgentTrace],
    exec_logs: List[Dict[str, Any]],
    repro_artifacts: Dict[str, bytes],
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest", "workspace_target_file"],
    verification_tier: AckVerificationTierType,
    executed_checks: List[str],
    not_executed_checks: List[str],
    blue_summary: str,
    cert_verdict: str,
    rationale: str,
    pre_breach: bool,
    func_survival: float,
    total_valid: int,
    rej_rate: Optional[float] = None,
    mis_rate: Optional[float] = None,
    sem_rate: Optional[float] = None,
    sem_checked: int = 0,
    patch_diff: str = "",
    regression_code: str = "",
    ws_info: Optional[AckWorkspaceTargetInfo] = None,
    manual_review_required: bool = False,
) -> _MissionExecutionOutcome:
    """Shared fail-closed Mission 4 early-exit outcome builder."""
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=[],
        tpr_fpr_matrix=AckTprFprMatrix(
            metric_kind="parser_fuzz_verification",
            detector_metrics_applicable=False,
            true_positive_rate=None,
            false_positive_rate=None,
            crash_mitigation_rate=0.0,
            valid_input_rejection_rate=rej_rate,
            valid_output_mismatch_rate=mis_rate,
            semantic_assertion_pass_rate=sem_rate,
            semantic_assertions_count=sem_checked,
            evasion_resistance_rate=0.0,
            functional_survival_rate=func_survival,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=0,
            fpr_measured=False,
            benign_corpus_size=total_valid,
            attack_variants_tested=0,
        ),
        blue_summary=blue_summary,
        certified=False,
        certification_verdict=cert_verdict,
        rationale=rationale,
        audit_scope=audit_scope,
        verification_tier=verification_tier,
        executed_checks=executed_checks,
        not_executed_checks=not_executed_checks,
        subagent_traces=traces,
        patch_diff=patch_diff,
        regression_test_code=regression_code,
        execution_logs=exec_logs,
        repro_artifacts=repro_artifacts,
        workspace_target=ws_info,
        patch_classification="none",
        patch_applicable=False,
        manual_review_required=manual_review_required,
        manual_review_reasons=[rationale] if manual_review_required else [],
    )


def build_m4_final_outcome(
    *,
    patch_origin: str,
    defense_mode: str,
    is_builtin_tlv: bool,
    pre_breach: bool,
    func_ok: bool,
    post_crashes: int,
    exec_errors: int,
    rounds_to_run: int,
    evasion_res: float,
    rej_rate: Optional[float],
    mis_rate: Optional[float],
    sem_rate: Optional[float],
    sem_checked: int,
    sem_passed: int,
    func_survival: float,
    total_valid: int,
    benign_corpus_size: int,
    target_filename: str,
    fn_name: str,
    patch_meta: dict,
    blue_summary: str,
    audit_scope: Literal["synthetic_fixture_simulation", "cloned_target_manifest", "workspace_target_file"],
    verification_tier: AckVerificationTierType,
    has_user_supplied_corpus: bool,
    transitions: List[AckStateTransition],
    contracts: List[ConstrainedActionContract],
    evidences: List[OutOfBandOracleEvidence],
    mut_results: List[AckMutationRoundResult],
    traces: List[AckSubAgentTrace],
    patch_diff: str,
    regression_code: str,
    exec_logs: List[Dict[str, Any]],
    repro_artifacts: Dict[str, bytes],
    ws_info: Optional[AckWorkspaceTargetInfo],
) -> _MissionExecutionOutcome:
    """Classify and construct the final Mission 4 outcome cleanly after mutation rounds."""
    cls_res = classify_m4_outcome(
        patch_origin=patch_origin,
        defense_mode=defense_mode,
        is_builtin_tlv=is_builtin_tlv,
        pre_breach=pre_breach,
        func_ok=func_ok,
        post_crashes=post_crashes,
        exec_errors=exec_errors,
        rounds_to_run=rounds_to_run,
        semantic_checked=sem_checked,
        semantic_passed=sem_passed,
        target_filename=target_filename,
        fn_name=fn_name,
        total_valid=total_valid,
        patch_meta=patch_meta,
    )
    certified = bool(cls_res["certified"])
    rationale = str(cls_res["rationale"])
    if ws_info is not None:
        ws_info.patch_classification = cls_res["patch_classification"]
        ws_info.semantic_tests_verified = bool(sem_checked > 0 and sem_passed == sem_checked)
        ws_info.semantic_assertions_count = sem_checked
        ws_info.manual_review_required = bool(cls_res["manual_review_required"])

    executed = [
        "valid_baseline_capture", "red_subagent_recon_and_weaponize", "crash_delta_minimization",
        "blue_subagent_triage_and_patch", "post_patch_valid_regression", "red_bypass_mutation_rounds",
    ]
    not_executed = ["real_asan_ubsan_native_sanitizers", "real_container_or_microvm_sandbox", "autonomous_shell_tool_agent_team"]
    if not is_builtin_tlv and not has_user_supplied_corpus:
        not_executed.append("user_supplied_valid_corpus_regression")
    if sem_checked == 0:
        not_executed.append("external_semantic_output_assertions")

    transitions.append(AckStateTransition(state="CERTIFY_REPORT", actor="ORACLE", summary=rationale, passed=certified))
    return _MissionExecutionOutcome(
        transitions=transitions,
        contracts=contracts,
        evidences=evidences,
        mutation_rounds=mut_results,
        tpr_fpr_matrix=AckTprFprMatrix(
            metric_kind="parser_fuzz_verification",
            detector_metrics_applicable=False,
            true_positive_rate=None,
            false_positive_rate=None,
            crash_mitigation_rate=evasion_res,
            valid_input_rejection_rate=rej_rate,
            valid_output_mismatch_rate=mis_rate,
            semantic_assertion_pass_rate=sem_rate,
            semantic_assertions_count=sem_checked,
            evasion_resistance_rate=evasion_res,
            functional_survival_rate=func_survival,
            pre_patch_breach_confirmed=pre_breach,
            post_patch_breaches=post_crashes + exec_errors,
            fpr_measured=False,
            benign_corpus_size=benign_corpus_size,
            attack_variants_tested=rounds_to_run,
        ),
        blue_summary=blue_summary,
        certified=certified,
        certification_verdict=str(cls_res["cert_verdict"]),
        rationale=rationale,
        audit_scope=audit_scope,
        verification_tier=verification_tier,
        executed_checks=executed,
        not_executed_checks=not_executed,
        subagent_traces=traces,
        patch_diff=patch_diff,
        regression_test_code=regression_code,
        execution_logs=exec_logs,
        repro_artifacts=repro_artifacts,
        workspace_target=ws_info,
        patch_classification=cls_res["patch_classification"],
        patch_applicable=bool(cls_res["patch_applicable"]),
        manual_review_required=bool(cls_res["manual_review_required"]),
        manual_review_reasons=list(cls_res["manual_review_reasons"]),
    )
