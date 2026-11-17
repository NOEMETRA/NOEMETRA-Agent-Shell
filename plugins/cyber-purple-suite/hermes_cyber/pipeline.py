"""Multi-agent Purple Team orchestrator, dual-model arena state, and comparative benchmark."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union

from hermes_cyber.blue_agent import BlueInvestigatorAgent, _build_sigma_yaml
from hermes_cyber.models import (
    AnalyticalClaim,
    ArtifactIngestionResult,
    BenchmarkCaseResult,
    BenchmarkComparisonReport,
    CyberAnalysisReport,
    PurpleReplayReport,
    RemediationVerificationSummary,
    ScenarioDescriptor,
    VerdictType,
)
from hermes_cyber.observer import CyberObserver
from hermes_cyber.red_agent import RedOperatorAgent
from hermes_cyber.router_bridge import (
    ModelRouter,
    assert_voice_home_live,
    bind_cyber_profile_scope,
    compute_home_fingerprint,
    ensure_voice_dir,
    get_gateway_served_profile_homes,
    resolve_cyber_profile_dir,
    validate_path_profile_ownership,
)
from hermes_cyber.scenarios import _SCENARIOS, get_scenario, list_scenario_descriptors
from hermes_cyber.verifier import PurpleVerifier, build_simulation_summary, run_purple_replay

logger = logging.getLogger(__name__)


def _claims_semantically_match(c1: AnalyticalClaim, c2: AnalyticalClaim) -> bool:
    """Match two claims across re-analysis by tactic, technique family, and shared entities rather than ordinal ID."""
    if c1.tactic.strip().lower() != c2.tactic.strip().lower():
        return False
    id1 = c1.technique_id.strip().upper()
    id2 = c2.technique_id.strip().upper()
    if id1 != id2 and id1.split(".")[0] != id2.split(".")[0]:
        return False

    h1 = {h.lower() for h in c1.subject_entities.get("hosts", []) if h}
    h2 = {h.lower() for h in c2.subject_entities.get("hosts", []) if h}
    if h1 and h2 and h1.isdisjoint(h2):
        return False

    if not (h1 and h2):
        i1 = {x.lower() for x in c1.subject_entities.get("ips", []) if x}
        i2 = {x.lower() for x in c2.subject_entities.get("ips", []) if x}
        u1 = {x.lower() for x in c1.subject_entities.get("users", []) if x}
        u2 = {x.lower() for x in c2.subject_entities.get("users", []) if x}
        e1 = {x.lower() for x in c1.subject_entities.get("endpoints", []) if x}
        e2 = {x.lower() for x in c2.subject_entities.get("endpoints", []) if x}
        if i1 and i2 and i1.isdisjoint(i2) and not (u1 & u2) and not (e1 & e2):
            return False
        if u1 and u2 and u1.isdisjoint(u2) and not (e1 & e2) and not (i1 & i2):
            return False

    return True


def _extract_func_defs(ing: ArtifactIngestionResult) -> Set[str]:
    defs: Set[str] = set()
    for ev in ing.evidences:
        if ev.is_benign_baseline:
            continue
        m = re.search(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", ev.raw_content)
        if m:
            defs.add(m.group(1).lower())
    return defs


def _is_claim_remediated_by_patch(
    orig_claim: AnalyticalClaim,
    orig_ing: ArtifactIngestionResult,
    patched_ing: ArtifactIngestionResult,
    new_active: List[AnalyticalClaim],
) -> bool:
    """Confirm an original threat claim is both absent from new_active and genuinely mitigated on its original surface."""
    if any(_claims_semantically_match(orig_claim, nc) for nc in new_active):
        return False

    claim_evs = [ev for ev in orig_ing.evidences if ev.evidence_id in orig_claim.evidence_ids]
    claim_sinks = {s for ev in claim_evs for s in ev.entities.get("sinks", [])}

    orig_routes = {
        ep for ev in orig_ing.evidences if not ev.is_benign_baseline for ep in ev.entities.get("endpoints", []) if ep.startswith("/")
    }
    patched_routes = {
        ep for ev in patched_ing.evidences for ep in ev.entities.get("endpoints", []) if ep.startswith("/")
    }
    orig_hosts = {h.lower() for h in orig_claim.subject_entities.get("hosts", []) if h}
    patched_hosts = {h.lower() for ev in patched_ing.evidences for h in ev.entities.get("hosts", []) if h}
    orig_defs = _extract_func_defs(orig_ing)
    patched_defs = _extract_func_defs(patched_ing)
    patched_controls = {ctrl for ev in patched_ing.evidences for ctrl in ev.entities.get("controls", [])}

    if orig_hosts and not (orig_hosts & patched_hosts):
        return False

    if orig_routes and "container_priv" not in claim_sinks and orig_claim.technique_id != "T1611":
        if not (orig_routes & patched_routes) and not (orig_defs and (orig_defs & patched_defs)):
            return False

    required_for_sink = {
        "sql_concat": "parameterized_sql",
        "ssrf_fetch": "url_allowlist",
        "container_priv": "privilege_dropped",
        "cmd_exec": "input_validation",
        "deserialization": "input_validation",
    }
    if claim_sinks:
        return all(required_for_sink[s] in patched_controls for s in claim_sinks if s in required_for_sink)

    if orig_claim.technique_id == "T1552.005":
        return "url_allowlist" in patched_controls
    if orig_claim.technique_id == "T1611":
        return "privilege_dropped" in patched_controls
    if orig_claim.technique_id == "T1190":
        return "parameterized_sql" in patched_controls or "input_validation" in patched_controls

    has_surface = bool((orig_hosts & patched_hosts) or (orig_routes & patched_routes) or (orig_defs & patched_defs))
    return has_surface and bool(patched_controls)


def _naive_single_agent_verdict(artifact_text: str) -> VerdictType:
    """Baseline simulating a linear single-agent alert triager without contradiction search or abstention."""
    low = artifact_text.lower()
    if "writes_enc_ext" in low or "vssadmin" in low or "auth=failed" in low or "wmic" in low:
        return VerdictType.CONFIRMED_ATTACK
    if "select " in low and "requests.get" in low:
        return VerdictType.EXPLOITABLE_CHAIN
    if "alert=\"http flood" in low:
        return VerdictType.CONFIRMED_ATTACK
    if "sh -c" in low or "pickle.loads" in low:
        return VerdictType.CONFIRMED_ATTACK
    return VerdictType.CONFIRMED_ATTACK


class CyberPurpleAssistant:
    """Orchestrator uniting Red Operator, Blue Investigator/Critic, and deterministic Purple Verifier."""

    def __init__(
        self,
        *,
        profile: Optional[str] = None,
        home_dir: Optional[Union[str, Path]] = None,
        allow_remote: bool = False,
        red_provider: str = "ollama",
        red_model: str = "gemma4:12b",
        blue_provider: str = "ollama",
        blue_model: str = "gemma4:12b",
        use_llm: bool = False,
    ):
        self.profile = profile or "default"
        self.home_dir = Path(home_dir).resolve() if home_dir else None
        self.storage_dir = resolve_cyber_profile_dir(profile=profile, home_dir=home_dir)
        self.cases_path = self.storage_dir / "cyber_cases.json"
        self.use_llm = use_llm

        self.observer = CyberObserver()
        self.red_agent = RedOperatorAgent()
        self.blue_agent = BlueInvestigatorAgent()
        self.verifier = PurpleVerifier()

        # Dual independent ModelRouter instances for Red vs Blue multi-model dialectics
        self.red_router = ModelRouter(
            default_provider=red_provider,
            ollama_model=red_model,
            allow_remote=allow_remote,
        )
        self.blue_router = ModelRouter(
            default_provider=blue_provider,
            ollama_model=blue_model,
            allow_remote=allow_remote,
        )

        self._cases: Dict[str, CyberAnalysisReport] = {}
        self._active_case_id: Optional[str] = None
        self._last_benchmark: Optional[BenchmarkComparisonReport] = None
        self._load_cases()

    def _check_profile_storage_live(self) -> None:
        assert_voice_home_live(self.cases_path)
        validate_path_profile_ownership(
            str(self.cases_path),
            profile=self.profile,
            home_dir=self.home_dir,
            served_homes=get_gateway_served_profile_homes(),
        )

    def _load_cases(self) -> None:
        if not self.cases_path.exists():
            return
        try:
            raw = json.loads(self.cases_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._active_case_id = raw.get("active_case_id")
                for cid, entry in (raw.get("cases") or {}).items():
                    if isinstance(entry, dict):
                        self._cases[cid] = CyberAnalysisReport.model_validate(entry)
        except Exception as exc:
            logger.warning("Impossibile caricare i casi cyber salvati: %s", exc)

    def _save_cases(self) -> None:
        self._check_profile_storage_live()
        ensure_voice_dir(self.cases_path.parent)
        payload = {
            "active_case_id": self._active_case_id,
            "cases": {cid: rep.model_dump(mode="json") for cid, rep in self._cases.items()},
        }
        self.cases_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @property
    def allow_remote(self) -> bool:
        return bool(self.red_router.allow_remote and self.blue_router.allow_remote)

    def set_allow_remote(self, allowed: bool) -> None:
        self.red_router.set_allow_remote(allowed)
        self.blue_router.set_allow_remote(allowed)

    def configure_arena(
        self,
        *,
        allow_remote: Optional[bool] = None,
        red_provider: Optional[str] = None,
        red_model: Optional[str] = None,
        blue_provider: Optional[str] = None,
        blue_model: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        use_llm: Optional[bool] = None,
    ) -> None:
        if allow_remote is not None:
            self.set_allow_remote(bool(allow_remote))
        if red_provider:
            self.red_router.set_provider(red_provider, base_url=llm_base_url)
        if red_model:
            self.red_router.set_model(red_model)
        if blue_provider:
            self.blue_router.set_provider(blue_provider, base_url=llm_base_url)
        if blue_model:
            self.blue_router.set_model(blue_model)
        if use_llm is not None:
            self.use_llm = bool(use_llm)

    def list_scenarios(self) -> List[ScenarioDescriptor]:
        return list_scenario_descriptors()

    def list_cases(self) -> List[Dict[str, Any]]:
        return [
            {
                "case_id": c.case_id,
                "title": c.title,
                "created_at": c.created_at,
                "scenario_id": c.scenario_id,
                "verdict": c.verdict.verdict.value,
                "confidence_score": c.verdict.confidence_score,
                "detection_coverage": c.verdict.replay.detection_coverage,
                "false_positive_rate": c.verdict.replay.false_positive_rate,
            }
            for c in self._cases.values()
        ]

    def get_case(self, case_id: str) -> CyberAnalysisReport:
        if case_id not in self._cases:
            raise KeyError(f"Caso cyber '{case_id}' non trovato.")
        return self._cases[case_id]

    def _run_transient_analysis(
        self,
        content: str,
        *,
        title: str,
        source_kind: str,
        scenario_id: Optional[str] = None,
        preserve_case_id: Optional[str] = None,
    ) -> CyberAnalysisReport:
        with bind_cyber_profile_scope(home_dir=self.home_dir, profile=self.profile):
            self._check_profile_storage_live()
            ingestion = self.observer.ingest_text(content, title=title, source_kind=source_kind)
            if preserve_case_id:
                ingestion = ingestion.model_copy(update={"case_id": preserve_case_id})
            r_router = self.red_router if self.use_llm else None
            b_router = self.blue_router if self.use_llm else None

            raw_red, red_scrub, red_stats = self.red_agent.analyze(ingestion, router=r_router)
            raw_blue, blue_scrub, blue_stats = self.blue_agent.analyze(ingestion, raw_red, router=b_router)
            clean_red, clean_blue, verdict = self.verifier.verify(ingestion, raw_red, raw_blue)

            merged_stats = {
                k: int(red_stats.get(k, 0)) + int(blue_stats.get(k, 0))
                for k in ("private_ips", "secrets", "emails")
            }
            return CyberAnalysisReport(
                case_id=ingestion.case_id,
                title=title,
                created_at=datetime.now(timezone.utc).isoformat(),
                scenario_id=scenario_id,
                ingestion=ingestion,
                red_report=clean_red,
                blue_report=clean_blue,
                verdict=verdict,
                privacy_scrubbed=bool(red_scrub or blue_scrub),
                scrub_stats=merged_stats,
            )

    def _analyze_ingested(
        self,
        content: str,
        *,
        title: str,
        source_kind: str,
        scenario_id: Optional[str] = None,
        preserve_case_id: Optional[str] = None,
    ) -> CyberAnalysisReport:
        report = self._run_transient_analysis(
            content,
            title=title,
            source_kind=source_kind,
            scenario_id=scenario_id,
            preserve_case_id=preserve_case_id,
        )
        self._cases[report.case_id] = report
        self._active_case_id = report.case_id
        self._save_cases()
        return report

    def analyze_scenario(self, scenario_id: str) -> CyberAnalysisReport:
        scen = get_scenario(scenario_id)
        return self._analyze_ingested(
            scen.artifact_text,
            title=scen.title,
            source_kind=scen.source_kind,
            scenario_id=scen.scenario_id,
        )

    def analyze_custom(
        self,
        *,
        title: str,
        content: str,
        source_kind: str = "auto",
    ) -> CyberAnalysisReport:
        return self._analyze_ingested(
            content,
            title=title.strip() or "Custom Security Artifact",
            source_kind=source_kind,
            scenario_id=None,
        )

    def rerun_replay(
        self,
        *,
        case_id: str,
        detection_keywords: Optional[List[str]] = None,
        exclude_values: Optional[List[str]] = None,
    ) -> PurpleReplayReport:
        report = self.get_case(case_id)
        refuted_ids = {c.claim_id for c in report.red_report.claims if c.status == "refuted"}
        has_supported = any(c.status == "supported" for c in report.red_report.claims)
        updated_replay = run_purple_replay(
            report.ingestion,
            report.red_report,
            report.blue_report,
            custom_keywords=detection_keywords,
            custom_excludes=exclude_values,
            skip_claim_ids=refuted_ids if (has_supported and refuted_ids) else None,
        )
        updated_blue = report.blue_report
        if detection_keywords is not None or exclude_values is not None:
            tuned_sigma = report.blue_report.sigma_rule.model_copy(deep=True)
            if detection_keywords is not None:
                tuned_sigma.detection_keywords = [k.strip() for k in detection_keywords if k.strip()]
            if exclude_values is not None:
                tuned_sigma.exclude_fields = {"custom_filter": [x.strip() for x in exclude_values if x.strip()]}
            tuned_sigma.yaml_text = _build_sigma_yaml(tuned_sigma)
            updated_blue = report.blue_report.model_copy(update={"sigma_rule": tuned_sigma})

        updated_verdict = report.verdict.model_copy(
            update={
                "replay": updated_replay,
                "simulation": build_simulation_summary(updated_replay),
            }
        )
        self._cases[case_id] = report.model_copy(update={"blue_report": updated_blue, "verdict": updated_verdict})
        self._save_cases()
        return updated_replay

    def verify_case_update(
        self,
        *,
        case_id: str,
        content: str,
        mode: Literal["append_evidence", "verify_patch"] = "verify_patch",
    ) -> CyberAnalysisReport:
        """Close open investigations with additional evidence or verify remediated/patched artifacts."""
        if mode not in ("append_evidence", "verify_patch"):
            raise ValueError("Il parametro 'mode' deve essere 'append_evidence' o 'verify_patch'.")
        clean_addition = str(content or "").strip()
        if not clean_addition:
            raise ValueError("Il contenuto di verifica/evidenza non può essere vuoto.")

        orig_report = self.get_case(case_id)
        if mode == "append_evidence":
            orig_raw = "\n".join(ev.raw_content for ev in orig_report.ingestion.evidences)
            orig_ids = {ev.evidence_id for ev in orig_report.ingestion.evidences}
            updated = self._analyze_ingested(
                f"{orig_raw}\n{clean_addition}",
                title=orig_report.title,
                source_kind=orig_report.ingestion.source_kind,
                scenario_id=orig_report.scenario_id,
                preserve_case_id=case_id,
            )
            added_eids = [ev.evidence_id for ev in updated.ingestion.evidences if ev.evidence_id not in orig_ids]
            orig_open_claims = [c for c in orig_report.red_report.claims if c.status == "open"]
            new_claims = updated.red_report.claims
            resolved: List[str] = []
            still_open: List[str] = []

            for orig_c in orig_open_claims:
                matched_new = next((nc for nc in new_claims if _claims_semantically_match(orig_c, nc)), None)
                if matched_new is not None:
                    if matched_new.status in ("supported", "refuted"):
                        resolved.append(orig_c.claim_id)
                    elif matched_new.claim_id not in still_open:
                        still_open.append(matched_new.claim_id)
                elif orig_c.claim_id not in still_open:
                    still_open.append(orig_c.claim_id)

            for nc in new_claims:
                if nc.status == "open" and nc.claim_id not in still_open:
                    still_open.append(nc.claim_id)

            rem_summary = RemediationVerificationSummary(
                status="EVIDENCE_UPDATED",
                verified_at=datetime.now(timezone.utc).isoformat(),
                verification_source="append_evidence",
                added_evidence_ids=added_eids,
                resolved_claim_ids=resolved,
                remaining_open_claim_ids=still_open,
                before_verdict=orig_report.verdict.verdict,
                after_verdict=updated.verdict.verdict,
                summary=(
                    f"Appended {len(added_eids)} evidence record(s); resolved={len(resolved)} claim(s), "
                    f"open={len(still_open)}; verdict {orig_report.verdict.verdict.value} -> {updated.verdict.verdict.value}."
                ),
            )
        else:
            candidate = self._run_transient_analysis(
                clean_addition,
                title=f"{orig_report.title} (Post-Remediation)",
                source_kind=orig_report.ingestion.source_kind,
                scenario_id=orig_report.scenario_id,
                preserve_case_id=case_id,
            )
            orig_active = [c for c in orig_report.red_report.claims if c.status in ("supported", "open")]
            new_active = [c for c in candidate.red_report.claims if c.status in ("supported", "open")]

            resolved_ids = [
                orig_c.claim_id
                for orig_c in orig_active
                if _is_claim_remediated_by_patch(orig_c, orig_report.ingestion, candidate.ingestion, new_active)
            ]
            unresolved_orig = [c for c in orig_active if c.claim_id not in resolved_ids]

            if orig_active and len(resolved_ids) == len(orig_active) and len(new_active) == 0:
                rem_status = "VERIFIED_FIXED"
            elif resolved_ids:
                rem_status = "PARTIALLY_MITIGATED"
            else:
                rem_status = "STILL_VULNERABLE"

            if unresolved_orig and len(new_active) == 0:
                # Submitted snippet omitted or failed to cover all original vulnerable surfaces:
                # preserve original forensic ingestion records alongside unresolved claims.
                remaining_ids = [c.claim_id for c in unresolved_orig]
                sup_ids = [c.claim_id for c in unresolved_orig if c.status == "supported"]
                open_ids = [c.claim_id for c in unresolved_orig if c.status == "open"]
                diag_status = "CONFIRMED_THREAT" if sup_ids else "OPEN_HYPOTHESIS"
                preserved_diag = orig_report.verdict.diagnosis.model_copy(
                    update={
                        "status": diag_status,
                        "supported_claims_count": len(sup_ids),
                        "open_claims_count": len(open_ids),
                        "supported_claim_ids": sup_ids,
                        "open_claim_ids": open_ids,
                        "summary": (
                            f"{len(unresolved_orig)} original threat claim(s) remain unverified or missing from submitted patch."
                        ),
                    }
                )
                updated = orig_report.model_copy(
                    update={
                        "red_report": orig_report.red_report.model_copy(update={"claims": unresolved_orig}),
                        "verdict": orig_report.verdict.model_copy(update={"diagnosis": preserved_diag}),
                    }
                )
            else:
                updated = candidate
                remaining_ids = [c.claim_id for c in new_active] or [c.claim_id for c in unresolved_orig]

            after_v = updated.verdict.verdict
            rem_summary = RemediationVerificationSummary(
                status=rem_status,  # type: ignore[arg-type]
                verified_at=datetime.now(timezone.utc).isoformat(),
                verification_source="verify_patch",
                added_evidence_ids=[ev.evidence_id for ev in candidate.ingestion.evidences],
                resolved_claim_ids=resolved_ids,
                remaining_open_claim_ids=remaining_ids,
                before_verdict=orig_report.verdict.verdict,
                after_verdict=after_v,
                summary=(
                    f"Post-remediation check: {rem_status} ({len(resolved_ids)}/{len(orig_active)} original claims verified fixed; "
                    f"verdict {orig_report.verdict.verdict.value} -> {after_v.value})."
                ),
            )

        final_report = updated.model_copy(
            update={"verdict": updated.verdict.model_copy(update={"remediation_verification": rem_summary})}
        )
        self._cases[case_id] = final_report
        self._active_case_id = case_id
        self._save_cases()
        return final_report

    def run_benchmark(self) -> BenchmarkComparisonReport:
        """Compare Single-Agent linear triage vs Multi-Agent Purple across all 6 dialectical scenarios."""
        results: List[BenchmarkCaseResult] = []
        for scen in _SCENARIOS:
            report = self.analyze_scenario(scen.scenario_id)
            sa_verdict = _naive_single_agent_verdict(scen.artifact_text)
            ma_verdict = report.verdict.verdict
            results.append(BenchmarkCaseResult(
                scenario_id=scen.scenario_id,
                title=scen.title,
                expected_verdict=scen.expected_verdict,
                single_agent_verdict=sa_verdict,
                purple_multi_agent_verdict=ma_verdict,
                single_agent_correct=(sa_verdict == scen.expected_verdict),
                purple_correct=(ma_verdict == scen.expected_verdict),
                contradictions_found=len(report.blue_report.contradictions),
                detection_coverage=report.verdict.replay.detection_coverage,
                false_positive_rate=report.verdict.replay.false_positive_rate,
            ))

        total = len(results)
        sa_acc = sum(1 for r in results if r.single_agent_correct) / total
        ma_acc = sum(1 for r in results if r.purple_correct) / total

        benign_cases = [r for r in results if r.expected_verdict == VerdictType.FALSE_POSITIVE_BENIGN]
        sa_fpr = (
            sum(1 for r in benign_cases if r.single_agent_verdict != VerdictType.FALSE_POSITIVE_BENIGN) / len(benign_cases)
            if benign_cases
            else 0.0
        )
        ma_fpr = (
            sum(1 for r in benign_cases if r.purple_multi_agent_verdict != VerdictType.FALSE_POSITIVE_BENIGN) / len(benign_cases)
            if benign_cases
            else 0.0
        )

        ambig_cases = [r for r in results if r.expected_verdict == VerdictType.INSUFFICIENT_EVIDENCE]
        abst_acc = (
            sum(1 for r in ambig_cases if r.purple_multi_agent_verdict == VerdictType.INSUFFICIENT_EVIDENCE) / len(ambig_cases)
            if ambig_cases
            else 1.0
        )

        contra_recall = sum(1 for r in results if r.contradictions_found >= 1) / total
        avg_cov = sum(r.detection_coverage for r in results) / total

        summary = BenchmarkComparisonReport(
            total_scenarios=total,
            single_agent_accuracy=round(sa_acc, 3),
            purple_multi_agent_accuracy=round(ma_acc, 3),
            single_agent_fpr=round(sa_fpr, 3),
            purple_fpr=round(ma_fpr, 3),
            contradiction_recall=round(contra_recall, 3),
            abstention_accuracy=round(abst_acc, 3),
            avg_detection_coverage=round(avg_cov, 3),
            results=results,
        )
        self._last_benchmark = summary
        return summary

    def get_status(self) -> Dict[str, Any]:
        active = self._cases.get(self._active_case_id) if self._active_case_id else None
        return {
            "status": "ready",
            "profile": self.profile,
            "home_fingerprint": compute_home_fingerprint(self.storage_dir.parent),
            "allow_remote": self.allow_remote,
            "use_llm": self.use_llm,
            "red_provider": self.red_router.default_provider,
            "red_model": self.red_router.ollama_model,
            "red_is_local": self.red_router.is_active_endpoint_local(),
            "blue_provider": self.blue_router.default_provider,
            "blue_model": self.blue_router.ollama_model,
            "blue_is_local": self.blue_router.is_active_endpoint_local(),
            "total_cases": len(self._cases),
            "active_case_id": self._active_case_id,
            "active_case": active.model_dump(mode="json") if active else None,
            "last_benchmark": self._last_benchmark.model_dump(mode="json") if self._last_benchmark else None,
        }
