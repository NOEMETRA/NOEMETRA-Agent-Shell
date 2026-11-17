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
from hermes_cyber.red_agent import RedOperatorAgent, _collect_subject_entities, _format_observed_fact
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
from hermes_cyber.verifier import (
    PurpleVerifier,
    build_simulation_summary,
    classify_supported_verdict,
    run_purple_replay,
)

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

    e1 = {x.split("?", 1)[0].lower() for x in c1.subject_entities.get("endpoints", []) if x}
    e2 = {x.split("?", 1)[0].lower() for x in c2.subject_entities.get("endpoints", []) if x}
    if e1 and e2 and e1.isdisjoint(e2):
        return False

    if not (h1 and h2):
        i1 = {x.lower() for x in c1.subject_entities.get("ips", []) if x}
        i2 = {x.lower() for x in c2.subject_entities.get("ips", []) if x}
        u1 = {x.lower() for x in c1.subject_entities.get("users", []) if x}
        u2 = {x.lower() for x in c2.subject_entities.get("users", []) if x}
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


def _map_evidence_to_surface_blocks(
    ing: ArtifactIngestionResult,
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """Partition artifact evidences into logical route/function/config/host surface blocks."""
    ev_to_block: Dict[str, int] = {}
    blocks: List[Dict[str, Any]] = []

    def _new_block(kind: str = "generic") -> int:
        idx = len(blocks)
        blocks.append({
            "kind": kind,
            "routes": set(),
            "funcs": set(),
            "hosts": set(),
            "controls": set(),
            "sinks": set(),
        })
        return idx

    cur_idx = _new_block()
    has_func_in_cur = False

    for ev in ing.evidences:
        if ev.is_benign_baseline:
            continue
        raw = ev.raw_content.strip()
        low = raw.lower()
        routes = {ep.split("?", 1)[0] for ep in ev.entities.get("endpoints", []) if ep.startswith("/")}
        func_m = re.search(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", raw)
        is_decorator = raw.startswith("@")
        is_config_line = ev.source_type == "config" or low.startswith(("apiversion:", "kind:", "# deploy/", "privileged:", "allowprivilegeescalation:"))

        if ev.line_or_seq == 1 and ev_to_block:
            cur_idx = _new_block("config" if is_config_line else ("code" if (is_decorator or func_m or ev.source_type == "code") else ev.source_type))
            has_func_in_cur = False
        elif is_decorator and has_func_in_cur:
            cur_idx = _new_block("code")
            has_func_in_cur = False
        elif func_m and has_func_in_cur:
            cur_idx = _new_block("code")
            has_func_in_cur = False
        elif is_config_line and blocks[cur_idx]["kind"] != "config":
            cur_idx = _new_block("config")
            has_func_in_cur = False
        elif not is_config_line and blocks[cur_idx]["kind"] == "config":
            cur_idx = _new_block(ev.source_type)
            has_func_in_cur = False
        elif low.startswith(("apiversion:", "kind:")):
            if blocks[cur_idx]["controls"] or blocks[cur_idx]["sinks"]:
                cur_idx = _new_block("config")
                has_func_in_cur = False

        blk = blocks[cur_idx]
        if is_config_line:
            blk["kind"] = "config"
        elif is_decorator or func_m or ev.source_type == "code":
            if blk["kind"] == "generic":
                blk["kind"] = "code"

        blk["routes"].update(routes)
        if func_m:
            blk["funcs"].add(func_m.group(1).lower())
            has_func_in_cur = True
        for h in ev.entities.get("hosts", []):
            if h:
                blk["hosts"].add(h.lower())
        blk["controls"].update(ev.entities.get("controls", []))
        blk["sinks"].update(ev.entities.get("sinks", []))
        ev_to_block[ev.evidence_id] = cur_idx

    return ev_to_block, blocks


def _block_is_mitigated_in_patched(
    orig_claim: AnalyticalClaim,
    blk: Optional[Dict[str, Any]],
    expected_sinks: Set[str],
    patched_blocks: List[Dict[str, Any]],
    claim_hosts: Set[str],
) -> bool:
    """Verify whether a specific original surface block has matching surface and required controls in patched_blocks."""
    required_for_sink = {
        "sql_concat": "parameterized_sql",
        "ssrf_fetch": "url_allowlist",
        "container_priv": "privilege_dropped",
        "cmd_exec": "input_validation",
        "deserialization": "input_validation",
    }
    blk_routes = blk["routes"] if blk else set()
    blk_funcs = blk["funcs"] if blk else set()
    blk_hosts = (blk["hosts"] if blk else set()) | claim_hosts
    is_container_blk = "container_priv" in expected_sinks or orig_claim.technique_id == "T1611"

    matched_patched: List[Dict[str, Any]] = []
    for p_blk in patched_blocks:
        if not (p_blk["controls"] or p_blk["sinks"] or p_blk["routes"] or p_blk["funcs"] or p_blk["hosts"]):
            continue
        if blk_hosts and p_blk["hosts"] and blk_hosts.isdisjoint(p_blk["hosts"]):
            continue
        if is_container_blk:
            if p_blk["kind"] == "config" or "privilege_dropped" in p_blk["controls"]:
                matched_patched.append(p_blk)
            continue
        if blk_routes or blk_funcs or blk_hosts:
            route_hit = bool(blk_routes and (blk_routes & p_blk["routes"]))
            func_hit = bool(blk_funcs and (blk_funcs & p_blk["funcs"]))
            host_hit = bool(blk_hosts and (blk_hosts & p_blk["hosts"]))
            if route_hit or func_hit or host_hit:
                matched_patched.append(p_blk)
        else:
            matched_patched.append(p_blk)

    if not matched_patched:
        return False

    local_controls: Set[str] = {ctrl for pb in matched_patched for ctrl in pb["controls"]}
    if expected_sinks:
        return all(required_for_sink[s] in local_controls for s in expected_sinks if s in required_for_sink)
    if orig_claim.technique_id == "T1552.005":
        return "url_allowlist" in local_controls
    if orig_claim.technique_id == "T1611":
        return "privilege_dropped" in local_controls
    if orig_claim.technique_id == "T1190":
        return "parameterized_sql" in local_controls or "input_validation" in local_controls
    return bool(local_controls)


def _retain_unresolved_claim_surfaces(
    orig_claim: AnalyticalClaim,
    orig_ing: ArtifactIngestionResult,
    patched_ing: ArtifactIngestionResult,
    new_active: List[AnalyticalClaim],
) -> Optional[AnalyticalClaim]:
    """Keep only the subset of blocks/evidences from orig_claim that were neither mitigated nor covered in new_active."""
    orig_ev_by_id = {ev.evidence_id: ev for ev in orig_ing.evidences}
    orig_ev_to_blk, orig_blocks = _map_evidence_to_surface_blocks(orig_ing)
    cand_ev_to_blk, patched_blocks = _map_evidence_to_surface_blocks(patched_ing)

    claim_evs = [orig_ev_by_id[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_by_id]
    claim_sinks = {s for ev in claim_evs for s in ev.entities.get("sinks", [])}
    claim_blk_ids = sorted({orig_ev_to_blk[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_to_blk})
    claim_hosts = {h.lower() for h in orig_claim.subject_entities.get("hosts", []) if h}

    if not claim_blk_ids:
        if _block_is_mitigated_in_patched(orig_claim, None, claim_sinks, patched_blocks, claim_hosts):
            return None
        if any(_claims_semantically_match(orig_claim, nc) for nc in new_active):
            return None
        return orig_claim

    # Build surface signatures for every new active claim
    matching_cand_claims = [nc for nc in new_active if _claims_semantically_match(orig_claim, nc)]
    cand_claim_surfaces: List[Tuple[Set[str], Set[str], Set[str], bool]] = []
    for nc in matching_cand_claims:
        nc_blk_ids = {cand_ev_to_blk[eid] for eid in nc.evidence_ids if eid in cand_ev_to_blk}
        nc_routes: Set[str] = {ep.split("?", 1)[0].lower() for ep in nc.subject_entities.get("endpoints", []) if ep.startswith("/")}
        nc_funcs: Set[str] = set()
        nc_hosts: Set[str] = {h.lower() for h in nc.subject_entities.get("hosts", []) if h}
        nc_is_config = False
        for nbid in nc_blk_ids:
            nb = patched_blocks[nbid]
            nc_routes.update(r.lower() for r in nb["routes"])
            nc_funcs.update(nb["funcs"])
            nc_hosts.update(nb["hosts"])
            if nb["kind"] == "config":
                nc_is_config = True
        cand_claim_surfaces.append((nc_routes, nc_funcs, nc_hosts, nc_is_config))

    retained_eids: List[str] = []
    retained_routes: List[str] = []
    for bid in claim_blk_ids:
        blk = orig_blocks[bid]
        blk_eids = [eid for eid in orig_claim.evidence_ids if orig_ev_to_blk.get(eid) == bid]
        blk_evs = [orig_ev_by_id[eid] for eid in blk_eids if eid in orig_ev_by_id]
        blk_sinks = {s for ev in blk_evs for s in ev.entities.get("sinks", [])}
        expected_sinks = blk_sinks or (claim_sinks if len(claim_blk_ids) == 1 else set())

        if _block_is_mitigated_in_patched(orig_claim, blk, expected_sinks, patched_blocks, claim_hosts):
            continue

        blk_routes_low = {r.lower() for r in blk["routes"]}
        blk_funcs = set(blk["funcs"])
        blk_hosts = set(blk["hosts"]) | claim_hosts
        blk_is_config = blk["kind"] == "config" or "container_priv" in expected_sinks

        covered_by_new = False
        for nc_routes, nc_funcs, nc_hosts, nc_is_cfg in cand_claim_surfaces:
            if blk_is_config and nc_is_cfg:
                if not (blk_hosts and nc_hosts and blk_hosts.isdisjoint(nc_hosts)):
                    covered_by_new = True
                    break
            if blk_routes_low or blk_funcs or blk_hosts:
                routes_ok = (not blk_routes_low) or (blk_routes_low <= nc_routes)
                funcs_ok = (not blk_funcs) or (blk_funcs <= nc_funcs)
                hosts_ok = (not blk_hosts) or (blk_hosts <= nc_hosts)
                if routes_ok and funcs_ok and hosts_ok and ((blk_routes_low & nc_routes) or (blk_funcs & nc_funcs) or (blk_hosts & nc_hosts)):
                    covered_by_new = True
                    break
            elif matching_cand_claims:
                covered_by_new = True
                break

        if not covered_by_new:
            for eid in blk_eids:
                if eid not in retained_eids:
                    retained_eids.append(eid)
            for rt in blk["routes"]:
                if rt not in retained_routes:
                    retained_routes.append(rt)

    if not retained_eids:
        return None
    if len(retained_eids) == len(orig_claim.evidence_ids):
        return orig_claim

    subj = _collect_subject_entities(orig_ev_by_id, retained_eids)
    for rt in retained_routes:
        if rt not in subj["endpoints"]:
            subj["endpoints"].append(rt)
    obs = _format_observed_fact(orig_ev_by_id, retained_eids, "Unresolved omitted/unmitigated surface:")
    return orig_claim.model_copy(
        update={
            "evidence_ids": retained_eids,
            "subject_entities": subj,
            "observed_fact": obs,
        }
    )


def _is_claim_remediated_by_patch(
    orig_claim: AnalyticalClaim,
    orig_ing: ArtifactIngestionResult,
    patched_ing: ArtifactIngestionResult,
    new_active: List[AnalyticalClaim],
) -> bool:
    """Confirm every surface block cited by an original claim is absent from new_active and mitigated on its own block."""
    if any(_claims_semantically_match(orig_claim, nc) for nc in new_active):
        return False

    orig_ev_to_blk, orig_blocks = _map_evidence_to_surface_blocks(orig_ing)
    _, patched_blocks = _map_evidence_to_surface_blocks(patched_ing)

    claim_evs = [ev for ev in orig_ing.evidences if ev.evidence_id in orig_claim.evidence_ids]
    claim_sinks = {s for ev in claim_evs for s in ev.entities.get("sinks", [])}
    claim_blk_ids = sorted({orig_ev_to_blk[eid] for eid in orig_claim.evidence_ids if eid in orig_ev_to_blk})
    claim_hosts = {h.lower() for h in orig_claim.subject_entities.get("hosts", []) if h}

    if claim_blk_ids:
        for bid in claim_blk_ids:
            blk = orig_blocks[bid]
            blk_evs = [ev for ev in claim_evs if orig_ev_to_blk.get(ev.evidence_id) == bid]
            blk_sinks = {s for ev in blk_evs for s in ev.entities.get("sinks", [])}
            expected_sinks = blk_sinks or (claim_sinks if len(claim_blk_ids) == 1 else set())
            if blk_evs and not _block_is_mitigated_in_patched(orig_claim, blk, expected_sinks, patched_blocks, claim_hosts):
                return False
        return True

    return _block_is_mitigated_in_patched(orig_claim, None, claim_sinks, patched_blocks, claim_hosts)


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
                updated = candidate
                added_ids = [ev.evidence_id for ev in candidate.ingestion.evidences]
                remaining_ids = []
            else:
                rem_status = "PARTIALLY_MITIGATED" if resolved_ids else "STILL_VULNERABLE"
                unmatched_unresolved: List[AnalyticalClaim] = []
                for orig_c in unresolved_orig:
                    retained_c = _retain_unresolved_claim_surfaces(
                        orig_c, orig_report.ingestion, candidate.ingestion, new_active
                    )
                    if retained_c is not None:
                        unmatched_unresolved.append(retained_c)

                orig_evs = list(orig_report.ingestion.evidences)
                base_seq = len(orig_evs)
                cand_eid_map: Dict[str, str] = {}
                appended_evs = []
                for offset, cev in enumerate(candidate.ingestion.evidences, start=1):
                    new_eid = f"EV-{base_seq + offset:04d}"
                    cand_eid_map[cev.evidence_id] = new_eid
                    # Preserve cev.line_or_seq so line 1 marks candidate boundary in surface blocks
                    appended_evs.append(cev.model_copy(update={"evidence_id": new_eid}))

                merged_ingestion = orig_report.ingestion.model_copy(
                    update={
                        "total_records": len(orig_evs) + len(appended_evs),
                        "evidences": [*orig_evs, *appended_evs],
                    }
                )
                added_ids = [cev.evidence_id for cev in appended_evs]

                cand_cid_map: Dict[str, str] = {}
                shifted_cand_claims: List[AnalyticalClaim] = []
                used_cids = {c.claim_id for c in unmatched_unresolved}
                next_idx = 1
                cand_claims_to_keep = list(candidate.red_report.claims) if new_active else []
                for nc in cand_claims_to_keep:
                    old_cid = nc.claim_id
                    cid = old_cid
                    while not cid or cid in used_cids:
                        cid = f"CLM-{next_idx:02d}"
                        next_idx += 1
                    used_cids.add(cid)
                    if old_cid:
                        cand_cid_map[old_cid] = cid
                    shifted_cand_claims.append(
                        nc.model_copy(
                            update={
                                "claim_id": cid,
                                "evidence_ids": [cand_eid_map.get(eid, eid) for eid in nc.evidence_ids],
                            }
                        )
                    )

                combined_claims = [*shifted_cand_claims, *unmatched_unresolved]
                all_combined_cids = {c.claim_id for c in combined_claims}
                remaining_ids = [c.claim_id for c in combined_claims if c.status in ("supported", "open")]
                sup_ids = [c.claim_id for c in combined_claims if c.status == "supported"]
                open_ids = [c.claim_id for c in combined_claims if c.status == "open"]
                refuted_ids = [c.claim_id for c in combined_claims if c.status == "refuted"]

                base_verdict_source = candidate if new_active else orig_report
                has_code = (
                    orig_report.ingestion.source_kind in ("code", "config")
                    or candidate.ingestion.source_kind in ("code", "config")
                )
                supported_ev_count = len({
                    eid for c in combined_claims if c.status == "supported" for eid in c.evidence_ids
                })
                if sup_ids:
                    eff_verdict = classify_supported_verdict(
                        "code" if has_code else "log",
                        len(sup_ids),
                        supported_ev_count,
                    )
                    diag_status = "CONFIRMED_THREAT"
                elif open_ids:
                    eff_verdict = VerdictType.INSUFFICIENT_EVIDENCE
                    diag_status = "OPEN_HYPOTHESIS"
                else:
                    eff_verdict = base_verdict_source.verdict.verdict
                    diag_status = "OPEN_HYPOTHESIS"

                retained_orig_cids = {c.claim_id for c in unmatched_unresolved}
                retained_orig_by_cid = {c.claim_id: c for c in unmatched_unresolved}
                remapped_steps = []
                if new_active:
                    for step in candidate.red_report.kill_chain:
                        mapped_cid = cand_cid_map.get(step.claim_id, step.claim_id)
                        if mapped_cid in all_combined_cids:
                            remapped_steps.append(
                                step.model_copy(
                                    update={
                                        "claim_id": mapped_cid,
                                        "evidence_ids": [cand_eid_map.get(eid, eid) for eid in step.evidence_ids],
                                    }
                                )
                            )
                for step in orig_report.red_report.kill_chain:
                    if step.claim_id in retained_orig_cids:
                        rc = retained_orig_by_cid[step.claim_id]
                        remapped_steps.append(
                            step.model_copy(
                                update={
                                    "evidence_ids": list(rc.evidence_ids),
                                    "observed_fact": rc.observed_fact,
                                }
                            )
                        )

                remapped_sims = []
                cand_new_cids = set(cand_cid_map.values())
                if new_active:
                    for sim in candidate.red_report.simulated_events:
                        new_scid = cand_cid_map.get(sim.claim_id, sim.claim_id)
                        if not sim.claim_id or new_scid in cand_new_cids:
                            remapped_sims.append(
                                sim.model_copy(
                                    update={
                                        "event_id": f"SIM-RED-{len(remapped_sims) + 1:02d}",
                                        "claim_id": new_scid,
                                    }
                                )
                            )
                for sim in orig_report.red_report.simulated_events:
                    if sim.claim_id in retained_orig_cids or (not new_active and not sim.claim_id):
                        remapped_sims.append(
                            sim.model_copy(update={"event_id": f"SIM-RED-{len(remapped_sims) + 1:02d}"})
                        )

                red_cited = list(dict.fromkeys([eid for c in combined_claims for eid in c.evidence_ids]))
                merged_red = base_verdict_source.red_report.model_copy(
                    update={
                        "kill_chain": remapped_steps,
                        "claims": combined_claims,
                        "simulated_events": remapped_sims,
                        "cited_evidence_ids": red_cited,
                    }
                )

                remapped_contras = []
                if new_active:
                    for contra in candidate.blue_report.contradictions:
                        mapped_tcid = (
                            cand_cid_map.get(contra.target_claim_id, contra.target_claim_id)
                            if contra.target_claim_id
                            else None
                        )
                        if contra.target_claim_id and mapped_tcid not in all_combined_cids:
                            mapped_tcid = None
                        remapped_contras.append(
                            contra.model_copy(
                                update={
                                    "target_claim_id": mapped_tcid,
                                    "target_evidence_ids": [cand_eid_map.get(e, e) for e in contra.target_evidence_ids],
                                    "contradicting_evidence_ids": [
                                        cand_eid_map.get(e, e) for e in contra.contradicting_evidence_ids
                                    ],
                                }
                            )
                        )
                    blue_cited_base = [cand_eid_map.get(e, e) for e in candidate.blue_report.cited_evidence_ids]
                else:
                    blue_cited_base = list(orig_report.blue_report.cited_evidence_ids)

                seen_contras = {(c.claim_challenged, tuple(c.contradicting_evidence_ids)) for c in remapped_contras}
                for contra in orig_report.blue_report.contradictions:
                    if not new_active or contra.target_claim_id in retained_orig_cids:
                        sig = (contra.claim_challenged, tuple(contra.contradicting_evidence_ids))
                        if sig not in seen_contras:
                            seen_contras.add(sig)
                            remapped_contras.append(contra)
                            for eid in contra.contradicting_evidence_ids:
                                if eid not in blue_cited_base:
                                    blue_cited_base.append(eid)

                merged_blue = base_verdict_source.blue_report.model_copy(
                    update={
                        "contradictions": remapped_contras,
                        "cited_evidence_ids": list(dict.fromkeys(blue_cited_base)),
                    }
                )

                refuted_cids = set(refuted_ids)
                merged_replay = run_purple_replay(
                    merged_ingestion,
                    merged_red,
                    merged_blue,
                    skip_claim_ids=refuted_cids if (sup_ids and refuted_cids) else None,
                )
                merged_sim_summary = build_simulation_summary(merged_replay)
                merged_verified = list(dict.fromkeys([*merged_red.cited_evidence_ids, *merged_blue.cited_evidence_ids]))

                merged_diag = base_verdict_source.verdict.diagnosis.model_copy(
                    update={
                        "status": diag_status,
                        "supported_claims_count": len(sup_ids),
                        "open_claims_count": len(open_ids),
                        "refuted_claims_count": len(refuted_ids),
                        "supported_claim_ids": sup_ids,
                        "open_claim_ids": open_ids,
                        "refuted_claim_ids": refuted_ids,
                        "summary": (
                            f"{len(remaining_ids)} unresolved/new active threat claim(s) remain after patch check."
                        ),
                    }
                )
                updated = base_verdict_source.model_copy(
                    update={
                        "ingestion": merged_ingestion,
                        "red_report": merged_red,
                        "blue_report": merged_blue,
                        "verdict": base_verdict_source.verdict.model_copy(
                            update={
                                "verdict": eff_verdict,
                                "verified_citations": merged_verified,
                                "replay": merged_replay,
                                "simulation": merged_sim_summary,
                                "diagnosis": merged_diag,
                            }
                        ),
                    }
                )

            after_v = updated.verdict.verdict
            rem_summary = RemediationVerificationSummary(
                status=rem_status,  # type: ignore[arg-type]
                verified_at=datetime.now(timezone.utc).isoformat(),
                verification_source="verify_patch",
                added_evidence_ids=added_ids,
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
