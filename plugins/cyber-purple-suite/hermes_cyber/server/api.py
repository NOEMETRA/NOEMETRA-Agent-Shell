"""FastAPI REST router for NOEMETRA Cyber Purple Suite (/api/plugins/cyber-purple-suite/)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from hermes_cyber.router_bridge import (
    bind_cyber_profile_scope,
    compute_home_fingerprint,
)
from hermes_cyber.server.state import _evict_dead_assistants, get_cyber_assistant
from hermes_voice.server.api import _resolve_authorized_context

logger = logging.getLogger(__name__)


async def _bind_cyber_scope(request: Request, response: Response):
    profile_name, authorized_home = _resolve_authorized_context(request)
    request.state._cyber_resolved_context = (profile_name, authorized_home)
    if authorized_home:
        response.headers["X-Hermes-Voice-Home-Sha256"] = compute_home_fingerprint(authorized_home)
    try:
        with bind_cyber_profile_scope(home_dir=authorized_home, profile=profile_name):
            yield
    except FileNotFoundError as exc:
        _evict_dead_assistants()
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


router = APIRouter(dependencies=[Depends(_bind_cyber_scope)])


def _req_assistant(request: Request):
    ctx = getattr(request.state, "_cyber_resolved_context", None)
    if isinstance(ctx, tuple) and len(ctx) == 2:
        profile_name, authorized_home = ctx
        return get_cyber_assistant(profile=profile_name, home_dir=authorized_home)
    return get_cyber_assistant()


class ScenarioAnalyzeRequest(BaseModel):
    scenario_id: str


class CustomAnalyzeRequest(BaseModel):
    title: str = "Custom Artifact"
    content: str
    source_kind: str = "auto"


class ReplayTuneRequest(BaseModel):
    case_id: str
    detection_keywords: List[str]
    exclude_values: List[str] = []


class CaseVerifyRequest(BaseModel):
    case_id: str
    content: str
    mode: Literal["append_evidence", "verify_patch"] = "verify_patch"


class ArenaConfigRequest(BaseModel):
    allow_remote: Optional[bool] = None
    red_provider: Optional[str] = None
    red_model: Optional[str] = None
    blue_provider: Optional[str] = None
    blue_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    use_llm: Optional[bool] = None


class AckMissionRunRequest(BaseModel):
    mission_id: str
    mutation_rounds: int = 3
    defense_mode: Literal[
        "structural",
        "naive_string_replace",
        "naive_block_all",
        "overbroad_alert_all",
    ] = "structural"


@router.get("/status")
async def get_cyber_status(request: Request):
    return _req_assistant(request).get_status()


@router.get("/scenarios")
async def get_cyber_scenarios(request: Request):
    return {"scenarios": [s.model_dump(mode="json") for s in _req_assistant(request).list_scenarios()]}


@router.get("/cases")
async def list_cyber_cases(request: Request):
    return {"cases": _req_assistant(request).list_cases()}


@router.get("/cases/{case_id}")
async def get_cyber_case(case_id: str, request: Request):
    try:
        return _req_assistant(request).get_case(case_id).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/analyze/scenario")
async def analyze_cyber_scenario(req: ScenarioAnalyzeRequest, request: Request):
    assistant = _req_assistant(request)
    try:
        report = await asyncio.to_thread(assistant.analyze_scenario, req.scenario_id)
        return report.model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/analyze/custom")
async def analyze_cyber_custom(req: CustomAnalyzeRequest, request: Request):
    assistant = _req_assistant(request)
    try:
        report = await asyncio.to_thread(
            assistant.analyze_custom,
            title=req.title,
            content=req.content,
            source_kind=req.source_kind,
        )
        return report.model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/replay")
async def rerun_purple_replay(req: ReplayTuneRequest, request: Request):
    assistant = _req_assistant(request)
    try:
        replay = assistant.rerun_replay(
            case_id=req.case_id,
            detection_keywords=req.detection_keywords,
            exclude_values=req.exclude_values,
        )
        return replay.model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/verify")
async def verify_cyber_case_update(req: CaseVerifyRequest, request: Request):
    assistant = _req_assistant(request)
    try:
        report = await asyncio.to_thread(
            assistant.verify_case_update,
            case_id=req.case_id,
            content=req.content,
            mode=req.mode,
        )
        return report.model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/benchmark")
async def run_cyber_benchmark(request: Request):
    assistant = _req_assistant(request)
    bench = await asyncio.to_thread(assistant.run_benchmark)
    return bench.model_dump(mode="json")


@router.get("/ack/missions")
async def list_ack_missions(request: Request):
    assistant = _req_assistant(request)
    return {"missions": [m.model_dump(mode="json") for m in assistant.list_ack_missions()]}


@router.post("/ack/run")
async def run_ack_mission(req: AckMissionRunRequest, request: Request):
    assistant = _req_assistant(request)
    try:
        report = await asyncio.to_thread(
            assistant.run_ack_mission,
            req.mission_id,
            mutation_rounds=req.mutation_rounds,
            defense_mode=req.defense_mode,
        )
        return report.model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/models")
async def get_cyber_models(request: Request, refresh: bool = False):
    assistant = _req_assistant(request)
    red_status = await asyncio.to_thread(assistant.red_router.get_providers_status, refresh=refresh)
    return {
        **red_status,
        "red_provider": assistant.red_router.default_provider,
        "red_model": assistant.red_router.ollama_model,
        "red_is_local": assistant.red_router.is_active_endpoint_local(),
        "blue_provider": assistant.blue_router.default_provider,
        "blue_model": assistant.blue_router.ollama_model,
        "blue_is_local": assistant.blue_router.is_active_endpoint_local(),
        "use_llm": assistant.use_llm,
    }


@router.post("/config")
async def configure_cyber_arena(req: ArenaConfigRequest, request: Request):
    assistant = _req_assistant(request)
    assistant.configure_arena(
        allow_remote=req.allow_remote,
        red_provider=req.red_provider,
        red_model=req.red_model,
        blue_provider=req.blue_provider,
        blue_model=req.blue_model,
        llm_base_url=req.llm_base_url,
        use_llm=req.use_llm,
    )
    return assistant.get_status()
