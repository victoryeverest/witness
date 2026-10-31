"""FastAPI app for WITNESS backend.

Run with:
    uvicorn witness.api.app:app --host 0.0.0.0 --port 8000

All routes are documented via OpenAPI at /docs.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import init_db, get_session, session_scope, drop_db
from ..models import (
    Incident, Investigation, InvestigationTask, Hypothesis,
    Action, Approval, AuditLog, Asset, OTAsset, DetectionRule, ThreatIntel, Report, BenchmarkRun, Scenario,
)
from ..schemas import (
    AgentInput,
)
from ..core.evidence import (
    add_evidence, list_evidence, get_evidence, to_dto as ev_to_dto, verify_chain,
)
from ..core.hypothesis import HypothesisEngine
from ..core.timeline import TimelineEngine
from ..core.coverage import compute_coverage, investigation_gaps
from ..core.graph import build_graph_for_investigation
from ..core.counter_evidence import build_plans, would_change_mind, generate_counter_hypothesis
from ..policy.engine import (
    evaluate_tool_policy, record_action, approve_action, reject_action,
    execute_action, escalate_with_ot_assessment, user_has_permissions,
    PolicyError, _TOOL_PERMISSIONS,
)
from ..ot.safety import classify_ot_action, OT_ASSET_KINDS
from ..range.cyber_range import (
    load_scenario_into_db, get_scenario_telemetry_state, ALL_SCENARIOS,
)
from ..runtime.runtime import (
    create_investigation, run_investigation, pause_investigation,
    resume_investigation, cancel_investigation, InvestigationStateError,
    start_background_run, background_run_active,
)
from ..benchmark.bench import (
    run_benchmark, run_all_benchmarks, summarize_benchmarks, build_state_snapshot,
    run_baseline, evaluate_investigation, compute_investigation_score,
)
from .auth import Principal, get_principal, check_startup_security, require_role
from ..agents import list_agent_names, get_agent_class
from ..tools import list_tools  # auto-registers all tools
from ..detection.engine import load_builtin_rules, evaluate_all_rules
from ..detection.rulegen import (
    propose_sigma_rule_from_evidence, propose_yara_rule_from_evidence,
    validate_all_pending,
)
from ..knowledge.attack_loader import load_attack_knowledge, get_attack_index, reset_attack_index
from ..core.baseline import detect_deviations as detect_baseline_deviations, anomalies_as_evidence
from ..core.nl_query import translate as translate_nl_query
from ..utils.logging import configure_logging, get_logger
from ..utils.time import utc_now


configure_logging()
log = get_logger("witness.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup", extra={"ctx_env": settings.environment})
    check_startup_security()
    if settings.auth_mode == "none":
        log.warning("auth_disabled: WITNESS_AUTH_MODE=none — every caller is trusted. "
                    "Development only.")
    await init_db()
    # Load built-in detection rules (§19) and MITRE ATT&CK knowledge (§99).
    async with session_scope() as session:
        n_rules = await load_builtin_rules(session)
        if n_rules:
            log.info(f"builtin_rules_loaded:{n_rules}")
        if settings.autoload_attack:
            try:
                summary = await load_attack_knowledge(session)
                log.info(f"attack_knowledge_loaded:{summary}")
                await reset_attack_index()
            except Exception as e:
                log.warning(f"attack_knowledge_load_failed:{e}")
    yield
    from ..models_layer.base import close_all_providers
    await close_all_providers()
    log.info("shutdown")


API_VERSION = "1.0.0"

app = FastAPI(
    title="WITNESS — Evidence-Driven Autonomous Cyber Defense",
    description=(
        "WITNESS is an evidence-driven, hypothesis-based autonomous cyber-"
        "defense and investigation platform. Don't ask the AI what happened. "
        "Make it prove what happened."),
    version=API_VERSION,
    lifespan=lifespan,
    dependencies=[Depends(get_principal)],
)


@app.exception_handler(PolicyError)
async def _policy_error_handler(request: Request, exc: PolicyError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})


@app.exception_handler(InvestigationStateError)
async def _state_error_handler(request: Request, exc: InvestigationStateError) -> JSONResponse:
    return JSONResponse(status_code=409, content={"detail": str(exc)})


async def _require_investigation(session: AsyncSession, investigation_id: str) -> Investigation:
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "investigation_not_found")
    return inv


async def _scenario_state(session: AsyncSession, scenario_id: Optional[str]) -> dict[str, Any]:
    if not scenario_id:
        return {}
    scn = await session.get(Scenario, scenario_id)
    if not scn:
        raise HTTPException(404, "scenario_not_found")
    state = get_scenario_telemetry_state(scn)
    state["scenario_id"] = scn.id
    return state


@app.get("/health")
async def health() -> dict[str, Any]:
    from ..core.model_assist import assist_enabled
    return {"status": "ok", "version": API_VERSION,
            "model_provider": settings.model_provider,
            "model_assist": assist_enabled(),
            "privacy_mode": settings.privacy_mode,
            "auth_mode": settings.auth_mode}


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

class LoginIn(BaseModel):
    email: str
    password: Optional[str] = None


@app.post("/auth/login")
async def login(body: LoginIn, session: AsyncSession = Depends(get_session),
                principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Development-only user lookup. It never authenticated anyone; with
    WITNESS_AUTH_MODE=token use bearer tokens and GET /auth/whoami instead."""
    if settings.auth_mode == "token":
        raise HTTPException(410, "login_disabled_in_token_mode: use a bearer token")
    from ..models import User
    res = await session.execute(select(User).where(User.email == body.email))
    u = res.scalar_one_or_none()
    if not u:
        u = User(id=f"U-{uuid.uuid4().hex[:8]}", email=body.email, role="analyst")
        session.add(u)
        await session.flush()
    return {"user_id": u.id, "email": u.email, "role": u.role}


@app.get("/auth/whoami")
async def whoami(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    return {"user_id": principal.user_id, "role": principal.role,
            "authenticated": principal.authenticated, "auth_mode": settings.auth_mode}


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #

def _asset_dict(a: Asset) -> dict[str, Any]:
    return {
        "id": a.id, "name": a.name, "kind": a.kind, "hostname": a.hostname,
        "ip_address": a.ipAddress, "zone": a.zone, "criticality": a.criticality,
        "owner": a.owner, "business_function": a.businessFunction,
        "safety_classification": a.safetyClassification,
        "maintenance_state": a.maintenanceState, "redundancy": a.redundancy,
        "dependencies": a.dependencies, "attributes": a.attributes,
    }


@app.get("/assets")
async def list_assets(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    # Serializing ORM `__dict__` leaked SQLAlchemy's InstanceState and
    # crashed this endpoint with a 500 on every call.
    res = await session.execute(select(Asset).order_by(Asset.id))
    return [_asset_dict(a) for a in res.scalars().all()]


@app.get("/assets/{asset_id}")
async def get_asset(asset_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = await session.get(Asset, asset_id)
    if not a:
        raise HTTPException(404, "asset_not_found")
    ot: Optional[OTAsset] = None
    res = await session.execute(select(OTAsset).where(OTAsset.assetId == asset_id))
    ot = res.scalar_one_or_none()
    out = _asset_dict(a)
    if ot:
        out["ot"] = {
            "ot_type": ot.otType, "protocol": ot.protocol,
            "vendor": ot.vendor, "firmware": ot.firmware,
            "physical_process": ot.physicalProcess,
            "safety_impact": ot.safetyImpact,
            "process_variables": ot.processVariables,
        }
    return out


@app.post("/assets")
async def create_asset(body: dict[str, Any],
                        session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    if not body.get("name") or not body.get("kind"):
        raise HTTPException(422, "name_and_kind_required")
    if body.get("id") and await session.get(Asset, body["id"]):
        raise HTTPException(409, "asset_exists")
    a = Asset(
        id=body.get("id") or f"ASSET-{uuid.uuid4().hex[:8].upper()}",
        name=body["name"], kind=body["kind"],
        hostname=body.get("hostname"), ipAddress=body.get("ip_address"),
        zone=body.get("zone"), criticality=body.get("criticality", "medium"),
        owner=body.get("owner"), businessFunction=body.get("business_function"),
        safetyClassification=body.get("safety_classification"),
        maintenanceState=body.get("maintenance_state"),
        redundancy=body.get("redundancy"),
        dependencies=body.get("dependencies", {}),
        attributes=body.get("attributes", {}),
    )
    session.add(a)
    await session.flush()
    return {"id": a.id, "name": a.name, "kind": a.kind}


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #

class IncidentIn(BaseModel):
    title: str
    summary: Optional[str] = None
    severity: str = "medium"
    scope: str = "enterprise"


@app.get("/incidents")
async def list_incidents(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(Incident).order_by(Incident.createdAt.desc()))
    return [{
        "id": i.id, "title": i.title, "summary": i.summary,
        "severity": i.severity, "status": i.status, "scope": i.scope,
        "campaign_id": i.campaignId,
        "created_at": i.createdAt.isoformat() if i.createdAt else None,
        "detection_confidence": i.detectionConfidence,
        "evidence_coverage": i.evidenceCoverage,
    } for i in res.scalars().all()]


@app.get("/incidents/priority")
async def priority_incidents_api(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """Rank open incidents by composite priority score per §111.
    Placed BEFORE /incidents/{incident_id} so 'priority' is not captured
    as an incident ID."""
    res = await session.execute(select(Incident).where(Incident.status != "closed"))
    incs = list(res.scalars().all())
    ranked = sorted(incs, key=_incident_priority, reverse=True)
    return [{
        "id": i.id, "title": i.title, "severity": i.severity,
        "scope": i.scope, "status": i.status,
        "priority_score": _incident_priority(i),
        "detection_confidence": i.detectionConfidence,
    } for i in ranked]


@app.post("/incidents")
async def create_incident(body: IncidentIn,
                           session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inc = Incident(
        id=f"INC-{uuid.uuid4().hex[:10].upper()}",
        title=body.title, summary=body.summary,
        severity=body.severity, scope=body.scope,
    )
    session.add(inc)
    await session.flush()
    return {"id": inc.id, "title": inc.title}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str,
                        session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inc = await session.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident_not_found")
    return {
        "id": inc.id, "title": inc.title, "summary": inc.summary,
        "severity": inc.severity, "status": inc.status, "scope": inc.scope,
        "created_at": inc.createdAt.isoformat(),
        "detection_confidence": inc.detectionConfidence,
        "attribution_confidence": inc.attributionConfidence,
        "timeline_confidence": inc.timelineConfidence,
        "technique_confidence": inc.techniqueConfidence,
        "impact_confidence": inc.impactConfidence,
        "remediation_confidence": inc.remediationConfidence,
        "evidence_coverage": inc.evidenceCoverage,
    }


# --------------------------------------------------------------------------- #
# Investigations
# --------------------------------------------------------------------------- #

class InvestigationIn(BaseModel):
    title: str
    objective: str
    incident_id: Optional[str] = None
    mode: str = "alert"
    scope: Optional[list[str]] = None


@app.get("/investigations")
async def list_investigations(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(Investigation).order_by(Investigation.createdAt.desc()))
    return [{
        "id": i.id, "title": i.title, "objective": i.objective,
        "status": i.status, "mode": i.mode, "iteration": i.iteration,
        "created_at": i.createdAt.isoformat(),
        "completed_at": i.completedAt.isoformat() if i.completedAt else None,
        "final_conclusion": i.finalConclusion,
        "incident_id": i.incidentId,
    } for i in res.scalars().all()]


@app.post("/investigations")
async def create_investigation_api(body: InvestigationIn,
                                     session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inv = await create_investigation(session,
                                       title=body.title, objective=body.objective,
                                       incident_id=body.incident_id, mode=body.mode,
                                       scope=body.scope)
    return {"id": inv.id, "title": inv.title, "status": inv.status}


class RunInvestigationIn(BaseModel):
    scenario_id: Optional[str] = None  # if set, loads scenario telemetry into state
    max_iterations: Optional[int] = Field(default=None, ge=1, le=100)
    background: bool = False  # run outside the request; poll GET /investigations/{id}


@app.post("/investigations/{investigation_id}/run")
async def run_investigation_api(investigation_id: str, body: RunInvestigationIn,
                                 session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inv = await _require_investigation(session, investigation_id)
    if background_run_active(investigation_id):
        raise HTTPException(409, "investigation_already_running")
    ctx_state = await _scenario_state(session, body.scenario_id or (inv.state or {}).get("scenario_id"))
    if body.background:
        if inv.status in {"completed", "cancelled"}:
            raise HTTPException(409, f"investigation_already_{inv.status}")
        # Release the request transaction first so the runner's per-iteration
        # commits (and pause/cancel from other requests) are not blocked.
        await session.commit()
        start_background_run(investigation_id, ctx_state, body.max_iterations)
        return {"id": inv.id, "status": "running", "background": True}
    inv = await run_investigation(session, investigation_id,
                                  ctx_state=ctx_state,
                                  max_iterations=body.max_iterations)
    return {
        "id": inv.id, "status": inv.status, "iteration": inv.iteration,
        "final_conclusion": inv.finalConclusion,
    }


@app.post("/investigations/{investigation_id}/pause")
async def pause_investigation_api(investigation_id: str,
                                    session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    await _require_investigation(session, investigation_id)
    inv = await pause_investigation(session, investigation_id)
    return {"id": inv.id, "status": inv.status,
            "note": ("takes effect at the next iteration boundary"
                     if background_run_active(investigation_id) else None)}


@app.post("/investigations/{investigation_id}/resume")
async def resume_investigation_api(investigation_id: str, body: RunInvestigationIn,
                                     session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inv = await _require_investigation(session, investigation_id)
    if background_run_active(investigation_id):
        raise HTTPException(409, "investigation_already_running")
    # Telemetry is re-attached from the scenario recorded at first run, so a
    # resume without a body continues with the same data.
    ctx_state = await _scenario_state(session, body.scenario_id or (inv.state or {}).get("scenario_id"))
    if body.background:
        if inv.status in {"completed", "cancelled"}:
            raise HTTPException(409, f"cannot_resume_{inv.status}_investigation")
        inv.status = "active"
        await session.commit()
        start_background_run(investigation_id, ctx_state, body.max_iterations)
        return {"id": inv.id, "status": "running", "background": True}
    inv = await resume_investigation(session, investigation_id, ctx_state=ctx_state,
                                     max_iterations=body.max_iterations)
    return {"id": inv.id, "status": inv.status, "iteration": inv.iteration,
            "final_conclusion": inv.finalConclusion}


@app.post("/investigations/{investigation_id}/cancel")
async def cancel_investigation_api(investigation_id: str,
                                     session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    await _require_investigation(session, investigation_id)
    inv = await cancel_investigation(session, investigation_id)
    return {"id": inv.id, "status": inv.status}


@app.get("/investigations/{investigation_id}/integrity")
async def integrity_api(investigation_id: str,
                        session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Verify every evidence content hash and the chain of custody (§8)."""
    await _require_investigation(session, investigation_id)
    return await verify_chain(session, investigation_id)


@app.get("/investigations/{investigation_id}")
async def get_investigation_api(investigation_id: str,
                                 session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    inv = await _require_investigation(session, investigation_id)
    # Pull all associated state for the workspace view.
    hyps = await HypothesisEngine.list_for_investigation(session, investigation_id)
    evs = await list_evidence(session, investigation_id)
    tl = await TimelineEngine.list_for_investigation(session, investigation_id)
    coverage = await compute_coverage(session, investigation_id)
    gaps = await investigation_gaps(session, investigation_id)
    res = await session.execute(select(InvestigationTask).where(
        InvestigationTask.investigationId == investigation_id))
    tasks = res.scalars().all()
    res = await session.execute(select(Action).where(Action.investigationId == investigation_id))
    actions = res.scalars().all()
    return {
        "id": inv.id, "title": inv.title, "objective": inv.objective,
        "status": inv.status, "mode": inv.mode, "iteration": inv.iteration,
        "created_at": inv.createdAt.isoformat(),
        "completed_at": inv.completedAt.isoformat() if inv.completedAt else None,
        "final_conclusion": inv.finalConclusion,
        "incident_id": inv.incidentId,
        "coverage": coverage,
        "gaps": gaps,
        "hypotheses": [HypothesisEngine.to_dto(h).model_dump(by_alias=True) for h in hyps],
        "evidence": [ev_to_dto(e).model_dump(by_alias=True) for e in evs],
        "timeline": [TimelineEngine.to_dto(t).model_dump(by_alias=True) for t in tl],
        "tasks": [{
            "id": t.id, "agent": t.agentName, "objective": t.objective,
            "status": t.status, "confidence": t.confidence,
            "risk_level": t.riskLevel, "requires_approval": t.requiresApproval,
            "started_at": t.startedAt.isoformat() if t.startedAt else None,
            "completed_at": t.completedAt.isoformat() if t.completedAt else None,
            "error": t.error,
        } for t in tasks],
        "actions": [{
            "id": a.id, "tool_name": a.toolName, "arguments": a.arguments,
            "risk_level": a.riskLevel, "status": a.status,
            "requires_approval": a.requiresApproval,
            "approval_scope": a.approvalScope, "reversibility": a.reversibility,
            "blast_radius": a.blastRadius, "proposed_by": a.proposedBy,
            "approved_by": a.approvedBy, "verification": a.verification,
        } for a in actions],
        "running": background_run_active(investigation_id),
    }


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

class EvidenceIn(BaseModel):
    source: str
    source_type: str
    timestamp: datetime
    host: Optional[str] = None
    asset_id: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    network_context: dict[str, Any] = Field(default_factory=dict)
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    reliability: str = "high"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    synthetic: bool = False
    raw_reference: Optional[str] = None


@app.get("/evidence")
async def list_evidence_api(investigation_id: str, session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    evs = await list_evidence(session, investigation_id)
    return [ev_to_dto(e).model_dump(by_alias=True) for e in evs]


@app.post("/evidence")
async def add_evidence_api(body: EvidenceIn,
                           investigation_id: str,
                           session: AsyncSession = Depends(get_session),
                           principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    await _require_investigation(session, investigation_id)
    ev = await add_evidence(
        session, investigation_id,
        source=body.source, source_type=body.source_type,
        timestamp=body.timestamp, host=body.host,
        asset_id=body.asset_id, user=body.user, process=body.process,
        network_context=body.network_context,
        normalized_data=body.normalized_data,
        reliability=body.reliability, confidence=body.confidence,
        synthetic=body.synthetic, raw_reference=body.raw_reference,
        collection_method=f"manual:{principal.user_id}",
    )
    return {"id": ev.id, "content_hash": ev.contentHash,
            "sequence": ev.sequence, "chain_hash": ev.chainHash}


@app.get("/evidence/{evidence_id}")
async def get_evidence_api(evidence_id: str,
                            session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    ev = await get_evidence(session, evidence_id)
    if not ev:
        raise HTTPException(404, "evidence_not_found")
    return ev_to_dto(ev).model_dump(by_alias=True)


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #

@app.get("/timeline")
async def list_timeline_api(investigation_id: str,
                              session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    tl = await TimelineEngine.list_for_investigation(session, investigation_id)
    return [TimelineEngine.to_dto(t).model_dump(by_alias=True) for t in tl]


# --------------------------------------------------------------------------- #
# Graph
# --------------------------------------------------------------------------- #

@app.get("/graph")
async def get_graph_api(investigation_id: str,
                         session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    g = await build_graph_for_investigation(session, investigation_id)
    return g.to_dict()


# --------------------------------------------------------------------------- #
# Hypotheses
# --------------------------------------------------------------------------- #

class HypothesisIn(BaseModel):
    statement: str
    prior: float = 0.35
    expected_evidence: list[dict[str, Any]] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)


@app.get("/hypotheses")
async def list_hypotheses_api(investigation_id: str,
                                session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    hyps = await HypothesisEngine.list_for_investigation(session, investigation_id)
    return [HypothesisEngine.to_dto(h).model_dump(by_alias=True) for h in hyps]


@app.post("/hypotheses")
async def create_hypothesis_api(body: HypothesisIn,
                                  investigation_id: str,
                                  session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    h = await HypothesisEngine.create(
        session, investigation_id, body.statement,
        prior=body.prior, expected_evidence=body.expected_evidence,
        attack_techniques=body.attack_techniques,
        attack_tactics=body.attack_tactics,
    )
    return HypothesisEngine.to_dto(h).model_dump(by_alias=True)


@app.get("/hypotheses/{hypothesis_id}/challenge")
async def challenge_hypothesis_api(hypothesis_id: str,
                                    investigation_id: str,
                                    session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """'What would change your mind?' endpoint (§49)."""
    h = await session.get(Hypothesis, hypothesis_id)
    if not h:
        raise HTTPException(404, "hypothesis_not_found")
    return would_change_mind(h)


@app.post("/hypotheses/{hypothesis_id}/explain")
async def explain_hypothesis_api(hypothesis_id: str,
                                 session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """'Why do you believe this?' (§142). Uses the model when assistance is
    enabled and its answer passes citation checks; otherwise a deterministic
    explanation built from the evidence links."""
    from ..core.model_assist import assist_enabled, deterministic_explanation, explain_hypothesis
    h = await session.get(Hypothesis, hypothesis_id)
    if not h:
        raise HTTPException(404, "hypothesis_not_found")
    if assist_enabled():
        explanation, result = await explain_hypothesis(session, h)
        if explanation:
            return {"hypothesis_id": h.id, "source": "model", **explanation}
        fallback = deterministic_explanation(h)
        return {"hypothesis_id": h.id, "source": "deterministic",
                "model_unavailable_reason": result.reason, **fallback}
    return {"hypothesis_id": h.id, "source": "deterministic", **deterministic_explanation(h)}


@app.get("/hypotheses/{hypothesis_id}/counter_plans")
async def counter_plans_api(hypothesis_id: str,
                              investigation_id: str,
                              session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    h = await session.get(Hypothesis, hypothesis_id)
    if not h:
        raise HTTPException(404, "hypothesis_not_found")
    return build_plans(h).to_dict()


@app.post("/hypotheses/{hypothesis_id}/counter")
async def create_counter_hypothesis_api(hypothesis_id: str,
                                          investigation_id: str,
                                          session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    h = await session.get(Hypothesis, hypothesis_id)
    if not h:
        raise HTTPException(404, "hypothesis_not_found")
    ch = await generate_counter_hypothesis(session, investigation_id, h)
    return HypothesisEngine.to_dto(ch).model_dump(by_alias=True)


# --------------------------------------------------------------------------- #
# Hunting
# --------------------------------------------------------------------------- #

class HuntIn(BaseModel):
    investigation_id: str
    objective: str  # e.g. "hunt for lateral movement"
    scenario_id: Optional[str] = None  # telemetry to hunt over


@app.post("/hunting")
async def hunt_api(body: HuntIn,
                    session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Trigger a hunt-mode investigation. The orchestrator generates hunt-mode
    hypotheses (§30) and dispatches the threat hunter."""
    inv = await session.get(Investigation, body.investigation_id)
    if not inv:
        raise HTTPException(404, "investigation_not_found")
    inv.mode = "hunt"
    await session.flush()
    # Run the threat hunter agent in isolation.
    from ..agents import get_agent_class
    agent_cls = get_agent_class("threat_hunter")
    if agent_cls is None:
        raise HTTPException(500, "agent_unavailable")
    # The hunter needs the scenario telemetry, not an empty context.
    ctx_state = await _scenario_state(session, body.scenario_id or (inv.state or {}).get("scenario_id"))
    ctx_state.setdefault("synthetic", True)
    agent = agent_cls(session, ctx_state)
    inp = AgentInput(investigation_id=body.investigation_id,
                      task_id=f"TK-HUNT-{uuid.uuid4().hex[:6].upper()}",
                      objective=body.objective)
    agent._inp = inp
    out = await agent.run(inp)
    query = translate_nl_query(body.objective)
    return {"findings": len(out.findings), "summary": out.summary,
            "telemetry_rows": len(ctx_state.get("telemetry", [])),
            "structured_query": query.model_dump()}


# --------------------------------------------------------------------------- #
# Threat Intel
# --------------------------------------------------------------------------- #

@app.get("/threat-intel")
async def list_ti_api(session: AsyncSession = Depends(get_session),
                       indicator_type: Optional[str] = None) -> list[dict[str, Any]]:
    stmt = select(ThreatIntel)
    if indicator_type:
        stmt = stmt.where(ThreatIntel.indicatorType == indicator_type)
    res = await session.execute(stmt)
    return [{
        "id": t.id, "indicator_type": t.indicatorType, "indicator": t.indicator,
        "confidence": t.confidence, "source": t.source,
        "expires_at": t.expiresAt.isoformat() if t.expiresAt else None,
        "attack_techniques": t.attackTechniques,
        "metadata": t.metadata_,
    } for t in res.scalars().all()]


# --------------------------------------------------------------------------- #
# ATT&CK
# --------------------------------------------------------------------------- #

@app.get("/attack/enterprise")
async def list_attack_enterprise() -> dict[str, Any]:
    from ..attack.mapper import ENTERPRISE_TECHNIQUES
    return {"techniques": ENTERPRISE_TECHNIQUES}


@app.get("/attack/ics")
async def list_attack_ics() -> dict[str, Any]:
    from ..attack.mapper import ICS_TECHNIQUES, ICS_TACTICS
    return {"techniques": ICS_TECHNIQUES, "tactics": ICS_TACTICS}


# --------------------------------------------------------------------------- #
# OT
# --------------------------------------------------------------------------- #

@app.get("/ot/assets")
async def list_ot_assets_api(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(OTAsset))
    return [{
        "id": o.id, "asset_id": o.assetId, "ot_type": o.otType,
        "protocol": o.protocol, "vendor": o.vendor, "firmware": o.firmware,
        "physical_process": o.physicalProcess,
        "safety_impact": o.safetyImpact,
        "process_variables": o.processVariables,
    } for o in res.scalars().all()]


@app.post("/ot/safety-assessment")
async def ot_safety_assessment_api(body: dict[str, Any]) -> dict[str, Any]:
    """Run the OT safety classification on a proposed action."""
    tool_name = body.get("tool_name")
    args = body.get("arguments", {})
    asset = body.get("asset")
    a = classify_ot_action(tool_name, args, asset)
    return a.model_dump()


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #

class ProposeActionIn(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    proposed_by: str = "orchestrator"
    user_role: str = "analyst"  # ignored in token mode: the token's role is used
    rationale: str = ""


async def _asset_for_target(session: AsyncSession, target: Optional[str]) -> Optional[dict[str, Any]]:
    """Resolve a host/PLC argument to an asset dict for OT classification."""
    if not target:
        return None
    a = await session.get(Asset, target)
    if a is None:
        a = (await session.execute(select(Asset).where(
            (Asset.hostname == target) | (Asset.ipAddress == target)))).scalars().first()
    if a is None:
        return None
    d = _asset_dict(a)
    ot = (await session.execute(select(OTAsset).where(OTAsset.assetId == a.id))).scalars().first()
    ot_type = (a.attributes or {}).get("ot_type") or (ot.otType if ot else None)
    if a.kind in OT_ASSET_KINDS:
        pass
    elif ot_type in {"engineering_workstation", "hmi", "plc", "historian"}:
        d["kind"] = ot_type
    elif ot_type == "scada":
        d["kind"] = "scada_server"
    return d


@app.post("/actions/propose")
async def propose_action_api(body: ProposeActionIn,
                              investigation_id: str,
                              session: AsyncSession = Depends(get_session),
                              principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Evaluate a proposed action through the policy engine and the OT safety
    engine. The OT assessment can only make the decision stricter — it used
    to *replace* it, turning a PROHIBITED PLC command into an approvable one."""
    await _require_investigation(session, investigation_id)
    role = principal.effective_role(body.user_role) or "analyst"
    decision = evaluate_tool_policy(body.tool_name, body.arguments, user_role=role)
    target = body.arguments.get("host") or body.arguments.get("plc")
    asset = await _asset_for_target(session, target)
    if target and (asset is None or asset.get("kind") in OT_ASSET_KINDS
                   or body.tool_name == "plc_control_action"):
        # Unknown targets are treated conservatively, like OT assets (§25).
        decision = escalate_with_ot_assessment(
            decision, classify_ot_action(body.tool_name, body.arguments, asset))
    action = await record_action(
        session, investigation_id=investigation_id,
        tool_name=body.tool_name, arguments=body.arguments,
        decision=decision, proposed_by=principal.effective_user(body.proposed_by),
        rationale=body.rationale,
    )
    return {
        "action_id": action.id,
        "decision": decision.model_dump(),
        "status": action.status,
        "requires_approval": action.requiresApproval,
        "approval_scope": action.approvalScope,
    }


@app.get("/actions")
async def list_actions_api(investigation_id: Optional[str] = None, status: Optional[str] = None,
                           session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    stmt = select(Action).order_by(Action.createdAt.desc())
    if investigation_id:
        stmt = stmt.where(Action.investigationId == investigation_id)
    if status:
        stmt = stmt.where(Action.status == status)
    actions = (await session.execute(stmt)).scalars().all()
    approvals: dict[str, list[Approval]] = {}
    if actions:
        rows = (await session.execute(select(Approval).where(
            Approval.actionId.in_([a.id for a in actions])))).scalars().all()
        for ap in rows:
            approvals.setdefault(ap.actionId, []).append(ap)
    return [{
        "id": a.id, "investigation_id": a.investigationId, "tool_name": a.toolName,
        "arguments": a.arguments, "risk_level": a.riskLevel, "status": a.status,
        "requires_approval": a.requiresApproval, "approval_scope": a.approvalScope,
        "proposed_by": a.proposedBy, "approved_by": a.approvedBy,
        "reversibility": a.reversibility, "blast_radius": a.blastRadius,
        "result": a.result, "verification": a.verification,
        "created_at": a.createdAt.isoformat() if a.createdAt else None,
        "approvals": [{"role": ap.approverRole, "status": ap.status,
                       "approver_id": ap.approverId, "reason": ap.reason}
                      for ap in approvals.get(a.id, [])],
    } for a in actions]


class ApproveActionIn(BaseModel):
    action_id: str
    approver_id: Optional[str] = None  # ignored in token mode
    approver_role: str  # the approval scope signed: security | ot_engineering | process_owner
    reason: str = ""


async def _audit_human(session: AsyncSession, action: Action, actor: str,
                       verb: str, scope: str, reason: str) -> None:
    session.add(AuditLog(
        id=f"AU-{uuid.uuid4().hex[:10].upper()}", timestamp=utc_now(),
        actor=f"user:{actor}", tool=action.toolName,
        arguments={"action_id": action.id, "scope": scope, "reason": reason},
        policyDecision=verb, result={"action_status": action.status},
        humanApproval=verb == "approved", investigationId=action.investigationId,
    ))
    await session.flush()


@app.post("/actions/approve")
async def approve_action_api(body: ApproveActionIn,
                              session: AsyncSession = Depends(get_session),
                              principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    approver = principal.effective_user(body.approver_id)
    if approver == "anonymous":
        raise HTTPException(422, "approver_id_required")
    action, ap = await approve_action(
        session, body.action_id, approver_id=approver,
        approver_role=body.approver_role, reason=body.reason,
        principal_role=principal.role if principal.authenticated else None)
    await _audit_human(session, action, approver, "approved", body.approver_role, body.reason)
    return {
        "action_id": action.id, "status": action.status,
        "approved_by": action.approvedBy, "signed_scope": ap.approverRole,
    }


class RejectActionIn(BaseModel):
    action_id: str
    approver_id: Optional[str] = None  # ignored in token mode
    approver_role: str
    reason: str


@app.post("/actions/reject")
async def reject_action_api(body: RejectActionIn,
                             session: AsyncSession = Depends(get_session),
                             principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    approver = principal.effective_user(body.approver_id)
    action, ap = await reject_action(
        session, body.action_id, approver_id=approver,
        approver_role=body.approver_role, reason=body.reason,
        principal_role=principal.role if principal.authenticated else None)
    await _audit_human(session, action, approver, "rejected", body.approver_role, body.reason)
    return {"action_id": action.id, "status": action.status}


class ExecuteActionIn(BaseModel):
    action_id: str


@app.post("/actions/execute")
async def execute_action_api(body: ExecuteActionIn,
                              session: AsyncSession = Depends(get_session),
                              principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Execute a fully approved action, then verify its effect (§38)."""
    action = await session.get(Action, body.action_id)
    if not action:
        raise HTTPException(404, "action_not_found")
    if principal.authenticated and not user_has_permissions(
            principal.role or "", _TOOL_PERMISSIONS.get(action.toolName, {"*"})):
        raise HTTPException(403, f"role_cannot_execute:{action.toolName}")
    action = await execute_action(session, body.action_id, executor_id=principal.user_id)
    return {
        "action_id": action.id, "status": action.status,
        "result": action.result,
        "error": (action.result or {}).get("error") if action.status == "failed" else None,
        "verification": action.verification,
    }


# --------------------------------------------------------------------------- #
# Approvals
# --------------------------------------------------------------------------- #

@app.get("/approvals")
async def list_approvals_api(session: AsyncSession = Depends(get_session),
                              status: Optional[str] = None) -> list[dict[str, Any]]:
    stmt = select(Approval)
    if status:
        stmt = stmt.where(Approval.status == status)
    res = await session.execute(stmt.order_by(Approval.createdAt.desc()))
    return [{
        "id": a.id, "action_id": a.actionId, "approver_role": a.approverRole,
        "approver_id": a.approverId, "status": a.status, "reason": a.reason,
        "decided_at": a.decidedAt.isoformat() if a.decidedAt else None,
    } for a in res.scalars().all()]


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

@app.post("/reports/generate")
async def generate_report_api(investigation_id: str, audience: str = "analyst",
                                session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Generate an evidence-backed incident report."""
    from ..agents import get_agent_class
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "investigation_not_found")
    agent_cls = get_agent_class("reporting")
    if not agent_cls:
        raise HTTPException(500, "agent_unavailable")
    agent = agent_cls(session, {"synthetic": True})
    inp = AgentInput(investigation_id=investigation_id,
                      task_id=f"TK-REP-{uuid.uuid4().hex[:6].upper()}",
                      objective=f"Generate report for audience={audience}",
                      context={"audience": audience})
    agent._inp = inp
    out = await agent.run(inp)
    body = out.metrics.get("report", {})
    md = _render_markdown_report(body)
    report = Report(
        id=f"REP-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id, title=body.get("executive_summary", "Incident Report"),
        audience=audience, body=body, markdownBody=md,
    )
    session.add(report)
    await session.flush()
    return {
        "id": report.id, "audience": audience, "markdown": md,
        "body": body,
    }


def _render_markdown_report(body: dict[str, Any]) -> str:
    """Render the structured report. Sections follow the audience (§114-§118)."""
    md: list[str] = []
    add = md.append
    sections = body.get("sections") or ["stages", "hypotheses", "evidence", "unknown", "actions"]
    add("# WITNESS Incident Report\n\n")
    add(f"**Audience:** {body.get('audience', 'analyst')}  \n")
    add(f"**Classification:** {body.get('incident_classification', 'unknown')}  \n")
    add(f"**Severity:** {body.get('severity', 'unknown')}  \n")
    add(f"**Containment:** {body.get('containment_status', 'unknown')}\n")
    add("\n## Executive Summary\n\n" + body.get("executive_summary", "N/A") + "\n")
    narrative = body.get("narrative")
    if narrative:
        add(f"\n## Narrative\n\n_Written by {narrative.get('model') or 'the model'}; every cited "
            "evidence ID and technique was checked against the investigation._\n\n"
            + narrative["text"] + "\n")

    def bullet_list(title: str, items: list[Any]) -> None:
        add(f"\n## {title}\n\n")
        if not items:
            add("_None._\n")
        for it in items:
            add(f"- {it}\n")

    conf = body.get("confidence") or {}
    rr = body.get("remaining_risk") or {}
    for section in sections:
        if section in {"what_happened", "stages"}:
            add("\n## Attack Reconstruction\n\n")
            stages = body.get("attack_stages") or []
            if not stages:
                add("_No stage is supported by evidence._\n")
            for st in stages:
                add(f"1. **{st['stage'].replace('_', ' ').title()}** — {st['first_seen']} — "
                    f"{', '.join(st['assets']) or 'n/a'} — {', '.join(st['techniques']) or 'n/a'} "
                    f"(evidence: {', '.join(st['evidence_ids'][:3])})\n")
        elif section == "risk":
            add("\n## What Is the Risk?\n\n")
            add(f"**{rr.get('level', 'unknown')}** — {rr.get('reason', '')}\n")
        elif section == "containment":
            bullet_list("Is the Attack Contained?",
                        [f"{a['tool']} {a['arguments']} — verified: "
                         f"{(a.get('verification') or {}).get('verified')}"
                         for a in body.get("actions_performed", [])]
                        or [f"Not contained ({body.get('containment_status')})"])
        elif section == "known":
            bullet_list("What Do We Know?",
                        [f"{t} — backed by {', '.join(ids[:3])}"
                         for t, ids in (body.get("evidence_backed_techniques") or {}).items()])
        elif section == "unknown":
            bullet_list("What Don't We Know?", body.get("what_we_do_not_know", []))
        elif section == "decisions":
            bullet_list("What Must Be Decided?", body.get("decisions_required", []))
        elif section == "hypotheses":
            bullet_list("Hypotheses", [
                f"**{h['id']}** ({h['status']}, {h['confidence']:.0%}) — {h['statement']} "
                f"(support: {h['support']}, contradict: {h['contradict']})"
                for h in body.get("hypotheses", [])])
        elif section == "evidence":
            add("\n## Evidence & Coverage\n\n")
            add(f"{body.get('evidence_count', 0)} evidence items; confidence: " +
                ", ".join(f"{k} {v:.0%}" for k, v in conf.items()) + "\n")
            for d, v in (body.get("evidence_coverage") or {}).items():
                add(f"- **{d}**: {v*100:.0f}%\n")
        elif section == "actions":
            bullet_list("Response Actions", [
                f"{a['tool']} {a['arguments']} — **{a['status']}** (approval: {a['approval_scope'] or 'n/a'})"
                for a in body.get("recommended_actions", [])])
        elif section == "ot_impact":
            ot = body.get("ot_impact") or {}
            bullet_list("OT / Process Impact", [
                f"Affected OT assets: {', '.join(ot.get('affected_ot_assets', [])) or 'none'}",
                f"Process impact observed: {ot.get('process_impact_observed')}",
                f"Safety function inhibited: {ot.get('safety_function_inhibited')}",
            ])
        elif section == "provenance":
            pv = body.get("provenance") or {}
            bullet_list("Evidence Provenance", [
                f"Chain of custody intact: {pv.get('evidence_chain_intact')}",
                f"Chain head: `{pv.get('evidence_chain_head')}`",
                f"Content mismatches: {pv.get('content_mismatches')}; chain breaks: {pv.get('chain_breaks')}",
                f"Synthetic (cyber-range) evidence items: {pv.get('synthetic_evidence')}",
            ])
    add("\n## Remaining Risk\n\n")
    add(f"**Level:** {rr.get('level', 'unknown')}\n\n{rr.get('reason', '')}\n")
    return "".join(md)


@app.get("/reports/{report_id}")
async def get_report_api(report_id: str,
                          session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    r = await session.get(Report, report_id)
    if not r:
        raise HTTPException(404, "report_not_found")
    return {"id": r.id, "title": r.title, "audience": r.audience,
            "markdown": r.markdownBody, "body": r.body,
            "created_at": r.createdAt.isoformat()}


# --------------------------------------------------------------------------- #
# Benchmarks
# --------------------------------------------------------------------------- #

class BenchmarkIn(BaseModel):
    scenario_id: Optional[str] = None  # if None, run all
    model_name: Optional[str] = None


@app.post("/benchmarks/run")
async def run_benchmark_api(body: BenchmarkIn,
                              session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    if body.scenario_id and body.scenario_id not in ALL_SCENARIOS:
        raise HTTPException(404, f"unknown_scenario:{body.scenario_id}")
    if body.scenario_id:
        run = await run_benchmark(session, body.scenario_id,
                                    model_name=body.model_name or "mock-medium")
        return {"runs": 1, "summary": summarize_benchmarks([run]),
                "results": [{
                    "id": run.id, "scenario_id": run.scenarioId,
                    "model_name": run.modelName, "metrics": run.metrics,
                    "energy_estimate": run.metrics.get("energy_estimate_joules"),
                    "tokens_used": run.tokensUsed,
                    "tool_calls": run.toolCalls,
                }]}
    runs = await run_all_benchmarks(session)
    return {"runs": len(runs), "summary": summarize_benchmarks(runs),
            "results": [{
                "id": r.id, "scenario_id": r.scenarioId,
                "model_name": r.modelName, "metrics": r.metrics,
                "energy_estimate": r.metrics.get("energy_estimate_joules"),
                "tokens_used": r.tokensUsed,
                "tool_calls": r.toolCalls,
            } for r in runs]}


@app.get("/benchmarks")
async def list_benchmarks_api(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(BenchmarkRun).order_by(BenchmarkRun.startedAt.desc()))
    return [{
        "id": r.id, "scenario_id": r.scenarioId, "model_name": r.modelName,
        "status": r.status, "metrics": r.metrics,
        "energy_estimate": (r.metrics or {}).get("energy_estimate_joules"),
        "tokens_used": r.tokensUsed, "tool_calls": r.toolCalls,
        "started_at": r.startedAt.isoformat(),
        "completed_at": r.completedAt.isoformat() if r.completedAt else None,
    } for r in res.scalars().all()]


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

@app.get("/models")
async def list_models_api() -> dict[str, Any]:
    from ..core.model_assist import assist_enabled
    from ..models_layer.base import endpoint_is_local
    return {
        "provider": settings.model_provider,
        "small": settings.model_small,
        "medium": settings.model_medium,
        "strong": settings.model_strong,
        "endpoint": settings.model_endpoint or None,
        "endpoint_is_local": endpoint_is_local(settings.model_endpoint) if settings.model_endpoint else None,
        "privacy_mode": settings.privacy_mode,
        "assist": assist_enabled(),
        "assist_mode": settings.model_assist,
    }


@app.get("/models/executions")
async def list_model_executions_api(investigation_id: Optional[str] = None, limit: int = 100,
                                    session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """Every model call: tokens, latency, and whether its output was accepted (§16)."""
    from ..models import ModelExecution
    stmt = select(ModelExecution).order_by(ModelExecution.timestamp.desc()).limit(min(limit, 1000))
    if investigation_id:
        stmt = stmt.where(ModelExecution.investigationId == investigation_id)
    return [{
        "id": m.id, "investigation_id": m.investigationId, "purpose": m.taskId,
        "provider": m.provider, "model": m.model, "role": m.role,
        "prompt_tokens": m.promptTokens, "completion_tokens": m.completionTokens,
        "latency_ms": m.latencyMs, "accepted": m.success, "rejection_reason": m.error,
        "timestamp": m.timestamp.isoformat(),
    } for m in (await session.execute(stmt)).scalars().all()]


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

@app.get("/tools")
async def list_tools_api() -> list[dict[str, Any]]:
    return [t.describe() for t in list_tools()]


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #

@app.get("/agents")
async def list_agents_api() -> list[dict[str, Any]]:
    out = []
    for name in list_agent_names():
        cls = get_agent_class(name)
        out.append({
            "name": name, "description": cls.description if cls else "",
            "default_role": cls.default_role if cls else "medium",
            "domain": cls.domain if cls else None,
        })
    return out


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #

@app.get("/audit")
async def list_audit_api(session: AsyncSession = Depends(get_session),
                          investigation_id: Optional[str] = None,
                          limit: int = 100) -> list[dict[str, Any]]:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if investigation_id:
        stmt = stmt.where(AuditLog.investigationId == investigation_id)
    res = await session.execute(stmt)
    return [{
        "id": a.id, "timestamp": a.timestamp.isoformat(), "actor": a.actor,
        "agent": a.agent, "tool": a.tool, "arguments": a.arguments,
        "result": a.result, "policy_decision": a.policyDecision,
        "evidence_refs": a.evidenceRefs,
        "investigation_id": a.investigationId,
    } for a in res.scalars().all()]


# --------------------------------------------------------------------------- #
# Scenarios / Cyber Range
# --------------------------------------------------------------------------- #

@app.post("/scenarios/load")
async def load_scenario_api(scenario_key: str,
                              session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    if scenario_key not in ALL_SCENARIOS:
        raise HTTPException(404, f"unknown_scenario:{scenario_key}")
    scn = await load_scenario_into_db(session, scenario_key)
    return {"id": scn.id, "name": scn.name, "scope": scn.scope,
            "difficulty": scn.difficulty,
            "telemetry_count": len(scn.telemetry)}


@app.get("/scenarios")
async def list_scenarios_api(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(Scenario))
    return [{
        "id": s.id, "name": s.name, "scope": s.scope,
        "difficulty": s.difficulty, "description": s.description,
        "telemetry_count": len(s.telemetry),
        "has_ground_truth": bool(s.groundTruth),
    } for s in res.scalars().all()]


@app.get("/scenarios/available")
async def list_available_scenarios_api() -> list[dict[str, Any]]:
    out = []
    for key, builder in ALL_SCENARIOS.items():
        spec = builder()
        out.append({
            "key": key, "name": spec["name"], "scope": spec["scope"],
            "difficulty": spec["difficulty"], "description": spec["description"],
        })
    return out


# --------------------------------------------------------------------------- #
# Demo / Flagship endpoint (§84)
# --------------------------------------------------------------------------- #

class FlagshipDemoIn(BaseModel):
    max_iterations: int = Field(default=10, ge=1, le=100)


@app.post("/demo/flagship")
async def flagship_demo_api(body: FlagshipDemoIn,
                              session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Run the flagship IT→OT demo end-to-end."""
    # 1. Load the flagship scenario.
    scn = await load_scenario_into_db(session, "flagship")
    ctx_state = get_scenario_telemetry_state(scn)
    ctx_state["scenario_id"] = scn.id
    # 2. Create an investigation.
    inv = await create_investigation(
        session,
        title="Flagship IT→OT Intrusion Investigation",
        objective="Investigate suspicious activity. Discover the IT→OT chain.",
        mode="alert", scope=["identity", "endpoint", "network",
                              "persistence", "c2", "dfir", "ot", "process", "safety"],
    )
    # 3. Run the investigation.
    inv = await run_investigation(session, inv.id, ctx_state=ctx_state,
                                    max_iterations=body.max_iterations)
    # 4. Evaluate against ground truth with the benchmark's evaluator.
    hyps = await HypothesisEngine.list_for_investigation(session, inv.id)
    snapshot = await build_state_snapshot(session, inv.id)
    metrics = evaluate_investigation(snapshot, inv, scn.groundTruth)
    metrics["investigation_score"] = compute_investigation_score(metrics)
    return {
        "investigation_id": inv.id,
        "scenario_id": scn.id,
        "status": inv.status,
        "iteration": inv.iteration,
        "final_conclusion": inv.finalConclusion,
        "metrics": metrics,
        "hypotheses": [{
            "id": h.id, "statement": h.statement, "status": h.status,
            "confidence": h.currentConfidence,
            "support": len(h.supportEvidenceIds),
            "contradict": len(h.contradictEvidenceIds),
            "attack_techniques": h.attackTechniques,
        } for h in hyps],
        "evidence_count": len(snapshot["evidence"]),
        "timeline_count": len(snapshot["timeline"]),
        "actions_count": len(snapshot["actions"]),
        "pending_approvals": sum(a["status"] == "proposed" for a in snapshot["actions"]),
    }


# --------------------------------------------------------------------------- #
# Investigation gaps + counterfactuals
# --------------------------------------------------------------------------- #

@app.get("/investigations/{investigation_id}/gaps")
async def list_gaps_api(investigation_id: str,
                         session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    return await investigation_gaps(session, investigation_id)


@app.get("/investigations/{investigation_id}/coverage")
async def coverage_api(investigation_id: str,
                         session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await compute_coverage(session, investigation_id)


@app.get("/investigations/{investigation_id}/what-would-change-mind")
async def wwcm_api(investigation_id: str,
                    session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """§49 — list what would change the mind about each hypothesis."""
    hyps = await HypothesisEngine.list_for_investigation(session, investigation_id)
    return [would_change_mind(h) for h in hyps]


# --------------------------------------------------------------------------- #
# Detection engine (§19) — real Sigma + YARA + IOC + behavioral runtime
# --------------------------------------------------------------------------- #

@app.get("/detection/rules")
async def list_detection_rules_api(session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    res = await session.execute(select(DetectionRule))
    return [{
        "id": r.id, "rule_type": r.ruleType, "name": r.name,
        "source": r.source, "version": r.version,
        "attack_techniques": r.attackTechniques,
        "validated": r.validated, "deployed": r.deployed,
        "content_hash": r.contentHash,
    } for r in res.scalars().all()]


@app.post("/detection/evaluate")
async def evaluate_detection_api(investigation_id: str,
                                  session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Evaluate all deployed detection rules against the evidence for the
    investigation (§19). Returns matches + baseline anomalies."""
    return await evaluate_all_rules(session, investigation_id)


# --------------------------------------------------------------------------- #
# Baseline engine (§31) — detect behavioral deviations
# --------------------------------------------------------------------------- #

@app.post("/baselines/detect-deviations")
async def detect_baseline_deviations_api(investigation_id: str,
                                            session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Run the baseline engine over the investigation's evidence (§31).
    Returns deviations. Optionally ingests them as evidence."""
    deviations = await detect_baseline_deviations(session, investigation_id)
    ev_ids = await anomalies_as_evidence(session, investigation_id, deviations)
    return {"deviations": deviations, "evidence_inserted": ev_ids}


# --------------------------------------------------------------------------- #
# Knowledge layer (§99-101) — MITRE ATT&CK index + RAG
# --------------------------------------------------------------------------- #

@app.post("/knowledge/load")
async def load_knowledge_api(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Download (or use cache) MITRE ATT&CK STIX bundles and persist to
    KnowledgeItem (§99). Returns the count inserted per kind."""
    summary = await load_attack_knowledge(session)
    await reset_attack_index()
    return {"summary": summary}


@app.get("/knowledge/search")
async def search_knowledge_api(q: str, top_k: int = 10,
                                  session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """RAG-style retrieval over the MITRE ATT&CK knowledge index (§101)."""
    idx = await get_attack_index(session)
    return idx.retrieve(q, top_k=top_k)


@app.get("/knowledge/techniques")
async def list_knowledge_techniques_api(kind: Optional[str] = None,
                                            session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    idx = await get_attack_index(session)
    return idx.all_techniques(kind=kind)


@app.get("/knowledge/technique/{external_id}")
async def get_knowledge_technique_api(external_id: str,
                                          session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    idx = await get_attack_index(session)
    t = idx.technique(external_id)
    if not t:
        raise HTTPException(404, "technique_not_found")
    return t


# --------------------------------------------------------------------------- #
# PCAP investigation (§33)
# --------------------------------------------------------------------------- #

class PcapAnalyzeIn(BaseModel):
    pcap_path: str  # relative to WITNESS_PCAP_DIR


def _pcap_root() -> Path:
    root = Path(settings.pcap_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_pcap_path(user_path: str) -> Path:
    """Resolve a client-supplied path strictly inside the PCAP directory.

    Anything else is refused, so a client cannot make the server read
    arbitrary files (or learn about them from parser errors)."""
    root = _pcap_root()
    candidate = Path(user_path)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise HTTPException(403, "pcap_path_outside_pcap_dir")
    if not resolved.is_file():
        raise HTTPException(404, "pcap_not_found")
    return resolved


@app.post("/pcap/analyze")
async def analyze_pcap_api(body: PcapAnalyzeIn, investigation_id: str,
                              session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Parse a PCAP from the PCAP directory and ingest it as evidence (§33)."""
    from ..tools.pcap import parse_pcap_as_evidence
    await _require_investigation(session, investigation_id)
    path = resolve_pcap_path(body.pcap_path)
    n = await parse_pcap_as_evidence(session, investigation_id, str(path), synthetic=False)
    return {"evidence_inserted": n, "pcap": path.name}


@app.post("/pcap/upload")
async def upload_pcap_api(investigation_id: str, file: UploadFile = File(...),
                          analyze: bool = True,
                          session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Upload a capture into the PCAP directory (size-limited) and optionally
    analyze it immediately."""
    from ..tools.pcap import parse_pcap_as_evidence
    from ..utils.crypto import sha256_bytes
    await _require_investigation(session, investigation_id)
    data = await file.read(settings.pcap_max_upload_bytes + 1)
    if len(data) > settings.pcap_max_upload_bytes:
        raise HTTPException(413, "pcap_too_large")
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
        raise HTTPException(415, "not_a_pcap_or_pcapng_file")
    digest = sha256_bytes(data)
    # Name by content hash: no client-controlled path components.
    dest = _pcap_root() / f"{digest[:16]}.pcap"
    dest.write_bytes(data)
    out: dict[str, Any] = {"pcap_path": dest.name, "sha256": digest, "bytes": len(data)}
    if analyze:
        out["evidence_inserted"] = await parse_pcap_as_evidence(
            session, investigation_id, str(dest), synthetic=False)
    return out


# --------------------------------------------------------------------------- #
# Incident prioritization (§111) — _incident_priority helper.
# The actual /incidents/priority endpoint is registered at the top of the
# incidents block so it doesn't get shadowed by /incidents/{incident_id}.
# --------------------------------------------------------------------------- #

def _incident_priority(inc: Incident) -> float:
    sev_w = {"info": 0.1, "low": 0.3, "medium": 0.6, "high": 0.85, "critical": 1.0}.get(inc.severity, 0.5)
    scope_w = {"enterprise": 0.7, "ot": 0.9, "hybrid_it_ot": 1.0, "cloud": 0.7, "identity": 0.8, "network": 0.7}.get(inc.scope, 0.6)
    conf = max(0.1, inc.detectionConfidence)
    cov = max(0.1, inc.evidenceCoverage)
    return sev_w * scope_w * conf * cov


# --------------------------------------------------------------------------- #
# Rule generation (§105) — agents author Sigma/YARA rules from evidence
# --------------------------------------------------------------------------- #

class ProposeSigmaRuleIn(BaseModel):
    name: str
    event_kind: str
    matching_fields: list[str]
    description: str = ""
    attack_techniques: list[str] = Field(default_factory=list)


@app.post("/rules/propose-sigma")
async def propose_sigma_rule_api(body: ProposeSigmaRuleIn, investigation_id: str,
                                    session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Propose a Sigma rule from observed evidence (§105). The rule is
    persisted with `validated=False, deployed=False` — it requires human
    review before deployment. Auto-validation runs via /rules/validate-all.
    """
    rule = await propose_sigma_rule_from_evidence(
        session, investigation_id, name=body.name, event_kind=body.event_kind,
        matching_fields=body.matching_fields, description=body.description,
        attack_techniques=body.attack_techniques,
    )
    return {"id": rule.id, "name": rule.name, "rule_type": rule.ruleType,
            "validated": rule.validated, "deployed": rule.deployed,
            "body": rule.body}


class ProposeYaraRuleIn(BaseModel):
    name: str
    suspicious_strings: list[str]
    description: str = ""
    attack_techniques: list[str] = Field(default_factory=list)


@app.post("/rules/propose-yara")
async def propose_yara_rule_api(body: ProposeYaraRuleIn, investigation_id: str,
                                   session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    rule = await propose_yara_rule_from_evidence(
        session, investigation_id, name=body.name,
        suspicious_strings=body.suspicious_strings,
        description=body.description,
        attack_techniques=body.attack_techniques,
    )
    return {"id": rule.id, "name": rule.name, "rule_type": rule.ruleType,
            "validated": rule.validated, "deployed": rule.deployed,
            "body": rule.body}


@app.post("/rules/validate-all")
async def validate_all_rules_api(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Validate every pending (un-validated) detection rule (§105)."""
    summary = await validate_all_pending(session)
    return {"summary": summary}


# --------------------------------------------------------------------------- #
# Natural-language → query translator (§47, §107)
# --------------------------------------------------------------------------- #

class TranslateNLIn(BaseModel):
    objective: str


@app.post("/query/translate")
async def translate_nl_api(body: TranslateNLIn) -> dict[str, Any]:
    """Translate a natural-language objective into a structured query (§47, §107).

    Example:
      "Find unusual authentication into engineering workstations outside
      maintenance hours" → data_sources, filters, agent, attack_techniques.
    """
    q = translate_nl_query(body.objective)
    return q.model_dump()


# --------------------------------------------------------------------------- #
# Competitive benchmarking (§95) — non-agent LLM baseline
# --------------------------------------------------------------------------- #

@app.post("/benchmarks/run-baseline")
async def run_baseline_benchmark_api(scenario_id: str) -> dict[str, Any]:
    """Run the non-agent direct-classification baseline (§95). It is scored
    by the same evaluator and composite formula as WITNESS itself."""
    if scenario_id not in ALL_SCENARIOS:
        raise HTTPException(404, f"unknown_scenario:{scenario_id}")
    return run_baseline(scenario_id)


# --------------------------------------------------------------------------- #
# Reset (for tests / demo)
# --------------------------------------------------------------------------- #

@app.post("/system/reset")
async def reset_api(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Drop and recreate every table. Never available in production."""
    if settings.is_production or not settings.allow_reset:
        raise HTTPException(403, "reset_disabled")
    require_role(principal, "admin")
    await drop_db()
    await init_db()
    return {"status": "ok"}
