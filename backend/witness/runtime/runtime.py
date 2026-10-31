"""Agent runtime (§128, §129, §5 central loop).

The runtime owns:
- investigation state machine (active / paused / awaiting_approval / completed)
- task scheduling (one task per agent invocation)
- model-call audit + tool-call audit
- human interrupt/resume (§129)
- timeout / retry / failure handling

Investigations are resumable: state is persisted in Investigation.state and
InvestigationTask rows, so a crash does not corrupt incident state (§73).
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..agents import get_agent_class
from ..models import (
    Investigation, InvestigationTask, AuditLog, Action,
)
from ..schemas import AgentInput, AgentOutput
from ..config import settings
from ..utils.time import utc_now
from ..utils.logging import get_logger


log = get_logger("witness.runtime")


# States per §128.
S_ACTIVE = "active"
S_PAUSED = "paused"
S_AWAITING_APPROVAL = "awaiting_approval"
S_COMPLETED = "completed"
S_CANCELLED = "cancelled"


class InvestigationPaused(Exception):
    pass


class InvestigationCancelled(Exception):
    pass


class InvestigationTimeout(Exception):
    pass


async def create_investigation(
    session: AsyncSession,
    *,
    title: str,
    objective: str,
    incident_id: Optional[str] = None,
    mode: str = "alert",
    scope: list[str] | None = None,
) -> Investigation:
    inv = Investigation(
        id=f"INV-{uuid.uuid4().hex[:10].upper()}",
        incidentId=incident_id,
        title=title,
        objective=objective,
        status=S_ACTIVE,
        mode=mode,
        iteration=0,
        startedAt=utc_now(),
        state={},
        coverage={d: "active" for d in scope or [
            "identity", "endpoint", "network", "cloud", "application",
            "persistence", "c2", "dfir", "ot", "process", "safety", "memory",
        ]},
    )
    session.add(inv)
    await session.flush()
    return inv


async def _record_audit(session: AsyncSession, *,
                         investigation_id: str, actor: str, tool: Optional[str] = None,
                         arguments: Optional[dict] = None,
                         result: Optional[dict] = None,
                         policy_decision: Optional[str] = None,
                         evidence_refs: Optional[list[str]] = None,
                         task_id: Optional[str] = None) -> None:
    log.info("audit_event", extra={
        "investigation_id": investigation_id, "actor": actor, "tool": tool or "",
    })
    al = AuditLog(
        id=f"AU-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        timestamp=utc_now(),
        actor=actor,
        tool=tool,
        arguments=arguments or {},
        result=result,
        policyDecision=policy_decision,
        evidenceRefs=evidence_refs or [],
        taskIdentifier=task_id,
    )
    session.add(al)
    await session.flush()


async def _execute_task(session: AsyncSession, task: InvestigationTask,
                        ctx_state: dict[str, Any]) -> AgentOutput:
    """Execute one agent task. Captures output and persists it."""
    agent_cls = get_agent_class(task.agentName)
    if agent_cls is None:
        task.status = "failed"
        task.error = f"unknown_agent:{task.agentName}"
        task.completedAt = utc_now()
        await session.flush()
        await _record_audit(session, investigation_id=task.investigationId,
                           actor=f"agent:{task.agentName}", tool=None,
                           arguments={"task_id": task.id, "objective": task.objective},
                           result={"error": f"unknown_agent:{task.agentName}"},
                           policy_decision="agent_lookup_failed",
                           task_id=task.id)
        return AgentOutput(
            investigation_id=task.investigationId, task_id=task.id,
            agent_name=task.agentName,
            completion="blocked", summary=f"unknown agent {task.agentName}",
        )
    inp = AgentInput(
        investigation_id=task.investigationId,
        task_id=task.id,
        objective=task.objective,
        evidence_refs=task.evidenceRefs or [],
        hypothesis_refs=task.hypothesisRefs or [],
        risk_level=task.riskLevel,  # type: ignore
        context=task.input_ or {},
    )
    agent = agent_cls(session, ctx_state)
    agent._inp = inp  # type: ignore[attr-defined]
    task.status = "running"
    task.startedAt = utc_now()
    await session.flush()
    try:
        # Wrap the agent call in a timeout to honor §128.
        out = await asyncio.wait_for(
            agent.run(inp),
            timeout=settings.investigation_step_timeout_seconds,
        )
    except asyncio.TimeoutError:
        task.status = "failed"
        task.error = "agent_timeout"
        task.completedAt = utc_now()
        await session.flush()
        await _record_audit(session, investigation_id=task.investigationId,
                           actor=f"agent:{task.agentName}", tool=None,
                           arguments={"task_id": task.id},
                           result={"error": "timeout"},
                           policy_decision="timeout",
                           task_id=task.id)
        return AgentOutput(
            investigation_id=task.investigationId, task_id=task.id,
            agent_name=task.agentName, completion="blocked",
            summary="agent_timeout",
        )
    except Exception as exc:
        log.error("agent_failed", exc_info=exc, extra={
            "agent": task.agentName, "investigation_id": task.investigationId})
        task.status = "failed"
        task.error = str(exc)
        task.completedAt = utc_now()
        await session.flush()
        await _record_audit(session, investigation_id=task.investigationId,
                           actor=f"agent:{task.agentName}", tool=None,
                           arguments={"task_id": task.id},
                           result={"error": str(exc)},
                           policy_decision="agent_error",
                           task_id=task.id)
        return AgentOutput(
            investigation_id=task.investigationId, task_id=task.id,
            agent_name=task.agentName, completion="blocked",
            summary=f"error: {exc}",
        )
    # Persist the output.
    task.status = "completed"
    task.output_ = out.model_dump(by_alias=True, exclude_none=True)
    task.confidence = out.confidence_delta
    task.completedAt = utc_now()
    await session.flush()
    await _record_audit(session, investigation_id=task.investigationId,
                       actor=f"agent:{task.agentName}", tool=None,
                       arguments={"task_id": task.id, "objective": task.objective},
                       result={"completion": out.completion,
                              "findings": len(out.findings),
                              "new_evidence": len(out.new_evidence),
                              "proposed_actions": len(out.proposed_actions)},
                       evidence_refs=out.findings[0].evidence_refs if out.findings else [],
                       task_id=task.id)
    return out


async def _make_task(session: AsyncSession, *, investigation_id: str,
                     agent_name: str, objective: str,
                     parent_id: Optional[str] = None,
                     risk_level: str = "low",
                     requires_approval: bool = False,
                     context: Optional[dict] = None) -> InvestigationTask:
    t = InvestigationTask(
        id=f"TK-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        parentTaskId=parent_id,
        agentName=agent_name,
        objective=objective,
        status="pending",
        input_=context or {},
        riskLevel=risk_level,
        requiresApproval=requires_approval,
    )
    session.add(t)
    await session.flush()
    return t


# ctx_state keys persisted on the Investigation so approved actions can be
# executed and verified later, after the run's request has finished.
_SNAPSHOT_KEYS = ("assets", "active_sessions", "memory_available", "synthetic", "threat_intel")


class InvestigationStateError(Exception):
    """The investigation is not in a state that allows the request."""


def _persist_snapshot(inv: Investigation, ctx_state: dict[str, Any]) -> None:
    state = dict(inv.state or {})
    state["ctx_snapshot"] = {k: ctx_state[k] for k in _SNAPSHOT_KEYS if k in ctx_state}
    if ctx_state.get("scenario_id"):
        state["scenario_id"] = ctx_state["scenario_id"]
    inv.state = state


async def _checkpoint(session: AsyncSession, inv: Investigation, commit: bool) -> str:
    """Commit progress (when running in the background) and pick up status
    changes made by other requests — this is what makes pause/cancel work."""
    if commit:
        await session.commit()
        await session.refresh(inv)
    return inv.status


async def run_investigation(session: AsyncSession, investigation_id: str,
                            *, ctx_state: Optional[dict[str, Any]] = None,
                            max_iterations: Optional[int] = None,
                            approved_agent_names: Optional[list[str]] = None,
                            commit_each_iteration: bool = False,
                            ) -> Investigation:
    """Drive an investigation through the central loop (§5).

    Each call runs at most `max_iterations` further iterations, continuing
    from `Investigation.iteration`. The loop stops when hypotheses converge,
    when the planner has nothing left to do, at the iteration cap, or when the
    investigation is paused/cancelled (checked at every iteration boundary).
    Concluding runs the closing phase: risk ranking, response planning
    (proposals only — every action waits for human approval) and
    verification of anything already executed.
    """
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise ValueError(f"Unknown investigation {investigation_id}")
    if inv.status in {S_COMPLETED, S_CANCELLED}:
        raise InvestigationStateError(f"investigation_already_{inv.status}")
    ctx_state = ctx_state or {}
    ctx_state.setdefault("synthetic", True)
    max_iter = max_iterations or settings.investigation_max_iterations
    inv.status = S_ACTIVE
    inv.startedAt = inv.startedAt or utc_now()
    _persist_snapshot(inv, ctx_state)

    await _record_audit(session, investigation_id=inv.id, actor="runtime",
                       arguments={"mode": inv.mode, "max_iter": max_iter,
                                  "resume_from_iteration": inv.iteration},
                       result={"status": "starting"})

    from ..core.hypothesis import HypothesisEngine
    concluded = False
    for _ in range(max_iter):
        status = await _checkpoint(session, inv, commit_each_iteration)
        if status in {S_PAUSED, S_CANCELLED}:
            await _record_audit(session, investigation_id=inv.id, actor="runtime",
                               result={"status": status, "iteration": inv.iteration})
            return inv
        inv.iteration = (inv.iteration or 0) + 1
        await session.flush()

        # 1. Orchestrator generates hypotheses + next steps.
        orch_task = await _make_task(session, investigation_id=inv.id,
                                     agent_name="orchestrator",
                                     objective=inv.objective or "Investigate.")
        await _execute_task(session, orch_task, ctx_state)

        # 2. Planner ranks next steps.
        planner_task = await _make_task(session, investigation_id=inv.id,
                                        agent_name="planner",
                                        objective="Plan next investigation steps.")
        planner_out = await _execute_task(session, planner_task, ctx_state)
        next_steps = planner_out.recommended_next_steps
        if not next_steps:
            concluded = True
            break

        # 3. Execute each recommended next step (capped fan-out).
        for step in next_steps[:6]:
            agent_name = step.agent or "evidence_analyst"
            if approved_agent_names and agent_name not in approved_agent_names:
                continue
            task = await _make_task(session, investigation_id=inv.id,
                                    agent_name=agent_name,
                                    objective=step.objective,
                                    risk_level=step.risk_level)
            await _execute_task(session, task, ctx_state)

        # 3.5–3.7. Map evidence → ATT&CK, enrich with TI, and actively look
        # for disconfirming evidence (§7, §50) every iteration.
        for agent_name, objective in (
            ("attack_mapper", "Map observed evidence to ATT&CK techniques."),
            ("threat_intel_analyst", "Enrich evidence with threat intelligence."),
            ("contradiction_analyst", "Search for disconfirming evidence."),
        ):
            t = await _make_task(session, investigation_id=inv.id,
                                 agent_name=agent_name, objective=objective)
            await _execute_task(session, t, ctx_state)

        # 3.8. Model-proposed hypotheses (once, after evidence exists). They
        # start at the prior; the mapper and contradiction analyst then
        # evaluate them against the evidence in this same iteration.
        if await _model_hypotheses(session, inv):
            for agent_name, objective in (
                ("attack_mapper", "Map evidence to model-proposed hypotheses."),
                ("contradiction_analyst", "Challenge model-proposed hypotheses."),
            ):
                t = await _make_task(session, investigation_id=inv.id,
                                     agent_name=agent_name, objective=objective)
                await _execute_task(session, t, ctx_state)

        # 4. Convergence check.
        hyps = await HypothesisEngine.list_for_investigation(session, inv.id)
        top_conf = max((h.currentConfidence for h in hyps), default=0.0)
        open_count = sum(h.status in {"open", "probable"} for h in hyps)
        if top_conf >= settings.investigation_confidence_threshold and open_count <= 1:
            concluded = True
            break
    else:
        concluded = True  # iteration cap reached

    if concluded:
        status = await _checkpoint(session, inv, commit_each_iteration)
        if status in {S_PAUSED, S_CANCELLED}:
            return inv
        await _closing_phase(session, inv, ctx_state)
        inv.status = S_COMPLETED
        inv.completedAt = utc_now()
        inv.finalConclusion = await _final_conclusion_async(session, inv.id)
        await session.flush()
        if commit_each_iteration:
            await session.commit()
    return inv


async def _model_hypotheses(session: AsyncSession, inv: Investigation) -> bool:
    """Run model hypothesis proposal once per investigation. Returns True if
    any hypothesis was created. Failures are recorded and ignored."""
    from ..core.model_assist import assist_enabled, propose_hypotheses
    state = dict(inv.state or {})
    if not assist_enabled() or state.get("model_hypotheses"):
        return False
    try:
        created, result = await propose_hypotheses(session, inv.id)
    except Exception as exc:  # never let the model break an investigation
        log.error("model_hypotheses_failed", exc_info=exc, extra={"investigation_id": inv.id})
        created, result = [], None
    if result is not None and result.reason == "no_evidence":
        return False  # try again next iteration
    state["model_hypotheses"] = {
        "attempted": True, "created": [h.id for h in created],
        "ok": bool(result and result.ok), "reason": result.reason if result else "exception",
        "execution_id": result.execution_id if result else None,
        "dropped": ((result.data or {}).get("dropped", []) if result else []),
    }
    inv.state = state
    await session.flush()
    return bool(created)


async def _closing_phase(session: AsyncSession, inv: Investigation,
                         ctx_state: dict[str, Any]) -> None:
    """§5 tail: IMPACT ASSESSMENT → REMEDIATION PLANNING → (HUMAN APPROVAL)
    → POST-ACTION VERIFICATION. These agents existed but were never
    dispatched by the original loop."""
    steps = [("risk_analyst", "Rank affected assets by risk."),
             ("response_planner", "Propose containment for implicated entities.")]
    if (inv.state or {}).get("executed_actions"):
        steps.append(("verification", "Verify executed actions."))
    for agent_name, objective in steps:
        t = await _make_task(session, investigation_id=inv.id,
                             agent_name=agent_name, objective=objective)
        await _execute_task(session, t, ctx_state)


async def _final_conclusion_async(session: AsyncSession, investigation_id: str) -> str:
    from ..core.hypothesis import HypothesisEngine
    hyps = await HypothesisEngine.list_for_investigation(session, investigation_id)
    if not hyps:
        return "No hypotheses were generated."
    top = max(hyps, key=lambda h: h.currentConfidence)
    pending = (await session.execute(select(Action).where(
        Action.investigationId == investigation_id, Action.status == "proposed"
    ))).scalars().all()
    text = (
        f"Top hypothesis: '{top.statement}' "
        f"(confidence {top.currentConfidence:.0%}, status={top.status}, "
        f"support={len(top.supportEvidenceIds)}, "
        f"contradict={len(top.contradictEvidenceIds)})."
    )
    if pending:
        text += f" {len(pending)} proposed action(s) await human approval."
    return text


async def pause_investigation(session: AsyncSession, investigation_id: str) -> Investigation:
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise ValueError("not found")
    if inv.status in {S_COMPLETED, S_CANCELLED}:
        raise InvestigationStateError(f"cannot_pause_{inv.status}_investigation")
    inv.status = S_PAUSED
    await session.flush()
    return inv


async def resume_investigation(session: AsyncSession, investigation_id: str,
                                ctx_state: Optional[dict[str, Any]] = None,
                                max_iterations: Optional[int] = None) -> Investigation:
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise ValueError("not found")
    if inv.status in {S_COMPLETED, S_CANCELLED}:
        raise InvestigationStateError(f"cannot_resume_{inv.status}_investigation")
    inv.status = S_ACTIVE
    await session.flush()
    # Continues from inv.iteration (the original restarted at iteration 1).
    return await run_investigation(session, investigation_id, ctx_state=ctx_state,
                                   max_iterations=max_iterations)


async def cancel_investigation(session: AsyncSession, investigation_id: str) -> Investigation:
    inv = await session.get(Investigation, investigation_id)
    if not inv:
        raise ValueError("not found")
    if inv.status == S_COMPLETED:
        raise InvestigationStateError("cannot_cancel_completed_investigation")
    inv.status = S_CANCELLED
    inv.completedAt = utc_now()
    await session.flush()
    return inv


# Strong references to in-flight background runs (asyncio only keeps weak ones).
_BACKGROUND_RUNS: dict[str, asyncio.Task] = {}


def background_run_active(investigation_id: str) -> bool:
    t = _BACKGROUND_RUNS.get(investigation_id)
    return bool(t and not t.done())


async def _background_runner(investigation_id: str, ctx_state: dict[str, Any],
                             max_iterations: Optional[int]) -> None:
    from ..db import AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        try:
            await run_investigation(session, investigation_id, ctx_state=ctx_state,
                                    max_iterations=max_iterations,
                                    commit_each_iteration=True)
            await session.commit()
        except Exception as exc:  # pragma: no cover - logged and recorded
            log.error("background_run_failed", exc_info=exc,
                      extra={"investigation_id": investigation_id})
            await session.rollback()
            inv = await session.get(Investigation, investigation_id)
            if inv is not None:
                inv.status = "failed"
                inv.state = {**(inv.state or {}), "error": str(exc)}
                await session.commit()
        finally:
            _BACKGROUND_RUNS.pop(investigation_id, None)


def start_background_run(investigation_id: str, ctx_state: dict[str, Any],
                         max_iterations: Optional[int] = None) -> None:
    """Run an investigation outside the request. Progress is committed every
    iteration, so GET /investigations/{id} shows it live and pause/cancel
    requests take effect at the next iteration boundary (§129)."""
    if background_run_active(investigation_id):
        raise InvestigationStateError("investigation_already_running")
    _BACKGROUND_RUNS[investigation_id] = asyncio.create_task(
        _background_runner(investigation_id, ctx_state, max_iterations))
