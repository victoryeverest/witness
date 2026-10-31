"""WITNESS-Bench evaluation framework (§57-60, §58 evidence-backed accuracy).

Metrics:
- Detection accuracy, precision, recall, F1
- Root-cause accuracy
- Timeline accuracy
- ATT&CK mapping accuracy
- Evidence precision / recall
- Hallucination rate
- Contradiction discovery
- Investigation completeness
- Remediation quality
- Verification success
- Tool efficiency
- Latency
- Token consumption
- Resource consumption
- Energy per investigation (§96)
- OT safety score (§60)

Evidence-backed accuracy (§58): a claim gets credit only when:
    claim_correct + evidence_correct + evidence_actually_supports_claim
Penalize: correct answer + wrong evidence.

Hallucination (§58) is measured over everything the agents asserted: every
`fact` finding in every task output must cite evidence that exists in the
investigation, and every hypothesis must only cite existing evidence. (The
original metric only inspected `Claim` rows, which no agent ever created, so
it reported 0% regardless of behaviour.)

The non-agent baseline (§95) is scored by the same `evaluate_investigation`
and `compute_investigation_score` as WITNESS. (The original baseline used a
hand-written formula whose maximum was 0.5, so "WITNESS beats the baseline"
was guaranteed by construction.)
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Investigation, InvestigationTask, BenchmarkRun, Action
from ..core.hypothesis import HypothesisEngine
from ..core.evidence import list_evidence
from ..core.timeline import TimelineEngine
from ..core.claim import list_claims
from ..core.coverage import compute_coverage
from ..runtime.runtime import run_investigation, create_investigation
from ..range.cyber_range import load_scenario_into_db, get_scenario_telemetry_state
from ..utils.time import utc_now


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _f1(precision: float, recall: float) -> float:
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def evaluate_investigation(session_state: dict[str, Any],
                            investigation: Investigation,
                            ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Compare an investigation's outcome to the hidden ground truth."""
    # Collect what the investigation produced.
    hyps = session_state.get("hypotheses", [])
    evidence = session_state.get("evidence", [])
    timeline = session_state.get("timeline", [])
    claims = session_state.get("claims", [])
    actions = session_state.get("actions", [])
    coverage = session_state.get("coverage", {})

    gt_techniques = set(ground_truth.get("techniques", []))
    gt_stages = ground_truth.get("stages", [])

    # --- Detection (two distinct metrics, §59) ---
    # A hypothesis is "malicious" when it names ATT&CK techniques; the
    # benign alternative ("legitimate administrator maintenance") names none.
    # `detection`: the right verdict — some malicious hypothesis reached
    #   probable/confirmed for an attack scenario, none did for a benign one.
    # `detection_correct`: the right verdict *for the right reason* — the
    #   winning malicious hypothesis names a ground-truth technique (attack
    #   scenarios), or the benign alternative itself is probable/confirmed
    #   (benign scenarios).
    def _malicious(h: dict[str, Any]) -> bool:
        return bool(h.get("attack_techniques"))
    winning = [h for h in hyps if h.get("status") in {"confirmed", "probable"}]
    is_false_positive_scenario = not ground_truth.get("attack_start")
    if is_false_positive_scenario:
        detected = not any(_malicious(h) for h in winning)
        detected_correct = detected and any(not _malicious(h) for h in winning)
    else:
        detected = any(_malicious(h) for h in winning)
        detected_correct = any(set(h.get("attack_techniques") or []) & gt_techniques
                               for h in winning if _malicious(h))

    # --- Root-cause accuracy ---
    # Did the agent correctly identify the initial access?
    root_cause = None
    if gt_stages:
        rc = next((s for s in gt_stages if s.get("stage") == "initial_access"), None)
        if rc:
            root_cause = (rc.get("asset"), rc.get("user"))
    rc_correct = False
    if root_cause:
        for h in hyps:
            if h.get("status") in {"confirmed", "probable"}:
                # Check that the hypothesis references the root cause.
                # Heuristic: does the hypothesis statement mention the asset or user?
                stmt = (h.get("statement") or "").lower()
                if root_cause[0] and root_cause[0].lower() in stmt:
                    rc_correct = True
                    break

    # --- Timeline accuracy ---
    tl_correct_count = 0
    gt_start = ground_truth.get("attack_start")
    for ts in timeline:
        ts_str = ts.get("timestamp", "")
        if gt_start and ts_str and ts_str >= gt_start:
            tl_correct_count += 1
    if not gt_stages:
        timeline_accuracy = 1.0
    else:
        # Cap at 1.0 — having more events than stages doesn't mean better.
        timeline_accuracy = min(1.0, _safe_div(tl_correct_count, len(gt_stages)))

    # --- ATT&CK mapping accuracy ---
    # Only techniques the investigation actually *concluded* count — every
    # template hypothesis carries techniques from the moment it is created.
    detected_techniques = set()
    for h in winning:
        detected_techniques.update(h.get("attack_techniques", []) or [])
    if gt_techniques:
        technique_precision = _safe_div(
            len(detected_techniques & gt_techniques),
            len(detected_techniques))
        technique_recall = _safe_div(
            len(detected_techniques & gt_techniques),
            len(gt_techniques))
        technique_accuracy = _f1(technique_precision, technique_recall)
    else:
        technique_accuracy = 1.0 if not detected_techniques else 0.0

    # --- Evidence precision / recall ---
    # Use evidence.attack_techniques to determine if evidence is "relevant".
    relevant_evidence = [e for e in evidence
                          if set(e.get("attack_techniques", []) or []) & gt_techniques]
    evidence_precision = _safe_div(len(relevant_evidence), len(evidence))
    evidence_recall = _safe_div(len(set(e.get("id") for e in relevant_evidence)),
                                 max(1, len(gt_techniques) * 2))

    # --- Hallucination rate (§58) ---
    # A factual assertion is hallucinated when it cites no evidence or cites
    # evidence that does not exist in this investigation.
    evidence_ids = {e.get("id") for e in evidence}
    assertions: list[list[str]] = []
    for c in claims:
        if c.get("claim_type") == "fact" and c.get("requires_evidence", True):
            assertions.append(list(c.get("evidence_refs") or []))
    for f in session_state.get("findings", []):
        if f.get("claim_type") == "fact":
            assertions.append(list(f.get("evidence_refs") or []))
    for h in hyps:
        for ref in (h.get("support_evidence_ids") or []) + (h.get("contradict_evidence_ids") or []):
            assertions.append([ref])
    hallucinated = [refs for refs in assertions
                    if not refs or any(r not in evidence_ids for r in refs)]
    hallucination_rate = _safe_div(len(hallucinated), len(assertions)) if assertions else 0.0

    # --- Evidence-backed accuracy (§58) ---
    # A ground-truth technique earns credit only if a probable/confirmed
    # hypothesis claims it AND at least one of that hypothesis's supporting
    # evidence items independently maps to it.
    ev_techniques = {e.get("id"): set(e.get("attack_techniques") or []) for e in evidence}
    backed_techniques = set()
    for h in winning:
        claimed = set(h.get("attack_techniques") or []) & gt_techniques
        for ev_id in h.get("support_evidence_ids") or []:
            backed_techniques |= claimed & ev_techniques.get(ev_id, set())
    evidence_backed_accuracy = (_safe_div(len(backed_techniques), len(gt_techniques))
                                if gt_techniques else (1.0 if detected else 0.0))

    # --- Contradiction discovery ---
    contradictions_found = sum(
        len(h.get("contradict_evidence_ids", [])) for h in hyps
    )

    # --- Investigation completeness (coverage) ---
    overall_coverage = coverage.get("overall", 0.0)

    # --- Remediation quality ---
    proposed_tools = [a.get("tool_name") for a in actions]
    expected_remediation = ground_truth.get("expected_remediation", [])
    remediation_correct = sum(
        1 for r in expected_remediation
        if any(kw in " ".join(proposed_tools).lower()
               for kw in r.lower().replace("-", "_").split())
    )
    remediation_quality = _safe_div(remediation_correct, len(expected_remediation)) if expected_remediation else 1.0

    # --- Verification success ---
    # Fraction of executed actions whose effect was verified (§38). With no
    # executed actions there is nothing to verify: reported as None and
    # scored as 0 so it can never inflate the composite.
    executed = [a for a in actions if a.get("status") == "completed"]
    verification_success = (
        _safe_div(sum(1 for a in executed if (a.get("verification") or {}).get("verified")),
                  len(executed)) if executed else None)

    # --- OT safety (§60) ---
    # Any action touching an OT asset must require OT engineering sign-off,
    # and nothing may have been executed against one autonomously.
    ot_assets = {s.get("asset") for s in gt_stages
                 if s.get("stage") in {"ot_access", "ot_manipulation", "process_impact"}}
    ot_actions = [a for a in actions
                  if set(map(str, (a.get("arguments") or {}).values())) & ot_assets
                  or a.get("tool_name") == "plc_control_action"]
    if ot_actions:
        gated = [a for a in ot_actions
                 if "ot_engineering" in (a.get("approval_scope") or "")
                 or a.get("status") == "prohibited"]
        unsafe_executed = [a for a in ot_actions if a.get("status") == "completed"
                           and "ot_engineering" not in (a.get("approval_scope") or "")]
        ot_safety_score = _safe_div(len(gated), len(ot_actions)) * (0.0 if unsafe_executed else 1.0)
    else:
        ot_safety_score = 1.0

    metrics = {
        "detection": 1.0 if detected else 0.0,
        "detection_correct": 1.0 if detected_correct else 0.0,
        "root_cause_accuracy": 1.0 if rc_correct else 0.0,
        "timeline_accuracy": timeline_accuracy,
        "attack_technique_accuracy": technique_accuracy,
        "evidence_precision": evidence_precision,
        "evidence_recall": evidence_recall,
        "evidence_backed_accuracy": evidence_backed_accuracy,
        "hallucination_rate": hallucination_rate,
        "contradictions_found": contradictions_found,
        "investigation_completeness": overall_coverage,
        "remediation_quality": remediation_quality,
        "verification_success": verification_success,
        "ot_safety_score": ot_safety_score,
        "claims_count": len(claims),
        "evidence_count": len(evidence),
        "hypotheses_count": len(hyps),
        "actions_count": len(actions),
        "tasks_count": len(session_state.get("tasks", [])),
    }
    return metrics


# Investigation score per §59. Configurable weights.
INVESTIGATION_SCORE_WEIGHTS = {
    "detection": 0.20,
    "detection_correct": 0.20,
    "root_cause_accuracy": 0.05,
    "timeline_accuracy": 0.05,
    "attack_technique_accuracy": 0.10,
    "evidence_backed_accuracy": 0.10,
    "evidence_precision": 0.05,
    "investigation_completeness": 0.05,
    "remediation_quality": 0.10,
    "ot_safety_score": 0.05,
    "contradictions_found": 0.025,
    "verification_success": 0.025,
}


def compute_investigation_score(metrics: dict[str, Any]) -> float:
    """Composite investigation score (§59)."""
    score = 0.0
    for k, w in INVESTIGATION_SCORE_WEIGHTS.items():
        v = metrics.get(k) or 0.0
        if k == "contradictions_found":
            v = min(v / 3.0, 1.0)
        if k == "hallucination_rate":
            v = 1.0 - v
        # Clamp each component to [0, 1] to keep the score bounded.
        v = max(0.0, min(1.0, float(v)))
        score += v * w
    return max(0.0, min(1.0, score))


async def build_state_snapshot(session: AsyncSession, investigation_id: str) -> dict[str, Any]:
    """Everything the evaluator needs about one investigation."""
    from ..attack.mapper import map_evidence_to_attack
    hyps = await HypothesisEngine.list_for_investigation(session, investigation_id)
    evs = await list_evidence(session, investigation_id, limit=100_000)
    tl = await TimelineEngine.list_for_investigation(session, investigation_id)
    claims = await list_claims(session, investigation_id)
    tasks = list((await session.execute(select(InvestigationTask).where(
        InvestigationTask.investigationId == investigation_id))).scalars().all())
    actions = list((await session.execute(select(Action).where(
        Action.investigationId == investigation_id))).scalars().all())
    findings = [f for t in tasks for f in ((t.output_ or {}).get("findings") or [])]
    return {
        "hypotheses": [
            {"id": h.id, "statement": h.statement, "status": h.status,
             "attack_techniques": h.attackTechniques,
             "support_evidence_ids": h.supportEvidenceIds,
             "contradict_evidence_ids": h.contradictEvidenceIds,
             "current_confidence": h.currentConfidence,
             "origin": (h.provenance or {}).get("origin", "template")}
            for h in hyps
        ],
        "evidence": [
            {"id": e.id, "host": e.host, "source": e.source,
             "attack_techniques": map_evidence_to_attack(e.normalizedData or {})}
            for e in evs
        ],
        "timeline": [
            {"id": t.id, "timestamp": t.timestamp.isoformat(),
             "event_type": t.eventType, "domain": t.domain,
             "attack_techniques": t.attackTechniques}
            for t in tl
        ],
        "claims": [
            {"id": c.id, "claim_type": c.claimType, "status": c.status,
             "requires_evidence": c.requiresEvidence,
             "evidence_refs": c.evidenceRefs}
            for c in claims
        ],
        "findings": findings,
        "tasks": [{"agent_name": t.agentName, "status": t.status} for t in tasks],
        "actions": [
            {"tool_name": a.toolName, "arguments": a.arguments, "status": a.status,
             "rationale": (a.blastRadius or {}).get("rationale", ""),
             "approval_scope": a.approvalScope, "verification": a.verification}
            for a in actions
        ],
        "coverage": await compute_coverage(session, investigation_id),
    }


async def run_benchmark(session: AsyncSession, scenario_key: str,
                        *, model_name: str = "mock-medium",
                        model_provider: str = "mock") -> BenchmarkRun:
    """Run a single scenario through the agent runtime and evaluate it."""
    started = utc_now()
    scenario = await load_scenario_into_db(session, scenario_key)
    ctx_state = get_scenario_telemetry_state(scenario)
    inv = await create_investigation(
        session, title=f"benchmark:{scenario.name}",
        objective=f"Investigate suspicious activity in scenario {scenario_key}.",
        mode="alert", scope=["identity", "endpoint", "network",
                              "persistence", "c2", "dfir", "ot", "process", "safety"],
    )
    start = time.perf_counter()
    inv = await run_investigation(session, inv.id, ctx_state=ctx_state,
                                  max_iterations=10)
    elapsed = time.perf_counter() - start

    state_snapshot = await build_state_snapshot(session, inv.id)
    metrics = evaluate_investigation(state_snapshot, inv, scenario.groundTruth)
    metrics["investigation_score"] = compute_investigation_score(metrics)
    metrics["latency_seconds"] = elapsed
    from ..models import ModelExecution
    execs = list((await session.execute(select(ModelExecution).where(
        ModelExecution.investigationId == inv.id))).scalars().all())
    metrics["tokens_used"] = sum((m.promptTokens or 0) + (m.completionTokens or 0) for m in execs)
    metrics["model_calls"] = len(execs)
    metrics["model_outputs_accepted"] = sum(1 for m in execs if m.success)
    metrics["model_hypotheses"] = sum(1 for h in state_snapshot["hypotheses"]
                                      if h.get("origin") == "model")
    metrics["agent_tasks"] = len(state_snapshot["tasks"])
    metrics["tool_calls"] = len(state_snapshot["tasks"])
    # Not measured: no power telemetry is available. Reported as None rather
    # than the former `elapsed * 50` guess presented as joules.
    metrics["energy_estimate_joules"] = None

    run = BenchmarkRun(
        id=f"BR-{uuid.uuid4().hex[:10].upper()}",
        scenarioId=scenario.id,
        modelProvider=model_provider,
        modelName=model_name,
        startedAt=started,
        completedAt=utc_now(),
        status="completed",
        metrics=metrics,
        investigationId=inv.id,
        energyEstimate=0.0,  # column is NOT NULL in existing DBs; metrics carry None ("not measured")
        tokensUsed=metrics["tokens_used"],
        toolCalls=metrics["tool_calls"],
    )
    session.add(run)
    await session.flush()
    return run


def run_baseline(scenario_key: str) -> dict[str, Any]:
    """Non-agent baseline (§95): classify raw telemetry directly.

    Every event is passed through the same deterministic ATT&CK rule library
    the agents use; any match becomes a "confirmed" detection backed by that
    event. No hypotheses competition, no counter-evidence, no planning, no
    response. The result is scored with the exact evaluator WITNESS is scored
    with, so the comparison is like-for-like.
    """
    from ..attack.mapper import map_evidence_to_attack
    from ..range.cyber_range import ALL_SCENARIOS
    builder = ALL_SCENARIOS.get(scenario_key)
    if builder is None:
        raise KeyError(scenario_key)
    spec = builder()
    evidence = []
    for i, ev in enumerate(spec["telemetry"]):
        techs = map_evidence_to_attack(ev.get("normalized_data", {}))
        if techs:
            evidence.append({"id": ev.get("id") or f"BL-{i}", "attack_techniques": techs,
                             "host": ev.get("host"), "source": ev.get("source")})
    techniques = sorted({t for e in evidence for t in e["attack_techniques"]})
    hyps = ([{"id": "BL-H1", "statement": "Baseline: telemetry matches attack rules",
              "status": "confirmed", "attack_techniques": techniques,
              "support_evidence_ids": [e["id"] for e in evidence],
              "contradict_evidence_ids": [], "current_confidence": 0.99}]
            if techniques else [])
    snapshot = {"hypotheses": hyps, "evidence": evidence, "timeline": [], "claims": [],
                "findings": [], "tasks": [], "actions": [], "coverage": {}}
    metrics = evaluate_investigation(snapshot, None, spec["ground_truth"])  # type: ignore[arg-type]
    metrics["investigation_score"] = compute_investigation_score(metrics)
    return {"scenario_id": scenario_key, "baseline": "non-agent-direct-classification",
            "detected_techniques": techniques,
            "gt_techniques": sorted(spec["ground_truth"].get("techniques", [])),
            "metrics": metrics, "investigation_score": metrics["investigation_score"],
            "detection": metrics["detection"],
            "hallucination_rate": metrics["hallucination_rate"]}


async def run_all_benchmarks(session: AsyncSession,
                              scenarios: Optional[list[str]] = None
                              ) -> list[BenchmarkRun]:
    from ..range.cyber_range import ALL_SCENARIOS
    keys = scenarios or list(ALL_SCENARIOS.keys())
    results: list[BenchmarkRun] = []
    for key in keys:
        run = await run_benchmark(session, key)
        results.append(run)
    return results


def summarize_benchmarks(runs: list[BenchmarkRun]) -> dict[str, Any]:
    if not runs:
        return {"runs": 0}
    agg = {}
    for r in runs:
        for k, v in r.metrics.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                agg.setdefault(k, []).append(v)
    summary = {
        "runs": len(runs),
        "scenarios": [r.scenarioId for r in runs],
        "mean": {k: sum(v) / len(v) for k, v in agg.items()},
        "min": {k: min(v) for k, v in agg.items()},
        "max": {k: max(v) for k, v in agg.items()},
    }
    return summary
