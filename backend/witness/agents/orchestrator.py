"""Orchestrator agent — top-level coordinator (§14 #1).

The orchestrator:
- receives the investigation objective
- generates initial hypotheses (via HypothesisEngine + templates)
- dispatches specialized agents
- evaluates counter-evidence
- drives the investigation to completion per §5 central loop
"""
from __future__ import annotations



from .base import Agent, register_agent
from ..schemas import (
    AgentInput, AgentOutput, FindingItem, NextStep,
)
from ..core.hypothesis import HypothesisEngine
from ..core.counter_evidence import build_plans


HYPOTHESIS_TEMPLATES = [
    {
        "statement": "Anomalous PowerShell execution represents malicious activity",
        "category": "powershell_execution",
        "attack": ["T1059.001"], "tactic": ["execution"],
    },
    {
        "statement": "Observed authentication anomalies indicate credential compromise",
        "category": "credential_compromise",
        "attack": ["T1003", "T1003.001", "T1078", "T1078.002"],
        "tactic": ["credential-access", "defense-evasion"],
    },
    {
        "statement": "Multiple failed authentications indicate brute force attack",
        "category": "credential_compromise",
        "attack": ["T1110"], "tactic": ["credential-access"],
    },
    {
        "statement": "SMB connections from the suspect host indicate lateral movement",
        "category": "lateral_movement",
        "attack": ["T1021.002"], "tactic": ["lateral-movement"],
    },
    {
        "statement": "Observed industrial protocol activity is unauthorized PLC access",
        "category": "ot_plc_compromise",
        "attack": ["T0855", "T0836"], "tactic": ["impair-process-control"],
    },
    {
        "statement": "Observed process variable deviation indicates process impact",
        "category": "ot_plc_compromise",
        "attack": ["T0831"], "tactic": ["impact"],
    },
    {
        "statement": "Industrial alarms were suppressed to inhibit the safety response",
        "category": "ot_plc_compromise",
        "attack": ["T0878"], "tactic": ["inhibit-response-function"],
    },
    {
        "statement": "A phishing email delivered the initial payload",
        "category": "phishing_initial_access",
        "attack": ["T1566.001"], "tactic": ["initial-access"],
    },
    {
        "statement": "The intruder installed a persistence mechanism",
        "category": "persistence",
        "attack": ["T1543.003", "T1547.001"], "tactic": ["persistence"],
    },
    {
        "statement": "Periodic outbound connections indicate C2 beaconing",
        "category": "lateral_movement",
        "attack": ["T1071.001"], "tactic": ["command-and-control"],
    },
    {
        "statement": "Activity represents legitimate administrator maintenance",
        "category": "benign",
        "attack": [], "tactic": [],
        # The competing benign explanation (§50). Most alerting activity is
        # benign, so it starts from an even prior rather than the 0.35 used
        # for specific attack hypotheses; evidence must still move it.
        "prior": 0.5,
    },
]


@register_agent
class OrchestratorAgent(Agent):
    name = "orchestrator"
    description = "Top-level investigation orchestrator (§14 #1, §5 central loop)."
    default_role = "strong"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        # 1. If this is the first iteration, generate initial hypotheses.
        existing = await HypothesisEngine.list_for_investigation(self.session, inp.investigation_id)
        if not existing:
            for tmpl in HYPOTHESIS_TEMPLATES:
                await HypothesisEngine.create(
                    self.session, inp.investigation_id,
                    tmpl["statement"],
                    prior=tmpl.get("prior", 0.35),
                    expected_evidence=[
                        {"description": "Direct evidence: " + tmpl["statement"],
                         "severity": "high"}
                    ],
                    attack_techniques=tmpl["attack"],
                    attack_tactics=tmpl["tactic"],
                )

        # 2. Plan next steps: dispatch each analyst agent over the highest-
        # confidence open hypotheses.
        hyps = await HypothesisEngine.list_for_investigation(self.session, inp.investigation_id)
        open_hyps = [h for h in hyps if h.status in {"open", "probable"}]

        next_steps: list[NextStep] = []
        for h in open_hyps[:3]:
            plans = build_plans(h)
            for step in plans.support_steps[:2]:
                next_steps.append(NextStep(
                    objective=step["objective"],
                    agent=step.get("agent"),
                    information_gain=0.7,
                    confidence_impact=0.5,
                    cost=0.3,
                    risk_level="low",
                    target_hypothesis_id=h.id,
                    expected_evidence=[step.get("evidence_kind", "direct_evidence")],
                ))
            for step in plans.counter_steps[:1]:
                next_steps.append(NextStep(
                    objective=step["objective"],
                    agent=step.get("agent"),
                    information_gain=0.6,
                    confidence_impact=0.5,
                    cost=0.3,
                    risk_level="low",
                    target_hypothesis_id=h.id,
                    expected_evidence=[step.get("evidence_kind", "disconfirming_evidence")],
                ))

        # 3. Determine whether to stop or continue.
        top_conf = max((h.currentConfidence for h in hyps), default=0.0)
        completion = "incomplete"
        if top_conf >= 0.85 and len(open_hyps) <= 1:
            completion = "complete"

        return self._output(
            inp,
            findings=[FindingItem(
                statement=f"Orchestrator: {len(hyps)} hypotheses open; top confidence {top_conf:.2f}",
                claim_type="inference",
                confidence=top_conf,
                evidence_refs=[],
                attack_techniques=[],
                domain=None,
            )],
            new_hypotheses=[HypothesisEngine.to_dto(h) for h in hyps if h not in existing],
            recommended_next_steps=next_steps[:10],
            completion=completion,
            summary=f"Generated {len(hyps) - len(existing)} new hypotheses; "
                    f"{len(open_hyps)} open.",
        )
