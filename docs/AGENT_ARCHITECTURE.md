# WITNESS Agent Architecture

> Do not make agents communicate through unstructured natural-language chains. Agents communicate through typed schemas. (§14)

## 19 specialized agents (§14)

| # | Agent | Role | Domain |
|---|---|---|---|
| 1 | **orchestrator** | Top-level coordinator (§5 central loop) | — |
| 2 | **triage** | Initial triage on signals (§14 #2) | endpoint |
| 3 | **planner** | Decides what to investigate next (§12, §13) | — |
| 4 | **evidence_analyst** | Cross-source correlation (§14 #4) | — |
| 5 | **threat_hunter** | Hunt-mode agent (§30, §106) | — |
| 6 | **identity_analyst** | Authentication / identity activity (§14 #6) | identity |
| 7 | **endpoint_analyst** | Endpoint activity (§14 #7) | endpoint |
| 8 | **network_analyst** | Network activity (§14 #8) | network |
| 9 | **cloud_analyst** | Cloud audit logs (§14 #9) | cloud |
| 10 | **dfir_analyst** | Forensics: filesystem, registry, memory (§14 #10) | dfir |
| 11 | **ot_analyst** | OT/ICS activity (§14 #11, §22) | ot |
| 12 | **threat_intel_analyst** | TI enrichment (§14 #12) | — |
| 13 | **attack_mapper** | Evidence → MITRE ATT&CK (§14 #13, §21) | — |
| 14 | **hypothesis_engine** | Generates new hypotheses (§14 #14) | — |
| 15 | **contradiction_analyst** | Actively searches for disconfirming evidence (§14 #15, §7, §50) | — |
| 16 | **risk_analyst** | Asset risk scoring (§110, §111) | — |
| 17 | **response_planner** | Proposes remediation (§14 #17, §37) | — |
| 18 | **verification** | Verifies remediation (§38) | — |
| 19 | **reporting** | Evidence-backed incident reports (§34, §114-118) | — |

## Typed agent contract (§15)

Every agent receives an `AgentInput` and returns an `AgentOutput`. Both are Pydantic v2 models with `extra="forbid"` — malformed outputs are rejected, never silently accepted.

```python
class AgentInput(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    investigation_id: str
    task_id: str
    objective: str
    evidence_refs: list[str]
    hypothesis_refs: list[str]
    asset_refs: list[str]
    constraints: dict
    risk_level: Literal["low", "medium", "high", "critical", "prohibited"]
    role: Literal["small", "medium", "strong", "verification"]
    context: dict

class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    investigation_id: str
    task_id: str
    agent_name: str
    findings: list[FindingItem]
    new_evidence: list[EvidenceDTO]
    new_hypotheses: list[HypothesisDTO]
    confidence_delta: float
    contradictions: list[str]
    recommended_next_steps: list[NextStep]
    proposed_actions: list[ProposedAction]
    completion: Literal["incomplete", "complete", "blocked"]
    summary: str
    metrics: dict
```

## What an agent actually does

1. Receives `AgentInput` (objective, refs, constraints, role).
2. Calls tools through `self.call_tool(tool_name, args)`. The `call_tool` helper:
   - Looks up the tool in the registry
   - Builds a `ToolContext` with the investigation ID + shared ctx_state
   - Executes the tool, which records a `ToolExecution` row for audit
   - Auto-ingests any evidence the tool returns via `add_evidence`
3. Updates hypotheses:
   - `HypothesisEngine.add_support(h.id, ev.id)` raises confidence
   - `HypothesisEngine.add_contradiction(h.id, ev.id)` lowers confidence
   - The engine owns the confidence math (Bayesian-style bounded log-odds) — never the LLM
4. Updates timeline (`TimelineEngine.add_event`) — every evidence insertion should be reflected in the timeline.
5. Returns a typed `AgentOutput`.

Agents are deliberately small and deterministic. They do NOT call the LLM to "decide" — they apply rules to tool output. This makes the agent layer:
- Testable without an LLM
- Reproducible across runs
- Immune to hallucination
- Safe against prompt injection in tool output (§40)

## The orchestrator's hypothesis templates

The orchestrator generates an initial set of hypotheses from templates (one per attack pattern). Each hypothesis has:
- a `statement` (what is asserted)
- a `prior` confidence (typically 0.35)
- expected `attack_techniques` (MITRE ATT&CK IDs)
- expected `attack_tactics`

This seeds the investigation. The planner then uses each hypothesis to generate support and counter-evidence investigation plans (§7).

## The counter-evidence engine (§7)

For every hypothesis, the planner generates TWO plans:

```
SUPPORT PLAN     ← what evidence would confirm this hypothesis?
COUNTER PLAN     ← what evidence would disconfirm this hypothesis?
```

The `contradiction_analyst` agent runs every iteration to actively search for disconfirming evidence. This is the signature WITNESS feature: the agent is rewarded for finding disconfirming evidence, not just for confirming its first conclusion.

Templates live in `witness/core/counter_evidence.py` and are keyed by claim category (e.g. `credential_compromise`, `lateral_movement`, `ot_plc_compromise`, `phishing_initial_access`, `powershell_execution`). Each template lists support and counter steps with the agent to dispatch.

## The runtime loop (§128)

```python
for iteration in range(max_iterations):
    # 1. Orchestrator generates hypotheses
    # 2. Planner ranks next steps
    # 3. Dispatch analysts (endpoint, identity, network, ot, ...)
    # 4. Attack mapper maps evidence → ATT&CK techniques
    # 5. Threat intel analyst enriches evidence
    # 6. Contradiction analyst searches for disconfirming evidence
    # 7. Check for proposed actions requiring approval → pause
    # 8. Convergence check: top_confidence ≥ 0.75 AND open_hypotheses ≤ 1 → completed
```

The runtime is:
- **Resumable** — state is persisted in `Investigation.state` and `InvestigationTask` rows. A crash does not corrupt incident state (§73).
- **Interruptible** — `pause_investigation()` safely stops the loop; `resume_investigation()` re-enters from the next iteration (§129).
- **Auditable** — every agent/tool/policy action is recorded in `AuditLog` with actor, tool, arguments, result, policy_decision, evidence_refs.
- **Bounded** — `asyncio.wait_for(agent.run(), timeout=60s)` per task. Failures degrade gracefully: a single agent timeout does not corrupt the investigation.

## Memory model (§41)

Memory is partitioned:

- **Working memory** — the current investigation's `InvestigationTask` rows and the in-flight ctx_state. Cleared when the investigation ends.
- **Incident memory** — the `Evidence`, `Hypothesis`, `Claim`, `TimelineEvent` rows for the investigation. Preserved permanently.
- **Long-term knowledge** — `KnowledgeItem` rows (MITRE ATT&CK, NIST, Sigma, etc.). Versioned with provenance.
- **System policy** — the policy engine's static config + RBAC role-permission map.

Incident data can never modify system policy (§41). The memory wall is enforced by architecture, not by LLM self-discipline.

## No fake reasoning (§143)

The UI exposes:
- investigation objective
- hypothesis
- evidence consulted
- tools executed
- findings
- confidence change
- decision
- next step

It does NOT expose fabricated chain-of-thought. The agent's reasoning is the audit trail — the deterministic sequence of tool calls, evidence insertions, hypothesis updates, and policy decisions. Nothing more.
