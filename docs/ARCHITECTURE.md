# WITNESS Architecture

## System architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Next.js frontend (port 3000) — security operations console        │
│  Dashboard / Incidents / Investigations / Evidence / Timeline /    │
│  Attack Graph / Hypotheses / OT-ICS / Benchmarks / Audit / System │
└─────────────────────┬───────────────────────────────────────────┘
                      │ HTTP /api/witness/* (proxied)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│ FastAPI backend (port 8000)                                      │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ API layer (§67) — 56 routes, OpenAPI at /docs             │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                          │                                       │
│  ┌───────────────────────┴───────────────────────────────────┐   │
│  │ Agent runtime (§128) — planning, tool calls, memory,      │   │
│  │   interrupt/resume, audit, timeout/retry, resumability     │   │
│  └──────────────────────┬────────────────────────────────────┘   │
│                          │                                       │
│  ┌───────────────────────┴───────────────────────────────────┐   │
│  │ 19 specialized agents (§14) — orchestrator, triage,        │   │
│  │   planner, evidence, threat_hunter, identity, endpoint,     │   │
│  │   network, cloud, dfir, ot, threat_intel, attack_mapper,     │   │
│  │   hypothesis_engine, contradiction, risk, response,         │   │
│  │   verification, reporting                                   │   │
│  └────┬─────────────────────────┬────────────────────────┬───┘   │
│       │                         │                        │       │
│  ┌────▼────┐  ┌──────────────┐  ┌▼────────────────┐  ┌────▼──┐   │
│  │ Tools   │  │ Policy/Risk  │  │ Core engines     │  │ Model │   │
│  │ registry│  │ + OT safety  │  │ Evidence, Hypo,   │  │ layer │   │
│  │ (§42)   │  │ (§25, §39)   │  │ CounterEvidence, │  │ (§16) │   │
│  └────┬────┘  └──────┬───────┘  │ Timeline, Graph,  │  └───┬───┘   │
│       │            │           │ Claim, Coverage   │      │       │
│       └─────┬──────┘           └────────┬──────────┘      │       │
│             │                           │                 │       │
│       ┌─────▼─────────────────────┐  ┌──▼──────┐  ┌──────▼────┐  │
│       │ SQLAlchemy (SQLite/PG)     │  │ Cyber  │  │ Mock /     │  │
│       │ — authoritative state       │  │ Range  │  │ Ollama /   │  │
│       │   (§66 full data model)     │  │ (§53)  │  │ OpenAI-    │  │
│       └────────────────────────────┘  └────────┘  │ compatible │  │
│                                                    └────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Data model

WITNESS uses SQLAlchemy 2.0 async with SQLite by default (PostgreSQL-ready via env var). The full entity set per spec §66:

- **Identity / RBAC**: `Organization`, `User`
- **Assets**: `Asset` (unified IT+OT), `AssetRelationship` (static), `OTAsset` (OT-specific extension)
- **Investigations**: `Incident`, `Campaign`, `Investigation`, `InvestigationTask`
- **Evidence**: `Evidence` (immutable, hash-chained), `EvidenceRelationship` (observed)
- **Reasoning**: `Hypothesis`, `Claim`, `Finding`
- **Timeline**: `TimelineEvent`
- **Detection / TI**: `DetectionRule`, `ThreatIntel`, `KnowledgeItem`
- **Actions**: `Action`, `Approval`
- **Audit**: `AuditLog`, `ToolExecution`, `ModelExecution`
- **Reports**: `Report`
- **Benchmark**: `Scenario` (with hidden ground truth), `BenchmarkRun`

State is authoritative in the relational DB. The evidence graph is a derived view (§10) — built in-memory from `Asset`, `AssetRelationship`, and `EvidenceRelationship`.

## Request flow

1. UI calls `/api/witness/investigations/INV-...` on its own origin; Next.js (dev) or Caddy (docker) forwards it to the backend.
2. Gateway forwards to the Python backend on port 8000.
3. FastAPI route authenticates (dummy login by default; production uses NextAuth/OIDC) and validates input via Pydantic.
4. Route calls into the appropriate engine (Evidence, Hypothesis, Timeline, etc.).
5. Engine reads/writes via the shared `AsyncSession`, which auto-commits on success and rolls back on exception (§73).
6. Response is serialized as JSON with camelCase aliases for the frontend.

## Investigation lifecycle

```
POST /investigations                    → create Investigation row
POST /investigations/{id}/run            → invoke runtime.run_investigation()
                                          → central loop (§5) for up to N iterations
                                          → each iteration:
                                             - orchestrator generates hypotheses
                                             - planner ranks next steps (info_gain × conf_impact × criticality / cost)
                                             - analyst agents dispatched (endpoint, identity, network, ot, ...)
                                             - attack_mapper maps evidence → ATT&CK
                                             - threat_intel_analyst enriches with TI
                                             - contradiction_analyst searches for disconfirming evidence
                                             - convergence check: top_conf ≥ 0.75 AND open_hyps ≤ 1 → completed
POST /investigations/{id}/pause         → safe pause (state preserved)
POST /investigations/{id}/resume        → re-enter the loop
POST /investigations/{id}/cancel        → mark cancelled
GET  /investigations/{id}               → full workspace state (hypotheses, evidence,
                                          timeline, gaps, coverage, actions)
```

## Action safety flow

```
POST /actions/propose                   → policy engine evaluates tool + arguments
                                          → returns PolicyDecision:
                                             - allow (read-only, low-risk)
                                             - require_approval (high-risk)
                                             - prohibited (e.g. PLC control action)
                                          → OT safety engine classifies OT-related tools:
                                             SAFE | LOW_RISK | OPERATIONALLY_SENSITIVE |
                                             HIGH_RISK | SAFETY_CRITICAL |
                                             REQUIRES_HUMAN_OT_AUTHORITY | PROHIBITED
                                          → for OT safety_critical / prohibited: dual approval required
                                             (security + ot_engineering + process_owner)
POST /actions/approve                   → record Approval for one role; action.status
                                          becomes "approved" only when all required
                                          approvals are in place
POST /actions/execute                   → execute via tool registry (with approved=True)
                                          → blast-radius computed, dry-run supported,
                                          → post-action verification via verification agent
```

## Model layer (§16)

WITNESS is provider-independent. The default `mock` provider makes the entire system run with zero LLM dependency — agents are rule-driven, pulling telemetry through the tool registry and applying deterministic logic. This is essential for:
- Tests (deterministic, reproducible)
- Benchmarks (no LLM variance)
- Demo mode (deterministic)
- Air-gapped deployments (no external API)

To plug in a real model:
- `WITNESS_MODEL_PROVIDER=openai_compatible` (any OpenAI /v1/chat/completions endpoint)
- `WITNESS_MODEL_PROVIDER=ollama` (native Ollama API)

The `ModelRouter` (§63) routes by role:
- `small` — extraction, classification, normalization
- `medium` — investigation planning, correlation
- `strong` — difficult cross-domain reasoning, final synthesis
- `verification` — high-risk final assessment (verification + strong model)

All model usage is measured and recorded in `ModelExecution` rows: tokens, latency, model, VRAM estimate, tool calls.

## Open source / no cloud dependency

Per §97, the tournament build remains functional without external AI APIs. The default `mock` provider and local SQLite DB make WITNESS runnable on a single machine with no internet access. External integrations are strictly optional.
