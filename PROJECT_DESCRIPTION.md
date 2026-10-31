# WITNESS — Project Package Description

**Weighted Intelligence for Threat Narrative, Evidence, Synthesis & Security**

> Don't ask the AI what happened. Make it prove what happened.

This document is the map of the project package. For the competition
proposal read [`docs/PROPOSAL.md`](docs/PROPOSAL.md); for setup read
[`README.md`](README.md).

---

## 1. What WITNESS is

WITNESS is an **evidence-driven, hypothesis-based investigation and
decision-support system** for SOC, DFIR and OT/ICS defenders. Four principles:

1. **Evidence is first-class.** Every hypothesis and finding references evidence IDs. Evidence is append-only and hash-chained; `GET /investigations/{id}/integrity` proves nothing was edited, deleted or reordered.
2. **Hypotheses are tested against counter-evidence.** Competing hypotheses, including a benign one, are scored side by side; a contradiction analyst looks for disconfirming evidence (change tickets, maintenance windows) matched to user, host and time.
3. **The model doesn't own confidence.** A deterministic Bayesian log-odds engine does. An open-source LLM (Qwen3-8B (uncensored variant)) may *propose* hypotheses, narratives and explanations; every citation is verified and proposals are scored by the same evidence rules as everything else — "the model proposes, evidence disposes".
4. **Safety is enforced by architecture.** Agents can only propose actions. Execution needs a human signature per approval scope, from different people; OT safety can only make a decision stricter; PLC control commands are prohibited outright.

Built for the Hackers-Arise Wittgenstein AI Tournament and meant to be credible beyond it.

## 2. What this package contains

```
witness/
├── README.md                    # Setup, quickstart, results
├── PROJECT_DESCRIPTION.md       # This file
├── CHANGELOG.md                 # Release notes
├── SECURITY.md                  # Security model and reporting
├── LICENSE                      # MIT
├── .env.example                 # Every setting, documented
├── docker-compose.yml           # Backend + console + Caddy gateway, token auth
│
├── backend/
│   ├── requirements.txt         # Single source of truth for Python deps
│   ├── pyproject.toml           # Ruff + pytest config
│   ├── witness/                 # 59 modules, ~13k lines
│   │   ├── api/                 # FastAPI app (72 routes) + bearer-token auth
│   │   ├── agents/              # 19 agents + orchestrator (11 hypothesis templates)
│   │   ├── attack/mapper.py     # Evidence → ATT&CK Enterprise + ICS rules
│   │   ├── benchmark/           # WITNESS-Bench + `python -m witness.benchmark`
│   │   ├── core/                # Evidence chain, hypotheses, counter-evidence,
│   │   │                        #   timeline, graph, coverage, model_assist, …
│   │   ├── detection/           # Sigma (pySigma) + YARA runtime, rule generation
│   │   ├── knowledge/           # ATT&CK STIX loader + local retrieval
│   │   ├── models_layer/        # OpenAI-compatible / Ollama / mock providers,
│   │   │                        #   privacy enforcement, `python -m witness.models_layer.check`
│   │   ├── ot/                  # OT assets + safety engine
│   │   ├── policy/engine.py     # RBAC, approval scopes, separation of duties
│   │   ├── range/cyber_range.py # 4 scenarios with hidden ground truth
│   │   ├── runtime/runtime.py   # Investigation loop, pause/resume/cancel, background runs
│   │   └── tools/               # 25 policy-gated tools (telemetry, DFIR, PCAP, response)
│   └── tests/                   # 171 tests
│       ├── test_witness.py      # Reasoning contracts, evidence chain, flagship
│       ├── test_hardening.py    # Safety and correctness invariants
│       ├── test_model_assist.py # Grounding, prompt injection, fallback, providers
│       ├── test_api.py / test_new_api.py
│       ├── test_new_modules.py  # Detection, baseline, knowledge, PCAP
│       └── test_rulegen_nlquery.py
│
├── src/                         # Next.js 16 console (12 tabs incl. Response)
│   ├── app/page.tsx
│   └── lib/witness-api.ts       # Typed client; calls /api/witness/* (proxied)
│
├── docs/
│   ├── PROPOSAL.md              # Competition proposal
│   ├── MODEL_CARD.md            # Model lineage, guardrails, how to evaluate
│   ├── LIMITATIONS.md           # What is reduced, and why
│   ├── ARCHITECTURE.md, AGENT_ARCHITECTURE.md, MODEL_ARCHITECTURE.md,
│   ├── EVIDENCE_MODEL.md, OT_SAFETY.md, THREAT_MODEL.md,
│   ├── BENCHMARK.md, CYBER_RANGE.md, API.md,
│   └── DEVELOPER_GUIDE.md, DEPLOYMENT.md, CROSS_PLATFORM.md, ROADMAP.md
│
├── docker/                      # Dockerfiles + production Caddyfile
├── scripts/                     # start.sh / start.ps1 / start.bat (backend)
└── .github/workflows/ci.yml     # Tests (3 OS × Py 3.11/3.12), ruff, tsc, build,
                                 #   pip-audit, Docker e2e through the gateway
```

## 3. The investigation loop

```
SIGNAL → CONTEXT → HYPOTHESES (templates + model proposals) → PLANNING →
EVIDENCE COLLECTION → CHAIN → HYPOTHESIS SCORING → COUNTER-EVIDENCE →
ATT&CK RECONSTRUCTION → RISK → RESPONSE PROPOSALS → HUMAN APPROVAL →
EXECUTION → VERIFICATION → REPORT
```

The loop iterates until convergence or a human pauses/cancels it. Pause and
cancel take effect at iteration boundaries; resume continues where it stopped.

## 4. Signature features

1. **Counter-evidence engine.** The false-positive scenario is an authorized change; WITNESS concludes "authorized" from the change ticket where the rule-only baseline raises an alarm.
2. **OT safety engine.** Isolating an engineering workstation needs security, OT-engineering *and* process-owner signatures from three different people. PLC commands are `prohibited`, a terminal state no approval can lift.
3. **Tamper-evident evidence.** Sequence-numbered hash chain with a verifier; the console shows "chain intact".
4. **Grounded model assistance.** Closed output schemas, one fabricated citation rejects the output, attacker-controlled log text is passed as untrusted data, every call is metered; any failure falls back to rules.
5. **Honest benchmark.** WITNESS and a rule-only baseline are scored by the same evaluator; we publish where the baseline wins.
6. **Flagship IT→OT scenario.** Phishing → encoded PowerShell → LSASS access → VPN → engineering workstation → rogue Modbus write (T0855/T0836) → process deviation (T0831) → alarm suppression (T0878), reconstructed stage by stage.

## 5. What's real vs. simulated

| Component | Status | Notes |
|---|---|---|
| Investigation runtime, 19 agents | Real | Rule-driven agents; typed contracts; audit trail |
| Evidence store | Real | Append-only, hash-chained, verifiable after reload |
| Hypothesis scoring | Real | Deterministic log-odds; re-observation never inflates confidence |
| Policy, approvals, OT safety | Real | Enforced in the tool registry, not only the API |
| Auth | Real | Static bearer tokens with roles; production refuses to run without auth |
| Sigma / YARA / PCAP (dpkt) | Real | Rules really compile; PCAP parsing is IPv4 |
| ATT&CK mapping | Real | Deterministic rules over a corrected offline catalogue (Enterprise + ICS) |
| Model assistance | Real code, **not yet run against a real model** | Tested with a scripted stand-in and mocked HTTP servers; see `docs/MODEL_CARD.md` |
| Telemetry tools (Windows events, Sysmon, Zeek, EDR, VPN, Modbus, …) | **Simulated** | Read cyber-range fixtures, not live SIEM/EDR |
| DFIR tools (registry, prefetch, amcache, Plaso) | **Simulated** | Return cyber-range fixtures; memory acquisition returns a placeholder flagged `synthetic: true` |
| Response tools (isolate, disable account, …) | **Simulated** | Record their effect in investigation state |
| Docker Compose, GitHub CI | Written, **not yet run** | No Docker or repository in the build environment |

The tool interface is the seam: replacing a fixture reader with a real
connector does not touch agent code. Full list: `docs/LIMITATIONS.md`.

## 6. How to run it

```bash
# Backend (Python 3.11+)
cd backend
pip install -r requirements.txt
python -m uvicorn witness.api.app:app --host 127.0.0.1 --port 8000

# Console (separate terminal, Node 18+ or Bun)
bun install && bun run dev          # or: npm install && npm run dev
# Open http://localhost:3000
```

Start scripts that install dependencies and start the backend:
`bash scripts/start.sh`, `pwsh scripts/start.ps1`, or `scripts\start.bat`.

Docker Compose: `cp .env.example .env`, set `WITNESS_API_TOKENS`, then
`docker compose up --build` (gateway on http://localhost).

One-shot checks once the backend is up:

```bash
curl -X POST http://localhost:8000/demo/flagship \
  -H 'Content-Type: application/json' -d '{"max_iterations": 5}'

cd backend
python -m witness.benchmark        # WITNESS vs baseline, throwaway database
python -m pytest -q                # 171 tests
python -m witness.models_layer.check   # validate a deployed model endpoint
```

## 7. Benchmark results

Rule-only pipeline (no model), same evaluator for both systems:

| Scenario | WITNESS | Baseline | Note |
|---|---|---|---|
| IT→OT intrusion (flagship) | 0.79 | 0.68 | Both detect it; the baseline is more precise on ATT&CK IDs (0.95 vs 0.80) |
| Brute force | 0.72 | 0.62 | Both detect it |
| Authorized maintenance (false positive) | 0.81 | 0.20 | WITNESS concludes "authorized"; the baseline raises a false alarm |
| Silent beaconing | 0.80 | 0.05 | WITNESS finds it; the baseline misses it |

0% hallucination and intact evidence chains in every run. Model-assisted
results will be added once the model is deployed. Metric definitions:
`docs/BENCHMARK.md`.

## 8. Thesis

Evidence-grounded, hypothesis-driven investigation produces more reliable
verdicts than direct classification when the situation is ambiguous: the
largest gaps above are the false-positive and silent-compromise scenarios,
where counter-evidence and correlation decide the answer. Where the answer is
a direct pattern match, a simple rule set is as good or better, and we say so.

## 9. What to read first

1. `docs/PROPOSAL.md` — the competition proposal
2. `README.md` — setup and results
3. `docs/ARCHITECTURE.md` — system architecture
4. `docs/OT_SAFETY.md` — the OT safety engine
5. `docs/EVIDENCE_MODEL.md` — evidence and chain of custody
6. `docs/MODEL_CARD.md` — how the open-source model is used and constrained
7. `docs/BENCHMARK.md` — WITNESS-Bench
8. `docs/LIMITATIONS.md` — what's not done, and why

## 10. License

MIT. See `LICENSE`.

WITNESS is defensive security software. Anything that touches systems must
run only against systems you are authorized to test, isolated labs,
synthetic environments or the bundled cyber range.

---

*Don't ask the AI what happened. Make it prove what happened.*
