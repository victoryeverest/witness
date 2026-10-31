# WITNESS — Evidence-Driven Autonomous Cyber Defense

**Weighted Intelligence for Threat Narrative, Evidence, Synthesis & Security**

> Don't ask the AI what happened. Make it prove what happened.

WITNESS is an evidence-driven, hypothesis-based autonomous cyber-defense and investigation platform. It does not merely tell the defender what happened — it constructs a defensible explanation of what happened, shows the evidence supporting it, actively searches for evidence that contradicts it, identifies what remains unknown, and guides the defender toward the safest appropriate action.

**This is not a chatbot. This is not a SOC copilot. This is not a collection of agents.**

This is an autonomous cyber-investigation and decision-support system built around evidence, hypotheses, verification, and controlled action.

---

## Quickstart (cross-platform)

WITNESS runs on Linux, macOS, and Windows. Choose the path that fits your environment:

### Option A — Native install (developer / single-machine)

```bash
# Linux / macOS / Windows — same steps.
# Requires: Python 3.11+ and Node.js 18+ (or Bun).

# 1. Clone
git clone https://github.com/victoryeverest/witness.git witness && cd witness

# 2. Backend
cd backend
pip install -r requirements.txt
python3 -m uvicorn witness.api.app:app --host 127.0.0.1 --port 8000

# 3. Frontend (separate terminal)
cd ..
bun install       # or: npm install
bun run dev        # or: npm run dev — starts Next.js on port 3000

# 4. Open http://localhost:3000 — the console proxies /api/witness/* to the
#    backend (override with WITNESS_BACKEND_URL)
```

Or use the bundled start script:

| Platform | Script |
|---|---|
| Linux / macOS | `bash scripts/start.sh` |
| Windows (cmd) | `scripts\start.bat` |
| Windows PowerShell 5.1 / PowerShell 7+ (any OS) | `pwsh scripts/start.ps1` (or `powershell -File scripts\start.ps1`) |

The scripts install `backend/requirements.txt` if needed, start the backend on port 8000 (`WITNESS_PORT` to change) and print how to start the console.

### Option B — Docker Compose (production / reproducible)

```bash
cp .env.example .env
# Production runs with token auth. Put real tokens in .env, e.g.
#   WITNESS_API_TOKENS=<long-random>:alice:security_engineer,<long-random>:bob:ot_engineer
docker compose up --build
# Backend on http://localhost:8000, frontend on http://localhost:3000,
# gateway on http://localhost (port 80).
```

### Option C — One-shot demo (no install)

If you just want to see the flagship IT→OT demo run end-to-end:

```bash
# After the backend is up on port 8000:
curl -X POST 'http://localhost:8000/demo/flagship' \
  -H 'Content-Type: application/json' \
  -d '{"max_iterations": 5}'

# Or the whole benchmark, printed as a table, against a throwaway database:
cd backend && python -m witness.benchmark
```

## Cross-platform compatibility

| Component | Linux | macOS | Windows |
|---|---|---|---|
| Backend (Python 3.12 / FastAPI / SQLAlchemy / aiosqlite) | ✓ | ✓ | ✓ |
| yara-python (YARA detection runtime) | ✓ | ✓ | ✓ (pre-built wheels) |
| pysigma (Sigma detection runtime) | ✓ | ✓ | ✓ (pure Python) |
| dpkt + scapy (PCAP investigation) | ✓ | ✓ | ✓ (scapy needs Npcap on Windows) |
| Frontend (Next.js 16 / React 19 / Bun or npm) | ✓ | ✓ | ✓ |
| Docker Compose stack | ✓ | ✓ (Docker Desktop) | ✓ (Docker Desktop or WSL2) |
| Cross-platform start scripts | `start.sh` | `start.sh` / `start.ps1` | `start.bat` / `start.ps1` |
| CI matrix (`.github/workflows/ci.yml`) | ubuntu-latest | macos-latest | windows-latest |

**Database**: SQLite by default (zero config, cross-platform file). Production: PostgreSQL (one env var change).

**Path handling**: All paths use `pathlib.Path` and forward slashes. The data dir, knowledge cache, and PCAP paths all work cross-platform.

**Network binding**: The backend binds to `0.0.0.0` so it's reachable through reverse proxies on every OS.

## What's inside

- **Backend** (Python / FastAPI / SQLAlchemy 2.0 / Pydantic v2):
  - **19 specialized agents** (§14) with typed AgentInput/AgentOutput contracts — agents *propose* actions; only humans approve them
  - **25 tools** with permissions, risk levels, rollback capability (§42) — including real Sigma + YARA + PCAP investigation; a registry-level guard refuses any side-effecting call that lacks an executor-verified approval
  - **Evidence integrity**: content-hashed, sequence-numbered hash chain with a verifier (`GET /investigations/{id}/integrity`)
  - **Human approval**: per-scope sign-off with separation of duties (one person cannot sign two scopes), terminal `denied`/`prohibited` states, post-action verification
  - **Authentication**: optional bearer tokens with server-side roles; production refuses to start unauthenticated
  - **Core engines**: Evidence (§8), Hypothesis (§6), CounterEvidence (§7), Timeline (§11), EvidenceGraph (§10), Claim (§9), Coverage (§36), InfoGain (§13), **Baseline (§31)**
  - **Policy engine + OT safety engine** — the signature feature (§25, §39): refuses to autonomously isolate PLCs (returns PROHIBITED for PLC control commands)
  - **MITRE ATT&CK mapping** (Enterprise + ICS) — deterministic, evidence-backed (§21, §27)
  - **Cyber range** with 4 scenarios (flagship IT→OT, brute force, false positive, silent compromise) + hidden ground truth (§53-§56)
  - **WITNESS-Bench** with evidence-backed accuracy metric (§57-§60) + non-agent baseline for competitive comparison (§95)
  - **Knowledge layer**: MITRE ATT&CK STIX loader + RAG retrieval (§99-§101)
  - **Detection runtime**: real Sigma + YARA + IOC + behavioral rules + statistical baseline deviation (§19)
  - **Rule generation**: agents author Sigma/YARA rules from observed evidence, validate, then human review (§105)
  - **Natural-language → query translator** (§47, §107)
  - **Incident prioritization** (§111)
  - **PCAP investigation** with dpkt — flow extraction, DNS/HTTP/TLS, Modbus/DNP3 parsing (§33)
  - **Open-source LLM assistance** (Qwen3-8B (uncensored variant); any OpenAI-compatible or Ollama server works): proposes hypotheses, writes report narratives, explains conclusions. Outputs are schema-checked and every citation verified; the model can never act, approve or set confidence (`docs/MODEL_CARD.md`)
  - **Local-first default**: privacy_mode=LOCAL_ONLY, no outbound calls unless explicitly enabled
- **Frontend** (Next.js 16 / React 19 / Tailwind / shadcn/ui): security-operations console with 12 tabs, including a Response tab for approving, rejecting and executing actions
- **Tests**: **171 passing** — §144 reasoning contracts, safety invariants (approval bypasses, evidence tampering, prompt injection), module and API tests
- **CI/CD**: GitHub Actions matrix (Linux + macOS + Windows × Python 3.11 + 3.12) + security scan + docker build + e2e smoke test (§124)
- **Documentation**: 16 docs covering architecture, threat model, OT safety, evidence model, agents, models, evaluation, deployment, limitations, roadmap

## The flagship demo

```bash
curl -X POST 'http://localhost:8000/demo/flagship' \
  -H 'Content-Type: application/json' \
  -d '{"max_iterations": 5}'
```

This:
1. Loads the flagship scenario (phishing → PowerShell → LSASS → VPN → EWS → Modbus → process deviation → alarm suppression)
2. Creates an investigation
3. Runs the central investigation loop (§5) with 19 specialized agents
4. Evaluates the result against the hidden ground truth (§56)
5. Returns detection score, ATT&CK accuracy, evidence-backed accuracy, hallucination rate, OT safety score, and composite investigation score
6. Leaves the proposed containment actions (e.g. isolate WS-01; isolate EWS-01 needing security + OT engineering + process-owner sign-off) waiting in the Response tab — nothing executes without humans

### Results (rule-based pipeline, deterministic)

| Scenario | System | Score | Correct verdict | ATT&CK acc. | Evidence-backed | Hallucination |
|---|---|---|---|---|---|---|
| flagship (IT→OT) | WITNESS | 0.79 | ✓ | 0.80 | 0.80 | 0% |
| | baseline | 0.68 | ✓ | 0.95 | 0.90 | 0% |
| brute_force | WITNESS | 0.72 | ✓ | 0.57 | 0.50 | 0% |
| | baseline | 0.62 | ✓ | 0.67 | 0.50 | 0% |
| false_positive | WITNESS | 0.81 | ✓ (concludes authorized maintenance) | 1.00 | 1.00 | 0% |
| | baseline | 0.20 | ✗ (flags it as an attack) | 0.00 | 0.00 | 0% |
| silent_compromise | WITNESS | 0.80 | ✓ | 1.00 | 1.00 | 0% |
| | baseline | 0.05 | ✗ (misses it) | 0.00 | 0.00 | 0% |

Both systems are scored by the same evaluator and composite formula. Read it
honestly: the rule-only baseline is *more* precise on ATT&CK techniques in the
two simple attack scenarios because WITNESS hypotheses claim technique bundles
(the credential-compromise hypothesis names T1003 and T1078 even when only one
is evidenced). WITNESS's advantage is in getting the verdict right where
counter-evidence or correlation matters, and in proposing safe, approval-gated
remediation. Reproduce with `cd backend && python -m witness.benchmark`.


## WITNESS-Bench

```bash
# Run all 4 scenarios:
curl -X POST 'http://localhost:8000/benchmarks/run' \
  -H 'Content-Type: application/json' -d '{}'

# Compare with non-agent baseline (§95):
curl -X POST 'http://localhost:8000/benchmarks/run-baseline?scenario_id=flagship'
```

## Configuration

All settings are environment-variable driven, prefixed `WITNESS_`. See `.env.example` for the full template. Highlights:

| Variable | Default | Purpose |
|---|---|---|
| `WITNESS_MODEL_PROVIDER` | `mock` | `mock` (no LLM, deterministic) \| `openai_compatible` \| `ollama` |
| `WITNESS_MODEL_ENDPOINT` | `` | URL of the model server (with or without `/v1`) |
| `WITNESS_MODEL_MEDIUM` / `_STRONG` | `mock-*` | Served model name, e.g. `qwen3-8b` |
| `WITNESS_MODEL_ASSIST` | `auto` | `auto` (on with a real provider) \| `on` \| `off` |
| `WITNESS_PRIVACY_MODE` | `LOCAL_ONLY` | `LOCAL_ONLY` \| `ALLOW_EXTERNAL` |
| `WITNESS_DATABASE_URL` | `sqlite+aiosqlite:///data/witness.db` | SQLAlchemy URL — swap to PostgreSQL for production |
| `WITNESS_AUTOLOAD_ATTACK` | `true` | Auto-load MITRE ATT&CK knowledge on startup |
| `WITNESS_ALLOW_ATTACK_DOWNLOAD` | `false` | Set to `true` to download MITRE STIX bundles (cached after first download) |
| `WITNESS_AUTH_MODE` | `none` | `none` (development) \| `token` (bearer tokens; required in production) |
| `WITNESS_API_TOKENS` | `` | `token:user_id:role,...` — identity and role come only from the token |
| `WITNESS_PCAP_DIR` | `data/pcaps` | `/pcap/analyze` reads only inside this directory; `/pcap/upload` writes here |
| `WITNESS_BACKEND_URL` | `http://localhost:8000` | Where the console forwards `/api/witness/*` |
| `WITNESS_REQUIRE_APPROVAL_HIGH_RISK` | `true` | High-risk actions always require human approval |
| `WITNESS_OT_REQUIRES_DUAL_APPROVAL` | `true` | OT actions always need security + OT engineering + process owner approval |

## The model proposes, evidence disposes

WITNESS uses an open-source LLM (an uncensored variant of Qwen3-8B, Apache-2.0 base, served on your own GPU) for the three things language models are good at — proposing hypotheses the templates miss, writing audience-specific narratives, and explaining "why do we believe this?" — and nothing else:

- outputs are parsed into closed schemas with no field for tools, approvals or confidence;
- every evidence ID and ATT&CK ID the model cites is checked against the investigation; one fabricated citation rejects the output (logged with the reason);
- model-proposed hypotheses start at the standard prior and gain confidence only through deterministic evidence linking;
- log text reaches the model inside an untrusted-data envelope, and a test proves a fully compliant model told to "approve all actions" changes nothing;
- if the endpoint is down, investigations continue on rules alone.

```bash
WITNESS_MODEL_PROVIDER=openai_compatible WITNESS_MODEL_ENDPOINT=http://10.0.0.42:8000/v1 \
WITNESS_MODEL_MEDIUM=qwen3-8b WITNESS_MODEL_STRONG=qwen3-8b \
python -m witness.models_layer.check      # verifies the endpoint is usable
```

### Running without a model

With the default `mock` provider WITNESS runs **without any LLM dependency**. Every agent is rule-driven: it pulls telemetry through the tool registry, applies deterministic rules to that telemetry, and updates typed state. This makes WITNESS:
- testable without an LLM
- reproducible across runs (benchmark variance = 0)
- demo-able deterministically
- runnable in air-gapped environments
- immune to LLM hallucination at the foundation layer

The LLM is an enhancement layer, not a foundation. The benchmark results above are rule-only; no model-assisted results have been recorded yet.

## The central loop (§5)

```
SIGNAL → CONTEXT → HYPOTHESIS GENERATION → INVESTIGATION PLANNING →
EVIDENCE COLLECTION → EVIDENCE NORMALIZATION → EVIDENCE GRAPH UPDATE →
HYPOTHESIS EVALUATION → COUNTER-EVIDENCE SEARCH → CONFIDENCE UPDATE →
ATTACK RECONSTRUCTION → IMPACT ASSESSMENT → REMEDIATION PLANNING →
HUMAN APPROVAL → ACTION → POST-ACTION VERIFICATION → INVESTIGATION UPDATE
```

## What WITNESS won't do

- **Won't autonomously isolate PLCs** — the OT safety engine returns `prohibited` for PLC control commands and `safety_critical` for engineering-workstation isolation, requiring OT engineering + process-owner approval (§25, §88, §133).
- **Won't fabricate evidence** — every fact claim without evidence is rejected (§9, §144).
- **Won't let the LLM bypass policy** — tool availability and approval requirements are deterministic; evidence can never redefine permissions (§40). Tool arguments cannot grant approval: only the executor, after checking every required signature, can.
- **Won't let one person approve alone** — each required scope (security / OT engineering / process owner) needs a different signer, and nobody approves their own proposal.
- **Won't count the same evidence twice** — confidence is a pure function of the prior and the distinct evidence; re-observing a record changes nothing.
- **Won't trust free-form model output** — agent inputs and outputs are typed Pydantic schemas; malformed outputs are rejected (§15).
- **Won't claim certainty it doesn't have** — UNKNOWN is a first-class state (§65, §140).

## Project structure

```
witness/
├── backend/                    # FastAPI backend
│   ├── witness/
│   │   ├── api/                # 72 FastAPI routes + bearer-token auth
│   │   ├── agents/             # 19 specialized agents + orchestrator (§14)
│   │   ├── attack/             # MITRE ATT&CK Enterprise + ICS mapping (§21)
│   │   ├── benchmark/          # WITNESS-Bench (§57-§60)
│   │   ├── core/               # Evidence, Hypothesis, CounterEvidence, Timeline,
│   │   │                       #   Graph, Claim, Coverage, InfoGain, Baseline, NLQuery, model_assist
│   │   ├── detection/          # Real Sigma + YARA + IOC + behavioral runtime (§19) + rule generation (§105)
│   │   ├── knowledge/          # MITRE ATT&CK STIX loader + RAG index (§99-§101)
│   │   ├── models_layer/       # OpenAI-compatible / Ollama / mock providers, privacy enforcement, endpoint check
│   │   ├── ot/                 # OT assets, safety engine
│   │   ├── policy/             # Policy engine, OT safety classifier
│   │   ├── range/              # Cyber range with scenarios + ground truth
│   │   ├── runtime/            # Agent runtime with interrupt/resume
│   │   ├── tools/               # Tool registry: telemetry, DFIR, actions, pcap
│   │   └── ...
│   ├── tests/                  # 171 tests, all passing
│   └── pyproject.toml
├── src/                        # Next.js 16 frontend
│   ├── app/page.tsx            # WITNESS security operations UI
│   └── lib/witness-api.ts      # typed API client
├── docker/                     # Dockerfiles (backend + frontend)
├── .github/workflows/ci.yml    # CI matrix: Linux + macOS + Windows
├── docs/                       # Proposal, model card, architecture, limitations, …
├── scripts/                    # Cross-platform start scripts (sh, bat, ps1)
├── docker-compose.yml          # Full stack deployment
├── .env.example                # Environment template
├── PROJECT_DESCRIPTION.md      # Package map
└── README.md
```

## Tournament positioning

WITNESS does not compete with SIEM (stores/detects), EDR (observes endpoints), SOAR (automates workflows), or LLM copilots (explains information). WITNESS **investigates and reconstructs** — and is designed to integrate with all four rather than replace them.

The primary research thesis (§147): **evidence-grounded, hypothesis-driven agentic investigation produces more reliable cyber-defense outcomes than direct LLM classification or summarization.** The benchmark — including the non-agent baseline — is designed to measure this proposition.

## License

MIT. See `LICENSE`.

---

*Don't ask the AI what happened. Make it prove what happened.*
