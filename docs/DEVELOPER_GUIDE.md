# WITNESS Developer Guide

## Setting up the dev environment

```bash
# Python backend
cd backend
pip install -r requirements.txt   # or: uv pip install -r requirements.txt

# Frontend (Next.js 16)
cd ..
bun install
```

## Running the dev environment

```bash
# Terminal 1: backend
cd backend
python3 -m uvicorn witness.api.app:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2: frontend
bun install && bun run dev   # or: npm install && npm run dev
# Visit http://localhost:3000 — the console forwards /api/witness/* to the backend
```

## Running the tests

```bash
cd backend
python3 -m pytest tests/ -v
# 171 tests, all should pass. conftest.py points them at a throwaway
# database, so running the suite never touches data/witness.db.
```

## Project layout

```
backend/
├── witness/
│   ├── api/app.py             # FastAPI app — all routes
│   ├── agents/
│   │   ├── base.py            # Agent abstract base + registry
│   │   ├── orchestrator.py    # top-level coordinator (§14 #1)
│   │   ├── specialized.py     # 18 other agents (triage, planner, ...)
│   │   └── __init__.py        # imports all agents to populate registry
│   ├── attack/mapper.py       # MITRE ATT&CK Enterprise + ICS mapping (§21)
│   ├── benchmark/bench.py    # WITNESS-Bench (§57-§60)
│   ├── core/
│   │   ├── evidence.py        # immutable, hash-chained evidence (§8)
│   │   ├── hypothesis.py      # Bayesian-style confidence (§6)
│   │   ├── counter_evidence.py  # support + counter plans (§7)
│   │   ├── timeline.py        # cross-domain timeline (§11)
│   │   ├── graph.py           # evidence graph + blast radius (§10, §131)
│   │   ├── claim.py           # claim verification (§9, §144)
│   │   ├── coverage.py        # per-domain coverage (§36, §48)
│   │   └── info_gain.py       # investigation priority scoring (§13)
│   ├── models_layer/
│   │   ├── base.py            # ModelProvider, MockProvider, OpenAICompatible, Ollama
│   │   └── router.py          # ModelRouter (§63)
│   ├── ot/
│   │   ├── assets.py          # OT asset factory (§22)
│   │   └── safety.py          # OT safety engine (§25)
│   ├── policy/
│   │   └── engine.py          # policy engine, RBAC, OT safety classification (§39)
│   ├── range/cyber_range.py  # scenarios + ground truth (§53-§56)
│   ├── runtime/runtime.py    # agent runtime, interrupt/resume (§128)
│   ├── tools/
│   │   ├── base.py            # Tool abstract base + registry (§42)
│   │   ├── telemetry.py       # read tools (sysmon, zeek, edr, ...)
│   │   ├── dfir.py            # DFIR tools (registry, prefetch, memory)
│   │   └── actions.py         # response actions (isolate, disable, plc_control)
│   ├── config.py              # pydantic-settings, all env vars
│   ├── db.py                  # SQLAlchemy engine + session
│   ├── models.py              # full ORM data model (§66)
│   ├── schemas.py             # Pydantic DTOs + typed agent contract (§15)
│   └── utils/                  # crypto, time, logging
├── tests/
│   ├── test_witness.py        # unit/integration/e2e tests (§144 contracts)
│   ├── test_api.py            # API surface tests
│   ├── test_hardening.py      # safety and correctness invariants
│   └── conftest.py            # path setup
└── pyproject.toml

src/                            # Next.js 16 frontend
├── app/page.tsx                # single-page WITNESS UI
├── app/layout.tsx              # root layout
└── lib/witness-api.ts          # typed API client
```

## Adding a new agent

1. Create a class in `witness/agents/specialized.py` (or a new file):
```python
@register_agent
class MyNewAgent(Agent):
    name = "my_new_agent"
    description = "Does X for the investigation"
    default_role = "medium"  # small / medium / strong / verification
    domain = "endpoint"      # one of the SourceDomain values

    async def run(self, inp: AgentInput) -> AgentOutput:
        # 1. Call tools via self.call_tool(tool_name, args)
        # 2. Insert evidence via add_evidence()
        # 3. Update hypotheses via HypothesisEngine.add_support / add_contradiction
        # 4. Add timeline events via TimelineEngine.add_event
        return self._output(inp,
            findings=[FindingItem(...)],
            summary="...",
        )
```

2. The `@register_agent` decorator adds it to the registry. It's now available via `get_agent_class("my_new_agent")` and visible in the UI's System tab.

3. To invoke it from the runtime loop, either:
   - Add it to a counter-evidence template's `support` or `counter` steps in `witness/core/counter_evidence.py` — the planner will dispatch it.
   - OR add it to the runtime loop directly in `witness/runtime/runtime.py`.

## Adding a new tool

1. Create a class in `witness/tools/telemetry.py`, `witness/tools/dfir.py`, or `witness/tools/actions.py`:
```python
class MyTool(Tool):
    name = "my_tool"
    description = "Does X"
    permissions = [READ_TELEMETRY]   # from witness/tools/base.py
    risk_level = "low"               # low / medium / high / critical / prohibited
    read_write = "read"             # read / write
    rollback_capable = False
    side_effect = False
    approval_required = False

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        # Read from ctx.state (the investigation's telemetry fixtures)
        telemetry = ctx.state.get("telemetry", [])
        # ... do work ...
        return ToolResult(success=True, data={"result": ...})
```

2. Register it at the bottom of the file: `register(MyTool())`.

3. Add it to the policy engine's permission map in `witness/policy/engine.py`:
```python
_TOOL_PERMISSIONS["my_tool"] = {"READ_TELEMETRY"}
_TOOL_STATIC_POLICY["my_tool"] = {"risk": "low", "approval": False}
```

## Adding a new scenario

1. Write a builder function in `witness/range/cyber_range.py`:
```python
def my_scenario() -> dict[str, Any]:
    telemetry = [...]  # list of telemetry rows
    return {
        "name": "My Scenario",
        "scope": "enterprise",  # enterprise / ot / hybrid / false_positive / silent / ...
        "difficulty": "medium",
        "description": "...",
        "scenario_seed": 100,
        "ground_truth": {
            "attack_start": "...",
            "attack_end": "...",
            "techniques": ["T1059"],
            "stages": [...],
            "expected_remediation": [...],
            "false_positive_traps": [...],
        },
        "telemetry": telemetry,
    }

ALL_SCENARIOS["my_scenario"] = my_scenario
```

2. Add a test in `tests/test_witness.py::TestCyberRange` asserting the ground truth has the expected techniques.

## Adding a new ATT&CK technique mapping

Add a rule function and add it to the `_RULES` list in `witness/attack/mapper.py`:

```python
def _rule_my_new_pattern(nd: dict) -> bool:
    return nd.get("event_kind") == "my_new_event_kind"

_RULES = [
    ...
    (_rule_my_new_pattern, "T1234.001"),
]
```

The rule is deterministic — it must inspect specific fields in the evidence's `normalized_data` and return True/False. Never use LLM introspection to decide mapping (§21: "Never claim an ATT&CK technique merely because an LLM thinks it 'sounds similar.'").

## Debugging

### Backend won't start

```bash
# Check the log
tail -50 /tmp/witness.log

# Most common issues:
# - Port 8000 already in use → pkill -f "uvicorn witness"
# - Database locked → rm -f data/witness.db
# - Import error → check the traceback
```

### Frontend can't reach backend

The console calls `/api/witness/*` on its own origin. `next dev`/`next start` rewrite that to `WITNESS_BACKEND_URL` (default `http://localhost:8000`); in Docker the Caddy gateway strips the prefix. If the console shows "Cannot connect", check that the backend is up and that `WITNESS_BACKEND_URL` points at it.

### Benchmarks fail

```bash
# Try a single scenario first
curl -X POST 'http://localhost:8000/benchmarks/run' \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id": "flagship"}'

# If a specific scenario fails, look at the backend log for the traceback
```

### UI shows "Cannot connect to WITNESS backend"

The backend isn't running, OR it's not bound to 0.0.0.0 (must be 0.0.0.0, not 127.0.0.1, because the Caddy gateway proxies from a different network namespace).

```bash
bash scripts/start.sh          # Windows: scripts\start.bat or pwsh scripts/start.ps1
```

## CI/CD (§124)

A minimal CI pipeline:

```yaml
# .github/workflows/ci.yml
name: WITNESS CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - uses: oven-sh/setup-bun@v1
      - run: pip install -r backend/requirements.txt
      - run: cd backend && python3 -m pytest tests/ -v
      - run: bun install
      - run: bun run lint
```

The build must fail when core tests fail (§124).
