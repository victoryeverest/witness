# WITNESS API Reference

The WITNESS backend exposes 56 routes. All routes are documented in OpenAPI at `/docs` (Swagger UI) and `/redoc` (ReDoc) when the backend is running.

## Base URL

All routes are at the backend root: `http://localhost:8000/`. Through the console (`next dev`) or the Caddy gateway they are also served under `/api/witness/<path>`.

## Authentication

With `WITNESS_AUTH_MODE=token`, every route except `/health`, `/docs`, `/redoc` and `/openapi.json` needs `Authorization: Bearer <token>`. Identity and role come from `WITNESS_API_TOKENS`; body fields such as `approver_id`, `user_role` and `proposed_by` are ignored. `GET /auth/whoami` shows who you are. In `none` mode (development) callers may identify themselves with `X-Witness-User` / `X-Witness-Role`; nothing is verified.

## Error semantics

`404` unknown object · `409` the policy or state machine refuses the request (e.g. approving a prohibited action, signing a scope twice, re-running a completed investigation) · `403` your role may not do this · `401` missing/invalid token.

## Approvals, integrity and uploads

- `GET /auth/whoami`
- `GET /actions?investigation_id=&status=` — actions with their per-scope approvals and verification
- `GET /investigations/{id}/integrity` — content hashes + chain-of-custody verification
- `POST /pcap/upload?investigation_id=` — multipart upload into the PCAP directory (pcap/pcapng magic checked, size-limited), analyzed by default
- `POST /investigations/{id}/run` and `/resume` accept `"background": true`; poll `GET /investigations/{id}` (`running` field). Pause/cancel take effect at the next iteration boundary.

## Model assistance

- `POST /hypotheses/{id}/explain` — "why do we believe this?". `source` is `model` (citations verified) or `deterministic` (with `model_unavailable_reason` when the model's answer was rejected).
- `GET /models` — provider, model names, whether assistance is on, whether the endpoint is local.
- `GET /models/executions?investigation_id=` — every model call: purpose, tokens, latency, accepted, rejection reason.
- Hypotheses carry `provenance` (`{"origin": "template"}` or `{"origin": "model", "model", "rationale", "cited_evidence", ...}`).
- Reports include `narrative` (model-written, citations verified) or `narrative_unavailable` (reason).

## Action lifecycle

`proposed` → (each required scope signed by a distinct person) → `approved` → `executing` → `completed` | `failed`, with `verification` attached. `denied` (RBAC) and `prohibited` (OT safety) are terminal and recorded only for audit; `rejected` is terminal. There is no auto-approve.

## Authentication

The `/auth/login` endpoint accepts an email and returns a user ID. In production, replace this with NextAuth.js / OIDC / SAML. RBAC roles per §68: `viewer`, `analyst`, `senior_analyst`, `responder`, `ot_analyst`, `ot_engineer`, `security_engineer`, `admin`, `approver`, `auditor`.

## Endpoints by group (§67)

### `/health`
- `GET /health` — liveness probe

### `/auth`
- `POST /auth/login` — dummy login (creates user if not exists)

### `/assets`
- `GET /assets` — list all assets
- `GET /assets/{asset_id}` — get asset with OT extension if present
- `POST /assets` — create asset

### `/incidents`
- `GET /incidents` — list incidents
- `POST /incidents` — create incident
- `GET /incidents/{incident_id}` — get incident

### `/investigations`
- `GET /investigations` — list
- `POST /investigations` — create
- `GET /investigations/{id}` — full workspace state (hypotheses, evidence, timeline, gaps, coverage, tasks, actions)
- `POST /investigations/{id}/run` — invoke the central loop
- `POST /investigations/{id}/pause`
- `POST /investigations/{id}/resume`
- `POST /investigations/{id}/cancel`
- `GET /investigations/{id}/gaps` — "What haven't we checked?" (§48)
- `GET /investigations/{id}/coverage` — per-domain coverage (§36)
- `GET /investigations/{id}/what-would-change-mind` — §49 challenge for all hypotheses

### `/evidence`
- `GET /evidence?investigation_id=...` — list evidence for investigation
- `POST /evidence?investigation_id=...` — manually add evidence
- `GET /evidence/{evidence_id}` — get one evidence row

### `/timeline`
- `GET /timeline?investigation_id=...` — unified cross-domain timeline

### `/graph`
- `GET /graph?investigation_id=...` — evidence graph (nodes + edges)

### `/hypotheses`
- `GET /hypotheses?investigation_id=...` — list
- `POST /hypotheses?investigation_id=...` — manually create
- `GET /hypotheses/{hypothesis_id}/challenge?investigation_id=...` — §49 "What would change your mind?"
- `GET /hypotheses/{hypothesis_id}/counter_plans?investigation_id=...` — support + counter plans (§7)
- `POST /hypotheses/{hypothesis_id}/counter?investigation_id=...` — generate counter-hypothesis

### `/hunting`
- `POST /hunting` — trigger hunt-mode investigation (§30, §106)

### `/threat-intel`
- `GET /threat-intel?indicator_type=...` — list TI entries

### `/attack`
- `GET /attack/enterprise` — MITRE ATT&CK Enterprise technique catalog
- `GET /attack/ics` — MITRE ATT&CK ICS technique catalog + tactics

### `/ot`
- `GET /ot/assets` — list OT-specific assets
- `POST /ot/safety-assessment` — run the OT safety classifier on a proposed action

### `/actions`
- `POST /actions/propose?investigation_id=...` — propose an action; runs through policy engine
- `POST /actions/approve` — approve an action (with role)
- `POST /actions/reject` — reject an action (with role + reason)
- `POST /actions/execute` — execute an approved action via the tool registry

### `/approvals`
- `GET /approvals?status=...` — list approvals

### `/reports`
- `POST /reports/generate?investigation_id=...&audience=...` — generate report (audience: analyst / executive / ot_engineer / auditor / ciso)
- `GET /reports/{report_id}` — get one report

### `/benchmarks`
- `POST /benchmarks/run` — run benchmark (single scenario or all)
- `GET /benchmarks` — list historical runs

### `/models`
- `GET /models` — show configured model provider + roles

### `/tools`
- `GET /tools` — list all registered tools with permissions, risk levels

### `/agents`
- `GET /agents` — list all 19 agents

### `/audit`
- `GET /audit?investigation_id=...&limit=...` — audit log

### `/scenarios`
- `POST /scenarios/load?scenario_key=...` — load a scenario into the DB
- `GET /scenarios` — list loaded scenarios
- `GET /scenarios/available` — list available scenario builders

### `/demo`
- `POST /demo/flagship` — one-shot flagship IT→OT demo (§84)

### `/system`
- `POST /system/reset` — drop all tables and recreate (tests / demo). Always `403` in production; admin-only in token mode.

## Common patterns

### Run the flagship demo end-to-end

```bash
curl -X POST 'http://localhost:8000/demo/flagship' \
  -H 'Content-Type: application/json' \
  -d '{"max_iterations": 5}'
```

Returns the investigation_id, status, iteration count, metrics, hypotheses, and evidence/timeline/action counts.

### Propose + approve + execute an action

```bash
# 1. Propose
curl -X POST 'http://localhost:8000/actions/propose?investigation_id=INV-XYZ' \
  -H 'Content-Type: application/json' \
  -d '{"tool_name": "isolate_endpoint", "arguments": {"host": "WS-01"}, "user_role": "responder"}'
# → { action_id: "AC-...", decision: { decision: "require_approval", required_approvals: ["security"] } }

# 2. Approve (one role at a time)
curl -X POST 'http://localhost:8000/actions/approve' \
  -H 'Content-Type: application/json' \
  -d '{"action_id": "AC-...", "approver_id": "U-alice", "approver_role": "security"}'

# 3. Execute
curl -X POST 'http://localhost:8000/actions/execute' \
  -H 'Content-Type: application/json' \
  -d '{"action_id": "AC-..."}'
```

For OT actions, the policy engine requires multiple approvals (`security` + `ot_engineering` + `process_owner`). The action only moves to `status=approved` when all required-role approvals are recorded.

### Generate a report

```bash
curl -X POST 'http://localhost:8000/reports/generate?investigation_id=INV-XYZ&audience=executive'
# → { id: "REP-...", markdown: "...", body: { executive_summary, ... } }
```

Audiences: `analyst`, `executive`, `ot_engineer`, `auditor`, `ciso`. The report generator produces a different view per audience (§114-118).
