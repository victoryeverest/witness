# Security model

WITNESS proposes containment actions that can disrupt IT and OT systems. This
document describes what stands between a proposal and its execution, and how
to deploy safely. For the full threat analysis see `docs/THREAT_MODEL.md`;
for known gaps see `docs/LIMITATIONS.md`.

## The path from proposal to execution

```
agent / API caller
   │  propose (tool, arguments)
   ▼
policy engine ── RBAC: does the proposer's role hold the tool's permission?   → denied (terminal)
   │          ── static risk: does the tool need approval?
   ▼
OT safety engine ── target is an OT asset (or unknown)? classify the action  → prohibited (terminal)
   │                 can only make the decision stricter, never looser          or more approval scopes
   ▼
Action row: proposed, one pending Approval per required scope
   │  humans sign scopes: security · ot_engineering · process_owner
   │  ─ a scope is signed once ─ one identity signs at most one scope
   │  ─ the proposer cannot sign ─ (token mode) the role must be allowed to sign that scope
   ▼
approved ──► executor ── re-checks status and risk, then calls the tool with
                         ToolContext.authorized_action_id set
                         │
tool registry guard ─────┘ refuses: prohibited tools always · cyber-range-only tools
                           in production · any side-effecting call without an
                           executor-set authorization (dry runs are allowed)
   ▼
completed / failed ── effect persisted, then verified (verification attached)
```

Key properties, each covered by `backend/tests/test_hardening.py`:

- **Arguments cannot authorize.** An `"approved": true` argument is stripped.
  Only the executor sets `authorized_action_id`, after checking the Action row.
  This matters because agent arguments may one day come from an LLM reading
  attacker-controlled telemetry.
- **Terminal states are terminal.** `denied`, `prohibited`, `rejected`,
  `completed` and `failed` actions can never be approved or (re-)executed.
- **Agents never execute side effects.** They call `Agent.propose_action`,
  which records a proposal. Read-only tools and dry runs run directly.
- **PLC control commands are prohibited** (§133) at both the policy engine and
  the tool registry.

## Deploying

1. Set `WITNESS_ENVIRONMENT=production`.
2. Set `WITNESS_AUTH_MODE=token` and `WITNESS_API_TOKENS` with long random
   tokens (`python -c "import secrets; print(secrets.token_urlsafe(32))"`),
   one per person, each with the least-privileged role:

   | Role | Can sign scopes | Typical holder |
   |---|---|---|
   | `security_engineer`, `responder`, `senior_analyst` | security | SOC / IR |
   | `ot_engineer` | ot_engineering | plant OT engineering |
   | `approver` | security, process_owner | process owner / duty manager |
   | `admin` | all (still one per action) | platform admin |
   | `viewer`, `analyst`, `ot_analyst`, `auditor` | none | read / investigate |

   The server refuses to start in production without auth, and rejects
   production tokens shorter than 16 characters.
3. Terminate TLS at the gateway (replace `:80` with your hostname in
   `docker/Caddyfile.prod`). Do not expose port 8000 beyond the host.
4. Keep `WITNESS_PRIVACY_MODE=LOCAL_ONLY` unless you have reviewed where model
   calls would go.
5. Verify retained cases periodically with
   `GET /investigations/{id}/integrity` (`intact: true`).

## Reporting a vulnerability

Please report privately to the maintainers rather than opening a public issue,
with steps to reproduce and the affected version.
