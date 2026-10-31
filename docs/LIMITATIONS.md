# WITNESS Known Limitations (§152)

What is reduced, and why.

## Model layer

- **Published benchmark numbers are from the rule-based pipeline.** Model assistance (hypothesis proposals, narratives, explanations) with the uncensored Qwen3-8B is covered by tests against a scripted stand-in and mocked HTTP servers; see `docs/MODEL_CARD.md` for the model-assisted evaluation.
- **The model's role is deliberately narrow.** Investigation steps, evidence collection, scoring, policy and OT safety stay rule-driven; the model cannot plan tool calls. That keeps runs reproducible and safe, and also means most "agentic" behaviour is a fixed rule library.
- **Grounding checks verify citations, not prose.** A narrative citing only valid evidence IDs can still characterise them loosely; the check catches fabricated references, not every misstatement.
- **Privacy mode checks the model endpoint, not the network.** Under `LOCAL_ONLY`, model providers refuse endpoints that are not loopback/private/single-label hosts. A DNS name is treated as remote. Nothing stops other code from making outbound calls; the ATT&CK downloader has its own check.
- **The `ModelRouter` is trivial** — no availability, latency or budget awareness, no circuit breaker (§63).

## Reasoning

- **Without a model, hypotheses come from a fixed template library** (11 statements). With a model, up to 3 more per investigation are proposed and validated.
- **Hypotheses claim technique bundles.** E.g. the credential-compromise hypothesis names T1003, T1003.001, T1078 and T1078.002; when it wins on one of them, the others are reported too. This is why ATT&CK precision trails the simple baseline. The report's `evidence_backed_techniques` section lists only what evidence supports.
- **Confidence calibration is heuristic.** Log-odds weights (support 0.6, contradiction 1.0, correlation decay 0.85) and priors (0.35 attack, 0.5 benign) are reasoned choices, not fitted to data.
- **Counter-evidence covers two patterns:** change tickets (matched on user/host/time window) and scheduled maintenance windows (matched on asset).

## Cyber range

- **Telemetry is fixed fixtures.** No live traffic, PCAP replay or Modbus simulation. Deterministic on purpose.
- **4 scenarios only.** The spec (§55) lists ~25.
- **No physical process simulation (§134).** `plc_state` is a dict.
- **Memory acquisition is simulated.** In the range it returns a placeholder image path flagged `synthetic: true`; there is nothing to analyse.

## Tools & integrations

- **No real SIEM/EDR/Zeek/identity connectors.** Telemetry tools read `ctx.state["telemetry"]`. PCAP parsing (dpkt), Sigma (pySigma) and YARA (yara-python) are real. PCAP parsing is IPv4-only.
- **Response tools act on the cyber range only.** `isolate_endpoint` etc. record their effect in investigation state; they do not call firewalls or EDR.
- **`plc_control_action` can never run.** Its risk level is `prohibited`; the registry refuses it regardless of approvals. Intentional (§133).

## Security model

- **Token auth is the only authentication mode.** Tokens are static, configured via environment, compared in constant time, and carry one role each. No OIDC/SAML, no expiry, no rotation API, no per-tenant isolation or row-level security.
- **Development mode (`WITNESS_AUTH_MODE=none`) trusts the caller.** Identity comes from headers or request bodies. Separation-of-duties checks still apply, but anyone can claim any identity. Production refuses to start in this mode unless `WITNESS_ALLOW_INSECURE_PRODUCTION=true`.
- **Read endpoints are not role-restricted.** Any authenticated principal can read every investigation.
- **The audit log is append-only by convention, not cryptographically chained** (unlike evidence).
- **No rate limiting.**

## Runtime

- **Background runs live in the API process.** No external queue (Celery/Arq); a restart abandons a running investigation (its committed iterations are kept and it can be resumed).
- **Pause/cancel take effect at iteration boundaries**, not mid-agent.
- **No retries or dead-letter handling** for failed agent tasks; failures are recorded on the task and in the audit log.

## Frontend

- **No real-time push.** The console fetches on navigation; background runs are observed by refreshing.
- **Tabs for Hunting, Assets, Identity, Network, Threat Intel, Detection and Reports (§45) do not exist.** The API supports them.

## Benchmark

- **Only the non-agent baseline exists.** No RAG or single-agent baselines (§95), and no multi-model comparison (§62).
- **Energy and tokens are not measured** (`None` / 0 under the mock provider).
