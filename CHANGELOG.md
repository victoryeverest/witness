# Changelog

## 1.0.0 — first public release

### Investigation
- Investigation loop with 19 specialist agents (identity, endpoint, network, DFIR, OT, threat intel, contradiction analyst, risk, response planning, verification, reporting, …) dispatched through a policy-gated tool registry (25 tools).
- 11 hypothesis templates across IT and OT, always including a benign alternative; up to 3 more per investigation proposed by an open-source model.
- Deterministic Bayesian log-odds confidence: per-evidence weights, correlation decay, re-observation never inflates confidence.
- Counter-evidence engine matching change tickets and maintenance windows to the user, host and time of the activity.
- Staged attack reconstruction mapped to MITRE ATT&CK Enterprise and ICS (e.g. rogue Modbus write → T0855 + T0836, process deviation → T0831, alarm suppression → T0878).
- Audience-specific reports (executive, analyst, OT engineer, auditor) and "why do we believe this?" explanations.
- Pause, resume and cancel at iteration boundaries; background runs.

### Evidence
- Append-only, content-hashed, sequence-numbered hash chain with a verifier (`GET /investigations/{id}/integrity`) that detects edits, deletions and reordering.

### Safety and access control
- Agents only propose actions. Execution requires a signature per approval scope (security / OT engineering / process owner) from different people; the proposer cannot approve.
- `denied` (RBAC) and `prohibited` (OT safety) are terminal; OT safety can only make a decision stricter; PLC control commands are always prohibited.
- Authorization comes only from the executor, enforced in the tool registry; post-action verification.
- Bearer-token auth with server-side roles; production refuses to start without auth.
- PCAP analysis confined to `WITNESS_PCAP_DIR`; uploads size- and format-checked.
- `LOCAL_ONLY` privacy mode enforced for model endpoints; the console makes no third-party requests.

### Open-source model assistance
- OpenAI-compatible (vLLM, llama.cpp) and Ollama providers; built on Qwen3-8B (uncensored variant). JSON mode, retries with backoff, Qwen3 `<think>` handling.
- Closed output schemas; every evidence and ATT&CK citation verified (one fabrication rejects the output); untrusted log text passed in an envelope; every call metered in `ModelExecution` and the audit log; automatic fallback to rules.
- `python -m witness.models_layer.check` validates a deployed endpoint, including whether the model follows instructions injected into logs.

### Detection and analysis
- Sigma (pySigma) and YARA runtimes, agent-authored rule generation with validation, PCAP parsing (flows, DNS, HTTP, TLS, Modbus, DNP3), statistical baselines, NL → query, ATT&CK STIX loader.

### Evaluation
- WITNESS-Bench: 4 cyber-range scenarios with hidden ground truth, scored together with a rule-only baseline by the same evaluator; `python -m witness.benchmark`.

### Console and deployment
- Next.js console with 12 tabs, including Response (per-scope signing, reject, execute, verification) and evidence-chain status.
- Docker Compose with a Caddy gateway; start scripts for Linux/macOS, PowerShell and cmd; GitHub Actions CI (3 OSes × Python 3.11/3.12, ruff, tsc, build, pip-audit, Docker end-to-end).
- 171 tests.
