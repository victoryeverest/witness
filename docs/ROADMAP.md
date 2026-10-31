# WITNESS Roadmap

The current build is a complete, runnable, tested implementation. It is not the final form. Below is the prioritized list of what comes next.

## Phase 1 — Make the agents actually use the model (when configured)

Today, the agent layer is rule-driven even when `WITNESS_MODEL_PROVIDER` is set to a real LLM. The plumbing exists (`Agent.call_model`), but no agent calls it. The next step is to wire LLM calls into specific decision points:

- **Orchestrator**: use LLM to generate novel hypothesis statements beyond the template library. The LLM is given the current evidence + hypotheses and proposes new ones; the orchestrator validates them with the HypothesisEngine (the engine still owns confidence math).
- **Investigation planner**: use LLM to prioritize next steps based on the current state. The LLM proposes steps; the planner ranks them deterministically with the info-gain formula.
- **Reporting agent**: use LLM to draft the executive summary and audience-specific narrative, grounded in the structured state.

The deterministic engines stay in charge of confidence, evidence, policy, and OT safety. The LLM is purely an enhancement layer.

## Phase 2 — Expand the cyber range

Add scenarios from §55 that aren't yet covered:

- **Multi-stage intrusion** (different from flagship — e.g. ransomware staging)
- **OT lateral movement** (PLC → PLC, no IT origin)
- **Manipulated process variable** (no PLC write, just setpoint change)
- **Inhibit-response scenario** (alarm suppression without compromise)
- **IT/OT blended intrusion** (multiple paths into OT)
- **Simultaneous incidents** (correlation across two scenarios)
- **Compromised account + legitimate admin activity** (mixed benign + malicious signals)
- **Timestamp corruption** (clock-skew attack on timeline)
- **Multi-source disagreement** (SIEM says X, EDR says Y)

## Phase 3 — Real tool integrations

The tool layer is a clean abstraction. The implementations are stubs that read from `ctx_state["telemetry"]`. Replace each with a real integration:

- **SIEM**: Splunk / Elastic / Microsoft Sentinel search APIs
- **EDR**: CrowdStrike / Microsoft Defender / SentinelOne
- **Network**: Zeek / Suricata / Corelight
- **Identity**: Active Directory / Entra ID / Okta
- **Cloud**: AWS CloudTrail / Azure Activity / GCP Audit
- **OT**: Modbus TCP / DNP3 / OPC UA / S7 / IEC 60870-5-104 protocol parsers
- **DFIR**: Velociraptor / osquery / Volatility / Plaso

Each integration implements the existing tool interface — no agent code changes.

## Phase 4 — Detection engine (§19)

Add runtime evaluation of Sigma / YARA / Suricata rules against telemetry:

- `pip install sigma` and `yara-python`
- Implement `DetectionEngine.evaluate(rule, evidence_stream)` that returns matches as evidence
- The agent interprets the matches, doesn't trust them blindly (§102: knowledge vs evidence)

## Phase 5 — Knowledge ingestion

Replace the hand-curated MITRE ATT&CK technique dicts with live STIX bundle ingestion:

- Fetch the official MITRE ATT&CK Enterprise + ICS STIX bundles
- Parse into `KnowledgeItem` rows with proper provenance (version, retrieval date, license, content hash)
- Build a `KnowledgeIndex` for fast retrieval
- Use the index for `technique_name()` lookups and RAG (§101)

## Phase 6 — Multi-incident correlation (§112, §113)

Build the `Campaign` model — link incidents that share identity, infrastructure, IOCs, TTPs, or timeline. The orchestrator should be able to invoke a campaign-detection agent after N investigations.

## Phase 7 — Real-time updates

The UI currently polls on tab change. Add WebSocket push for:

- Investigation status changes
- New evidence insertion
- Hypothesis confidence updates
- Action approval requests
- Benchmark completion

## Phase 8 — RBAC enforcement

Today, the `User.role` field exists and the policy engine checks it for tool execution, but the API doesn't enforce RBAC on its own routes. Add:
- Per-route role requirements
- Per-investigation / per-incident ownership
- Per-organization data scoping

## Phase 9 — Model evaluation harness (§62)

Build the model comparison framework:
- Run WITNESS-Bench against multiple models (small / medium / strong / verification role)
- Produce automated benchmark reports comparing accuracy, reasoning quality, tool-call reliability, hallucination, latency, VRAM, tokens, energy, cost
- Persist reports in a `ModelComparison` table

## Phase 10 — UI polish

- Real-time investigation timeline animation
- Attack graph visualization (D3.js force-directed)
- Evidence detail panel with hash verification display
- Counter-evidence panel showing support vs contradict bars (§7)
- Investigation coverage heatmap (§36)
- Multi-audience report viewer (analyst / executive / OT engineer / auditor / CISO)

## Phase 11 — Performance

- Cache: ATT&CK data, threat intel, normalized evidence, repeated queries (§72)
- Async workers for expensive operations (PCAP analysis, memory acquisition, model calls)
- Streaming progress to UI via SSE / WebSocket
- Background benchmark queue

## Phase 12 — Reliability (§73)

- Timeouts, retries, circuit breakers
- Idempotency keys for tool calls
- Dead-letter queue for failed agent tasks
- Transaction boundaries around evidence ingestion
- Database constraints (some are missing in the demo build)

## Phase 13 — Security hardening (§77)

- SAST (Bandit / Ruff)
- Dependency scanning (pip-audit)
- Secret scanning (gitleaks)
- Container scanning (trivy)
- API authorization tests
- Prompt-injection tests (we have 2 — expand to cover §61)
- Tool authorization tests
- RBAC tests
- Audit integrity tests

## Phase 14 — Competitive benchmarking (§95)

Add baselines:
- Non-agent LLM classifier (just give the LLM the telemetry and ask "what happened?")
- RAG baseline (LLM with ATT&CK retrieval)
- Single-agent baseline (one orchestrator, no specialist agents)
- Multi-agent baseline (current WITNESS, no counter-evidence engine)

Compare on WITNESS-Bench. The hypothesis: WITNESS's architecture (evidence + counter-evidence + verification) outperforms all four baselines on investigation score.

## Phase 15 — Production deployment

- PostgreSQL with row-level security
- Redis for caching + task queue
- Celery / Arq for async workers
- Docker Compose + Kubernetes manifests
- Helm chart
- TLS termination at the gateway
- OIDC / SAML authentication
- Per-tenant data isolation
