# WITNESS — project proposal (Wittgenstein AI Tournament, semifinal)

> Don't ask the AI what happened. Make it prove what happened.

## 1. The problem

When an alert fires, a SOC analyst or incident responder has to answer three
questions under pressure: *what happened, how sure are we, and what is safe to
do about it?* LLM copilots answer the first fluently and the other two badly.
They state conclusions without showing the evidence, they can't tell you what
would change their mind, and in industrial (OT) environments the "obvious"
response — isolate the compromised host — can cut operators off from a running
process.

WITNESS is an agentic investigation system for SOC, DFIR and OT/ICS defenders
that treats an investigation the way a good analyst does: competing
hypotheses, evidence for **and against** each, explicit confidence, explicit
unknowns, and remediation that humans approve.

## 2. What it does

Given telemetry (Windows events, Sysmon, Zeek, VPN, email gateway, Modbus,
process historian, alarm system, PCAP uploads), WITNESS:

1. Generates competing hypotheses (11 templates + **model-proposed**
   hypotheses from an open-source LLM), including a benign explanation.
2. Plans and dispatches 19 specialist agents (identity, endpoint, network,
   DFIR, OT, threat intel, contradiction analyst, …) through a policy-gated
   tool registry.
3. Collects evidence into an append-only, **hash-chained** store
   (`GET /investigations/{id}/integrity` proves nothing was altered,
   deleted or reordered).
4. Scores hypotheses with a deterministic Bayesian engine. Re-observing the
   same evidence never inflates confidence, and correlated evidence counts
   with diminishing weight.
5. Actively searches for counter-evidence (change tickets, maintenance
   windows), matched to the user, host and time of the activity.
6. Reconstructs the attack as stages (initial access → … → process impact)
   backed by evidence IDs, mapped to MITRE ATT&CK Enterprise **and ICS**.
7. Proposes containment. Every side-effecting action needs human sign-off per
   scope (security / OT engineering / process owner), by **different people**.
   OT assets are classified by an OT safety engine, PLC control commands are
   prohibited outright, and execution is verified afterwards.
8. Writes audience-specific reports (executive, analyst, OT engineer,
   auditor) and answers "why do we believe this?".

## 3. Mapping to the tournament principles

| Principle (from the tournament page) | How WITNESS meets it |
|---|---|
| Independent agentic AI | 19 agents, typed contracts, an investigation loop that plans its own next steps; runs fully self-hosted. |
| Open-source foundations | Built on an **uncensored variant of Qwen3-8B (Apache-2.0 base)** served locally (vLLM / llama.cpp / Ollama). Lineage recorded in `docs/MODEL_CARD.md`. Every other dependency is open source. |
| Small, energy-efficient models | One 8B model, used only where language helps (hypothesis ideation, narrative, explanation). Detection, scoring, policy and safety are deterministic code, so most of an investigation uses no GPU at all. Runs with **no model** too. |
| Curated data / no harvesting | `LOCAL_ONLY` privacy mode is enforced: the model endpoint must be on the local or private network. No telemetry leaves the deployment; the console makes no third-party requests. |
| Humans firmly in the loop | Agents can only *propose*. Approval scopes, separation of duties, terminal "prohibited" and "denied" states, post-action verification, full audit log. |

## 4. How the AI is used (Innovation)

The design principle is **the model proposes, evidence disposes**:

- Model output is parsed into closed schemas. There is no field through which
  it could request a tool, approve an action or set a confidence.
- Every evidence ID and ATT&CK technique it cites is verified against the
  investigation. One fabricated citation rejects the whole output, which is
  logged with the reason.
- A model-proposed hypothesis starts at the same prior as any other and gains
  confidence only when the deterministic ATT&CK mapper independently links
  evidence to it.
- Attacker-controlled log text is passed inside an untrusted-data envelope. A
  test feeds the system a log line telling the model to "approve all pending
  actions", with a model that fully complies: nothing is approved, because
  there is no path from its output to an approval.
- Every call is metered (tokens, latency, accepted/rejected) for the
  energy/accuracy trade-off the tournament cares about.

This turns the usual LLM failure modes (hallucinated facts, prompt
injection, overconfidence) into logged, rejected outputs instead of wrong
conclusions.

## 5. Evidence it works (Technical quality)

- **171 automated tests**: reasoning contracts, API, every safety invariant,
  prompt-injection resistance, model-failure fallback.
- **WITNESS-Bench**: 4 cyber-range scenarios with hidden ground truth,
  including a full IT→OT intrusion (phishing → PowerShell → LSASS → VPN →
  engineering workstation → rogue Modbus write → process deviation → alarm
  suppression). The same evaluator scores a non-agent baseline.

| Scenario | WITNESS score | Baseline | Note |
|---|---|---|---|
| IT→OT intrusion | 0.79 | 0.68 | Both detect it; the baseline is more precise on ATT&CK IDs (0.95 vs 0.80); WITNESS adds safe, approval-gated remediation |
| Brute force | 0.72 | 0.62 | Both detect it |
| Authorized maintenance (false positive) | 0.81 | 0.20 | WITNESS concludes "authorized" from the change ticket; the baseline raises a false alarm |
| Silent beaconing | 0.80 | 0.05 | WITNESS finds it; the baseline misses it |

0% hallucination rate (every factual statement cites existing evidence) and
intact evidence chains in every run. These numbers are from the rule-based
pipeline; model-assisted results will be added once the model is deployed
(see `docs/MODEL_CARD.md`). Reproduce: `cd backend && python -m witness.benchmark`.

We publish where the baseline wins. WITNESS's value is the verdict under
ambiguity and the safety of the response, not raw technique matching.

## 6. Real-world impact

- **SOC**: competing hypotheses with explicit counter-evidence cut
  false-positive escalations (the false-positive scenario above).
- **DFIR**: a tamper-evident evidence chain, a stage-by-stage
  reconstruction and an auditor report.
- **OT/ICS**: refuses to autonomously isolate engineering workstations or
  touch PLCs, requires OT-engineering and process-owner sign-off, and names
  the correct ATT&CK for ICS techniques (T0855 Unauthorized Command Message,
  T0836 Modify Parameter, T0831 Manipulation of Control, T0878 Alarm
  Suppression).

## 7. Demo (5 minutes)

1. `docker compose up` (or backend + `bun run dev`) → console.
2. **Run Flagship Demo**. Hypotheses compete; the IT→OT chain is
   reconstructed; the Evidence tab shows "chain intact".
3. Hypotheses tab → **Why do we believe this?** (model explanation with
   verified citations, or the rule-based fallback).
4. Response tab → isolating EWS-01 needs three scopes. Try signing two as one
   person: refused. Three people sign → Execute → verification passes.
5. Benchmarks tab / `python -m witness.benchmark` → the honest comparison.

## 8. Limitations (stated plainly)

Synthetic cyber-range telemetry (no live SIEM/EDR connectors yet); 4
scenarios; static API tokens rather than SSO; no model-assisted results yet.
Full list: `docs/LIMITATIONS.md`.

## 9. Plan for the final (3 months)

1. Real connectors: Zeek/Suricata logs, Sysmon via Winlogbeat/EVTX,
   Velociraptor, Modbus/DNP3 captures.
2. Ten more scenarios from the spec (ransomware staging, OT lateral movement,
   timestamp tampering, simultaneous incidents).
3. Model evaluation: stock vs. uncensored vs. security-tuned 8B models on
   WITNESS-Bench (accuracy, rejection rate, tokens, energy per investigation).
4. Optional fine-tuning on curated, human-reviewed investigation traces.
5. OIDC sign-in and per-team data isolation.

## 10. Repository map

`backend/witness/` (agents, core engines, policy, OT safety, model assist),
`backend/tests/`, `src/` (console), `docs/` (architecture, security, OT
safety, benchmark, model card), `SECURITY.md`, `CHANGELOG.md`.
