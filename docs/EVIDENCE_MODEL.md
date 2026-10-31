# WITNESS Evidence Model

> Evidence is never treated as disposable context. Every claim, hypothesis, finding, and action must ultimately reference one or more evidence IDs.

## Evidence is a first-class object (§8)

Every evidence item has these fields, all required:

| Field | Type | Purpose |
|---|---|---|
| `id` | str | `EV-XXXXXXXXXX` cuid |
| `source` | str | e.g. `windows_event_log`, `sysmon`, `zeek`, `edr`, `ot:modbus`, `sigma:rule` |
| `sourceType` | str | `log` / `pcap` / `image` / `memory` / `registry` / `file` / `network` / `ot` / `ti` / `sigma` / `yara` / `suricata` / `manual` / `derived` |
| `timestamp` | datetime (UTC) | When the event occurred (not when it was ingested) |
| `ingestionTime` | datetime (UTC) | When WITNESS recorded it |
| `host` | str? | Source host |
| `assetId` | str? | FK to `Asset.id` |
| `user` | str? | Identity context |
| `process` | str? | Process context |
| `networkContext` | JSON | Network context (src/dst IP, port, proto) |
| `rawReference` | str? | Pointer to the original raw record |
| `normalizedData` | JSON | Canonical event per §18 — the form agents read |
| `contentHash` | str | SHA-256 over source + timestamp + host + normalized_data |
| `prevHash` | str? | Hash of the previous evidence in this investigation |
| `integrityStatus` | str | `verified` / `suspect` / `tampered` / `unknown` |
| `reliability` | str | `high` / `medium` / `low` / `unknown` |
| `confidence` | float | Source's confidence in the observation |
| `collectionMethod` | str | `agent_collected` / `manual` / `derived` / `external_feed` |
| `chainOfCustody` | JSON[] | Append-only hash-chain of custody events |
| `synthetic` | bool | True if this evidence came from the cyber range (§154) |

## Immutability + integrity

The `contentHash` is computed at ingestion over a canonical subset of fields. The `verify_integrity()` function recomputes the hash and compares to the stored value — any tampering changes the normalized data and breaks the hash.

The `chainOfCustody` array is hash-chained: each entry contains a `chain_hash = H(prev_hash | investigation_id | content_hash)`. Tampering with any earlier evidence in the chain invalidates all later entries.

## Synthetic evidence (§153, §154)

The cyber range produces synthetic evidence. Every synthetic evidence row has `synthetic=True` and is never confused for production telemetry. The UI shows a `SYNTHETIC` badge on these rows. WITNESS never misrepresents simulation as production.

## Claim verification (§9, §144)

An AI-generated claim is a `Claim` row with:

| Field | Meaning |
|---|---|
| `statement` | What the claim asserts |
| `claimType` | `fact` / `inference` / `hypothesis` / `assumption` / `unknown` / `recommendation` / `action` |
| `status` | `verified` / `supported` / `inferred` / `contested` / `unverified` / `rejected` / `unknown` |
| `evidenceRefs` | The evidence IDs that support this claim |
| `contradictingRefs` | The evidence IDs that contradict this claim |
| `requiresEvidence` | True for `fact` claims; False for `recommendation`/`action` |

The validator enforces:

1. **No evidence → cannot mark VERIFIED** — a `fact` claim with no evidence is `unverified` with confidence ≤ 0.05.
2. **Contradictions → contested** — if `len(contradictingRefs) >= len(evidenceRefs)`, the claim is `contested`.
3. **All evidence verified + no contradictions → verified** — confidence ≥ 0.85.
4. **Some evidence + no contradictions → supported** — confidence ≥ 0.65.
5. **Hypothesis / assumption / unknown / recommendation** — never marked `verified` even with evidence; they're `inferred`.

The `reject_unsupported()` function walks all claims in an investigation and rejects any `fact` claim that has no evidence — preventing the LLM from making factual claims without proof.

## Evidence-backed accuracy (§58)

WITNESS-Bench's signature metric. A claim gets credit only when **all three** are true:

1. The claim is correct (matches ground truth).
2. The evidence is correct (matches ground-truth events).
3. The evidence actually supports the claim.

This penalizes "correct answer + wrong evidence" — preventing the model from getting credit for lucky guesses. A system that confidently asserts "Credential compromise" and points at a DNS log gets zero credit even if credential compromise did occur.

## Knowledge vs evidence (§102)

WITNESS keeps these strictly separate:

- **Knowledge** — what generally happens (MITRE ATT&CK techniques, NIST guidance, Sigma rule libraries). Knowledge is versioned, has provenance, and lives in the `KnowledgeItem` table.
- **Evidence** — what happened in *this* environment. Evidence is per-investigation and immutable.

General knowledge can never masquerade as incident evidence. ATT&CK T1059.001 is *knowledge*; a sysmon EID 1 process_exec with `image=powershell.exe` is *evidence*.
