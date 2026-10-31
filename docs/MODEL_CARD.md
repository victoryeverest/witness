# Model card — WITNESS model assistance

## Status

WITNESS uses an **uncensored variant of Qwen3-8B**, served on the team's own
GPU through an OpenAI-compatible endpoint. The integration is tested against a
scripted stand-in (`backend/tests/test_model_assist.py`) and HTTP mocks of the
OpenAI-compatible and Ollama APIs. The benchmark numbers published in this
repository come from the rule-based pipeline; model-assisted numbers are
produced with the evaluation below.

## Lineage (competition requirement: open-source base)

| Field | Value |
|---|---|
| Base model | **Qwen3-8B** (Qwen team, Alibaba Cloud) |
| Base licence | Apache-2.0 |
| Deployed variant | **Uncensored Qwen3-8B** (refusal-removed derivative of Qwen3-8B); _exact repository / file to record_ |
| Revision / hash | _to fill in: commit SHA or GGUF sha256_ |
| Modification | Refusal removal by the variant's publisher; no further fine-tuning by the WITNESS team |
| Quantization | _to fill in: bf16 / AWQ / GGUF Q4_K_M ..._ |
| Serving stack | _to fill in: vLLM / llama.cpp / Ollama, version_ |
| Hardware | _to fill in: GPU, VRAM_ |

Any derivative of Qwen3-8B keeps an open-source lineage. Record the exact
artifact so results are reproducible.

### On "uncensored" variants

WITNESS asks the model only for defensive analysis (hypotheses, narratives,
explanations); stock Qwen3 rarely refuses these. Abliterated variants tend to
lose some instruction-following and JSON reliability, and remove one layer of
resistance to instructions injected into logs. WITNESS does not depend on that
layer — model output cannot act, cannot set confidence, and is citation-checked
— but `python -m witness.models_layer.check` reports whether the deployed model
follows an injected instruction, so the trade-off can be measured rather than
assumed. Compare stock and uncensored with `python -m witness.benchmark`.

## What the model does — and cannot do

| Use | Where | Guardrail |
|---|---|---|
| Propose hypotheses beyond the 11 templates | runtime, once per investigation after evidence exists | Closed schema; every cited evidence ID must exist (else the batch is rejected); unknown ATT&CK IDs are dropped; near-duplicates dropped; created at the standard 0.35 prior with `provenance.origin = "model"`. Only the deterministic ATT&CK mapper can link supporting evidence. |
| Report narrative per audience | `POST /reports/generate` | Facts passed are the structured report only; every evidence/technique ID in the text must belong to the report's established facts, else the narrative is dropped and `narrative_unavailable` explains why. |
| "Why do we believe this?" | `POST /hypotheses/{id}/explain`, console Hypotheses tab | Citations must be the hypothesis's own evidence; otherwise a rule-based explanation is returned with the reason. |

The model **cannot**: call tools, propose or approve actions, change
confidence or hypothesis status, edit evidence, or alter policy/OT-safety
decisions. Those paths do not exist in its output schemas.

Untrusted data (evidence fields) is passed inside an
`<untrusted_data>` envelope that cannot be closed from inside, truncated, and
the system prompt states it is data. Every call is logged to
`ModelExecution` (tokens, latency, accepted/rejected + reason) and the audit
log; see `GET /models/executions`.

If the endpoint is down or misbehaves, everything degrades to the rule-based
pipeline; investigations never fail because of the model.

## Serving it

Any OpenAI-compatible server works. Examples (check flags against your
installed versions):

```bash
# vLLM (bf16 needs ~16 GB+ VRAM; use an AWQ/GPTQ build on smaller cards)
vllm serve Qwen/Qwen3-8B --served-model-name qwen3-8b --host 0.0.0.0 --port 8000 \
  --max-model-len 16384 --api-key "$WITNESS_MODEL_API_KEY"

# llama.cpp (GGUF, e.g. Q4_K_M fits in 8 GB)
llama-server -m qwen3-8b-q4_k_m.gguf --alias qwen3-8b --jinja -ngl 99 -c 16384 \
  --host 0.0.0.0 --port 8000 --api-key "$WITNESS_MODEL_API_KEY"

# Ollama
ollama pull qwen3:8b && OLLAMA_HOST=0.0.0.0 ollama serve
```

Then on the WITNESS host:

```bash
WITNESS_MODEL_PROVIDER=openai_compatible        # or: ollama
WITNESS_MODEL_ENDPOINT=http://10.0.0.42:8000/v1 # private IP: allowed under LOCAL_ONLY
WITNESS_MODEL_API_KEY=...                       # if the server requires one
WITNESS_MODEL_MEDIUM=qwen3-8b                   # the served model name / Ollama tag
WITNESS_MODEL_STRONG=qwen3-8b
WITNESS_MODEL_TIMEOUT_SECONDS=120
cd backend && python -m witness.models_layer.check
```

`LOCAL_ONLY` privacy mode accepts loopback, private-range (10/8, 172.16/12,
192.168/16) and single-label hostnames. A public IP or DNS name is refused
unless `WITNESS_PRIVACY_MODE=ALLOW_EXTERNAL` — put the GPU box on the private
network or a VPN rather than relaxing this.

Qwen3 thinks by default; WITNESS appends `/no_think` (disable with
`WITNESS_MODEL_DISABLE_THINKING=false`) and strips any `<think>` block.

## Evaluating it

```bash
cd backend
python -m witness.benchmark            # rules only (WITNESS_MODEL_ASSIST=off or mock)
WITNESS_MODEL_PROVIDER=openai_compatible ... python -m witness.benchmark   # with the model
```

The second run adds a line per scenario: model calls, accepted outputs,
hypotheses proposed, tokens. Report both runs; the delta is the model's
measured contribution. Worth recording alongside: rejection reasons from
`GET /models/executions`, latency, and GPU power draw if available.
