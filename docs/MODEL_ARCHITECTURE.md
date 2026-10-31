# WITNESS Model Architecture (§16)

The model layer is provider-independent and measurable. WITNESS does not hard-code any one model into business logic.

## Provider abstraction

```
ModelProvider (abstract)
├── MockProvider         (deterministic, no LLM — default for tests/benchmarks/demo)
├── OpenAICompatibleProvider   (vLLM, llama.cpp server, Ollama in OpenAI mode, real OpenAI)
└── OllamaProvider       (native Ollama API)
```

The `ModelRouter` selects a provider based on the configured role:

| Role | Use case |
|---|---|
| `small` | extraction, classification, normalization, simple summarization |
| `medium` | investigation planning, correlation, reasoning |
| `strong` | difficult cross-domain reasoning, final synthesis |
| `verification` | critical final assessment (uses strong model + verification steps) |

## The mock provider — why it exists

The default `mock` provider is **deterministic and rule-based**. It returns a stub JSON response containing the user prompt echoed back. Agents that use this provider are *expected* to be rule-driven — they read tool output and the evidence graph, not the model's text.

This is the architecture the spec calls for (§16, §148):

> A smaller local model combined with deterministic tools, structured evidence, and verification can outperform a larger unconstrained model on specific cybersecurity investigation tasks while using fewer computational resources.

The mock provider is the extreme case: zero LLM, all deterministic. WITNESS is fully functional in this mode. Plugging in a real LLM is purely additive — it enhances reasoning where rule-based logic is insufficient, but it never replaces the deterministic safety, evidence, and policy layers.

## Why the mock provider is essential

1. **Tests must be deterministic.** A flaky test because the LLM changed its mind is unacceptable.
2. **Benchmarks must be reproducible.** Two runs of WITNESS-Bench on the same scenario should produce the same metrics.
3. **Demo mode must be deterministic.** A judge should see the same investigation each time.
4. **Air-gapped deployments** must work without any external API.
5. **Cost / latency measurement** — the mock provider establishes the deterministic baseline. Real LLMs are compared against it.

## Plugging in a real model

### Option 1: Any OpenAI-compatible endpoint (recommended for local)

This covers vLLM, llama.cpp server, Ollama (when started in OpenAI-compat mode), and real OpenAI.

```bash
export WITNESS_MODEL_PROVIDER=openai_compatible
export WITNESS_MODEL_ENDPOINT=http://localhost:11434/v1   # Ollama OpenAI mode
export WITNESS_MODEL_API_KEY=sk-...                         # any value for local
export WITNESS_MODEL_SMALL=qwen3:8b
export WITNESS_MODEL_MEDIUM=qwen3:8b
export WITNESS_MODEL_STRONG=qwen3:8b
```

### Option 2: Ollama native

```bash
export WITNESS_MODEL_PROVIDER=ollama
export WITNESS_MODEL_ENDPOINT=http://localhost:11434
export WITNESS_MODEL_SMALL=llama3.2:3b
export WITNESS_MODEL_MEDIUM=llama3.1:8b
export WITNESS_MODEL_STRONG=qwen3:8b
```

### Option 3: Real OpenAI

```bash
export WITNESS_MODEL_PROVIDER=openai_compatible
export WITNESS_MODEL_ENDPOINT=https://api.openai.com
export WITNESS_MODEL_API_KEY=sk-...   # real key
export WITNESS_MODEL_SMALL=gpt-4o-mini
export WITNESS_MODEL_MEDIUM=gpt-4o
export WITNESS_MODEL_STRONG=o1-preview
```

Note: this disables the LOCAL_ONLY privacy mode. Set `WITNESS_PRIVACY_MODE=ALLOW_EXTERNAL` explicitly.

## Measurement (§16, §96)

Every model call is recorded in the `ModelExecution` table:

| Field | Meaning |
|---|---|
| `provider` | mock / openai_compatible / ollama |
| `model` | the model name used |
| `role` | small / medium / strong / verification |
| `promptTokens` | input tokens |
| `completionTokens` | output tokens |
| `latencyMs` | wall-clock latency |
| `toolCalls` | number of tool calls triggered |
| `success` | bool |
| `error` | exception text if failed |
| `timestamp` | UTC timestamp |

The benchmark reports aggregate metrics:
- `tokens_used` per investigation
- `latency_seconds` per investigation
- `energy_estimate_joules` per investigation (latency × estimated CPU/GPU power)
- `tool_calls` per investigation

These enable the secondary thesis (§148): a smaller local model + tools can outperform a larger unconstrained model on specific tasks at lower cost.

## Model lineage (§98)

For real-LLM deployments, document:
- base model
- version
- license (verify it — many "open" models have restrictive licenses)
- modifications (fine-tuning, system prompt, quantization)
- evaluation (WITNESS-Bench score on this model)
- limitations

The `KnowledgeItem` table tracks lineage for knowledge packs; the `ModelExecution` table tracks runtime model identity. Production deployments should add a `Model` ORM table to track model metadata persistently.

## No hard-coded model (§16)

WITNESS business logic never imports a specific model SDK or hard-codes a model name. All model access goes through `get_provider()` in `witness/models_layer/base.py`. To add a new provider (e.g. Anthropic Claude), subclass `ModelProvider` and add a branch in `get_provider()` — no other code changes.
