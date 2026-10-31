"""Model provider abstraction (§16).

The model layer is provider-independent. Implementations:
- MockProvider: deterministic, no-LLM, rule-based. Required for tests/benchmarks
  and for the demo mode to be reproducible.
- OpenAICompatibleProvider: any OpenAI-chat-completions endpoint (vLLM,
  llama.cpp server, Ollama in OpenAI-compat mode, real OpenAI).
- OllamaProvider: native Ollama API.

The MockProvider is the default; production deployments set
WITNESS_MODEL_PROVIDER=openai_compatible (or ollama) to plug in real models.
Providers never raise on model errors: they return a response whose
finish_reason starts with "error:", and callers fall back to rules.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Optional

from ..config import settings
from ..schemas import ModelRequest, ModelResponse
from ..utils.logging import get_logger


log = get_logger("witness.models_layer.base")


class ModelProvider:
    """Abstract base."""
    name: str = "base"

    async def generate(self, req: ModelRequest) -> ModelResponse:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class MockProvider(ModelProvider):
    """Deterministic, no-LLM provider.

    Returns a structured JSON-like response derived from the prompt content
    itself. Agents that use this provider are expected to be rule-driven
    (using tool results and the evidence graph) rather than relying on the
    model's text. This is exactly the architecture the spec calls for:
    "Implement an abstraction" and "All model usage should be measurable" (§16)
    — and it makes WITNESS runnable without any LLM dependency.
    """
    name = "mock"

    def __init__(self) -> None:
        self.locks: dict[str, asyncio.Lock] = {}

    async def generate(self, req: ModelRequest) -> ModelResponse:
        start = time.perf_counter()
        # The mock returns a "thinking" response that contains the user prompt
        # echoed back with a small deterministic stub. Agents that depend on
        # structured output read it from `req.tools` results and the evidence
        # graph, not from the model text.
        stub = {
            "ok": True,
            "reasoning": "mock_provider",
            "echo": req.user_prompt[:200],
            "instructions_acknowledged": True,
        }
        text = json.dumps(stub, indent=2)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        # Tiny synthetic latency so async code paths are exercised.
        await asyncio.sleep(0.001)
        return ModelResponse(
            text=text,
            tool_calls=[],
            prompt_tokens=len(req.user_prompt) // 4,
            completion_tokens=len(text) // 4,
            latency_ms=max(elapsed_ms, 1),
            model=req.role,
            provider=self.name,
            finish_reason="stop",
        )


_THINK_RE = re.compile(r"<think>.*?</think>", re.S | re.I)


def strip_reasoning(text: str) -> str:
    """Remove <think>...</think> blocks (Qwen3, DeepSeek-R1 style). An
    unterminated block means the model ran out of tokens while thinking."""
    text = _THINK_RE.sub("", text or "")
    if "<think>" in text.lower():
        text = text[: text.lower().index("<think>")]
    return text.strip()


def _error_response(req: ModelRequest, provider: str, model: str, start: float,
                    exc: Exception) -> ModelResponse:
    return ModelResponse(
        text="", tool_calls=[], prompt_tokens=0, completion_tokens=0,
        latency_ms=int((time.perf_counter() - start) * 1000), model=model,
        provider=provider, finish_reason=f"error: {type(exc).__name__}: {exc}".rstrip(": "))


class _HTTPProvider(ModelProvider):
    """Shared retry loop. Retries transport errors, 429 and 5xx with
    exponential backoff (settings.model_max_retries); 4xx are not retried."""

    def __init__(self, model: str, timeout: float, client: Any = None):
        import httpx
        self.model = model
        self.client = client or httpx.AsyncClient(timeout=timeout)

    async def _post(self, url: str, payload: dict[str, Any],
                    headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        import httpx
        attempts = max(1, settings.model_max_retries + 1)
        for attempt in range(attempts):
            try:
                r = await self.client.post(url, json=payload, headers=headers or {})
                r.raise_for_status()
                return r.json()
            except httpx.HTTPStatusError as exc:
                retryable = exc.response.status_code == 429 or exc.response.status_code >= 500
                if not retryable or attempt == attempts - 1:
                    raise
            except (httpx.TransportError, httpx.TimeoutException):
                if attempt == attempts - 1:
                    raise
            await asyncio.sleep(min(8.0, 0.5 * 2 ** attempt))
        raise RuntimeError("unreachable")

    async def close(self) -> None:
        await self.client.aclose()


class OpenAICompatibleProvider(_HTTPProvider):
    """Any OpenAI /v1/chat/completions server: vLLM, llama.cpp `llama-server`,
    Ollama (OpenAI mode), LM Studio, TGI. `endpoint` may be given with or
    without the trailing `/v1`."""
    name = "openai_compatible"

    def __init__(self, endpoint: str, api_key: str = "", timeout: float = 30.0,
                 model: str = "", client: Any = None):
        super().__init__(model, timeout, client)
        base = endpoint.rstrip("/")
        self.url = (f"{base}/chat/completions" if base.endswith("/v1")
                    else f"{base}/v1/chat/completions")
        self.api_key = api_key

    async def generate(self, req: ModelRequest) -> ModelResponse:
        start = time.perf_counter()
        payload: dict[str, Any] = {
            # The configured model name, not the role ("medium"), which
            # real servers reject.
            "model": self.model,
            "messages": [
                {"role": "system", "content": req.system_prompt},
                {"role": "user", "content": req.user_prompt},
            ],
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
        }
        if req.prefer_json:
            payload["response_format"] = {"type": "json_object"}
        if req.tools:
            payload["tools"] = req.tools
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            data = await self._post(self.url, payload, headers)
            choice = data["choices"][0]
            usage = data.get("usage") or {}
            return ModelResponse(
                text=strip_reasoning(choice["message"].get("content") or ""),
                tool_calls=choice["message"].get("tool_calls") or [],
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                latency_ms=int((time.perf_counter() - start) * 1000),
                model=data.get("model", self.model),
                provider=self.name,
                finish_reason=choice.get("finish_reason") or "",
            )
        except Exception as exc:
            log.warning(f"model_call_failed: {type(exc).__name__}: {exc}", extra={"ctx_endpoint": self.url})
            return _error_response(req, self.name, self.model, start, exc)


class OllamaProvider(_HTTPProvider):
    """Native Ollama API (/api/chat)."""
    name = "ollama"

    def __init__(self, endpoint: str = "http://localhost:11434", timeout: float = 60.0,
                 model: str = "", client: Any = None):
        super().__init__(model, timeout, client)
        self.url = f"{(endpoint or 'http://localhost:11434').rstrip('/')}/api/chat"

    async def generate(self, req: ModelRequest) -> ModelResponse:
        start = time.perf_counter()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": req.system_prompt},
                {"role": "user", "content": req.user_prompt},
            ],
            "stream": False,
            "options": {"temperature": req.temperature, "num_predict": req.max_tokens},
        }
        if req.prefer_json:
            payload["format"] = "json"
        try:
            data = await self._post(self.url, payload)
            return ModelResponse(
                text=strip_reasoning(data.get("message", {}).get("content", "")),
                tool_calls=[],
                prompt_tokens=data.get("prompt_eval_count", 0),
                completion_tokens=data.get("eval_count", 0),
                latency_ms=int((time.perf_counter() - start) * 1000),
                model=data.get("model", self.model),
                provider=self.name,
                finish_reason=data.get("done_reason", ""),
            )
        except Exception as exc:
            log.warning(f"ollama_call_failed: {type(exc).__name__}: {exc}", extra={"ctx_endpoint": self.url})
            return _error_response(req, self.name, self.model, start, exc)


# --------------------------------------------------------------------------- #
# Factory & router
# --------------------------------------------------------------------------- #

_providers: dict[str, ModelProvider] = {}


class PrivacyViolation(RuntimeError):
    """A model endpoint would send data off-host while privacy_mode=LOCAL_ONLY."""


def endpoint_is_local(endpoint: str) -> bool:
    """True for loopback, private-range and link-local addresses, `localhost`
    and single-label hostnames (e.g. a docker-compose service name)."""
    import ipaddress
    from urllib.parse import urlparse
    host = (urlparse(endpoint if "://" in endpoint else f"http://{endpoint}").hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost") or "." not in host:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a DNS name: could resolve anywhere
    return ip.is_loopback or ip.is_private or ip.is_link_local


def enforce_privacy_mode(endpoint: str) -> None:
    if settings.privacy_mode == "LOCAL_ONLY" and not endpoint_is_local(endpoint):
        raise PrivacyViolation(
            f"Model endpoint {endpoint!r} is not local and WITNESS_PRIVACY_MODE=LOCAL_ONLY. "
            "Use a local endpoint or set WITNESS_PRIVACY_MODE=ALLOW_EXTERNAL.")


_override: Optional[ModelProvider] = None


def override_provider(provider: Optional[ModelProvider]) -> None:
    """Force every role to use `provider` (tests, evaluation harnesses).
    Pass None to restore configuration-driven selection."""
    global _override
    _override = provider


def model_name_for(role: str) -> str:
    return {
        "small": settings.model_small,
        "medium": settings.model_medium,
        "strong": settings.model_strong,
        "verification": settings.model_strong,
    }.get(role or "medium", settings.model_medium)


def get_provider(role: str = "medium") -> ModelProvider:
    """Return the provider configured for the given role.

    Raises PrivacyViolation when a remote endpoint is configured under
    LOCAL_ONLY (§17, §81).
    """
    if _override is not None:
        return _override
    model_name = model_name_for(role)
    key = f"{settings.model_provider}:{settings.model_endpoint}:{model_name}"
    if key in _providers:
        return _providers[key]
    if settings.model_provider == "mock":
        p: ModelProvider = MockProvider()
    elif settings.model_provider == "openai_compatible":
        enforce_privacy_mode(settings.model_endpoint)
        p = OpenAICompatibleProvider(settings.model_endpoint, settings.model_api_key,
                                     settings.model_timeout_seconds, model=model_name)
    elif settings.model_provider == "ollama":
        enforce_privacy_mode(settings.model_endpoint or "http://localhost:11434")
        p = OllamaProvider(settings.model_endpoint, settings.model_timeout_seconds,
                           model=model_name)
    else:
        # Fall back to mock so the system never fails to boot.
        log.warning("unknown_model_provider_falling_back_to_mock",
                    extra={"ctx_provider": settings.model_provider})
        p = MockProvider()
    _providers[key] = p
    return p


async def close_all_providers() -> None:
    for p in _providers.values():
        try:
            await p.close()
        except Exception:
            pass
    _providers.clear()
