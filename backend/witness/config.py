"""WITNESS configuration.

All environment-dependent settings live here. The system defaults to a
local-only, no-external-dependency mode so it runs in an air-gapped
environment, in CI, and on a developer laptop without any additional setup.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="WITNESS_",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Runtime ---
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8000

    # --- Database ---
    database_url: str = f"sqlite+aiosqlite:///{DATA_DIR}/witness.db"
    db_echo: bool = False

    # --- Privacy / Data residency ---
    privacy_mode: Literal["LOCAL_ONLY", "ALLOW_EXTERNAL"] = "LOCAL_ONLY"

    # --- Model layer ---
    # "mock" = deterministic rule-based provider (no LLM dependency, required for tests/benchmarks)
    # "openai_compatible" = any OpenAI-chat-completions endpoint (local vLLM, Ollama OpenAI mode, llama.cpp server, etc.)
    # "ollama" = native Ollama API
    model_provider: Literal["mock", "openai_compatible", "ollama"] = "mock"
    model_small: str = "mock-small"
    model_medium: str = "mock-medium"
    model_strong: str = "mock-strong"
    model_endpoint: str = ""  # e.g. http://localhost:11434/v1
    model_api_key: str = ""
    model_timeout_seconds: float = 30.0
    model_max_retries: int = 2
    # Model assistance (hypothesis proposals, report narratives, explanations).
    # "auto" = on whenever a real provider is configured; "off" keeps every
    # agent purely rule-driven. The deterministic engines always own
    # confidence, policy and OT safety; the model only proposes text and
    # hypotheses, which are validated against the evidence before use.
    model_assist: Literal["auto", "on", "off"] = "auto"
    model_assist_max_hypotheses: int = 3
    # Qwen3-family models emit <think> reasoning by default; "/no_think" in the
    # prompt disables it (faster, cleaner JSON). Harmless for other models.
    model_disable_thinking: bool = True

    # --- Safety defaults ---
    # When True, ANY high-risk action requires human approval before execution,
    # regardless of what the agent proposes.
    require_approval_high_risk: bool = True
    # OT actions always require OT-engineer + process-owner approval in addition
    # to security approval. This is non-negotiable per spec §69.
    ot_requires_dual_approval: bool = True

    # --- Investigation runtime ---
    investigation_max_iterations: int = 25
    investigation_confidence_threshold: float = 0.75
    investigation_step_timeout_seconds: float = 60.0

    # --- Benchmark ---
    benchmark_default_iterations: int = 1

    # --- Knowledge layer (§99-101) ---
    knowledge_dir: str = str(PROJECT_ROOT / "data" / "knowledge")
    autoload_attack: bool = True
    # Set to "1" to allow MITRE ATT&CK STIX download even when
    # privacy_mode=LOCAL_ONLY. Useful for first-time setup.
    allow_attack_download: bool = False

    # --- Authentication / authorization (§68, §77) ---
    # "none"  — development only: the caller's identity and role are taken
    #           from the request (X-Witness-User / X-Witness-Role headers or
    #           legacy body fields). Refused at startup in production.
    # "token" — every request must carry `Authorization: Bearer <token>`;
    #           identity and role come from `api_tokens`, never the request.
    auth_mode: Literal["none", "token"] = "none"
    # Comma-separated `token:user_id:role` triples, e.g.
    # "s3cret:alice:security_engineer,0tk3y:bob:ot_engineer".
    api_tokens: str = ""
    # Escape hatch for demo deployments that knowingly run production
    # without authentication. Never set this on a real network.
    allow_insecure_production: bool = False

    # --- PCAP ingestion (§33) ---
    # /pcap/analyze only reads files inside this directory; uploads land here.
    pcap_dir: str = str(DATA_DIR / "pcaps")
    pcap_max_upload_bytes: int = 200 * 1024 * 1024

    # --- Destructive maintenance endpoints ---
    # POST /system/reset drops every table. Disabled in production regardless.
    allow_reset: bool = True

    @property
    def is_test(self) -> bool:
        return self.environment == "test"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def parsed_api_tokens(self) -> dict[str, tuple[str, str]]:
        """Return {token: (user_id, role)} from `api_tokens`."""
        out: dict[str, tuple[str, str]] = {}
        for entry in self.api_tokens.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(":")
            if len(parts) != 3 or not all(p.strip() for p in parts):
                raise ValueError(
                    "WITNESS_API_TOKENS entries must be 'token:user_id:role' "
                    f"(got {len(parts)} field(s) in one entry)")
            token, user_id, role = (p.strip() for p in parts)
            out[token] = (user_id, role)
        return out


settings = Settings()


def get_settings() -> Settings:
    """Return the global Settings instance (FastAPI dependency)."""
    return settings
