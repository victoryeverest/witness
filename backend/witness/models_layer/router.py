"""Model router (§63).

Routes requests to the appropriate model based on:
- task difficulty
- risk (high-risk = verification + strong model)
- latency / cost budget
- model availability

When using the MockProvider, the router is trivial since all roles return
deterministic stubs. When using a real LLM, this router is where the
cost/latency/quality trade-off is enforced.
"""
from __future__ import annotations


from ..schemas import ModelRequest, ModelResponse, ModelRole
from .base import get_provider


def classify_difficulty(objective: str) -> str:
    """Heuristic difficulty classifier. Returns one of: trivial, simple,
    moderate, complex, critical."""
    o = objective.lower()
    if any(k in o for k in ["normalize", "parse", "format"]):
        return "trivial"
    if any(k in o for k in ["extract", "classify", "label"]):
        return "simple"
    if any(k in o for k in ["correlate", "investigate", "map"]):
        return "moderate"
    if any(k in o for k in ["cross-domain", "synthesize", "reconstruct"]):
        return "complex"
    if any(k in o for k in ["verify", "final assessment", "approve"]):
        return "critical"
    return "moderate"


def select_role(objective: str, *, risk_level: str = "low",
                verification: bool = False) -> ModelRole:
    """Select the appropriate model role for a given objective."""
    if verification or risk_level in {"high", "critical"}:
        return "verification"
    diff = classify_difficulty(objective)
    return {
        "trivial": "small",
        "simple": "small",
        "moderate": "medium",
        "complex": "strong",
        "critical": "verification",
    }.get(diff, "medium")


async def route(req: ModelRequest, *, verification: bool = False,
                risk_level: str = "low") -> ModelResponse:
    """Route a request to the appropriate model provider."""
    if not req.role or req.role == "medium":
        req.role = select_role(req.user_prompt, risk_level=risk_level,
                              verification=verification)
    provider = get_provider(req.role)
    return await provider.generate(req)
