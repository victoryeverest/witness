"""Request authentication (§68, §77).

Two modes, selected by ``WITNESS_AUTH_MODE``:

``token``
    Every request (except ``/health``) must send ``Authorization: Bearer <t>``.
    Tokens are configured in ``WITNESS_API_TOKENS`` as ``token:user_id:role``
    triples. Identity and role come *only* from the token: fields such as
    ``approver_id`` / ``user_role`` in request bodies are ignored, so a caller
    cannot claim to be someone else or to hold a role they do not have.

``none`` (development default)
    No credentials. The caller may describe itself with ``X-Witness-User`` /
    ``X-Witness-Role`` headers (or legacy body fields); nothing is verified.
    The server refuses to start in production with this mode unless
    ``WITNESS_ALLOW_INSECURE_PRODUCTION=true``.

Tokens are compared in constant time.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException, Request

from ..config import settings


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Optional[str]
    authenticated: bool

    def effective_user(self, claimed: Optional[str]) -> str:
        """Authenticated identity wins; otherwise the (unverified) claim."""
        if self.authenticated:
            return self.user_id
        return claimed or self.user_id

    def effective_role(self, claimed: Optional[str]) -> Optional[str]:
        if self.authenticated:
            return self.role
        return claimed or self.role


ANONYMOUS = Principal(user_id="anonymous", role=None, authenticated=False)


def check_startup_security() -> None:
    """Fail fast on an insecure production configuration."""
    if settings.auth_mode == "token":
        tokens = settings.parsed_api_tokens()  # raises on malformed entries
        if not tokens:
            raise RuntimeError("WITNESS_AUTH_MODE=token requires WITNESS_API_TOKENS")
        weak = [user for tok, (user, _) in tokens.items() if len(tok) < 16]
        if weak and settings.is_production:
            raise RuntimeError(f"API tokens shorter than 16 characters for: {', '.join(weak)}")
    elif settings.is_production and not settings.allow_insecure_production:
        raise RuntimeError(
            "Refusing to start: WITNESS_ENVIRONMENT=production with WITNESS_AUTH_MODE=none "
            "would let any network client approve and execute response actions. Set "
            "WITNESS_AUTH_MODE=token and WITNESS_API_TOKENS, or (demo only) "
            "WITNESS_ALLOW_INSECURE_PRODUCTION=true.")


def _match_token(presented: str) -> Optional[tuple[str, str]]:
    found = None
    for token, ident in settings.parsed_api_tokens().items():
        # Compare against every token so timing does not reveal which matched.
        if hmac.compare_digest(token.encode(), presented.encode()):
            found = ident
    return found


PUBLIC_PATHS = frozenset({"/health", "/docs", "/redoc", "/openapi.json"})


async def get_principal(request: Request) -> Principal:
    if request.url.path in PUBLIC_PATHS:
        return ANONYMOUS
    if settings.auth_mode == "none":
        user = request.headers.get("x-witness-user")
        role = request.headers.get("x-witness-role")
        if user or role:
            return Principal(user_id=user or "anonymous", role=role, authenticated=False)
        return ANONYMOUS
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(401, "missing_bearer_token",
                            headers={"WWW-Authenticate": "Bearer"})
    ident = _match_token(presented.strip())
    if ident is None:
        raise HTTPException(401, "invalid_token", headers={"WWW-Authenticate": "Bearer"})
    return Principal(user_id=ident[0], role=ident[1], authenticated=True)


def require_role(principal: Principal, *roles: str) -> None:
    """In token mode, require one of `roles` (admin always passes)."""
    if not principal.authenticated:
        return
    if principal.role != "admin" and principal.role not in roles:
        raise HTTPException(403, f"role_required:{'|'.join(roles)}")
