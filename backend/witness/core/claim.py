"""Claim verification engine (§9, §144).

Every AI-generated claim must be backed by evidence. The engine:
- rejects claims that require evidence but have none
- downgrades claims whose evidence contradicts them
- enforces the FACT / INFERENCE / HYPOTHESIS / ASSUMPTION / UNKNOWN /
  RECOMMENDATION / ACTION distinction (§4)
"""
from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Claim, Evidence
from ..schemas import ClaimDTO, ClaimType


async def create_claim(
    session: AsyncSession,
    investigation_id: str,
    *,
    statement: str,
    claim_type: ClaimType = "fact",
    evidence_refs: Optional[list[str]] = None,
    contradicting_refs: Optional[list[str]] = None,
    requires_evidence: bool = True,
    hypothesis_id: Optional[str] = None,
    confidence: float = 0.0,
) -> Claim:
    c = Claim(
        id=f"CL-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        hypothesisId=hypothesis_id,
        statement=statement,
        status="unverified",
        evidenceRefs=evidence_refs or [],
        contradictingRefs=contradicting_refs or [],
        claimType=claim_type,
        requiresEvidence=requires_evidence,
        confidence=confidence,
    )
    # Validate per §144.
    c = await validate_claim(session, c)
    session.add(c)
    await session.flush()
    return c


async def validate_claim(session: AsyncSession, c: Claim) -> Claim:
    """Enforce the no-hallucination contract (§9, §144)."""
    # Rule: claims that require evidence MUST have evidence.
    if c.requiresEvidence and not c.evidenceRefs:
        c.status = "unverified"
        c.confidence = min(c.confidence, 0.05)
        return c
    # Rule: claims with contradictions are contested.
    if c.contradictingRefs and len(c.contradictingRefs) >= len(c.evidenceRefs):
        c.status = "contested"
        c.confidence = min(c.confidence, 0.25)
        return c
    # Rule: claims of type "fact" require >= 1 verified evidence.
    if c.claimType == "fact" and c.evidenceRefs:
        verified_count = 0
        for ref in c.evidenceRefs:
            ev = await session.get(Evidence, ref)
            if ev and ev.integrityStatus == "verified":
                verified_count += 1
        if verified_count == 0:
            c.status = "unverified"
            c.confidence = min(c.confidence, 0.1)
            return c
        if verified_count == len(c.evidenceRefs) and not c.contradictingRefs:
            c.status = "verified"
            c.confidence = max(c.confidence, 0.85)
            return c
    # Default: supported by some evidence, no contradictions.
    if c.evidenceRefs and not c.contradictingRefs:
        c.status = "supported"
        c.confidence = max(c.confidence, 0.65)
        return c
    if c.claimType in {"hypothesis", "assumption", "unknown", "recommendation"}:
        # Non-evidentiary claims: don't pretend they're verified.
        if not c.evidenceRefs:
            c.status = "inferred"
            c.confidence = min(c.confidence, 0.45)
            return c
    c.status = "unverified"
    return c


async def list_claims(session: AsyncSession, investigation_id: str) -> list[Claim]:
    res = await session.execute(
        select(Claim).where(Claim.investigationId == investigation_id)
    )
    return list(res.scalars().all())


async def reject_unsupported(session: AsyncSession, investigation_id: str) -> int:
    """Walk all claims in an investigation and reject any 'fact' claim that
    has no evidence. Returns the count rejected."""
    claims = await list_claims(session, investigation_id)
    n = 0
    for c in claims:
        if c.claimType == "fact" and c.requiresEvidence and not c.evidenceRefs:
            c.status = "rejected"
            c.confidence = 0.0
            n += 1
    await session.flush()
    return n


def to_dto(c: Claim) -> ClaimDTO:
    return ClaimDTO(
        id=c.id,
        statement=c.statement,
        status=c.status,
        claim_type=c.claimType,
        evidence_refs=c.evidenceRefs,
        contradicting_refs=c.contradictingRefs,
        requires_evidence=c.requiresEvidence,
        confidence=c.confidence,
    )
