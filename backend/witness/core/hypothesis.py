"""Hypothesis engine (§6, §7, §144).

Hypotheses are evaluated with an explicit confidence model:
- prior confidence is set when the hypothesis is first created
- supporting evidence raises confidence
- contradicting evidence lowers confidence (and may cause rejection)
- missing evidence is tracked explicitly (§48)

The score is a deterministic Bayesian-style update so the LLM cannot "invent"
the final confidence. The model proposes hypotheses; the engine owns the math.
"""
from __future__ import annotations

import math
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Hypothesis, Evidence
from ..schemas import HypothesisDTO
from ..utils.time import utc_now


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


# Log-likelihood contribution of one unit of evidence weight. Contradicting
# evidence moves the score further than supporting evidence (§7: one solid
# counter-observation should outweigh several weak confirmations).
SUPPORT_LLR = 0.6
CONTRADICT_LLR = 1.0
# Evidence gathered for the same hypothesis is rarely independent (the same
# intrusion seen by Sysmon, the EDR and the SIEM). Each additional item counts
# for less than the previous one: weights are sorted descending and the k-th
# is multiplied by DECAY**k. Twenty corroborating rows therefore cannot push a
# hypothesis to certainty on their own.
CORRELATION_DECAY = 0.85
CONFIDENCE_FLOOR, CONFIDENCE_CEIL = 0.01, 0.99


def _logit(p: float) -> float:
    p = _clamp(p, 1e-6, 1 - 1e-6)
    return math.log(p / (1 - p))


def _effective_weight(weights: list[float]) -> float:
    return sum(w * CORRELATION_DECAY ** k
               for k, w in enumerate(sorted(weights, reverse=True)))


def posterior_confidence(prior: float, support_weights: list[float],
                         contradict_weights: list[float]) -> float:
    """Posterior confidence from the prior and the *full* set of evidence weights.

    This is a pure function of its inputs: adding the same evidence twice, or
    adding evidence in a different order, yields the same confidence. (The
    original update re-applied the cumulative evidence count to the *current*
    confidence on every call, so confidence compounded: one piece of evidence
    observed six times moved a hypothesis from 0.53 to 0.98 and "confirmed" it.)
    """
    lo = (_logit(prior)
          + SUPPORT_LLR * _effective_weight(support_weights)
          - CONTRADICT_LLR * _effective_weight(contradict_weights))
    lo = max(-8.0, min(8.0, lo))
    return _clamp(1.0 / (1.0 + math.exp(-lo)), CONFIDENCE_FLOOR, CONFIDENCE_CEIL)


def status_for(confidence: float, has_contradictions: bool) -> str:
    if confidence >= 0.85 and not has_contradictions:
        return "confirmed"
    if confidence >= 0.60:
        return "probable"
    if confidence <= 0.20:
        return "rejected"
    return "open"


class HypothesisEngine:
    """Owns hypothesis lifecycle and confidence updates."""

    @staticmethod
    async def create(
        session: AsyncSession,
        investigation_id: str,
        statement: str,
        *,
        prior: float = 0.4,
        counter: bool = False,
        parent_id: Optional[str] = None,
        expected_evidence: Optional[list[dict]] = None,
        attack_techniques: Optional[list[str]] = None,
        attack_tactics: Optional[list[str]] = None,
        provenance: Optional[dict] = None,
    ) -> Hypothesis:
        h = Hypothesis(
            id=f"H-{uuid.uuid4().hex[:8].upper()}",
            investigationId=investigation_id,
            statement=statement,
            priorConfidence=prior,
            currentConfidence=prior,
            status="open",
            supportEvidenceIds=[],
            contradictEvidenceIds=[],
            expectedEvidence=expected_evidence or [],
            missingEvidence=expected_evidence or [],
            confidenceHistory=[{
                "ts": utc_now().isoformat(),
                "value": prior,
                "delta": 0.0,
                "reason": "hypothesis_created",
            }],
            parentHypothesisId=parent_id,
            counterHypothesis=counter,
            attackTechniques=attack_techniques or [],
            attackTactics=attack_tactics or [],
            provenance=provenance or {"origin": "template"},
        )
        session.add(h)
        await session.flush()
        return h

    @staticmethod
    async def add_support(
        session: AsyncSession,
        hypothesis_id: str,
        evidence_id,
        *,
        evidence_reliability: float = 1.0,
        evidence_confidence: float = 1.0,
        reason: str = "",
    ) -> Hypothesis:
        return await HypothesisEngine._link_evidence(
            session, hypothesis_id, evidence_id, "support",
            weight=evidence_reliability * evidence_confidence,
            reason=reason)

    @staticmethod
    async def add_contradiction(
        session: AsyncSession,
        hypothesis_id: str,
        evidence_id,
        *,
        evidence_reliability: float = 1.0,
        evidence_confidence: float = 1.0,
        reason: str = "",
    ) -> Hypothesis:
        return await HypothesisEngine._link_evidence(
            session, hypothesis_id, evidence_id, "contradict",
            weight=evidence_reliability * evidence_confidence,
            reason=reason)

    @staticmethod
    async def _link_evidence(session: AsyncSession, hypothesis_id: str,
                             evidence_id, direction: str, *, weight: float,
                             reason: str) -> Hypothesis:
        # Accept either an Evidence ORM object or a string ID.
        if hasattr(evidence_id, "id"):
            evidence_id = evidence_id.id
        if not evidence_id:
            raise ValueError("evidence_id is required")
        h = await session.get(Hypothesis, hypothesis_id)
        if h is None:
            raise ValueError(f"Unknown hypothesis {hypothesis_id}")
        # A hypothesis may only cite evidence that exists in its own
        # investigation (§9: no fabricated or cross-case references).
        ev = await session.get(Evidence, evidence_id)
        if ev is None or ev.investigationId != h.investigationId:
            raise ValueError(
                f"Evidence {evidence_id} does not exist in investigation {h.investigationId}")

        weights = HypothesisEngine._weights(h)
        key = f"{direction}:{evidence_id}"
        weight = _clamp(float(weight))
        previous = weights.get(key, {}).get("weight")
        if previous is not None and previous >= weight:
            return h  # Already accounted for — re-observation changes nothing.
        weights[key] = {"direction": direction, "weight": weight, "evidence_id": evidence_id}
        h.evidenceWeights = weights

        if direction == "support":
            if evidence_id not in h.supportEvidenceIds:
                h.supportEvidenceIds = list(h.supportEvidenceIds) + [evidence_id]
            h.missingEvidence = [m for m in (h.missingEvidence or [])
                                 if m.get("evidence_id") != evidence_id]
        elif evidence_id not in h.contradictEvidenceIds:
            h.contradictEvidenceIds = list(h.contradictEvidenceIds) + [evidence_id]
        return await HypothesisEngine._recompute_confidence(
            session, h, reason=reason or f"{direction}:{evidence_id}",
            evidence_id=evidence_id)

    @staticmethod
    def _weights(h: Hypothesis) -> dict[str, dict]:
        """Per-evidence weights; backfills hypotheses written by older builds
        (which stored only ID lists) with a neutral weight of 1.0."""
        weights = dict(h.evidenceWeights or {})
        for direction, ids in (("support", h.supportEvidenceIds or []),
                               ("contradict", h.contradictEvidenceIds or [])):
            for ev_id in ids:
                weights.setdefault(f"{direction}:{ev_id}",
                                   {"direction": direction, "weight": 1.0, "evidence_id": ev_id})
        return weights

    @staticmethod
    async def mark_missing(
        session: AsyncSession,
        hypothesis_id: str,
        description: str,
        *,
        severity: str = "medium",
    ) -> Hypothesis:
        h = await session.get(Hypothesis, hypothesis_id)
        if h is None:
            raise ValueError(f"Unknown hypothesis {hypothesis_id}")
        h.missingEvidence = list(h.missingEvidence) + [{
            "description": description,
            "severity": severity,
            "ts": utc_now().isoformat(),
        }]
        await session.flush()
        return h

    @staticmethod
    async def _recompute_confidence(
        session: AsyncSession,
        h: Hypothesis,
        *,
        reason: str = "",
        evidence_id: Optional[str] = None,
    ) -> Hypothesis:
        weights = HypothesisEngine._weights(h)
        support = [w["weight"] for w in weights.values() if w["direction"] == "support"]
        contradict = [w["weight"] for w in weights.values() if w["direction"] == "contradict"]
        new_conf = posterior_confidence(h.priorConfidence, support, contradict)
        new_status = status_for(new_conf, bool(contradict))
        delta = new_conf - h.currentConfidence
        if abs(delta) > 1e-9 or new_status != h.status:
            entry = {
                "ts": utc_now().isoformat(),
                "value": new_conf,
                "delta": delta,
                "reason": reason,
            }
            if evidence_id:
                entry["evidence_id"] = evidence_id
            h.confidenceHistory = list(h.confidenceHistory) + [entry]
        h.currentConfidence = new_conf
        h.status = new_status
        await session.flush()
        return h

    @staticmethod
    async def list_for_investigation(
        session: AsyncSession, investigation_id: str
    ) -> list[Hypothesis]:
        res = await session.execute(
            select(Hypothesis).where(Hypothesis.investigationId == investigation_id)
            .order_by(Hypothesis.currentConfidence.desc())
        )
        return list(res.scalars().all())

    @staticmethod
    def to_dto(h: Hypothesis) -> HypothesisDTO:
        return HypothesisDTO(
            id=h.id,
            statement=h.statement,
            prior_confidence=h.priorConfidence,
            current_confidence=h.currentConfidence,
            status=h.status,
            support_evidence_ids=h.supportEvidenceIds,
            contradict_evidence_ids=h.contradictEvidenceIds,
            expected_evidence=h.expectedEvidence,
            missing_evidence=h.missingEvidence,
            attack_techniques=h.attackTechniques,
            attack_tactics=h.attackTactics,
            provenance=h.provenance or {"origin": "template"},
        )
