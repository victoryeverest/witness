"""Timeline engine (§11).

Unifies events across IT, identity, network, cloud, application, and OT
sources. Handles timezone normalization, clock-skew detection, dedup, and
out-of-order events.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Evidence, TimelineEvent
from ..schemas import TimelineEventDTO
from ..utils.time import to_utc, clock_skew_seconds


class TimelineEngine:
    @staticmethod
    async def add_event(
        session: AsyncSession,
        investigation_id: str,
        *,
        timestamp: datetime,
        domain: str,
        event_type: str,
        title: str,
        description: Optional[str] = None,
        asset_id: Optional[str] = None,
        asset_ids: Optional[list[str]] = None,
        evidence_id: Optional[str] = None,
        attack_techniques: Optional[list[str]] = None,
        confidence: float = 1.0,
        synthetic: bool = False,
        source_clock_skew_seconds: float = 0.0,
        attributes: Optional[dict[str, Any]] = None,
    ) -> TimelineEvent:
        ts_utc = to_utc(timestamp)
        if evidence_id:
            # Idempotent per (evidence, event type): agents re-run every loop
            # iteration and must not append the same event again.
            existing = (await session.execute(
                select(TimelineEvent).where(
                    TimelineEvent.investigationId == investigation_id,
                    TimelineEvent.evidenceId == evidence_id,
                    TimelineEvent.eventType == event_type,
                ).limit(1)
            )).scalar_one_or_none()
            if existing is not None:
                return existing
            # Synthetic-ness is a property of the source evidence (§153).
            src = await session.get(Evidence, evidence_id)
            if src is not None and src.synthetic:
                synthetic = True
        ev = TimelineEvent(
            id=f"TL-{uuid.uuid4().hex[:10].upper()}",
            investigationId=investigation_id,
            timestamp=ts_utc,
            sourceClockSkewSeconds=source_clock_skew_seconds,
            domain=domain,
            eventType=event_type,
            title=title,
            description=description,
            assetId=asset_id,
            assetIds=asset_ids or [],
            evidenceId=evidence_id,
            attackTechniques=attack_techniques or [],
            confidence=confidence,
            synthetic=synthetic,
            attributes=attributes or {},
        )
        session.add(ev)
        await session.flush()
        return ev

    @staticmethod
    async def list_for_investigation(
        session: AsyncSession,
        investigation_id: str,
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        domain: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = 1000,
    ) -> list[TimelineEvent]:
        stmt = select(TimelineEvent).where(
            TimelineEvent.investigationId == investigation_id)
        if start:
            stmt = stmt.where(TimelineEvent.timestamp >= to_utc(start))
        if end:
            stmt = stmt.where(TimelineEvent.timestamp <= to_utc(end))
        if domain:
            stmt = stmt.where(TimelineEvent.domain == domain)
        if asset_id:
            stmt = stmt.where(
                (TimelineEvent.assetId == asset_id) |
                (TimelineEvent.assetIds.contains(asset_id))
            )
        stmt = stmt.order_by(TimelineEvent.timestamp.asc()).limit(limit)
        res = await session.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def detect_clock_skew(
        session: AsyncSession,
        investigation_id: str,
        reference_domain: str = "identity",
        skew_threshold_seconds: float = 5.0,
    ) -> list[dict[str, Any]]:
        """Compare timestamps from each source domain against a reference
        domain to flag likely clock skew."""
        events = await TimelineEngine.list_for_investigation(session, investigation_id)
        if not events:
            return []
        by_domain: dict[str, list[TimelineEvent]] = {}
        for e in events:
            by_domain.setdefault(e.domain, []).append(e)
        ref_events = by_domain.get(reference_domain, [])
        if not ref_events:
            return []
        ref_min = min(e.timestamp for e in ref_events)
        findings: list[dict[str, Any]] = []
        for dom, evs in by_domain.items():
            if dom == reference_domain:
                continue
            dom_min = min(e.timestamp for e in evs)
            skew = clock_skew_seconds(dom_min, ref_min)
            if abs(skew) > skew_threshold_seconds:
                findings.append({
                    "domain": dom,
                    "skew_seconds": skew,
                    "reference_domain": reference_domain,
                    "likely_skewed": skew > 0,
                })
        return findings

    @staticmethod
    async def dedup(session: AsyncSession, investigation_id: str) -> int:
        """Remove duplicate events (same timestamp, type, asset, evidence)."""
        events = await TimelineEngine.list_for_investigation(session, investigation_id)
        seen: set[tuple] = set()
        removed = 0
        for e in events:
            key = (e.timestamp, e.eventType, e.assetId, e.evidenceId, e.title)
            if key in seen:
                await session.delete(e)
                removed += 1
            else:
                seen.add(key)
        await session.flush()
        return removed

    @staticmethod
    def to_dto(e: TimelineEvent) -> TimelineEventDTO:
        return TimelineEventDTO(
            id=e.id,
            timestamp=e.timestamp,
            domain=e.domain,
            event_type=e.eventType,
            title=e.title,
            description=e.description,
            asset_id=e.assetId,
            asset_ids=e.assetIds,
            evidence_id=e.evidenceId,
            attack_techniques=e.attackTechniques,
            confidence=e.confidence,
            synthetic=e.synthetic,
            attributes=e.attributes,
        )
