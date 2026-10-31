"""Evidence store — first-class immutable evidence objects (§8, §9).

Evidence is the atomic unit of WITNESS. Every claim, hypothesis, and finding
must ultimately reference one or more evidence IDs. Evidence is:
- immutable (content-hash protected)
- hash-chained (chain-of-custody)
- traceable back to source
- typed (source, sourceType, normalized_data)
- reliability-scored
- synthetic-flagged (for cyber-range data)
- ingested idempotently (re-observing the same fact returns the same row)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Evidence
from ..schemas import EvidenceDTO, EvidenceReliability
from ..utils.crypto import sha256_json, chain_hash
from ..utils.time import to_utc, utc_now


class EvidenceIntegrityError(Exception):
    """Raised when an evidence item's content hash does not match its data."""


def _content_payload(*, source: str, source_type: str, timestamp: datetime,
                     host: Optional[str], asset_id: Optional[str],
                     user: Optional[str], process: Optional[str],
                     normalized_data: dict[str, Any],
                     network_context: dict[str, Any]) -> dict[str, Any]:
    """The exact fields covered by an evidence row's content hash.

    The timestamp is canonicalized to UTC so the hash is stable no matter how
    the datetime was constructed or how the database hands it back.
    """
    return {
        "source": source,
        "source_type": source_type,
        "timestamp": to_utc(timestamp).isoformat(),
        "host": host,
        "asset_id": asset_id,
        "user": user,
        "process": process,
        "normalized_data": normalized_data,
        "network_context": network_context,
    }


def compute_content_hash(ev: Evidence) -> str:
    return sha256_json(_content_payload(
        source=ev.source, source_type=ev.sourceType, timestamp=ev.timestamp,
        host=ev.host, asset_id=ev.assetId, user=ev.user, process=ev.process,
        normalized_data=ev.normalizedData or {},
        network_context=ev.networkContext or {},
    ))


def _link_hash(prev_chain_hash: Optional[str], investigation_id: str,
               sequence: int, content_hash: str) -> str:
    return chain_hash(prev_chain_hash, f"{investigation_id}|{sequence}|{content_hash}")


async def add_evidence(
    session: AsyncSession,
    investigation_id: str,
    *,
    source: str,
    source_type: str,
    timestamp: datetime,
    host: Optional[str] = None,
    asset_id: Optional[str] = None,
    user: Optional[str] = None,
    process: Optional[str] = None,
    network_context: Optional[dict[str, Any]] = None,
    raw_reference: Optional[str] = None,
    normalized_data: Optional[dict[str, Any]] = None,
    reliability: EvidenceReliability = "high",
    confidence: float = 1.0,
    collection_method: str = "agent_collected",
    synthetic: bool = False,
    chain_of_custody: Optional[list[dict[str, Any]]] = None,
    dedupe: Optional[bool] = None,
) -> Evidence:
    """Insert an immutable evidence row, or return the existing one.

    Ingestion is idempotent when the caller can tell that two observations
    are the same record: if this investigation already holds evidence with
    the same content hash (and the same raw reference, when one is given)
    that row is returned unchanged. `dedupe` defaults to on when a
    `raw_reference` (source record ID) is supplied and off otherwise, since
    two genuinely distinct events can share every field. Agents opt in
    explicitly: they re-read the same records every loop iteration, and
    without this each observation was stored — and counted toward
    hypothesis confidence — again.

    New rows are appended to the investigation's hash chain (§8).
    """
    normalized_data = normalized_data or {}
    network_context = network_context or {}
    chain_of_custody = chain_of_custody or []
    timestamp = to_utc(timestamp)

    content_hash = sha256_json(_content_payload(
        source=source, source_type=source_type, timestamp=timestamp,
        host=host, asset_id=asset_id, user=user, process=process,
        normalized_data=normalized_data, network_context=network_context,
    ))

    if dedupe is None:
        dedupe = raw_reference is not None
    if dedupe:
        stmt = select(Evidence).where(
            Evidence.investigationId == investigation_id,
            Evidence.contentHash == content_hash,
        )
        if raw_reference is not None:
            stmt = stmt.where(Evidence.rawReference == raw_reference)
        existing = (await session.execute(stmt.limit(1))).scalar_one_or_none()
        if existing is not None:
            return existing

    # Chain-of-custody: link to the previous row *in ingestion order*. (The
    # original build ordered by the random UUID primary key, so the "chain"
    # linked arbitrary rows and could not detect anything.)
    prev_row = (await session.execute(
        select(Evidence)
        .where(Evidence.investigationId == investigation_id,
               Evidence.sequence.is_not(None))
        .order_by(Evidence.sequence.desc())
        .limit(1)
    )).scalar_one_or_none()
    sequence = (prev_row.sequence + 1) if prev_row else 1
    prev_chain = prev_row.chainHash if prev_row else None
    link = _link_hash(prev_chain, investigation_id, sequence, content_hash)

    chain_of_custody = list(chain_of_custody) + [{
        "ts": utc_now().isoformat(),
        "action": "ingested",
        "sequence": sequence,
        "prev_hash": prev_chain,
        "chain_hash": link,
        "collector": "witness:evidence_store",
    }]

    ev = Evidence(
        id=f"EV-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        source=source,
        sourceType=source_type,
        timestamp=timestamp,
        ingestionTime=utc_now(),
        host=host,
        assetId=asset_id,
        user=user,
        process=process,
        networkContext=network_context,
        rawReference=raw_reference,
        normalizedData=normalized_data,
        contentHash=content_hash,
        prevHash=prev_chain,
        sequence=sequence,
        chainHash=link,
        integrityStatus="verified",
        reliability=reliability,
        confidence=confidence,
        collectionMethod=collection_method,
        chainOfCustody=chain_of_custody,
        synthetic=synthetic,
    )
    session.add(ev)
    await session.flush()
    return ev


async def verify_integrity(session: AsyncSession, evidence_id: str) -> bool:
    """Recompute the content hash and compare to the stored one."""
    ev = await session.get(Evidence, evidence_id)
    if not ev:
        return False
    return compute_content_hash(ev) == ev.contentHash


async def verify_chain(session: AsyncSession, investigation_id: str) -> dict[str, Any]:
    """Verify every evidence row of an investigation and the chain linking them.

    Detects edited content (hash mismatch), forged chain links, and deleted or
    reordered rows (sequence gaps / broken links). Rows written by builds that
    predate the chain are reported as `legacy_unchained` and content-checked only.
    """
    rows = list((await session.execute(
        select(Evidence).where(Evidence.investigationId == investigation_id)
    )).scalars().all())
    chained = sorted((r for r in rows if r.sequence is not None), key=lambda r: r.sequence)
    legacy = [r for r in rows if r.sequence is None]

    content_mismatches = [r.id for r in rows if compute_content_hash(r) != r.contentHash]
    chain_breaks: list[dict[str, Any]] = []
    prev_link: Optional[str] = None
    for expected_seq, r in enumerate(chained, start=1):
        if r.sequence != expected_seq:
            chain_breaks.append({"evidence_id": r.id, "sequence": r.sequence,
                                 "problem": f"sequence_gap (expected {expected_seq})"})
        if r.prevHash != prev_link:
            chain_breaks.append({"evidence_id": r.id, "sequence": r.sequence,
                                 "problem": "prev_hash_mismatch"})
        recomputed = _link_hash(prev_link, investigation_id, r.sequence, compute_content_hash(r))
        if r.chainHash != recomputed:
            chain_breaks.append({"evidence_id": r.id, "sequence": r.sequence,
                                 "problem": "chain_hash_mismatch"})
        prev_link = r.chainHash

    return {
        "investigation_id": investigation_id,
        "evidence_count": len(rows),
        "chained_count": len(chained),
        "legacy_unchained": len(legacy),
        "content_mismatches": content_mismatches,
        "chain_breaks": chain_breaks,
        "head_hash": chained[-1].chainHash if chained else None,
        "intact": not content_mismatches and not chain_breaks,
    }


async def get_evidence(session: AsyncSession, evidence_id: str) -> Optional[Evidence]:
    return await session.get(Evidence, evidence_id)


async def list_evidence(
    session: AsyncSession,
    investigation_id: str,
    *,
    source: Optional[str] = None,
    host: Optional[str] = None,
    asset_id: Optional[str] = None,
    user: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 500,
) -> list[Evidence]:
    """Filtered evidence query."""
    stmt = select(Evidence).where(Evidence.investigationId == investigation_id)
    if source:
        stmt = stmt.where(Evidence.source == source)
    if host:
        stmt = stmt.where(Evidence.host == host)
    if asset_id:
        stmt = stmt.where(Evidence.assetId == asset_id)
    if user:
        stmt = stmt.where(Evidence.user == user)
    if start:
        stmt = stmt.where(Evidence.timestamp >= start)
    if end:
        stmt = stmt.where(Evidence.timestamp <= end)
    stmt = stmt.order_by(Evidence.timestamp.asc()).limit(limit)
    res = await session.execute(stmt)
    return list(res.scalars().all())


def to_dto(ev: Evidence) -> EvidenceDTO:
    return EvidenceDTO(
        id=ev.id,
        source=ev.source,
        source_type=ev.sourceType,
        timestamp=ev.timestamp,
        host=ev.host,
        asset_id=ev.assetId,
        user=ev.user,
        process=ev.process,
        network_context=ev.networkContext,
        normalized_data=ev.normalizedData,
        content_hash=ev.contentHash,
        reliability=ev.reliability,
        confidence=ev.confidence,
        synthetic=ev.synthetic,
        sequence=ev.sequence,
        chain_hash=ev.chainHash,
    )
