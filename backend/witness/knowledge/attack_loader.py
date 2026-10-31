"""WITNESS knowledge layer (§99-101) — MITRE ATT&CK loader.

Downloads and parses the official MITRE ATT&CK Enterprise + ICS STIX bundles,
persists them as KnowledgeItem rows with full provenance (version, retrieval
date, license, content hash), and builds an in-memory index for fast
technique-name lookup and RAG retrieval.

If offline (LOCAL_ONLY privacy mode + no cached bundle), the loader falls
back to the hand-curated ENTERPRISE_TECHNIQUES / ICS_TECHNIQUES dicts in
`witness.attack.mapper` so the system remains fully functional.

Usage:
    from witness.knowledge.attack_loader import load_attack_knowledge
    await load_attack_knowledge(session)

After loading, the technique names come from the authoritative MITRE source
with proper provenance, not from a hand-maintained dict.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models import KnowledgeItem
from ..utils.crypto import sha256_text
from ..utils.logging import get_logger
from ..utils.time import utc_now
from .attack_index import AttackIndex


log = get_logger("witness.knowledge")


# MITRE ATT&CK STIX bundle URLs (official, public domain).
# Per §21: "The ICS implementation must track the current MITRE ICS matrix
# rather than hardcoding an outdated list."
ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATTACK_ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
ATTACK_LICENSE = "https://github.com/mitre/cti/blob/master/LICENSE.txt"
ATTACK_VERSION_FALLBACK = "16.1"  # We update this manually if no version found.


async def _download(url: str, cache_path: Path) -> dict[str, Any] | None:
    """Download a URL into a cache file, return parsed JSON. Uses the cache
    if present (offline-friendly)."""
    if cache_path.exists():
        log.info(f"using_cached_bundle:{cache_path}")
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            log.warning(f"cache_corrupt_redownloading:{cache_path}")
            cache_path.unlink(missing_ok=True)

    # If LOCAL_ONLY privacy mode, don't fetch.
    if settings.privacy_mode == "LOCAL_ONLY" and not os.environ.get(
            "WITNESS_ALLOW_ATTACK_DOWNLOAD", ""):
        log.warning(
            "local_only_mode_skipping_download. Use WITNESS_ALLOW_ATTACK_DOWNLOAD=1 to allow."
        )
        return None

    try:
        import httpx
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
            cache_path.write_text(json.dumps(data), encoding="utf-8")
            log.info(f"downloaded:{url} → {cache_path}")
            return data
    except Exception as e:
        log.warning(f"download_failed:{url} {e}")
        return None


def _extract_techniques(bundle: dict[str, Any], matrix: str) -> list[dict[str, Any]]:
    """Extract technique objects from a MITRE STIX bundle.

    Returns a list of {external_id, name, description, tactics, deprecated,
    revoked, version} dicts.
    """
    objs = bundle.get("objects", []) if isinstance(bundle, dict) else []
    # Index attack-pattern by stix id for later reference resolution.
    by_id: dict[str, dict[str, Any]] = {}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        stix_id = o.get("id", "")
        # Find external_id in external_references.
        ext_id = None
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                break
        if not ext_id:
            continue
        # Extract description
        description = (o.get("description") or "").strip()
        # tactics via kill-chain-phases
        tactics: list[str] = []
        for kp in o.get("kill_chain_phases", []):
            tactics.append(kp.get("phase_name", ""))
        by_id[stix_id] = {
            "external_id": ext_id,
            "stix_id": stix_id,
            "name": o.get("name", ""),
            "description": description,
            "tactics": tactics,
            "deprecated": bool(o.get("x_mitre_deprecated", False)),
            "revoked": bool(o.get("revoked", False)),
            "matrix": matrix,
        }
    return list(by_id.values())


async def load_attack_knowledge(session: AsyncSession,
                                  cache_dir: Optional[Path] = None) -> dict[str, int]:
    """Download (or use cached) MITRE ATT&CK bundles, persist to KnowledgeItem.

    Returns {enterprise: count, ics: count} dict.
    """
    cache_dir = cache_dir or Path(settings.knowledge_dir if hasattr(settings, "knowledge_dir")
                                                 else "data/knowledge")
    cache_dir.mkdir(parents=True, exist_ok=True)

    summary = {"enterprise": 0, "ics": 0, "fallback": 0}

    # --- Enterprise ATT&CK ---
    ent_path = cache_dir / "enterprise-attack.json"
    ent_bundle = await _download(ATTACK_ENTERPRISE_URL, ent_path)
    if ent_bundle:
        ent_techs = _extract_techniques(ent_bundle, "enterprise-attack")
        for t in ent_techs:
            await _upsert_knowledge_item(
                session,
                kind="attack_enterprise",
                external_id=t["external_id"],
                name=t["name"],
                body={"description": t["description"], "tactics": t["tactics"],
                       "matrix": t["matrix"], "deprecated": t["deprecated"],
                       "revoked": t["revoked"]},
                source="mitre-cti",
                version=str(ent_bundle.get("x_mitre_version", ATTACK_VERSION_FALLBACK)),
                license_=ATTACK_LICENSE,
            )
            summary["enterprise"] += 1

    # --- ICS ATT&CK ---
    ics_path = cache_dir / "ics-attack.json"
    ics_bundle = await _download(ATTACK_ICS_URL, ics_path)
    if ics_bundle:
        ics_techs = _extract_techniques(ics_bundle, "ics-attack")
        for t in ics_techs:
            await _upsert_knowledge_item(
                session,
                kind="attack_ics",
                external_id=t["external_id"],
                name=t["name"],
                body={"description": t["description"], "tactics": t["tactics"],
                       "matrix": t["matrix"], "deprecated": t["deprecated"],
                       "revoked": t["revoked"]},
                source="mitre-cti",
                version=str(ics_bundle.get("x_mitre_version", ATTACK_VERSION_FALLBACK)),
                license_=ATTACK_LICENSE,
            )
            summary["ics"] += 1

    # If both downloads failed (offline) and the DB is empty, fall back to the
    # hand-curated dicts so the system remains usable.
    if summary["enterprise"] == 0 and summary["ics"] == 0:
        log.warning("attack_load_failed_using_fallback_dicts")
        from ..attack.mapper import ENTERPRISE_TECHNIQUES, ICS_TECHNIQUES, ICS_TACTICS
        for tid, name in ENTERPRISE_TECHNIQUES.items():
            await _upsert_knowledge_item(
                session, kind="attack_enterprise", external_id=tid, name=name,
                body={"description": "Fallback entry. Run with internet access "
                                     "to fetch the full MITRE ATT&CK description.",
                      "tactics": [], "matrix": "enterprise-attack",
                      "deprecated": False, "revoked": False},
                source="witness-builtin-fallback", version="local", license_="internal",
            )
            summary["fallback"] += 1
        for tid, name in ICS_TECHNIQUES.items():
            await _upsert_knowledge_item(
                session, kind="attack_ics", external_id=tid, name=name,
                body={"description": "Fallback entry. Run with internet access "
                                     "to fetch the full MITRE ICS ATT&CK description.",
                      "tactics": ICS_TACTICS, "matrix": "ics-attack",
                      "deprecated": False, "revoked": False},
                source="witness-builtin-fallback", version="local", license_="internal",
            )
            summary["fallback"] += 1

    await session.flush()
    log.info(f"attack_knowledge_loaded:{summary}")
    return summary


async def _upsert_knowledge_item(session: AsyncSession, *,
                                   kind: str, external_id: str, name: str,
                                   body: dict[str, Any], source: str,
                                   version: str, license_: str) -> KnowledgeItem:
    """Insert or update a KnowledgeItem by (kind, external_id)."""
    res = await session.execute(
        select(KnowledgeItem).where(
            KnowledgeItem.kind == kind, KnowledgeItem.externalId == external_id
        )
    )
    item = res.scalar_one_or_none()
    body_str = json.dumps(body, sort_keys=True, default=str)
    content_hash = sha256_text(f"{kind}|{external_id}|{name}|{body_str}|{version}")
    if item:
        # Update in place if the content hash differs.
        if item.contentHash != content_hash:
            item.name = name
            item.body = body
            item.source = source
            item.version = version
            item.license_ = license_
            item.retrievalDate = utc_now()
            item.contentHash = content_hash
    else:
        item = KnowledgeItem(
            id=f"KI-{external_id}",
            kind=kind,
            externalId=external_id,
            name=name,
            body=body,
            source=source,
            version=version,
            retrievalDate=utc_now(),
            license_=license_,
            contentHash=content_hash,
        )
        session.add(item)
    await session.flush()
    return item


# --------------------------------------------------------------------------- #
# In-memory index for fast lookup + RAG retrieval (§101)
# --------------------------------------------------------------------------- #

_INDEX: Optional[AttackIndex] = None


async def get_attack_index(session: AsyncSession) -> AttackIndex:
    """Get or build the in-memory ATT&CK index from the DB."""
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    res = await session.execute(
        select(KnowledgeItem).where(KnowledgeItem.kind.in_(
            ["attack_enterprise", "attack_ics"]
        ))
    )
    items = list(res.scalars().all())
    _INDEX = AttackIndex(items)
    return _INDEX


async def reset_attack_index() -> None:
    """Clear the in-memory index. Call after the DB changes."""
    global _INDEX
    _INDEX = None
