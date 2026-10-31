"""Investigation coverage (§36, §48).

Tracks per-domain coverage and identifies gaps. The 'What haven't we
checked?' question (§48) is grounded here, not in LLM introspection.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Evidence, Investigation


# Coverage targets: each domain has a set of expected evidence kinds.
# Coverage = (observed kinds) / (expected kinds).
EXPECTED_EVIDENCE_KINDS = {
    "identity": {"auth_event", "auth_lateral", "account_change",
                 "group_membership", "credential_use"},
    "endpoint": {"process_exec", "process_access", "file_create",
                 "registry_modify", "scheduled_task", "service_create"},
    "network": {"dns", "http", "tls", "flow", "smb", "wmi", "rdp"},
    "cloud": {"api_call", "iam_change", "storage_access",
              "network_acl_change", "log_delivery"},
    "persistence": {"registry_persist", "service_persist", "scheduled_task_persist",
                    "wmi_persist"},
    "c2": {"beacon_dns", "beacon_http", "tls_anomaly", "long_connection"},
    "dfir": {"memory_image", "prefetch", "amcache", "shimcache",
             "browser_artifact", "filesystem_metadata"},
    "ot": {"plc_read", "plc_write", "protocol_anomaly", "register_change"},
    "process": {"process_var_change", "alarm_event", "setpoint_change"},
    "safety": {"safety_alarm", "interlock_event", "trip_event"},
    "application": {"app_event", "db_query", "auth_log"},
    "memory": {"memory_image", "memory_string", "injection_artifact"},
}


async def compute_coverage(
    session: AsyncSession, investigation_id: str
) -> dict[str, float]:
    """Compute the per-domain coverage score and update the investigation."""
    res = await session.execute(
        select(Evidence.normalizedData).where(Evidence.investigationId == investigation_id)
    )
    rows = res.scalars().all()
    observed_kinds_by_domain: dict[str, set[str]] = {d: set() for d in EXPECTED_EVIDENCE_KINDS}
    for nd in rows:
        if not isinstance(nd, dict):
            continue
        kind = nd.get("event_kind") or nd.get("kind")
        domain = nd.get("domain")
        if not (kind and domain):
            continue
        if domain in observed_kinds_by_domain:
            observed_kinds_by_domain[domain].add(kind)

    coverage: dict[str, float] = {}
    for domain, expected in EXPECTED_EVIDENCE_KINDS.items():
        observed = observed_kinds_by_domain[domain]
        if not expected:
            coverage[domain] = 0.0
            continue
        coverage[domain] = len(observed & expected) / len(expected)

    # Overall coverage is the weighted average of per-domain scores. Domains
    # the investigation scope explicitly excluded are skipped.
    inv = await session.get(Investigation, investigation_id)
    if inv:
        active_domains = inv.coverage or {}
        if active_domains:
            relevant = {d: s for d, s in coverage.items()
                        if active_domains.get(d, "active") != "excluded"}
            overall = sum(relevant.values()) / len(relevant) if relevant else 0.0
        else:
            overall = sum(coverage.values()) / len(coverage) if coverage else 0.0
        coverage["overall"] = overall
        # Persist.
        inv.coverage = dict(coverage)
        await session.flush()
    return coverage


async def investigation_gaps(
    session: AsyncSession, investigation_id: str
) -> list[dict[str, Any]]:
    """Return the list of evidence gaps for the 'What haven't we checked?'
    question (§48)."""
    coverage = await compute_coverage(session, investigation_id)
    gaps: list[dict[str, Any]] = []
    for domain, expected_kinds in EXPECTED_EVIDENCE_KINDS.items():
        observed_count = coverage.get(domain, 0.0)
        if observed_count < 1.0:
            missing = expected_kinds  # in practice, we'd diff against observed set
            gaps.append({
                "domain": domain,
                "coverage": observed_count,
                "missing_kinds": sorted(missing),
                "severity": "high" if observed_count < 0.25 else (
                    "medium" if observed_count < 0.6 else "low"),
            })
    gaps.sort(key=lambda g: g["coverage"])
    return gaps
