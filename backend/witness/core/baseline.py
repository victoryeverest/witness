"""WITNESS baseline engine (§31).

Builds per-user / host / process / network / DNS / PLC baselines and detects
deviations. Deviations are not labeled malicious — they're surfaced as
anomalies that become hypotheses for the agent to investigate.

Per §31: "Do not automatically label deviations malicious. Treat them as:
anomaly → hypothesis → investigation."
"""
from __future__ import annotations

from collections import defaultdict, Counter
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Evidence
from ..core.evidence import add_evidence
from ..utils.time import utc_now, to_utc


# Baseline entity types per §31.
BASELINE_TYPES = (
    "user", "host", "process", "network_flow", "dns", "service",
    "plc_communication", "protocol", "register_access",
    "engineering_workstation_behavior",
)


class Baseline:
    """A baseline for one entity over a window of past observations."""
    def __init__(self, entity_type: str, entity_id: str):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.observations: list[dict[str, Any]] = []
        self.feature_counts: dict[str, Counter] = defaultdict(Counter)
        self.feature_totals: dict[str, int] = defaultdict(int)

    def add(self, observation: dict[str, Any]) -> None:
        self.observations.append(observation)
        for k, v in observation.items():
            if v is None:
                continue
            key = f"{k}={v}"
            self.feature_counts[k][key] += 1
            self.feature_totals[k] += 1

    def p(self, feature: str, value: Any) -> float:
        """Return the empirical probability P(feature=value | baseline)."""
        total = self.feature_totals.get(feature, 0)
        if total == 0:
            return 0.0
        key = f"{feature}={value}"
        return self.feature_counts[feature].get(key, 0) / total

    def is_deviation(self, feature: str, value: Any, threshold: float = 0.05) -> bool:
        """True if P(feature=value | baseline) < threshold.

        i.e. the value has never (or very rarely) been observed in the baseline.
        """
        return self.p(feature, value) < threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "observation_count": len(self.observations),
            "features": {k: dict(c) for k, c in self.feature_counts.items()},
            "totals": dict(self.feature_totals),
        }


def build_baselines(evidence: list[Evidence],
                    *,
                    window_start: Optional[datetime] = None,
                    window_end: Optional[datetime] = None,
                    ) -> dict[tuple[str, str], Baseline]:
    """Build per-(entity_type, entity_id) baselines from evidence.

    The window is [window_start, window_end]. If None, the full evidence range
    is used. By convention, the first 80% of the time range is the baseline
    window and the remaining 20% is the test window when callers want to
    detect deviations.
    """
    if not evidence:
        return {}
    # Determine time range.
    if window_start is None:
        window_start = min(e.timestamp for e in evidence)
    if window_end is None:
        window_end = max(e.timestamp for e in evidence)
    window_start = to_utc(window_start)
    window_end = to_utc(window_end)

    baselines: dict[tuple[str, str], Baseline] = {}
    for ev in evidence:
        ts = to_utc(ev.timestamp)
        if ts < window_start or ts > window_end:
            continue
        nd = ev.normalizedData or {}
        # Build baseline per host, per user, per process, per protocol.
        for etype, eid in (
            ("host", ev.host),
            ("user", ev.user),
            ("process", (nd.get("image") or ev.process)),
            ("dns", nd.get("query")),
            ("network_flow", f"{nd.get('src_ip')}→{nd.get('dst_ip')}:{nd.get('dst_port')}"),
            ("protocol", nd.get("protocol")),
            ("plc_communication",
             f"{nd.get('src_device')}→{nd.get('dst_device')}"),
            ("register_access",
             f"{nd.get('dst_device')}:{nd.get('register')}"),
            ("engineering_workstation_behavior", ev.host if nd.get("domain") == "ot" else None),
        ):
            if eid:
                key = (etype, str(eid))
                if key not in baselines:
                    baselines[key] = Baseline(etype, str(eid))
                baselines[key].add(nd)
    return baselines


async def detect_deviations(session: AsyncSession, investigation_id: str,
                              *, split_ratio: float = 0.8) -> list[dict[str, Any]]:
    """Build baselines from the first `split_ratio` of evidence and detect
    deviations in the remaining fraction. Returns a list of deviation dicts.

    Each deviation becomes a hypothesis candidate the agent can investigate.

    A deviation is flagged when:
    1. The test evidence belongs to an entity (host, user, process) whose
       baseline has >=3 observations, AND
    2. The test evidence introduces a feature value never seen in that
       baseline (novel-value deviation), OR
    3. The test evidence belongs to a NEW entity that has no baseline
       (e.g. a new process image, a new DNS domain — these are first-occurrence
       deviations, the strongest form of baseline deviation).
    """
    from ..core.evidence import list_evidence
    evidence = await list_evidence(session, investigation_id, limit=5000)
    if len(evidence) < 10:
        return []
    # Split by time.
    evidence_sorted = sorted(evidence, key=lambda e: e.timestamp)
    split_idx = int(len(evidence_sorted) * split_ratio)
    baseline_evs = evidence_sorted[:split_idx]
    test_evs = evidence_sorted[split_idx:]
    if not baseline_evs or not test_evs:
        return []
    baselines = build_baselines(baseline_evs)
    deviations: list[dict[str, Any]] = []
    # Index baselines by entity_type for "first occurrence" detection.
    baseline_entities_by_type: dict[str, set[str]] = defaultdict(set)
    for (etype, eid), b in baselines.items():
        baseline_entities_by_type[etype].add(eid)
    for ev in test_evs:
        nd = ev.normalizedData or {}
        # Per-entity check: novel-value deviation within existing baseline.
        for etype, eid in (
            ("host", ev.host),
            ("user", ev.user),
            ("process", (nd.get("image") or ev.process)),
            ("dns", nd.get("query")),
            ("protocol", nd.get("protocol")),
        ):
            if not eid:
                continue
            b = baselines.get((etype, str(eid)))
            if b is None or len(b.observations) < 3:
                continue
            for feature, value in nd.items():
                if value is None:
                    continue
                if feature in ("timestamp", "ts", "id"):
                    continue
                if b.is_deviation(feature, value, threshold=0.05):
                    deviations.append({
                        "entity_type": etype,
                        "entity_id": eid,
                        "feature": feature,
                        "value": value,
                        "evidence_id": ev.id,
                        "deviation_type": "novel_value",
                        "baseline_probability": b.p(feature, value),
                        "baseline_observations": len(b.observations),
                    })
                    break
        # First-occurrence deviation: an entity that has never been observed
        # in the baseline appears in the test window.
        for etype, eid in (
            ("process", (nd.get("image") or ev.process)),
            ("dns", nd.get("query")),
            ("network_flow",
             f"{nd.get('src_ip')}→{nd.get('dst_ip')}:{nd.get('dst_port')}"),
        ):
            if not eid:
                continue
            known = baseline_entities_by_type.get(etype, set())
            if str(eid) not in known:
                deviations.append({
                    "entity_type": etype,
                    "entity_id": str(eid),
                    "feature": "_first_occurrence",
                    "value": str(eid),
                    "evidence_id": ev.id,
                    "deviation_type": "first_occurrence",
                    "baseline_probability": 0.0,
                    "baseline_observations": 0,
                })
                # Don't repeat the same first-occurrence.
                baseline_entities_by_type[etype].add(str(eid))
    return deviations


async def anomalies_as_evidence(session: AsyncSession, investigation_id: str,
                                  deviations: list[dict[str, Any]]) -> list[str]:
    """Convert deviations to evidence rows. Each becomes its own evidence
    item so the agent can reference it."""
    evidence_ids: list[str] = []
    for dev in deviations:
        ev = await add_evidence(
            session, investigation_id,
            source="baseline_engine", source_type="derived",
            timestamp=utc_now(),
            normalized_data={
                "event_kind": "baseline_deviation",
                "domain": "endpoint",
                "entity_type": dev["entity_type"],
                "entity_id": dev["entity_id"],
                "feature": dev["feature"],
                "value": dev["value"],
                "baseline_probability": dev["baseline_probability"],
                "baseline_observations": dev["baseline_observations"],
                "original_evidence_id": dev["evidence_id"],
            },
            reliability="medium", confidence=0.7,
        )
        evidence_ids.append(ev.id)
    return evidence_ids
