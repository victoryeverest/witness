"""Information-gain scoring (§13).

Investigation prioritization:
    Priority = information_gain × confidence_impact × asset_criticality
               × evidence_reliability / investigation_cost

The score is deterministic — the LLM never invents it.
"""
from __future__ import annotations


from ..schemas import NextStep


CRITICALITY_WEIGHTS = {
    "low": 0.5, "medium": 1.0, "high": 1.5, "safety_critical": 3.0,
}

DOMAIN_WEIGHTS = {
    # Domains that are typically higher-value in incident reconstruction.
    "identity": 1.1, "endpoint": 1.0, "network": 0.9, "cloud": 1.0,
    "application": 0.8, "ot": 1.4, "process": 1.2, "safety": 2.0,
}


def score_next_step(step: NextStep, *, asset_criticality: str = "medium",
                    evidence_reliability: float = 1.0) -> float:
    """Compute the deterministic priority score for a proposed next step."""
    ig = max(0.01, step.information_gain)
    ci = max(0.01, step.confidence_impact)
    cost = max(0.01, step.cost)
    ac = CRITICALITY_WEIGHTS.get(asset_criticality, 1.0)
    er = max(0.01, evidence_reliability)
    return (ig * ci * ac * er) / cost


def rank_steps(steps: list[NextStep], *,
               asset_criticality: str = "medium",
               evidence_reliability: float = 1.0) -> list[NextStep]:
    """Sort by descending score."""
    scored = [(s, score_next_step(s, asset_criticality=asset_criticality,
                                  evidence_reliability=evidence_reliability))
              for s in steps]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [s for s, _ in scored]


# Cost tables — rough estimates of "how expensive is this step".
TOOL_COST_TABLE = {
    "search_windows_events": 0.5,
    "search_sysmon": 0.5,
    "search_auditd": 0.5,
    "query_zeek": 0.6,
    "query_dns": 0.4,
    "search_edr": 0.7,
    "query_cloud_audit": 0.8,
    "pcap_extract": 1.2,
    "memory_acquire": 2.5,
    "plc_register_read": 2.0,
    "ot_protocol_capture": 1.5,
    "deploy_sigma": 0.8,
    "deploy_yara": 0.8,
    "isolate_endpoint": 5.0,  # not a query, but we account for risk-adjusted cost
}


def tool_cost(tool_name: str) -> float:
    return TOOL_COST_TABLE.get(tool_name, 1.0)
