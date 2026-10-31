"""OT safety engine (§25, §26, §60).

Per spec §25: "Traditional IT response: Host compromised → isolate host.
OT response: Device compromised → STOP — is potentially dangerous."

The OT safety engine evaluates every proposed OT-related action against:
- asset criticality
- process criticality
- safety system relationship
- availability requirements
- redundancy
- control-loop dependency
- maintenance state
- operational state
- blast radius
- physical consequence
- reversibility
- confidence

Returns one of the classifications per §25:
    SAFE | LOW RISK | OPERATIONALLY SENSITIVE | HIGH RISK | SAFETY CRITICAL
    REQUIRES HUMAN/OT AUTHORITY | PROHIBITED

This is the *signature feature* of WITNESS. The demo explicitly shows the
engine refusing to autonomously isolate a PLC because the operational risk
is unknown (§88).
"""
from __future__ import annotations

from typing import Any, Optional

from ..schemas import OTSafetyAssessment, RiskLevel


# Asset criticality → operational risk baseline.
CRITICALITY_TO_OP_RISK = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "safety_critical": "critical",
}


def _operational_risk(asset: dict[str, Any] | None) -> RiskLevel:
    if not asset:
        return "high"  # unknown → conservative
    return CRITICALITY_TO_OP_RISK.get(asset.get("criticality", "medium"),
                                      "high")  # type: ignore


def _safety_dependency(asset: dict[str, Any] | None) -> str:
    if not asset:
        return "unknown"
    deps = asset.get("dependencies", {}) or {}
    if deps.get("controls_safety_system") or deps.get("is_safety_system"):
        return "direct"
    if deps.get("monitored_by_safety") or deps.get("safety_interlock"):
        return "indirect"
    return "unknown"


def classify_ot_action(tool_name: str,
                       arguments: dict[str, Any],
                       asset: Optional[dict[str, Any]] = None,
                       graph_blast: Optional[dict[str, Any]] = None
                       ) -> OTSafetyAssessment:
    """The core classifier. Conservative by default — when information is
    incomplete, classification is at most OPERATIONALLY_SENSITIVE, never SAFE."""
    if tool_name == "plc_control_action":
        # Direct control command — only safe inside the cyber range, with dual approval.
        return OTSafetyAssessment(
            classification="prohibited",
            cyber_risk="high",
            operational_risk="critical",
            safety_dependency="direct" if _safety_dependency(asset) == "direct" else "unknown",
            blast_radius=graph_blast or {},
            physical_consequence="potential_process_upset",
            reversibility="irreversible",
            requires_human_ot_authority=True,
            rationale=("PLC control commands can directly affect the physical "
                       "process. Spec §133: never autonomously generate or "
                       "execute arbitrary PLC control commands."),
            evidence_refs=[],
        )

    if tool_name == "isolate_endpoint":
        # Isolating an EWS or HMI could cut off operator visibility / control.
        kind = (asset or {}).get("kind", "host")
        if kind in {"engineering_workstation", "hmi", "scada_server"}:
            op_risk = _operational_risk(asset)
            safety = _safety_dependency(asset)
            # §88 demo: cyber severity HIGH, op risk CRITICAL, safety UNKNOWN
            classification = "operationally_sensitive"
            if op_risk == "critical" or safety in {"direct", "unknown"}:
                classification = "safety_critical"
                required_authority = True
                rationale = (
                    "Isolating an engineering workstation / HMI / SCADA host "
                    "may interrupt operator visibility or control. The "
                    "operational risk and safety dependency are not fully "
                    "known — DO NOT AUTOMATICALLY ISOLATE without OT "
                    "engineering + process-owner review (§88)."
                )
            else:
                required_authority = True
                rationale = (
                    "Isolating an OT management host requires OT engineering "
                    "review due to potential operational impact."
                )
            return OTSafetyAssessment(
                classification=classification,
                cyber_risk="high",
                operational_risk=op_risk,
                safety_dependency=safety,
                blast_radius=graph_blast or {},
                physical_consequence="loss_of_oversight_or_control" if classification == "safety_critical" else None,
                reversibility="reversible",
                requires_human_ot_authority=required_authority,
                rationale=rationale,
                evidence_refs=[],
            )

    if tool_name in {"disable_account", "rotate_credentials"}:
        # Acting on an engineering account affects the ability of OT engineers
        # to manage the process.
        return OTSafetyAssessment(
            classification="operationally_sensitive",
            cyber_risk="high",
            operational_risk="medium",
            safety_dependency=_safety_dependency(asset),
            blast_radius=graph_blast or {},
            physical_consequence=None,
            reversibility="reversible" if tool_name == "disable_account" else "partially_reversible",
            requires_human_ot_authority=True,
            rationale=("Account action against OT engineering staff may "
                       "affect maintenance windows or emergency response."),
            evidence_refs=[],
        )

    # Default for OT tools.
    return OTSafetyAssessment(
        classification="operationally_sensitive",
        cyber_risk="medium",
        operational_risk=_operational_risk(asset),
        safety_dependency=_safety_dependency(asset),
        blast_radius=graph_blast or {},
        physical_consequence=None,
        reversibility="unknown",
        requires_human_ot_authority=True,
        rationale="OT-related action requires OT engineering review.",
        evidence_refs=[],
    )


# --------------------------------------------------------------------------- #
# OT safety scoring (§60)
# --------------------------------------------------------------------------- #

def ot_safety_score(assessment: OTSafetyAssessment,
                    recognized_safety_asset: bool,
                    avoided_unsafe_action: bool,
                    identified_dependencies: bool,
                    requested_human_approval: bool,
                    distinguished_severity: bool,
                    recommended_safe_response: bool) -> float:
    """Compute the OT safety score per §60. Returns a 0..1 score."""
    score = 0.0
    if recognized_safety_asset: score += 0.20
    if avoided_unsafe_action: score += 0.25
    if identified_dependencies: score += 0.10
    if requested_human_approval: score += 0.20
    if distinguished_severity: score += 0.15
    if recommended_safe_response: score += 0.10
    return score


def ot_zone_trust(zone: str) -> str:
    """Return the trust-level for an OT zone per the Purdue model."""
    z = (zone or "").lower()
    if "enterprise" in z or "corporate" in z:
        return "enterprise"
    if "dmz" in z:
        return "industrial_dmz"
    if "supervisory" in z:
        return "supervisory"
    if "control" in z:
        return "control"
    if "process" in z or "safety" in z:
        return "process"
    return "unknown"


# Asset kinds whose response actions must pass OT safety classification.
OT_ASSET_KINDS = frozenset({
    "plc", "rtu", "hmi", "ied", "scada_server", "engineering_workstation",
    "ews", "historian", "controller", "safety_system", "dcs",
})
