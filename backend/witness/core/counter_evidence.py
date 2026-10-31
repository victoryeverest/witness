"""Counter-evidence engine (§7).

For every significant hypothesis, WITNESS must generate BOTH:
- a SUPPORT plan (what would confirm this hypothesis)
- a COUNTER plan (what would disconfirm this hypothesis)

The agent is rewarded for finding disconfirming evidence, not just for
confirming its first conclusion. This is one of WITNESS's signature features.
"""
from __future__ import annotations

import re

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .hypothesis import HypothesisEngine
from ..models import Hypothesis


class CounterEvidencePlan:
    """A pair of investigation plans for a hypothesis."""
    def __init__(self, hypothesis_id: str,
                 support_steps: list[dict[str, Any]],
                 counter_steps: list[dict[str, Any]]):
        self.hypothesis_id = hypothesis_id
        self.support_steps = support_steps
        self.counter_steps = counter_steps

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "support_plan": self.support_steps,
            "counter_plan": self.counter_steps,
        }


# Library of counter-evidence templates keyed by claim category.
# These are deterministic knowledge templates — NOT LLM-generated. They ensure
# the counter-evidence search is grounded even when the LLM is unavailable.
# `agent` values must match the names registered in witness/agents/.
_COUNTER_TEMPLATES: dict[str, dict[str, list[dict[str, Any]]]] = {
    "credential_compromise": {
        "support": [
            {"agent": "identity_analyst", "objective": "Look for abnormal authentication patterns",
             "evidence_kind": "authentication_anomaly"},
            {"agent": "endpoint_analyst", "objective": "Look for LSASS access",
             "evidence_kind": "process_access"},
            {"agent": "endpoint_analyst", "objective": "Look for credential-dumping tooling",
             "evidence_kind": "process_exec"},
            {"agent": "network_analyst", "objective": "Look for lateral authentication",
             "evidence_kind": "auth_lateral"},
        ],
        "counter": [
            {"agent": "identity_analyst", "objective": "Verify against change-management records",
             "evidence_kind": "change_ticket"},
            {"agent": "identity_analyst", "objective": "Check if user is in known admin role",
             "evidence_kind": "admin_role_membership"},
            {"agent": "dfir_analyst", "objective": "Check for credential dump artifact",
             "evidence_kind": "memory_image"},
            {"agent": "network_analyst", "objective": "Verify source IP against known admin subnets",
             "evidence_kind": "source_ip_reputation"},
        ],
    },
    "lateral_movement": {
        "support": [
            {"agent": "network_analyst", "objective": "Look for SMB/WMI outbound from host",
             "evidence_kind": "lateral_protocol"},
            {"agent": "endpoint_analyst", "objective": "Look for service creation on remote host",
             "evidence_kind": "service_create"},
            {"agent": "identity_analyst", "objective": "Look for new admin logon on remote host",
             "evidence_kind": "remote_admin"},
        ],
        "counter": [
            {"agent": "identity_analyst", "objective": "Check if remote admin matches admin job schedule",
             "evidence_kind": "scheduled_task_baseline"},
            {"agent": "network_analyst", "objective": "Check if SMB matches admin baseline",
             "evidence_kind": "admin_smb_baseline"},
        ],
    },
    "ot_plc_compromise": {
        "support": [
            {"agent": "ot_analyst", "objective": "Look for unauthorized PLC writes",
             "evidence_kind": "plc_write"},
            {"agent": "ot_analyst", "objective": "Look for new engineering-workstation → PLC path",
             "evidence_kind": "network_path"},
            {"agent": "ot_analyst", "objective": "Look for changed process variables",
             "evidence_kind": "process_var_change"},
        ],
        "counter": [
            {"agent": "ot_analyst", "objective": "Verify against scheduled maintenance window",
             "evidence_kind": "maintenance_window"},
            {"agent": "ot_analyst", "objective": "Verify engineer identity vs. authorized list",
             "evidence_kind": "authorized_engineer"},
            {"agent": "ot_analyst", "objective": "Verify change has process-owner approval",
             "evidence_kind": "change_control_record"},
        ],
    },
    "phishing_initial_access": {
        "support": [
            {"agent": "endpoint_analyst", "objective": "Look for suspicious email + click",
             "evidence_kind": "email_click"},
            {"agent": "endpoint_analyst", "objective": "Look for suspicious child process of mail client",
             "evidence_kind": "child_proc"},
            {"agent": "network_analyst", "objective": "Look for newly-registered-domain DNS resolution",
             "evidence_kind": "dns_nrd"},
        ],
        "counter": [
            {"agent": "endpoint_analyst", "objective": "Verify email was not quarantined by email security",
             "evidence_kind": "email_security_verdict"},
            {"agent": "identity_analyst", "objective": "Verify user is in group likely targeted by legitimate internal mail",
             "evidence_kind": "group_membership"},
        ],
    },
    "powershell_execution": {
        "support": [
            {"agent": "endpoint_analyst", "objective": "Look for encoded PowerShell command line",
             "evidence_kind": "encoded_command"},
            {"agent": "endpoint_analyst", "objective": "Look for PowerShell downloading from internet",
             "evidence_kind": "download_exec"},
        ],
        "counter": [
            {"agent": "endpoint_analyst", "objective": "Check against admin script baseline",
             "evidence_kind": "admin_script_baseline"},
            {"agent": "identity_analyst", "objective": "Verify executor is in admin/script-author group",
             "evidence_kind": "group_membership"},
        ],
    },
}


def classify_hypothesis(statement: str) -> str:
    """Map a hypothesis statement to a counter-evidence template category."""
    s = statement.lower()
    words = set(re.findall(r"[a-z0-9]+", s))
    # Whole-word matching: the original substring test (`"ot" in s`) filed
    # "Rootkit installed on another host" under OT/PLC compromise.
    if (words & {"plc", "plcs", "ot", "modbus", "scada", "industrial", "alarm", "alarms"}
            or "process variable" in s or "process impact" in s):
        return "ot_plc_compromise"
    if "credential" in s and ("compromise" in s or "theft" in s or "dump" in s):
        return "credential_compromise"
    if "lateral" in words:
        return "lateral_movement"
    if "phish" in s or "initial access" in s:
        return "phishing_initial_access"
    if "powershell" in s or "encoded command" in s:
        return "powershell_execution"
    # Default fallback: minimal counter plan.
    return "_generic"


def build_plans(hypothesis: Hypothesis) -> CounterEvidencePlan:
    """Build support + counter plans for a hypothesis."""
    category = classify_hypothesis(hypothesis.statement)
    template = _COUNTER_TEMPLATES.get(category, {
        "support": [
            {"agent": "evidence_analyst", "objective": "Find direct evidence supporting the hypothesis",
             "evidence_kind": "direct_evidence"},
        ],
        "counter": [
            {"agent": "contradiction_analyst", "objective": "Find evidence that would disconfirm the hypothesis",
             "evidence_kind": "disconfirming_evidence"},
        ],
    })
    return CounterEvidencePlan(
        hypothesis_id=hypothesis.id,
        support_steps=list(template["support"]),
        counter_steps=list(template["counter"]),
    )


async def generate_counter_hypothesis(
    session: AsyncSession,
    investigation_id: str,
    parent: Hypothesis,
) -> Hypothesis:
    """For a hypothesis H, create the negation hypothesis ~H (§50)."""
    counter_stmt = f"NOT({parent.statement})"
    h = await HypothesisEngine.create(
        session, investigation_id,
        counter_stmt,
        prior=1.0 - parent.currentConfidence,
        counter=True,
        parent_id=parent.id,
        attack_techniques=parent.attackTechniques,
        attack_tactics=parent.attackTactics,
    )
    return h


def would_change_mind(hypothesis: Hypothesis) -> dict[str, Any]:
    """Return the answer to: 'What would change your mind about this?' (§49)."""
    return {
        "hypothesis_id": hypothesis.id,
        "current_conclusion": hypothesis.statement,
        "current_confidence": hypothesis.currentConfidence,
        "strongest_supporting": hypothesis.supportEvidenceIds[:3],
        "strongest_contradicting": hypothesis.contradictEvidenceIds[:3],
        "missing_evidence": hypothesis.missingEvidence[:3],
        "would_reduce_confidence": [
            "Discovery of a change-management ticket matching the activity",
            "Discovery of authorized admin session from a known admin workstation",
            "Failure to find any artifact of credential dump in memory",
            "Discovery that the activity matches an established baseline",
        ],
    }


def _validate_template_agents() -> None:
    """Every plan step must route to a registered agent. Checked at import so a
    typo fails loudly instead of as a silently 'failed' task at runtime."""
    from ..agents import list_agent_names
    known = set(list_agent_names())
    for category, tmpl in _COUNTER_TEMPLATES.items():
        for kind in ("support", "counter"):
            for step in tmpl.get(kind, []):
                if step.get("agent") and step["agent"] not in known:
                    raise ValueError(f"counter template {category}.{kind} routes to "
                                     f"unknown agent {step['agent']!r}")
