"""Policy engine (§39, §40, §42).

Sits between the agent and tool execution. Enforces:
- schema validation of tool arguments
- permission checks (RBAC)
- risk-level → approval requirements
- OT safety classification
- prompt-injection defense (data never redefines policy)

Architecture (§39):
    LLM → ProposedAction → SchemaValidation → PolicyEngine → RiskEngine
        → ApprovalRequirement → Human → Execution
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from ..models import Action, Approval
from ..schemas import (
    PolicyDecision, ApprovalScope, OTSafetyAssessment,
)
from ..utils.time import utc_now
from ..core.graph import EvidenceGraph
from ..ot.safety import classify_ot_action


# Tool → required permission map. Mirrors the tool definitions.
_TOOL_PERMISSIONS = {
    "search_windows_events": {"READ_TELEMETRY"},
    "search_sysmon": {"READ_TELEMETRY"},
    "query_zeek": {"READ_TELEMETRY"},
    "query_dns": {"READ_TELEMETRY"},
    "search_edr": {"READ_TELEMETRY"},
    "query_cloud_audit": {"READ_TELEMETRY"},
    "query_ot_protocol": {"READ_OT"},
    "query_process_variables": {"READ_OT"},
    "search_threat_intel": {"READ_TELEMETRY"},
    "search_log_source": {"READ_TELEMETRY"},
    "pcap_analyze": {"READ_TELEMETRY"},
    "get_asset_context": {"READ_TELEMETRY"},
    "filesystem_metadata": {"READ_DFIR"},
    "registry_artifacts": {"READ_DFIR"},
    "prefetch": {"READ_DFIR"},
    "amcache": {"READ_DFIR"},
    "plaso_timeline": {"READ_DFIR"},
    "memory_acquire": {"MEMORY_ACQUIRE"},
    "isolate_endpoint": {"WRITE_CONTAINMENT"},
    "disable_account": {"WRITE_CONTAINMENT"},
    "rotate_credentials": {"WRITE_RESPONSE"},
    "block_ioc": {"WRITE_RESPONSE"},
    "deploy_sigma": {"WRITE_DETECTION"},
    "deploy_yara": {"WRITE_DETECTION"},
    "plc_control_action": {"WRITE_OT"},
}


# Per-tool static policy. Risk levels per spec §42.
_TOOL_STATIC_POLICY = {
    "search_windows_events": {"risk": "low", "approval": False},
    "search_sysmon": {"risk": "low", "approval": False},
    "query_zeek": {"risk": "low", "approval": False},
    "query_dns": {"risk": "low", "approval": False},
    "search_edr": {"risk": "low", "approval": False},
    "query_cloud_audit": {"risk": "low", "approval": False},
    "query_ot_protocol": {"risk": "low", "approval": False},
    "query_process_variables": {"risk": "low", "approval": False},
    "search_threat_intel": {"risk": "low", "approval": False},
    "search_log_source": {"risk": "low", "approval": False},
    "pcap_analyze": {"risk": "low", "approval": False},
    "get_asset_context": {"risk": "low", "approval": False},
    "filesystem_metadata": {"risk": "low", "approval": False},
    "registry_artifacts": {"risk": "low", "approval": False},
    "prefetch": {"risk": "low", "approval": False},
    "amcache": {"risk": "low", "approval": False},
    "plaso_timeline": {"risk": "low", "approval": False},
    "memory_acquire": {"risk": "medium", "approval": True},
    "isolate_endpoint": {"risk": "high", "approval": True},
    "disable_account": {"risk": "medium", "approval": True},
    "rotate_credentials": {"risk": "medium", "approval": True},
    "block_ioc": {"risk": "low", "approval": True},
    "deploy_sigma": {"risk": "low", "approval": True},
    "deploy_yara": {"risk": "low", "approval": True},
    "plc_control_action": {"risk": "prohibited", "approval": True},
}


def user_has_permissions(user_role: str, required: set[str]) -> bool:
    """Map RBAC role → permission set (§68)."""
    role_perms = {
        "viewer": {"READ_TELEMETRY"},
        "analyst": {"READ_TELEMETRY", "READ_DFIR", "READ_OT"},
        "senior_analyst": {"READ_TELEMETRY", "READ_DFIR", "READ_OT", "WRITE_DETECTION"},
        "responder": {"READ_TELEMETRY", "READ_DFIR", "WRITE_CONTAINMENT", "WRITE_RESPONSE"},
        "ot_analyst": {"READ_TELEMETRY", "READ_OT"},
        "ot_engineer": {"READ_OT", "WRITE_OT"},
        "security_engineer": {"READ_TELEMETRY", "READ_DFIR", "READ_OT",
                              "WRITE_DETECTION", "WRITE_CONTAINMENT", "WRITE_RESPONSE",
                              "MEMORY_ACQUIRE"},
        "admin": {"*"},  # wildcard
        "approver": {"READ_TELEMETRY"},
        "auditor": {"READ_TELEMETRY"},
    }
    user_perms = role_perms.get(user_role, set())
    if "*" in user_perms:
        return True
    return required.issubset(user_perms)


def evaluate_tool_policy(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    user_role: str = "analyst",
    graph: Optional[EvidenceGraph] = None,
) -> PolicyDecision:
    """Evaluate the policy for a proposed tool invocation."""
    perms = _TOOL_PERMISSIONS.get(tool_name, set())
    if not perms:
        return PolicyDecision(decision="deny", reason=f"unknown_tool:{tool_name}",
                              notes=["No permissions declared for tool."])
    if not user_has_permissions(user_role, perms):
        return PolicyDecision(
            decision="deny",
            reason="insufficient_permissions",
            required_approvals=[],
            risk_level="low",
            notes=[f"User role '{user_role}' lacks {perms}"],
        )
    static = _TOOL_STATIC_POLICY.get(tool_name, {"risk": "medium", "approval": True})
    risk = static["risk"]
    needs_approval = static["approval"]

    # OT safety classification: special handling for OT write tools.
    ot_assessment: Optional[OTSafetyAssessment] = None
    required_approvals: list[ApprovalScope] = []
    if "WRITE_OT" in perms or tool_name == "plc_control_action":
        ot_assessment = classify_ot_action(tool_name, arguments)
        if ot_assessment.classification == "prohibited":
            return PolicyDecision(
                decision="prohibited",
                reason="ot_safety_engine_classification_prohibited",
                risk_level="prohibited",
                required_approvals=["security", "ot_engineering", "process_owner"],
                notes=[ot_assessment.rationale],
                blast_radius=ot_assessment.blast_radius,
            )
        if ot_assessment.classification == "safety_critical":
            required_approvals = ["security", "ot_engineering", "process_owner"]
        elif ot_assessment.classification == "high_risk":
            required_approvals = ["security", "ot_engineering"]
        elif ot_assessment.classification == "requires_human_ot_authority":
            required_approvals = ["security", "ot_engineering"]
        elif ot_assessment.classification == "operationally_sensitive":
            required_approvals = ["security", "ot_engineering"]
        needs_approval = needs_approval or bool(required_approvals)

    if needs_approval:
        if not required_approvals:
            required_approvals = ["security"]
        return PolicyDecision(
            decision="require_approval",
            reason="risk_threshold_exceeded",
            required_approvals=required_approvals,
            risk_level=risk,
            reversibility="reversible" if tool_name in {
                "isolate_endpoint", "disable_account", "block_ioc",
                "deploy_sigma", "deploy_yara"} else "partially_reversible",
            notes=[f"Tool '{tool_name}' requires approval per §42"],
            blast_radius=ot_assessment.blast_radius if ot_assessment else {},
        )

    return PolicyDecision(
        decision="allow",
        reason="low_risk_read_tool",
        risk_level="low",
        reversibility="reversible",
    )


# --------------------------------------------------------------------------- #
# Action lifecycle errors
# --------------------------------------------------------------------------- #

class PolicyError(Exception):
    """A request that the policy layer refuses. Maps to HTTP 409."""
    status_code = 409


class ActionNotFound(PolicyError):
    status_code = 404


class ApprovalForbidden(PolicyError):
    """The caller may not sign for this approval scope. Maps to HTTP 403."""
    status_code = 403


# Which RBAC roles may sign which approval scope (§69). Separation of duties
# is enforced separately: one identity can sign at most one scope per action.
APPROVAL_SCOPE_SIGNERS: dict[str, set[str]] = {
    "security": {"security_engineer", "responder", "senior_analyst", "approver", "admin"},
    "ot_engineering": {"ot_engineer", "admin"},
    "process_owner": {"approver", "admin"},
}

# Terminal states. `denied` (RBAC) and `prohibited` (OT safety) actions are
# recorded for the audit trail but can never be approved or executed.
TERMINAL_STATUSES = {"denied", "prohibited", "rejected", "completed", "failed", "rolled_back"}


def can_sign(user_role: Optional[str], scope: str) -> bool:
    return user_role in APPROVAL_SCOPE_SIGNERS.get(scope, set())


_DECISION_RANK = {"allow": 0, "require_approval": 1, "deny": 2, "prohibited": 3}


def escalate_with_ot_assessment(decision: PolicyDecision,
                                assessment: OTSafetyAssessment) -> PolicyDecision:
    """Fold an OT safety assessment into a policy decision.

    Only ever makes the decision *stricter*. The original API handler
    overwrote the decision with "require_approval" whenever the OT engine
    said prohibited or safety_critical — which downgraded a PROHIBITED PLC
    command into an approvable one.
    """
    if assessment.classification == "prohibited":
        target, roles = "prohibited", ["security", "ot_engineering", "process_owner"]
    elif assessment.classification == "safety_critical":
        target, roles = "require_approval", ["security", "ot_engineering", "process_owner"]
    elif assessment.classification in {"high_risk", "requires_human_ot_authority",
                                       "operationally_sensitive"}:
        target, roles = "require_approval", ["security", "ot_engineering"]
    else:
        return decision
    out = decision.model_copy(deep=True)
    if _DECISION_RANK[target] > _DECISION_RANK[out.decision]:
        out.decision = target  # type: ignore[assignment]
        out.reason = f"ot_safety_{assessment.classification}"
    if out.decision in {"require_approval", "prohibited"}:
        out.required_approvals = sorted(set(out.required_approvals) | set(roles),
                                        key=["security", "ot_engineering", "process_owner"].index)
    risk_rank = ["low", "medium", "high", "critical", "prohibited"]
    candidate = "prohibited" if out.decision == "prohibited" else assessment.cyber_risk
    if risk_rank.index(candidate) > risk_rank.index(out.risk_level):
        out.risk_level = candidate  # type: ignore[assignment]
    if assessment.blast_radius:
        out.blast_radius = assessment.blast_radius
    out.notes = list(out.notes) + [assessment.rationale]
    return out


async def record_action(
    session, *,
    investigation_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    decision: PolicyDecision,
    proposed_by: str = "orchestrator",
    rationale: str = "",
) -> Action:
    """Persist a proposed action with its policy decision.

    The decision determines the initial status:
    - allow            → `approved` (policy pre-approves low-risk reads)
    - require_approval → `proposed`, with one pending Approval per role
    - deny             → `denied`     (terminal)
    - prohibited       → `prohibited` (terminal)

    Identical open proposals (same tool + arguments, not yet decided) are
    returned instead of duplicated, so agents that re-plan every iteration
    do not flood the approval queue.
    """
    from sqlalchemy import select

    if decision.decision in {"allow", "require_approval"}:
        res = await session.execute(select(Action).where(
            Action.investigationId == investigation_id,
            Action.toolName == tool_name,
            Action.status.in_(["proposed", "approved"]),
        ))
        for existing in res.scalars().all():
            if existing.arguments == arguments:
                return existing

    status = {"allow": "approved", "require_approval": "proposed",
              "deny": "denied", "prohibited": "prohibited"}[decision.decision]
    needs_approval = decision.decision == "require_approval"
    blast = dict(decision.blast_radius or {})
    if rationale:
        blast.setdefault("rationale", rationale)
    action = Action(
        id=f"AC-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        toolName=tool_name,
        arguments=arguments,
        riskLevel=decision.risk_level,
        requiresApproval=needs_approval,
        approvalScope=",".join(decision.required_approvals) if needs_approval else "",
        status=status,
        proposedBy=proposed_by,
        blastRadius=blast,
        reversibility=decision.reversibility,
        result=({"policy_reason": decision.reason, "notes": decision.notes}
                if status in {"denied", "prohibited"} else None),
    )
    session.add(action)
    await session.flush()

    if needs_approval:
        for role in decision.required_approvals:
            session.add(Approval(
                id=f"AP-{uuid.uuid4().hex[:10].upper()}",
                actionId=action.id,
                approverRole=role,
                status="pending",
            ))
        await session.flush()
    return action


async def _get_action(session, action_id: str) -> Action:
    action = await session.get(Action, action_id)
    if not action:
        raise ActionNotFound("action_not_found")
    return action


async def _approvals(session, action_id: str) -> list[Approval]:
    from sqlalchemy import select
    res = await session.execute(select(Approval).where(Approval.actionId == action_id))
    return list(res.scalars().all())


async def approve_action(session, action_id: str, *,
                          approver_id: str, approver_role: str,
                          reason: str = "",
                          principal_role: Optional[str] = None) -> tuple[Action, Approval]:
    """Sign one required approval scope of a pending action.

    Enforced invariants (each was violated by the original implementation):
    - only `proposed` actions can be approved — never denied, prohibited,
      rejected or already-executed ones;
    - `approver_role` must be one of the action's required scopes;
    - each scope is signed once;
    - separation of duties: one identity signs at most one scope, and never
      an action it proposed itself;
    - when `principal_role` is known (authenticated mode), that RBAC role
      must be allowed to sign the scope.
    The action becomes `approved` only when every required scope is signed.
    """
    action = await _get_action(session, action_id)
    if action.status != "proposed" or not action.requiresApproval:
        raise PolicyError(f"action_not_pending_approval (status={action.status})")
    required = [r for r in (action.approvalScope or "").split(",") if r]
    if approver_role not in required:
        raise PolicyError(f"approval_scope_not_required:{approver_role} (required={required})")
    if principal_role is not None and not can_sign(principal_role, approver_role):
        raise ApprovalForbidden(f"role_cannot_sign:{principal_role}->{approver_role}")
    if approver_id == action.proposedBy:
        raise PolicyError("proposer_cannot_approve_own_action")

    approvals = await _approvals(session, action_id)
    if any(a.status == "approved" and a.approverId == approver_id for a in approvals):
        raise PolicyError("separation_of_duties:approver_already_signed_another_scope")
    pending = next((a for a in approvals
                    if a.approverRole == approver_role and a.status == "pending"), None)
    if pending is None:
        raise PolicyError(f"approval_scope_already_signed:{approver_role}")

    pending.status = "approved"
    pending.approverId = approver_id
    pending.reason = reason
    pending.decidedAt = utc_now()

    signed = {a.approverRole for a in approvals if a.status == "approved"}
    if set(required) <= signed:
        action.status = "approved"
        action.approvedBy = ",".join(sorted({a.approverId for a in approvals
                                             if a.status == "approved" and a.approverId}))
    await session.flush()
    return action, pending


async def reject_action(session, action_id: str, *,
                         approver_id: str, approver_role: str,
                         reason: str,
                         principal_role: Optional[str] = None) -> tuple[Action, Approval]:
    """Veto a pending action. Any holder of a required scope can veto; the
    remaining pending approvals are cancelled and the action is terminal."""
    action = await _get_action(session, action_id)
    if action.status not in {"proposed", "approved"}:
        raise PolicyError(f"action_not_rejectable (status={action.status})")
    required = [r for r in (action.approvalScope or "").split(",") if r] or ["security"]
    if approver_role not in required:
        raise PolicyError(f"approval_scope_not_required:{approver_role} (required={required})")
    if principal_role is not None and not can_sign(principal_role, approver_role):
        raise ApprovalForbidden(f"role_cannot_sign:{principal_role}->{approver_role}")

    approvals = await _approvals(session, action_id)
    decided = next((a for a in approvals
                    if a.approverRole == approver_role and a.status == "pending"), None)
    if decided is None:
        decided = Approval(id=f"AP-{uuid.uuid4().hex[:10].upper()}",
                           actionId=action_id, approverRole=approver_role)
        session.add(decided)
    decided.status = "rejected"
    decided.approverId = approver_id
    decided.reason = reason
    decided.decidedAt = utc_now()
    for a in approvals:
        if a is not decided and a.status == "pending":
            a.status = "cancelled"
            a.decidedAt = utc_now()
    action.status = "rejected"
    await session.flush()
    return action, decided


async def execute_action(session, action_id: str, *, executor_id: str = "system",
                         extra_state: Optional[dict[str, Any]] = None) -> Action:
    """The single trusted path from an approved Action to a tool call.

    Re-checks the action at execution time, runs the tool with an
    executor-verified authorization (`ToolContext.authorized_action_id`),
    persists the effect on the Investigation, and immediately verifies it
    (§38: post-action verification).
    """
    from ..models import Investigation
    from ..tools.base import ToolContext, execute_tool, get_tool
    from ..tools.actions import verify_effect

    action = await _get_action(session, action_id)
    if action.status != "approved":
        raise PolicyError(f"action_not_approved (status={action.status})")
    if _TOOL_STATIC_POLICY.get(action.toolName, {}).get("risk") == "prohibited":
        # Defence in depth: should be impossible to reach `approved`.
        action.status = "prohibited"
        await session.flush()
        raise PolicyError("action_prohibited")
    if not get_tool(action.toolName):
        raise ActionNotFound("tool_not_found")

    inv = await session.get(Investigation, action.investigationId)
    inv_state = dict((inv.state if inv else None) or {})
    ctx_state: dict[str, Any] = dict(inv_state.get("ctx_snapshot") or {"synthetic": True})
    ctx_state.update(inv_state.get("effects") or {})
    if extra_state:
        ctx_state.update(extra_state)

    action.status = "executing"
    action.executedAt = utc_now()
    await session.flush()
    ctx = ToolContext(investigation_id=action.investigationId,
                      actor=f"executor:{executor_id}", state=ctx_state,
                      authorized_action_id=action.id)
    args = {k: v for k, v in (action.arguments or {}).items()
            if k not in {"approved", "dry_run"}}
    result = await execute_tool(session, action.toolName, args, ctx)
    action.status = "completed" if result.success else "failed"
    action.result = result.data if result.success else {"error": result.error, **(result.data or {})}
    action.completedAt = utc_now()
    if result.success:
        action.verification = verify_effect(action.toolName, args, ctx.state)
        if inv is not None:
            effects = {k: ctx.state[k] for k in EFFECT_KEYS if k in ctx.state}
            inv_state["effects"] = effects
            executed = list(inv_state.get("executed_actions") or [])
            executed.append({"action_id": action.id, "tool_name": action.toolName,
                             "arguments": args})
            inv_state["executed_actions"] = executed
            inv.state = inv_state
    await session.flush()
    return action


# State keys that record the effects of executed actions on the world.
EFFECT_KEYS = ("isolated_hosts", "disabled_accounts", "rotated_credentials",
               "blocked_iocs", "deployed_sigma_rules", "deployed_yara_rules",
               "plc_state", "active_sessions")
