"""Response action tools (§37, §38, §130, §131, §132).

These tools are the only way the agent can change the world. Every action:
- is recorded as an Action row (proposed → approved → executing → completed)
- supports a DRY RUN that returns blast-radius without executing
- only executes when the registry guard sees an executor-verified approval
  (`ToolContext.authorized_action_id`) — see tools/base.authorization_error
- supports post-action verification (§38)

Effects are recorded in `ctx.state` as JSON-serializable lists so they can be
persisted on the Investigation and verified later.
"""
from __future__ import annotations

from typing import Any

from .base import (
    Tool, ToolContext, ToolResult, register,
    WRITE_CONTAINMENT, WRITE_DETECTION, WRITE_OT, WRITE_RESPONSE,
)


def _record(state: dict[str, Any], key: str, value: Any) -> None:
    """Append `value` to the list at state[key] once (accepts legacy sets)."""
    current = state.get(key)
    items = list(current) if current else []
    if value not in items:
        items.append(value)
    state[key] = items


def _not_authorized(ctx: ToolContext) -> bool:
    # Defence in depth: the registry guard already refuses these calls.
    return not ctx.authorized_action_id


class IsolateEndpointTool(Tool):
    name = "isolate_endpoint"
    description = "Network-isolate an endpoint (block all but management traffic)."
    permissions = [WRITE_CONTAINMENT]
    risk_level = "high"
    read_write = "write"
    rollback_capable = True
    side_effect = True
    approval_required = True
    supported_environments = ["cyber_range", "production"]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        host = args.get("host")
        dry_run = args.get("dry_run", False)
        # Compute blast radius.
        affected = []
        assets = ctx.state.get("assets", {})
        for aid, a in assets.items():
            if a.get("hostname") == host or aid == host:
                affected.append(aid)
                # Look up OT dependencies if this is an EWS or other control-plane host.
                deps = a.get("dependencies", {})
                affected.extend(deps.get("controls", []))
                affected.extend(deps.get("monitored_by", []))
        blast = {
            "host": host,
            "affected_assets": list(set(affected)),
            "operational_impact": "isolates_management_network" if host in [a.get("hostname") for a in assets.values() if a.get("kind") == "engineering_workstation"] else "endpoint_only",
            "reversibility": "reversible",
            "estimated_users_affected": 1,
        }
        if dry_run:
            return ToolResult(success=True, data={"dry_run": True, "blast_radius": blast})
        if _not_authorized(ctx):
            return ToolResult(success=False,
                              error="not_approved",
                              data={"blast_radius": blast})
        # In cyber range: record isolated host in state.
        _record(ctx.state, "isolated_hosts", host)
        return ToolResult(success=True, data={
            "isolated": True, "host": host, "blast_radius": blast,
        })


class DisableAccountTool(Tool):
    name = "disable_account"
    description = "Disable an identity account. Reversible."
    permissions = [WRITE_CONTAINMENT]
    risk_level = "medium"
    read_write = "write"
    rollback_capable = True
    side_effect = True
    approval_required = True

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        user = args.get("user")
        dry_run = args.get("dry_run", False)
        if dry_run:
            sessions = ctx.state.get("active_sessions", {}).get(user, [])
            return ToolResult(success=True, data={"dry_run": True,
                "active_sessions": len(sessions),
                "tokens_issued": len(sessions)})
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved")
        _record(ctx.state, "disabled_accounts", user)
        # Verification: invalidate sessions.
        ctx.state.get("active_sessions", {}).pop(user, None)
        return ToolResult(success=True, data={"disabled": True, "user": user})


class RotateCredentialsTool(Tool):
    name = "rotate_credentials"
    description = "Rotate credentials for an account. Irreversible."
    permissions = [WRITE_RESPONSE]
    risk_level = "medium"
    read_write = "write"
    rollback_capable = False
    side_effect = True
    approval_required = True

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        user = args.get("user")
        dry_run = args.get("dry_run", False)
        if dry_run:
            return ToolResult(success=True, data={"dry_run": True,
                "tokens_issued": len(ctx.state.get("active_sessions", {}).get(user, []))})
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved")
        _record(ctx.state, "rotated_credentials", user)
        ctx.state.get("active_sessions", {}).pop(user, None)
        return ToolResult(success=True, data={"rotated": True, "user": user})


class BlockIOCTool(Tool):
    name = "block_ioc"
    description = "Block an IOC (IP/domain/URL) at the firewall / DNS sinkhole."
    permissions = [WRITE_RESPONSE]
    risk_level = "low"
    read_write = "write"
    rollback_capable = True
    side_effect = True
    approval_required = True

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        ioc = args.get("ioc")
        if args.get("dry_run"):
            return ToolResult(success=True, data={"dry_run": True, "would_block": ioc})
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved")
        _record(ctx.state, "blocked_iocs", ioc)
        return ToolResult(success=True, data={"blocked": ioc})


class DeploySigmaRuleTool(Tool):
    name = "deploy_sigma"
    description = "Validate and deploy a Sigma detection rule."
    permissions = [WRITE_DETECTION]
    risk_level = "low"
    read_write = "write"
    rollback_capable = True
    side_effect = True
    approval_required = True

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        rule = args.get("rule")
        if not rule:
            return ToolResult(success=False, error="missing_rule")
        if isinstance(rule, str):
            import yaml  # PyYAML is a pySigma dependency.
            try:
                rule = yaml.safe_load(rule)
            except yaml.YAMLError as exc:
                return ToolResult(success=False, error=f"invalid_sigma_rule: {exc}")
        if not isinstance(rule, dict) or not rule.get("title") \
                or not rule.get("logsource") or not rule.get("detection"):
            return ToolResult(success=False, error="invalid_sigma_rule")
        # Parse with pySigma for real: structural key checks alone would
        # accept rules that no Sigma backend can load.
        try:
            from sigma.rule import SigmaRule
            SigmaRule.from_dict(rule)
        except ImportError:  # pragma: no cover - pysigma is a hard dependency
            pass
        except Exception as exc:
            return ToolResult(success=False, error=f"invalid_sigma_rule: {exc}")
        if args.get("dry_run"):
            return ToolResult(success=True, data={"dry_run": True, "valid": True,
                                                  "title": rule["title"]})
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved")
        deployed = dict(ctx.state.get("deployed_sigma_rules") or {})
        ctx.state["deployed_sigma_rules"] = deployed
        deployed[rule["title"]] = rule
        return ToolResult(success=True, data={"deployed": rule["title"]})


class DeployYARARuleTool(Tool):
    name = "deploy_yara"
    description = "Validate and deploy a YARA rule for file/memory scanning."
    permissions = [WRITE_DETECTION]
    risk_level = "low"
    read_write = "write"
    rollback_capable = True
    side_effect = True
    approval_required = True

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        rule = args.get("rule")
        if not isinstance(rule, str) or "rule" not in rule:
            return ToolResult(success=False, error="invalid_yara_rule")
        # Compile for real: a rule that does not compile must never deploy.
        try:
            import yara
            compiled = yara.compile(source=rule)
            names = [r.identifier for r in compiled]
        except ImportError:  # pragma: no cover - yara-python is a hard dependency
            import re
            names = re.findall(r"rule\s+(\w+)", rule)
        except Exception as exc:
            return ToolResult(success=False, error=f"invalid_yara_rule: {exc}")
        if args.get("dry_run"):
            return ToolResult(success=True, data={"dry_run": True, "valid": True,
                                                  "rules": names})
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved")
        deployed = dict(ctx.state.get("deployed_yara_rules") or {})
        ctx.state["deployed_yara_rules"] = deployed
        name = names[0] if names else f"yara_{len(deployed)}"
        deployed[name] = rule
        return ToolResult(success=True, data={"deployed": name})


class PLCControlActionTool(Tool):
    """Deliberately high-risk. By default the policy engine refuses to
    execute this autonomously. Available in the cyber range for evaluation."""
    name = "plc_control_action"
    description = "Issue a control command to a PLC. SAFETY-CRITICAL."
    # Must match the policy engine's map (WRITE_OT).
    permissions = [WRITE_OT]
    risk_level = "prohibited"
    read_write = "write"
    rollback_capable = False
    side_effect = True
    approval_required = True
    supported_environments = ["cyber_range"]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        # risk_level == "prohibited" means the registry refuses this tool
        # before execute() is reached; this only matters if that guard is
        # ever bypassed by calling execute() directly.
        if _not_authorized(ctx):
            return ToolResult(success=False, error="not_approved",
                data={"reason": "PLC control commands are prohibited for autonomous execution (§133)"})
        plc = args.get("plc")
        cmd = args.get("command")
        # Cyber range only: apply to simulated process.
        sim = dict(ctx.state.get("plc_state") or {})
        sim[plc] = {"command": cmd, "ts": args.get("ts")}
        ctx.state["plc_state"] = sim
        return ToolResult(success=True, data={"plc": plc, "command": cmd})


for _t in (
    IsolateEndpointTool, DisableAccountTool, RotateCredentialsTool,
    BlockIOCTool, DeploySigmaRuleTool, DeployYARARuleTool,
    PLCControlActionTool,
):
    register(_t())


def verify_effect(tool_name: str, args: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Post-action verification (§38): re-check the world after an action.

    Returns {"verified": bool | None, "checks": [...]}. `None` means the
    effect cannot be verified from the available state, which is reported
    honestly rather than assumed successful.
    """
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "passed": ok, "detail": detail})

    if tool_name == "isolate_endpoint":
        host = args.get("host")
        check("host_isolated", host in (state.get("isolated_hosts") or []),
              f"{host} present in isolated host list")
    elif tool_name in {"disable_account", "rotate_credentials"}:
        user = args.get("user")
        key = "disabled_accounts" if tool_name == "disable_account" else "rotated_credentials"
        check("account_actioned", user in (state.get(key) or []), f"{user} recorded in {key}")
        sessions = (state.get("active_sessions") or {}).get(user, [])
        check("no_active_sessions", not sessions,
              f"{len(sessions)} active session(s) remain for {user}")
    elif tool_name == "block_ioc":
        ioc = args.get("ioc")
        check("ioc_blocked", ioc in (state.get("blocked_iocs") or []), f"{ioc} on block list")
    elif tool_name == "deploy_sigma":
        title = (args.get("rule") or {}).get("title") if isinstance(args.get("rule"), dict) else None
        deployed = state.get("deployed_sigma_rules") or {}
        check("rule_deployed", bool(deployed) if title is None else title in deployed,
              "Sigma rule present in deployed set")
    elif tool_name == "deploy_yara":
        check("rule_deployed", bool(state.get("deployed_yara_rules")), "YARA rule present in deployed set")
    else:
        return {"verified": None, "checks": [], "reason": f"no verifier for {tool_name}"}
    return {"verified": all(c["passed"] for c in checks), "checks": checks}
