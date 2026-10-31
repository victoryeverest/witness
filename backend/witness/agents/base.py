"""Agent base class and registry (§14, §15).

Every agent:
- has a name + role
- receives an AgentInput (typed)
- returns an AgentOutput (typed, validated)
- may call tools (only through the tool registry)
- may call the model provider (only through the model router)
- has its actions audited

Agents communicate through schemas, not free-form natural-language chains.
"""
from __future__ import annotations

import abc
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..schemas import (
    AgentInput, AgentOutput, ModelRole,
)
from ..utils.time import utc_now
from ..utils.logging import get_logger


log = get_logger("witness.agents")


_AGENT_REGISTRY: dict[str, type["Agent"]] = {}


def register_agent(cls: type["Agent"]) -> type["Agent"]:
    if not cls.name:
        raise ValueError(f"Agent {cls} has no name")
    _AGENT_REGISTRY[cls.name] = cls
    return cls


def get_agent_class(name: str) -> Optional[type["Agent"]]:
    return _AGENT_REGISTRY.get(name)


def list_agent_names() -> list[str]:
    return sorted(_AGENT_REGISTRY.keys())


class Agent(abc.ABC):
    name: str = ""
    description: str = ""
    default_role: ModelRole = "medium"
    domain: Optional[str] = None

    def __init__(self, session: AsyncSession, ctx_state: Optional[dict[str, Any]] = None):
        self.session = session
        self.ctx_state = ctx_state or {}
        self._inp: Optional[AgentInput] = None

    @abc.abstractmethod
    async def run(self, inp: AgentInput) -> AgentOutput:
        """Execute the agent. MUST return a typed AgentOutput."""
        raise NotImplementedError

    # ---------------- Tool helpers ---------------- #

    async def call_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Convenience for calling a tool from within an agent."""
        from ..tools.base import get_tool, execute_tool, ToolContext
        tool = get_tool(tool_name)
        if not tool:
            return {"success": False, "error": f"unknown_tool:{tool_name}"}
        if self._inp is None:
            return {"success": False, "error": "agent_input_not_set"}
        ctx = ToolContext(investigation_id=self._inp.investigation_id,
                          actor=f"agent:{self.name}", state=self.ctx_state)
        result = await execute_tool(self.session, tool_name, args, ctx)
        # Ingest any evidence produced.
        for ev in result.evidence:
            await self._ingest_evidence_from_tool(ev, self._inp.investigation_id)
        return {"success": result.success, "data": result.data, "error": result.error}

    async def propose_action(self, tool_name: str, args: dict[str, Any], *,
                             rationale: str = "") -> Any:
        """Propose a side-effecting action. Agents never execute these.

        The proposal is evaluated by the policy engine (as an agent acting
        with security-engineer privileges), escalated by the OT safety engine
        when the target is an OT asset, and recorded as an Action awaiting
        human approval. A dry run is attached when the tool supports one so
        approvers can see the blast radius (§130).
        """
        from ..policy.engine import (
            evaluate_tool_policy, escalate_with_ot_assessment, record_action,
        )
        from ..ot.safety import classify_ot_action, OT_ASSET_KINDS
        if self._inp is None:
            raise RuntimeError("agent_input_not_set")
        decision = evaluate_tool_policy(tool_name, args, user_role="security_engineer")
        target = args.get("host") or args.get("plc")
        asset = next((a for aid, a in (self.ctx_state.get("assets") or {}).items()
                      if target and (aid == target or a.get("hostname") == target)), None)
        if asset and asset.get("kind") in OT_ASSET_KINDS:
            decision = escalate_with_ot_assessment(
                decision, classify_ot_action(tool_name, args, asset))
        if decision.decision == "require_approval":
            preview = await self.call_tool(tool_name, {**args, "dry_run": True})
            if preview.get("success"):
                decision.blast_radius = {**decision.blast_radius,
                                         "dry_run": preview.get("data", {})}
        return await record_action(
            self.session, investigation_id=self._inp.investigation_id,
            tool_name=tool_name, arguments=args, decision=decision,
            proposed_by=f"agent:{self.name}", rationale=rationale)

    async def _ingest_evidence_from_tool(self, ev: dict[str, Any],
                                          investigation_id: str) -> str:
        from ..core.evidence import add_evidence
        normalized = ev.get("normalized_data", {})
        ev_obj = await add_evidence(
            self.session,
            investigation_id,
            source=ev["source"],
            source_type=ev["source_type"],
            timestamp=normalized.get("timestamp") or utc_now(),
            host=ev.get("host") or normalized.get("host"),
            asset_id=normalized.get("asset_id"),
            user=normalized.get("user"),
            process=normalized.get("process"),
            normalized_data=normalized,
            synthetic=self.ctx_state.get("synthetic", True),
            dedupe=True,
        )
        return ev_obj.id

    # ---------------- Model helper ---------------- #

    async def call_model(self, system_prompt: str, user_prompt: str,
                         *, role: Optional[ModelRole] = None,
                         prefer_json: bool = False) -> str:
        from ..schemas import ModelRequest
        from ..models_layer.router import route
        role = role or self.default_role
        req = ModelRequest(role=role, system_prompt=system_prompt,
                            user_prompt=user_prompt, prefer_json=prefer_json)
        # Record telemetry.
        resp = await route(req)
        # We do not record ModelExecution here to keep the helper simple; the
        # runtime wraps each agent invocation and records at that level.
        return resp.text

    # ---------------- Output builder ---------------- #

    def _output(self, inp: AgentInput, **fields: Any) -> AgentOutput:
        return AgentOutput(
            investigation_id=inp.investigation_id,
            task_id=inp.task_id,
            agent_name=self.name,
            **fields,
        )
