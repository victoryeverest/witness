"""Tool registry (§42).

Every tool declares:
- name, description
- input/output schema
- required permissions
- risk level
- read/write classification
- rollback capability
- supported environments

Tools are the ONLY way the agent can interact with the world (§39). The
LLM cannot bypass the registry; the policy engine sits between agent and
tool execution.
"""
from __future__ import annotations

import abc
import time
import uuid
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ToolExecution
from ..schemas import RiskLevel
from ..utils.time import utc_now


Permission = str  # e.g. "READ_TELEMETRY", "CONTAINMENT", "OT_WRITE"

READ_TELEMETRY = "READ_TELEMETRY"
READ_DFIR = "READ_DFIR"
READ_OT = "READ_OT"
WRITE_CONTAINMENT = "WRITE_CONTAINMENT"
WRITE_DETECTION = "WRITE_DETECTION"
WRITE_OT = "WRITE_OT"
WRITE_RESPONSE = "WRITE_RESPONSE"
MEMORY_ACQUIRE = "MEMORY_ACQUIRE"


from pydantic import BaseModel as _BM  # noqa: E402


class ToolContext(_BM):
    """Context passed to every tool invocation."""
    investigation_id: str
    actor: str = "agent"
    state: dict[str, Any] = {}
    # AsyncSession is not strongly typed here to avoid a circular import.
    session: Optional[Any] = None
    # Set ONLY by the policy layer's action executor after it has verified
    # that the Action row is fully approved. Tool arguments can never grant
    # authorization: arguments are authored by agents (and, with an LLM
    # configured, by a model reading attacker-influenced telemetry).
    authorized_action_id: Optional[str] = None

    @property
    def environment(self) -> str:
        """`cyber_range` when operating on synthetic scenario data."""
        return "cyber_range" if self.state.get("synthetic", False) else "production"


class ToolResult(_BM):
    success: bool = True
    data: dict[str, Any] = {}
    error: Optional[str] = None
    evidence: list[dict[str, Any]] = []  # evidence items to ingest
    timeline_events: list[dict[str, Any]] = []  # timeline events to add
    latency_ms: int = 0


class Tool(abc.ABC):
    name: str = ""
    description: str = ""
    input_schema: dict[str, Any] = {}
    output_schema: dict[str, Any] = {}
    permissions: list[Permission] = []
    risk_level: RiskLevel = "low"
    read_write: str = "read"  # "read" | "write"
    rollback_capable: bool = False
    supported_environments: list[str] = ["cyber_range", "production"]
    side_effect: bool = False
    approval_required: bool = False

    @abc.abstractmethod
    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Execute the tool. Pure functions for read tools; for write tools,
        the implementation must record enough state to roll back if supported."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "permissions": self.permissions,
            "risk_level": self.risk_level,
            "read_write": self.read_write,
            "rollback_capable": self.rollback_capable,
            "side_effect": self.side_effect,
            "approval_required": self.approval_required,
            "supported_environments": self.supported_environments,
        }


_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> None:
    if not tool.name:
        raise ValueError("Tool name is required")
    _REGISTRY[tool.name] = tool


def get_tool(name: str) -> Optional[Tool]:
    return _REGISTRY.get(name)


def list_tools() -> list[Tool]:
    return list(_REGISTRY.values())


def authorization_error(tool: Tool, args: dict[str, Any], ctx: ToolContext) -> Optional[str]:
    """Registry-level guard applied to every tool call, whoever the caller is.

    Returns an error code when the call must not run:
    - `prohibited_by_policy`: the tool's risk level is `prohibited` (§133).
    - `unsupported_environment`: e.g. a cyber-range-only tool in production.
    - `approval_required`: a side-effecting call (anything but a dry run)
      without an executor-verified approved Action.
    """
    if tool.risk_level == "prohibited":
        return "prohibited_by_policy"
    if ctx.environment not in tool.supported_environments:
        return "unsupported_environment"
    needs_authorization = tool.read_write == "write" or tool.approval_required
    if needs_authorization and not args.get("dry_run") and not ctx.authorized_action_id:
        return "approval_required"
    return None


async def execute_tool(session: AsyncSession, name: str,
                       args: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute a tool by name, recording the execution in the audit trail."""
    tool = get_tool(name)
    if not tool:
        return ToolResult(success=False, error=f"unknown_tool:{name}")
    # An "approved" argument is stripped so that no caller can
    # self-authorize; see ToolContext.authorized_action_id.
    args = {k: v for k, v in args.items() if k != "approved"}
    start = time.perf_counter()
    denial = authorization_error(tool, args, ctx)
    if denial:
        result = ToolResult(success=False, error=denial)
    else:
        try:
            ctx.session = session
            result = await tool.execute(args, ctx)
            result.latency_ms = int((time.perf_counter() - start) * 1000)
        except Exception as exc:
            result = ToolResult(success=False, error=str(exc),
                               latency_ms=int((time.perf_counter() - start) * 1000))
    # Persist the tool execution record.
    tx = ToolExecution(
        id=f"TX-{uuid.uuid4().hex[:10].upper()}",
        investigationId=ctx.investigation_id,
        toolName=name,
        arguments=args,
        result=result.data if result.success else {"error": result.error},
        success=result.success,
        error=result.error,
        latencyMs=result.latency_ms,
        approved=bool(ctx.authorized_action_id),
        timestamp=utc_now(),
    )
    session.add(tx)
    await session.flush()
    return result
