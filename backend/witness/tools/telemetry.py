"""Telemetry-query tools.

In the cyber-range mode these tools read from the synthetic telemetry
fixtures attached to the active scenario. In production mode, they would
proxy to SIEM/EDR/Zeek/etc. The contract is identical either way: the agent
calls the tool with a typed query, the tool returns normalized evidence.
"""
from __future__ import annotations

from typing import Any

from .base import (
    Tool, ToolResult, ToolContext, register,
    READ_TELEMETRY, READ_OT,
)


def _filter_telemetry(ctx: ToolContext, **filters: Any) -> list[dict[str, Any]]:
    """Pull the active investigation's telemetry fixtures (synthetic data
    attached to the running scenario) and apply simple filters."""
    telemetry: list[dict[str, Any]] = ctx.state.get("telemetry", [])
    results: list[dict[str, Any]] = []
    for t in telemetry:
        if all(t.get(k) == v or v is None for k, v in filters.items()):
            results.append(t)
    return results


class SearchWindowsEventsTool(Tool):
    name = "search_windows_events"
    description = "Query Windows Security / System / Application event log."
    permissions = [READ_TELEMETRY]
    input_schema = {
        "host": "string (optional)",
        "event_id": "int (optional)",
        "user": "string (optional)",
        "start": "ISO-8601 (optional)",
        "end": "ISO-8601 (optional)",
        "limit": "int (default 50)",
    }

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry
                if t.get("source") == "windows_event_log"
                and (args.get("host") is None or t.get("host") == args["host"])
                and (args.get("event_id") is None
                     or t.get("event_id") == args["event_id"])
                and (args.get("user") is None or t.get("user") == args["user"])]
        rows = rows[: args.get("limit", 50)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class SearchSysmonTool(Tool):
    name = "search_sysmon"
    description = "Query Sysmon EID 1 (process), 3 (network), 11 (file), 13 (registry)."
    permissions = [READ_TELEMETRY]
    input_schema = {
        "host": "string",
        "event_id": "int",
        "image": "string (optional, contains-match)",
        "user": "string (optional)",
        "limit": "int (default 50)",
    }

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = []
        for t in telemetry:
            if t.get("source") != "sysmon":
                continue
            if args.get("host") and t.get("host") != args["host"]:
                continue
            if args.get("event_id") and t.get("event_id") != args["event_id"]:
                continue
            if args.get("user") and t.get("user") != args["user"]:
                continue
            if args.get("image"):
                img = t.get("image", "")
                if args["image"] not in img:
                    continue
            rows.append(t)
        rows = rows[: args.get("limit", 50)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class QueryZeekTool(Tool):
    name = "query_zeek"
    description = "Query Zeek connection/DNS/HTTP/TLS logs."
    permissions = [READ_TELEMETRY]
    input_schema = {
        "log_type": "string (conn|dns|http|ssl|files)",
        "src_ip": "string (optional)",
        "dst_ip": "string (optional)",
        "dst_port": "int (optional)",
        "limit": "int (default 100)",
    }

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = []
        for t in telemetry:
            if t.get("source") != "zeek":
                continue
            if args.get("log_type") and t.get("log_type") != args["log_type"]:
                continue
            if args.get("src_ip") and t.get("src_ip") != args["src_ip"]:
                continue
            if args.get("dst_ip") and t.get("dst_ip") != args["dst_ip"]:
                continue
            if args.get("dst_port") and t.get("dst_port") != args["dst_port"]:
                continue
            rows.append(t)
        rows = rows[: args.get("limit", 100)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class QueryDNSTool(Tool):
    name = "query_dns"
    description = "Query DNS resolution logs."
    permissions = [READ_TELEMETRY]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry if t.get("source") == "dns"]
        if args.get("query"):
            rows = [t for t in rows if args["query"] in t.get("query", "")]
        if args.get("src_ip"):
            rows = [t for t in rows if t.get("src_ip") == args["src_ip"]]
        rows = rows[: args.get("limit", 100)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class SearchEDRTool(Tool):
    name = "search_edr"
    description = "Query EDR telemetry (process, network, file, registry, memory)."
    permissions = [READ_TELEMETRY]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry if t.get("source") == "edr"]
        if args.get("host"):
            rows = [t for t in rows if t.get("host") == args["host"]]
        if args.get("process"):
            rows = [t for t in rows if args["process"] in t.get("image", "")]
        rows = rows[: args.get("limit", 100)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class QueryCloudAuditTool(Tool):
    name = "query_cloud_audit"
    description = "Query cloud provider audit logs (AWS CloudTrail, Azure Activity, GCP Audit)."
    permissions = [READ_TELEMETRY]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry if t.get("source") == "cloud_audit"]
        if args.get("event_source"):
            rows = [t for t in rows if args["event_source"] in t.get("event_source", "")]
        if args.get("user"):
            rows = [t for t in rows if t.get("user") == args["user"]]
        rows = rows[: args.get("limit", 100)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class QueryOTProtocolTool(Tool):
    name = "query_ot_protocol"
    description = "Query industrial-protocol telemetry (Modbus, DNP3, OPC UA, S7, IEC104, EtherNet/IP)."
    permissions = [READ_OT]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry if t.get("source", "").startswith("ot:")
                or t.get("source") == "industrial_protocol"]
        if args.get("protocol"):
            rows = [t for t in rows if t.get("protocol") == args["protocol"]]
        if args.get("src_device"):
            rows = [t for t in rows if t.get("src_device") == args["src_device"]]
        if args.get("dst_device"):
            rows = [t for t in rows if t.get("dst_device") == args["dst_device"]]
        if args.get("function"):
            rows = [t for t in rows if t.get("function") == args["function"]]
        rows = rows[: args.get("limit", 200)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class QueryProcessVariablesTool(Tool):
    name = "query_process_variables"
    description = "Query OT process variable telemetry (setpoints, sensors, alarms)."
    permissions = [READ_OT]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        telemetry = ctx.state.get("telemetry", [])
        rows = [t for t in telemetry if t.get("source") == "process_variable"]
        if args.get("asset"):
            rows = [t for t in rows if t.get("asset") == args["asset"]]
        rows = rows[: args.get("limit", 200)]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class SearchLogSourceTool(Tool):
    """Read-only search over log sources that have no dedicated connector:
    email gateway, VPN concentrator, alarm management, maintenance and
    change-management systems. Without it, the agents could not see the
    initial-access, remote-access or safety-alarm stages at all."""
    name = "search_log_source"
    description = ("Search a named log source (email_gateway, vpn_log, alarm_system, "
                   "maintenance_log, change_management) with optional field filters.")
    permissions = [READ_TELEMETRY]
    input_schema = {"source": "string", "filters": "object (optional exact-match fields)",
                    "limit": "int"}
    ALLOWED_SOURCES = frozenset({"email_gateway", "vpn_log", "alarm_system",
                                 "maintenance_log", "change_management"})

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        source = args.get("source")
        if source not in self.ALLOWED_SOURCES:
            return ToolResult(success=False, error=f"unknown_log_source:{source}")
        filters = args.get("filters") or {}
        rows = [t for t in ctx.state.get("telemetry", [])
                if t.get("source") == source
                and all((t.get("normalized_data") or {}).get(k, t.get(k)) == v
                        for k, v in filters.items())]
        rows = rows[: int(args.get("limit", 200))]
        return ToolResult(success=True, data={"events": rows, "count": len(rows)})


class SearchThreatIntelTool(Tool):
    name = "search_threat_intel"
    description = "Query local threat intelligence (IOC IP/domain/URL/hash, ATT&CK, CVE)."
    permissions = [READ_TELEMETRY]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        ti: list[dict[str, Any]] = ctx.state.get("threat_intel", [])
        indicator = args.get("indicator")
        if indicator:
            rows = [t for t in ti if t.get("indicator") == indicator
                    or indicator in (t.get("aliases") or [])]
        else:
            rows = list(ti)
        return ToolResult(success=True, data={"items": rows, "count": len(rows)})


class GetAssetContextTool(Tool):
    name = "get_asset_context"
    description = "Get the asset metadata (zone, criticality, owner, OT type, dependencies) for a given asset ID or hostname."
    permissions = [READ_TELEMETRY]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        assets: dict[str, Any] = ctx.state.get("assets", {})
        asset_id = args.get("asset_id")
        hostname = args.get("hostname")
        result: dict[str, Any] | None = None
        if asset_id and asset_id in assets:
            result = assets[asset_id]
        elif hostname:
            for a in assets.values():
                if a.get("hostname") == hostname or a.get("name") == hostname:
                    result = a
                    break
        if not result:
            return ToolResult(success=False, error="asset_not_found")
        return ToolResult(success=True, data={"asset": result})


# Register all read tools.
for _t in (
    SearchLogSourceTool,
    SearchWindowsEventsTool, SearchSysmonTool, QueryZeekTool, QueryDNSTool,
    SearchEDRTool, QueryCloudAuditTool, QueryOTProtocolTool,
    QueryProcessVariablesTool, SearchThreatIntelTool, GetAssetContextTool,
):
    register(_t())
