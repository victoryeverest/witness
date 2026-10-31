"""DFIR tools (§32).

Forensic adapters for Velociraptor, osquery, Volatility, Plaso, YARA,
filesystem/registry artifacts. In the cyber range these read from the
synthetic evidence fixtures; in production they would proxy to real DFIR
endpoints.
"""
from __future__ import annotations

from typing import Any

from ..utils.time import utc_now
from .base import Tool, ToolContext, ToolResult, register, READ_DFIR, MEMORY_ACQUIRE


class FilesystemMetadataTool(Tool):
    name = "filesystem_metadata"
    description = "Query filesystem metadata (MFT entries, MACB times, owner)."
    permissions = [READ_DFIR]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        artifacts: list[dict[str, Any]] = ctx.state.get("filesystem_artifacts", [])
        if args.get("host"):
            artifacts = [a for a in artifacts if a.get("host") == args["host"]]
        if args.get("path"):
            artifacts = [a for a in artifacts if args["path"] in a.get("path", "")]
        return ToolResult(success=True, data={"entries": artifacts, "count": len(artifacts)})


class RegistryArtifactsTool(Tool):
    name = "registry_artifacts"
    description = "Query Windows registry artifacts (Run keys, services, scheduled tasks, Amcache, Shimcache)."
    permissions = [READ_DFIR]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        artifacts: list[dict[str, Any]] = ctx.state.get("registry_artifacts", [])
        if args.get("host"):
            artifacts = [a for a in artifacts if a.get("host") == args["host"]]
        if args.get("hive"):
            artifacts = [a for a in artifacts if a.get("hive") == args["hive"]]
        return ToolResult(success=True, data={"entries": artifacts, "count": len(artifacts)})


class PrefetchTool(Tool):
    name = "prefetch"
    description = "Read Windows Prefetch entries (process execution history)."
    permissions = [READ_DFIR]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        artifacts: list[dict[str, Any]] = ctx.state.get("prefetch", [])
        if args.get("host"):
            artifacts = [a for a in artifacts if a.get("host") == args["host"]]
        if args.get("image"):
            artifacts = [a for a in artifacts if args["image"] in a.get("image", "")]
        return ToolResult(success=True, data={"entries": artifacts, "count": len(artifacts)})


class AmcacheTool(Tool):
    name = "amcache"
    description = "Read Windows Amcache.hve (program execution history)."
    permissions = [READ_DFIR]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        artifacts: list[dict[str, Any]] = ctx.state.get("amcache", [])
        if args.get("host"):
            artifacts = [a for a in artifacts if a.get("host") == args["host"]]
        return ToolResult(success=True, data={"entries": artifacts, "count": len(artifacts)})


class MemoryImageTool(Tool):
    name = "memory_acquire"
    description = "Acquire a memory image from a host. Requires MEMORY_ACQUIRE permission and approval."
    permissions = [MEMORY_ACQUIRE]
    risk_level = "medium"
    read_write = "write"
    side_effect = True
    # Matches the policy engine (approval: True). Acquisition is heavy, can
    # disturb a live host, and is not something an agent may start on its own.
    approval_required = True
    supported_environments = ["cyber_range", "production"]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        # In the cyber range, mark whether the scenario provides a memory image.
        host = args.get("host")
        available: dict[str, bool] = ctx.state.get("memory_available", {})
        if args.get("dry_run"):
            return ToolResult(success=True, data={
                "dry_run": True, "host": host,
                "image_available": bool(available.get(host))})
        if available.get(host):
            # Cyber range: the image is simulated, and says so.
            return ToolResult(
                success=True,
                data={"host": host, "image_path": f"/range/memory/{host}.img",
                      "synthetic": True, "acquired_at": utc_now().isoformat()},
                evidence=[{
                    "source": "memory_image",
                    "source_type": "memory",
                    "host": host,
                    "normalized_data": {
                        "domain": "dfir",
                        "event_kind": "memory_image",
                        "path": f"/range/memory/{host}.img",
                    },
                }],
            )
        return ToolResult(success=False, error="memory_unavailable_for_host")


class PlasoTimelineTool(Tool):
    name = "plaso_timeline"
    description = "Run Plaso over a filesystem image to extract a forensic timeline."
    permissions = [READ_DFIR]

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        # In the cyber range we just expose the pre-built supertimeline.
        tl: list[dict[str, Any]] = ctx.state.get("plaso_timeline", [])
        if args.get("host"):
            tl = [e for e in tl if e.get("host") == args["host"]]
        return ToolResult(success=True, data={"timeline": tl, "count": len(tl)})


for _t in (
    FilesystemMetadataTool, RegistryArtifactsTool, PrefetchTool,
    AmcacheTool, MemoryImageTool, PlasoTimelineTool,
):
    register(_t())
