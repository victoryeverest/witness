"""Tool registry — imports all tool modules to populate the registry."""
from .base import Tool, ToolContext, ToolResult, register, get_tool, list_tools, execute_tool
from . import telemetry  # noqa: F401  (registers read telemetry tools)
from . import dfir  # noqa: F401  (registers DFIR tools)
from . import actions  # noqa: F401  (registers response action tools)
from . import pcap  # noqa: F401  (registers PCAP investigation tool, §33)

__all__ = [
    "Tool", "ToolContext", "ToolResult", "register", "get_tool",
    "list_tools", "execute_tool",
]
