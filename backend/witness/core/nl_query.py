"""WITNESS natural-language → query translator (§47, §107).

Takes a free-text objective like "Find unusual authentication into engineering
workstations outside maintenance hours" and produces a structured query:
- data sources to query
- time window
- filters
- expected result kind

This is a deterministic rule-based translator. For production, plug in an LLM
to handle arbitrary phrasing — the interface stays the same.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


# Domain-specific keywords → data sources.
KEYWORD_TO_SOURCE: dict[str, str] = {
    "authentication": "windows_event_log",
    "auth": "windows_event_log",
    "logon": "windows_event_log",
    "login": "windows_event_log",
    "powershell": "sysmon",
    "process": "sysmon",
    "command": "sysmon",
    "script": "sysmon",
    "smb": "zeek",
    "network": "zeek",
    "dns": "zeek",
    "http": "zeek",
    "tls": "zeek",
    "flow": "zeek",
    "lateral movement": "zeek",
    "lateral": "zeek",
    "cloud": "cloud_audit",
    "aws": "cloud_audit",
    "azure": "cloud_audit",
    "gcp": "cloud_audit",
    "iam": "cloud_audit",
    "edr": "edr",
    "endpoint": "sysmon",
    "file": "filesystem_metadata",
    "registry": "registry_artifacts",
    "memory": "memory_acquire",
    "plc": "ot_protocol",
    "modbus": "ot_protocol",
    "scada": "ot_protocol",
    "industrial": "ot_protocol",
    "alarm": "process_variables",
    "process_variable": "process_variables",
    "engineer": "sysmon",  # engineering workstation activity → endpoint
}

# Attack-pattern keywords → ATT&CK techniques.
KEYWORD_TO_TECHNIQUE: dict[str, list[str]] = {
    "powershell": ["T1059.001"],
    "encoded command": ["T1059.001"],
    "lateral movement": ["T1021.002"],
    "smb": ["T1021.002"],
    "credential": ["T1003.001", "T1078"],
    "lsass": ["T1003.001"],
    "phishing": ["T1566.001"],
    "brute force": ["T1110"],
    "persistence": ["T1547.001"],
    "registry run": ["T1547.001"],
    "scheduled task": ["T1053.005"],
    "c2": ["T1071.001"],
    "beacon": ["T1071.001"],
    "dns nrd": ["T1071.004"],
    "newly-registered domain": ["T1071.004"],
    "modbus write": ["T0855", "T0836"],
    "plc write": ["T0855", "T0836"],
    "process variable": ["T0831"],
    "alarm suppress": ["T0878"],
    "inhibit response": ["T0878", "T0838"],
}

# Time-window keywords.
TIME_KEYWORDS: dict[str, timedelta] = {
    "last hour": timedelta(hours=1),
    "last 24 hours": timedelta(days=1),
    "last day": timedelta(days=1),
    "last week": timedelta(weeks=1),
    "last month": timedelta(days=30),
}


class StructuredQuery(BaseModel):
    """The output of NL→query translation (§107).
    Display the generated query to the analyst before execution."""
    objective: str
    data_sources: list[str] = Field(default_factory=list)
    filters: dict[str, Any] = Field(default_factory=dict)
    time_window_seconds: Optional[int] = None
    expected_result: str = ""
    attack_techniques: list[str] = Field(default_factory=list)
    agent: str = ""  # which specialist agent should handle this
    read_only: bool = True


def translate(objective: str, *, now: Optional[datetime] = None) -> StructuredQuery:
    """Translate a natural-language objective into a StructuredQuery."""
    now = now or datetime.now(timezone.utc)
    obj_lower = objective.lower()
    q = StructuredQuery(objective=objective)

    # Detect data sources.
    for kw, source in KEYWORD_TO_SOURCE.items():
        if kw in obj_lower:
            if source not in q.data_sources:
                q.data_sources.append(source)

    # If nothing matched, default to broad search across all read sources.
    if not q.data_sources:
        q.data_sources = ["search_sysmon", "search_windows_events", "query_zeek"]

    # Detect ATT&CK techniques.
    for kw, techs in KEYWORD_TO_TECHNIQUE.items():
        if kw in obj_lower:
            for t in techs:
                if t not in q.attack_techniques:
                    q.attack_techniques.append(t)

    # Detect time window.
    for kw, delta in TIME_KEYWORDS.items():
        if kw in obj_lower:
            q.time_window_seconds = int(delta.total_seconds())
            break

    # Detect "engineering workstation" specifically.
    if "engineering workstation" in obj_lower or "ews" in obj_lower:
        q.filters["host"] = "EWS-01"
        q.data_sources.append("query_ot_protocol")
        q.agent = "ot_analyst"

    # Detect "plc" specifically.
    if "plc" in obj_lower:
        q.data_sources.append("query_ot_protocol")
        q.data_sources.append("query_process_variables")
        if "plc-07" in obj_lower:
            q.filters["dst_device"] = "PLC-07"
        q.agent = "ot_analyst"

    # Detect "lateral movement" / "smb".
    if "lateral movement" in obj_lower or "smb" in obj_lower:
        q.filters["dst_port"] = 445
        q.agent = "network_analyst"

    # Detect "credential" / "lsass".
    if "credential" in obj_lower or "lsass" in obj_lower:
        q.filters["event_kind"] = "process_access"
        q.agent = "endpoint_analyst"

    # Detect "phishing".
    if "phish" in obj_lower:
        q.filters["event_kind"] = "email_click"
        q.agent = "endpoint_analyst"

    # Detect "brute force".
    if "brute force" in obj_lower:
        q.filters["event_kind"] = "auth_failure"
        q.agent = "identity_analyst"

    # Expected result kind.
    if "investigate" in obj_lower or "discover" in obj_lower:
        q.expected_result = "evidence_with_attack_techniques"
    elif "hunt" in obj_lower:
        q.expected_result = "anomalies_or_ioc_hits"
    elif "show" in obj_lower or "find" in obj_lower:
        q.expected_result = "evidence_rows"
    else:
        q.expected_result = "findings"

    # Read-only is the default — generated queries never modify state.
    q.read_only = True

    # If agent not assigned yet, pick by data source.
    if not q.agent:
        sources_set = set(q.data_sources)
        # Match both bare source names ("sysmon") and tool names
        # ("search_sysmon").
        if (sources_set & {"ot_protocol", "query_ot_protocol", "process_variables",
                             "query_process_variables"}):
            q.agent = "ot_analyst"
        elif (sources_set & {"zeek", "query_zeek", "query_dns"}):
            q.agent = "network_analyst"
        elif (sources_set & {"cloud_audit", "query_cloud_audit"}):
            q.agent = "cloud_analyst"
        elif (sources_set & {"sysmon", "search_sysmon", "search_edr",
                               "filesystem_metadata", "registry_artifacts",
                               "prefetch", "amcache", "memory_acquire",
                               "plaso_timeline"}):
            q.agent = "endpoint_analyst"
        elif (sources_set & {"windows_event_log", "search_windows_events"}):
            q.agent = "identity_analyst"
        else:
            q.agent = "evidence_analyst"

    return q
