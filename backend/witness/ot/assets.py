"""OT asset model (§22, §23).

OT assets are first-class. They share the Asset table with IT assets but
have OT-specific extensions. We use a static registry of OT asset prototypes
for the cyber range.
"""
from __future__ import annotations

from typing import Any, Optional

from ..schemas import AssetDTO


def make_ot_asset(*, id: str, name: str, ot_type: str,
                  zone: str, hostname: Optional[str] = None,
                  ip: Optional[str] = None,
                  criticality: str = "high",
                  safety_classification: Optional[str] = None,
                  dependencies: Optional[dict[str, Any]] = None,
                  physical_process: Optional[str] = None) -> AssetDTO:
    """Construct an OT asset DTO with sensible defaults."""
    kind_map = {
        "plc": "plc", "rtu": "rtu", "ied": "rtu", "hmi": "hmi",
        "scada": "scada_server", "scada_server": "scada_server",
        "dcs": "controller", "ews": "engineering_workstation",
        "engineering_workstation": "engineering_workstation",
        "historian": "historian", "safety": "safety_system",
        "industrial_switch": "network_zone",
    }
    kind = kind_map.get(ot_type, ot_type)
    return AssetDTO(
        id=id, name=name, kind=kind, hostname=hostname, ip_address=ip,
        zone=zone, criticality=criticality,  # type: ignore
        safety_classification=safety_classification or "unknown",
        maintenance_state="normal",
        dependencies=dependencies or {},
        attributes={"ot_type": ot_type, "physical_process": physical_process},
    )


def build_enterprise_ot_assets() -> dict[str, AssetDTO]:
    """Build the cyber-range OT asset set."""
    assets: dict[str, AssetDTO] = {}

    # Engineering workstations.
    assets["EWS-01"] = make_ot_asset(
        id="EWS-01", name="Engineering Workstation 01",
        ot_type="engineering_workstation", zone="supervisory",
        hostname="EWS-01", ip="10.20.1.10", criticality="safety_critical",
        safety_classification="critical",
        dependencies={
            "communicates_with": ["PLC-01", "PLC-02", "PLC-07"],
            "monitored_by": ["HMI-01"],
            "controls": ["PLC-01", "PLC-02", "PLC-07"],
            "controls_safety_system": False,
            "is_safety_system": False,
        },
        physical_process="Reactor-A",
    )

    # SCADA server.
    assets["SCADA-01"] = make_ot_asset(
        id="SCADA-01", name="SCADA Server 01",
        ot_type="scada_server", zone="supervisory",
        hostname="SCADA-01", ip="10.20.1.20", criticality="safety_critical",
        safety_classification="critical",
        dependencies={
            "communicates_with": ["PLC-01", "PLC-02", "PLC-07"],
            "monitored_by": ["HMI-01"],
            "controls": ["PLC-01", "PLC-02", "PLC-07"],
            "controls_safety_system": False,
        },
        physical_process="Reactor-A",
    )

    # HMI.
    assets["HMI-01"] = make_ot_asset(
        id="HMI-01", name="HMI 01", ot_type="hmi", zone="supervisory",
        hostname="HMI-01", ip="10.20.1.30", criticality="high",
        safety_classification="important",
        dependencies={"monitored_by": ["SCADA-01"], "communicates_with": ["PLC-01", "PLC-02"]},
        physical_process="Reactor-A",
    )

    # Historian.
    assets["HIST-01"] = make_ot_asset(
        id="HIST-01", name="Historian 01", ot_type="historian", zone="supervisory",
        hostname="HIST-01", ip="10.20.1.40", criticality="high",
        dependencies={"communicates_with": ["SCADA-01", "PLC-01", "PLC-02", "PLC-07"]},
    )

    # PLCs.
    for i, name, proc, dep in (
        (1, "PLC-01", "Reactor-A", True),
        (2, "PLC-02", "Reactor-B", True),
        (7, "PLC-07", "Reactor-G", False),  # not safety-critical by default
    ):
        assets[name] = make_ot_asset(
            id=name, name=f"PLC {name}", ot_type="plc", zone="control",
            hostname=name, ip=f"10.30.1.{i}", criticality="safety_critical" if dep else "high",
            safety_classification="critical" if dep else "important",
            dependencies={
                "controls_safety_system": dep,
                "monitored_by": ["SCADA-01", "HMI-01"],
                "controlled_by": ["EWS-01"],
                "physical_process": proc,
            },
            physical_process=proc,
        )

    return assets
