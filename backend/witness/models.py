"""WITNESS ORM models — full data model per spec §66.

The model is intentionally normalized: authoritative state lives in the
relational DB, while the evidence graph is a derived view (§10). This avoids
duplicating state across stores while still exposing graph relationships.

Naming convention: snake_case everywhere, ISO-8601 timestamps with UTC
default, cuid-style string primary keys for portability.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text, JSON, Index,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UTCDateTime(TypeDecorator):
    """A DateTime that always round-trips as timezone-aware UTC.

    SQLite has no timezone storage, so a plain ``DateTime`` column hands back
    *naive* datetimes after a reload. That silently broke anything comparing
    or hashing timestamps — most importantly evidence integrity verification,
    whose content hash includes ``timestamp.isoformat()``: the stored hash was
    computed over ``...+00:00`` and the reloaded value serialized without it,
    so every reloaded evidence row failed verification. All timestamps in
    WITNESS are UTC, so we normalize on the way in and re-attach UTC on the
    way out. Works identically on PostgreSQL.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Identity & RBAC
# --------------------------------------------------------------------------- #

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, default="analyst")
    # Roles per §68: viewer, analyst, senior_analyst, responder, ot_analyst,
    # ot_engineer, security_engineer, admin, approver, auditor.
    passwordHash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Asset model (IT + OT unified)
# --------------------------------------------------------------------------- #

class Asset(Base):
    """Unified asset record. OT assets share this table and additionally have
    a row in `OTAsset` for OT-specific attributes."""
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    # kind ∈ {user, account, host, process, file, hash, ip, domain, url, port,
    #         connection, event, service, task, registry_key, credential,
    #         application, container, cloud_resource, plc, rtu, hmi, ied,
    #         scada_server, ews, historian, controller, sensor, actuator,
    #         network_zone, process_variable, control_command}
    hostname: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ipAddress: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    zone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    criticality: Mapped[str] = mapped_column(String, default="medium")
    # criticality ∈ {low, medium, high, safety_critical}
    owner: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    businessFunction: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    safetyClassification: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    maintenanceState: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    redundancy: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    dependencies: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=dict)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class AssetRelationship(Base):
    """Static, known relationships between assets (e.g. PLC-07 controls
    Reactor-Temp-Loop). Distinct from EvidenceRelationship which is observed."""
    __tablename__ = "asset_relationships"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    srcAssetId: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=False)
    dstAssetId: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=False)
    relation: Mapped[str] = mapped_column(String, nullable=False)
    # relation ∈ {controls, monitored_by, depends_on, in_zone, redundant_with,
    #             configured_by, communicates_with, authenticated_to, ...}
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class OTAsset(Base):
    """OT-specific extension of an Asset."""
    __tablename__ = "ot_assets"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    assetId: Mapped[str] = mapped_column(ForeignKey("assets.id"), nullable=False)
    otType: Mapped[str] = mapped_column(String, nullable=False)
    # otType ∈ {plc, rtu, ied, hmi, scada, dcs, ews, historian, safety_system,
    #           industrial_switch, industrial_firewall, sensor, actuator,
    #           process, control_loop}
    protocol: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    firmware: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    physicalProcess: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    safetyImpact: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # safetyImpact ∈ {none, minor, serious, catastrophic, unknown}
    processVariables: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=dict)


# --------------------------------------------------------------------------- #
# Incidents & investigations
# --------------------------------------------------------------------------- #

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="medium")
    # severity ∈ {info, low, medium, high, critical}
    status: Mapped[str] = mapped_column(String, default="open")
    # status ∈ {open, investigating, contained, closed, false_positive, escalated}
    scope: Mapped[str] = mapped_column(String, default="enterprise")
    # scope ∈ {enterprise, ot, hybrid_it_ot, cloud, identity, network}
    campaignId: Mapped[Optional[str]] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    updatedAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow, onupdate=_utcnow)
    # Confidence decomposition per §35.
    detectionConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    attributionConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    timelineConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    techniqueConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    impactConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    remediationConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidenceCoverage: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class Campaign(Base):
    """Multi-incident correlation (§113)."""
    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    sharedIndicators: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sharedIdentities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sharedTTPs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    incidentId: Mapped[Optional[str]] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    objective: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active")
    # status ∈ {active, paused, completed, cancelled, awaiting_approval}
    mode: Mapped[str] = mapped_column(String, default="alert")
    # mode ∈ {alert, hunt, post_action_verify}
    iteration: Mapped[int] = mapped_column(Integer, default=0)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    updatedAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow, onupdate=_utcnow)
    startedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    completedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Free-form state blob used by the runtime for resumability (§128).
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Per-domain coverage (§36): {identity, endpoint, network, cloud, app,
    # persistence, c2, dfir, ot, process, safety, memory}
    finalConclusion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class InvestigationTask(Base):
    """A unit of work within an investigation. Maps to a single agent call."""
    __tablename__ = "investigation_tasks"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    parentTaskId: Mapped[Optional[str]] = mapped_column(ForeignKey("investigation_tasks.id"), nullable=True)
    agentName: Mapped[str] = mapped_column(String, nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending")
    # status ∈ {pending, running, completed, failed, cancelled, awaiting_approval}
    input_: Mapped[dict[str, Any]] = mapped_column("input", JSON, default=dict)
    output_: Mapped[Optional[dict[str, Any]]] = mapped_column("output", JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidenceRefs: Mapped[list[str]] = mapped_column(JSON, default=list)
    hypothesisRefs: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    riskLevel: Mapped[str] = mapped_column(String, default="low")
    requiresApproval: Mapped[bool] = mapped_column(Boolean, default=False)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    startedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    completedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #

class Evidence(Base):
    """Immutable evidence record (§8). Hash + chain-of-custody for integrity."""
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    # e.g. "windows_event_log", "sysmon", "zeek", "edr", "ot:modbus", "sigma:rule"
    sourceType: Mapped[str] = mapped_column(String, nullable=False)
    # sourceType ∈ {log, pcap, image, memory, registry, file, network, ot,
    #               ti, sigma, yara, suricata, manual, derived}
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    ingestionTime: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    host: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    assetId: Mapped[Optional[str]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    process: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    networkContext: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=dict)
    rawReference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Pointer to the original raw record (file path + offset, log line id, etc.)
    normalizedData: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Canonical normalized event per §18.
    contentHash: Mapped[str] = mapped_column(String, nullable=False)
    prevHash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Chain-of-custody (§8): `sequence` is the 1-based ingestion position
    # within the investigation and `chainHash` = H(previous chainHash |
    # investigation | sequence | contentHash). Altering, deleting or
    # reordering any row breaks every later link.
    sequence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    chainHash: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    integrityStatus: Mapped[str] = mapped_column(String, default="verified")
    # integrityStatus ∈ {verified, suspect, tampered, unknown}
    reliability: Mapped[str] = mapped_column(String, default="high")
    # reliability ∈ {high, medium, low, unknown}
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    collectionMethod: Mapped[str] = mapped_column(String, default="agent_collected")
    chainOfCustody: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    # Flag for cyber-range / simulated evidence (§153, §154).
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class EvidenceRelationship(Base):
    """Observed relationship between two pieces of evidence or between
    evidence and assets. Forms the basis of the evidence graph (§10)."""
    __tablename__ = "evidence_relationships"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    srcEvidenceId: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    dstEvidenceId: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    srcAssetId: Mapped[Optional[str]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    dstAssetId: Mapped[Optional[str]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    relation: Mapped[str] = mapped_column(String, nullable=False)
    # relation ∈ {spawned, executed, connected_to, resolved, downloaded,
    #             created, modified, deleted, persisted_through, accessed,
    #             communicated_with, laterally_moved_to, controlled,
    #             monitored, configured, changed, triggered, observed,
    #             authenticated_to, ...}
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    sourceEvidenceId: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    # The evidence that established this relationship.
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


# --------------------------------------------------------------------------- #
# Hypotheses, Claims, Findings
# --------------------------------------------------------------------------- #

class Hypothesis(Base):
    __tablename__ = "hypotheses"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    priorConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    currentConfidence: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String, default="open")
    # status ∈ {open, probable, confirmed, rejected, superseded, unknown}
    supportEvidenceIds: Mapped[list[str]] = mapped_column(JSON, default=list)
    contradictEvidenceIds: Mapped[list[str]] = mapped_column(JSON, default=list)
    expectedEvidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    missingEvidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    confidenceHistory: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # [{ts, value, delta, reason, evidence_id}]
    evidenceWeights: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    # {evidence_id: {"direction": "support"|"contradict", "weight": float}}.
    # Confidence is recomputed from the prior and this map, so re-observing
    # the same evidence can never inflate it (§6).
    provenance: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    # Who proposed the hypothesis: {"origin": "template"} or {"origin":
    # "model", "model": ..., "execution_id": ..., "rationale": ...,
    # "cited_evidence": [...]}. Model-proposed hypotheses start at the same
    # prior as templates; only deterministic evidence linking moves them.
    parentHypothesisId: Mapped[Optional[str]] = mapped_column(ForeignKey("hypotheses.id"), nullable=True)
    counterHypothesis: Mapped[bool] = mapped_column(Boolean, default=False)
    # Counter-hypotheses are generated by §7.
    attackTechniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    # MITRE ATT&CK technique IDs (T-numbers or ICS T-numbers).
    attackTactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    updatedAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow, onupdate=_utcnow)


class Claim(Base):
    """An AI-generated assertion that must be backed by evidence (§9)."""
    __tablename__ = "claims"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    hypothesisId: Mapped[Optional[str]] = mapped_column(ForeignKey("hypotheses.id"), nullable=True)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, default="unverified")
    # status ∈ {verified, supported, inferred, contested, unverified,
    #           rejected, unknown}
    evidenceRefs: Mapped[list[str]] = mapped_column(JSON, default=list)
    contradictingRefs: Mapped[list[str]] = mapped_column(JSON, default=list)
    claimType: Mapped[str] = mapped_column(String, default="fact")
    # claimType ∈ {fact, inference, hypothesis, assumption, unknown,
    #               recommendation, action}
    requiresEvidence: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class Finding(Base):
    """A consolidated finding derived from one or more claims."""
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, default="medium")
    claimIds: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidenceIds: Mapped[list[str]] = mapped_column(JSON, default=list)
    attackTechniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Timeline
# --------------------------------------------------------------------------- #

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    sourceClockSkewSeconds: Mapped[float] = mapped_column(Float, default=0.0)
    # Detected clock skew vs. canonical clock (§11).
    domain: Mapped[str] = mapped_column(String, nullable=False)
    # domain ∈ {identity, endpoint, network, cloud, application, ot, process}
    eventType: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assetId: Mapped[Optional[str]] = mapped_column(ForeignKey("assets.id"), nullable=True)
    evidenceId: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    assetIds: Mapped[list[str]] = mapped_column(JSON, default=list)
    attackTechniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


# --------------------------------------------------------------------------- #
# Detection / Threat Intel / ATT&CK
# --------------------------------------------------------------------------- #

class DetectionRule(Base):
    """Sigma / YARA / Suricata / custom rule, with provenance."""
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    ruleType: Mapped[str] = mapped_column(String, nullable=False)
    # ruleType ∈ {sigma, yara, suricata, ioc, baseline, custom}
    name: Mapped[str] = mapped_column(String, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # Raw rule text (YAML for Sigma, rule text for YARA, etc.)
    parsed: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String, default="internal")
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    license_: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    contentHash: Mapped[str] = mapped_column(String, nullable=False)
    attackTechniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    deployed: Mapped[bool] = mapped_column(Boolean, default=False)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class ThreatIntel(Base):
    """Local threat intelligence (§20)."""
    __tablename__ = "threat_intel"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    indicatorType: Mapped[str] = mapped_column(String, nullable=False)
    # indicatorType ∈ {ioc_ip, ioc_domain, ioc_url, ioc_hash, ioc_cert,
    #                   malware_family, ttp, cve, cwe, attack, stix}
    indicator: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, default="internal")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    expiresAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    relationship: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    attackTechniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    contentHash: Mapped[str] = mapped_column(String, nullable=False)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Actions, approvals, audit
# --------------------------------------------------------------------------- #

class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    toolName: Mapped[str] = mapped_column(String, nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    riskLevel: Mapped[str] = mapped_column(String, default="low")
    # riskLevel ∈ {low, medium, high, critical, prohibited}
    requiresApproval: Mapped[bool] = mapped_column(Boolean, default=False)
    approvalScope: Mapped[str] = mapped_column(String, default="security")
    # approvalScope ∈ {security, ot_engineering, process_owner, multi}
    status: Mapped[str] = mapped_column(String, default="proposed")
    # status ∈ {proposed, approved, rejected, denied, prohibited, executing,
    #           completed, failed, rolled_back}
    # `denied` (RBAC) and `prohibited` (OT safety) are terminal: such actions
    # can never be approved or executed.
    proposedBy: Mapped[str] = mapped_column(String, default="orchestrator")
    approvedBy: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    blastRadius: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reversibility: Mapped[str] = mapped_column(String, default="reversible")
    # reversibility ∈ {reversible, partially_reversible, irreversible, unknown}
    result: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    verification: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    executedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    completedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    actionId: Mapped[str] = mapped_column(ForeignKey("actions.id"), nullable=False)
    approverRole: Mapped[str] = mapped_column(String, nullable=False)
    # approverRole ∈ {security, ot_engineering, process_owner}
    approverId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="pending")
    # status ∈ {pending, approved, rejected, expired}
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    decidedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)


class AuditLog(Base):
    """Every meaningful agent/tool/policy action is recorded (§43)."""
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    # actor ∈ {agent:<name>, tool:<name>, policy, user:<id>, system}
    agent: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    taskIdentifier: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    tool: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    policyDecision: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    result: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    evidenceRefs: Mapped[list[str]] = mapped_column(JSON, default=list)
    humanApproval: Mapped[bool] = mapped_column(Boolean, default=False)
    investigationId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    incidentId: Mapped[Optional[str]] = mapped_column(String, nullable=True)


# --------------------------------------------------------------------------- #
# Model execution telemetry (§16)
# --------------------------------------------------------------------------- #

class ModelExecution(Base):
    __tablename__ = "model_executions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    taskId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    model: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, default="medium")
    # role ∈ {small, medium, strong, verification}
    promptTokens: Mapped[int] = mapped_column(Integer, default=0)
    completionTokens: Mapped[int] = mapped_column(Integer, default=0)
    latencyMs: Mapped[int] = mapped_column(Integer, default=0)
    toolCalls: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

class ToolExecution(Base):
    __tablename__ = "tool_executions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    toolName: Mapped[str] = mapped_column(String, nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    latencyMs: Mapped[int] = mapped_column(Integer, default=0)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    investigationId: Mapped[str] = mapped_column(ForeignKey("investigations.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    audience: Mapped[str] = mapped_column(String, default="analyst")
    # audience ∈ {analyst, executive, ot_engineer, auditor, ciso}
    body: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    markdownBody: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #

class Scenario(Base):
    """A scenario in the cyber range (§55)."""
    __tablename__ = "scenarios"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str] = mapped_column(String, default="enterprise")
    # scope ∈ {enterprise, ot, hybrid, false_positive, conflicting, silent, ...}
    difficulty: Mapped[str] = mapped_column(String, default="medium")
    # difficulty ∈ {easy, medium, hard, expert}
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scenarioSeed: Mapped[int] = mapped_column(Integer, default=0)
    groundTruth: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Hidden ground truth (§56) — never shown to the agent.
    assets: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    telemetry: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # Pre-generated synthetic telemetry fixtures.
    createdAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)


class BenchmarkRun(Base):
    """A single execution of WITNESS-Bench (§57)."""
    __tablename__ = "benchmark_runs"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    scenarioId: Mapped[str] = mapped_column(ForeignKey("scenarios.id"), nullable=False)
    modelProvider: Mapped[str] = mapped_column(String, default="mock")
    modelName: Mapped[str] = mapped_column(String, default="mock-medium")
    startedAt: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    completedAt: Mapped[Optional[datetime]] = mapped_column(UTCDateTime, nullable=True)
    status: Mapped[str] = mapped_column(String, default="running")
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    investigationId: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    energyEstimate: Mapped[float] = mapped_column(Float, default=0.0)
    # Estimated joules (§96).
    tokensUsed: Mapped[int] = mapped_column(Integer, default=0)
    toolCalls: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------- #
# Knowledge / ATT&CK cache
# --------------------------------------------------------------------------- #

class KnowledgeItem(Base):
    """Versioned knowledge pack entry (§99, §100)."""
    __tablename__ = "knowledge_items"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    # kind ∈ {attack_enterprise, attack_ics, nist, cisa, sigma, stix, cve,
    #         cwe, protocol, ot_security}
    externalId: Mapped[str] = mapped_column(String, nullable=False)
    # e.g. ATT&CK T1059, ICS T0806, CVE-2024-12345
    name: Mapped[str] = mapped_column(String, nullable=False)
    body: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String, default="mitre-attack")
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    retrievalDate: Mapped[datetime] = mapped_column(UTCDateTime, default=_utcnow)
    license_: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    contentHash: Mapped[str] = mapped_column(String, nullable=False)


# --------------------------------------------------------------------------- #
# Indexes
# --------------------------------------------------------------------------- #

Index("idx_evidence_investigation", Evidence.investigationId, Evidence.timestamp)
Index("idx_evidence_host", Evidence.host)
Index("idx_evidence_asset", Evidence.assetId)
Index("idx_hypothesis_investigation", Hypothesis.investigationId, Hypothesis.currentConfidence)
Index("idx_timeline_investigation_ts", TimelineEvent.investigationId, TimelineEvent.timestamp)
Index("idx_audit_ts", AuditLog.timestamp)
Index("idx_actions_investigation", Action.investigationId, Action.status)
Index("idx_claims_investigation", Claim.investigationId, Claim.status)
Index("idx_tasks_investigation_status", InvestigationTask.investigationId, InvestigationTask.status)
Index("idx_tool_exec_investigation", ToolExecution.investigationId, ToolExecution.timestamp)
Index("idx_threat_intel_indicator", ThreatIntel.indicatorType, ThreatIntel.indicator)
