"""WITNESS typed agent contracts (§15).

Every agent receives a `AgentInput` and returns an `AgentOutput`. Both are
strictly validated by Pydantic. Malformed outputs are rejected — never trust
free-form model output when a typed representation is possible.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #

ClaimType = Literal[
    "fact", "inference", "hypothesis", "assumption", "unknown",
    "recommendation", "action",
]
ClaimStatus = Literal[
    "verified", "supported", "inferred", "contested",
    "unverified", "rejected", "unknown",
]
HypothesisStatus = Literal[
    "open", "probable", "confirmed", "rejected", "superseded", "unknown",
]
RiskLevel = Literal["low", "medium", "high", "critical", "prohibited"]
Reversibility = Literal[
    "reversible", "partially_reversible", "irreversible", "unknown"
]
ApprovalScope = Literal["security", "ot_engineering", "process_owner", "multi"]
EvidenceReliability = Literal["high", "medium", "low", "unknown"]
SourceDomain = Literal[
    "identity", "endpoint", "network", "cloud", "application",
    "ot", "process", "safety", "persistence", "memory", "dfir", "c2",
]
InvestigationDomain = Literal[
    "identity", "endpoint", "network", "cloud", "application",
    "persistence", "c2", "dfir", "ot", "process", "safety", "memory",
]
AssetCriticality = Literal[
    "low", "medium", "high", "safety_critical"
]
OTSafetyClassification = Literal[
    "safe", "low_risk", "operationally_sensitive", "high_risk",
    "safety_critical", "requires_human_ot_authority", "prohibited",
]
ModelRole = Literal["small", "medium", "strong", "verification"]


# --------------------------------------------------------------------------- #
# Domain DTOs
# --------------------------------------------------------------------------- #

class EvidenceDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    source: str
    source_type: str = Field(alias="sourceType")
    timestamp: datetime
    host: Optional[str] = None
    asset_id: Optional[str] = Field(default=None, alias="assetId")
    user: Optional[str] = None
    process: Optional[str] = None
    network_context: dict[str, Any] = Field(default_factory=dict, alias="networkContext")
    normalized_data: dict[str, Any] = Field(default_factory=dict, alias="normalizedData")
    content_hash: str = Field(alias="contentHash")
    reliability: EvidenceReliability = "high"
    confidence: float = 1.0
    synthetic: bool = False
    sequence: Optional[int] = None
    chain_hash: Optional[str] = Field(default=None, alias="chainHash")


class HypothesisDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    statement: str
    prior_confidence: float = Field(alias="priorConfidence")
    current_confidence: float = Field(alias="currentConfidence")
    status: HypothesisStatus = "open"
    support_evidence_ids: list[str] = Field(default_factory=list, alias="supportEvidenceIds")
    contradict_evidence_ids: list[str] = Field(default_factory=list, alias="contradictEvidenceIds")
    expected_evidence: list[dict[str, Any]] = Field(default_factory=list, alias="expectedEvidence")
    missing_evidence: list[dict[str, Any]] = Field(default_factory=list, alias="missingEvidence")
    attack_techniques: list[str] = Field(default_factory=list, alias="attackTechniques")
    attack_tactics: list[str] = Field(default_factory=list, alias="attackTactics")


class ClaimDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    statement: str
    status: ClaimStatus = "unverified"
    claim_type: ClaimType = "fact"
    evidence_refs: list[str] = Field(default_factory=list, alias="evidenceRefs")
    contradicting_refs: list[str] = Field(default_factory=list, alias="contradictingRefs")
    requires_evidence: bool = Field(default=True, alias="requiresEvidence")
    confidence: float = 0.0


class FindingDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    title: str
    description: str
    severity: str = "medium"
    claim_ids: list[str] = Field(default_factory=list, alias="claimIds")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    attack_techniques: list[str] = Field(default_factory=list, alias="attackTechniques")


class TimelineEventDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    timestamp: datetime
    domain: SourceDomain
    event_type: str = Field(alias="eventType")
    title: str
    description: Optional[str] = None
    asset_id: Optional[str] = Field(default=None, alias="assetId")
    asset_ids: list[str] = Field(default_factory=list, alias="assetIds")
    evidence_id: Optional[str] = Field(default=None, alias="evidenceId")
    attack_techniques: list[str] = Field(default_factory=list, alias="attackTechniques")
    confidence: float = 1.0
    synthetic: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)


class AssetDTO(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    id: str
    name: str
    kind: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = Field(default=None, alias="ipAddress")
    zone: Optional[str] = None
    criticality: AssetCriticality = "medium"
    owner: Optional[str] = None
    business_function: Optional[str] = Field(default=None, alias="businessFunction")
    safety_classification: Optional[str] = Field(default=None, alias="safetyClassification")
    maintenance_state: Optional[str] = Field(default=None, alias="maintenanceState")
    dependencies: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Agent contract
# --------------------------------------------------------------------------- #

class AgentInput(BaseModel):
    """Typed input to an agent (§15)."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    investigation_id: str = Field(alias="investigationId")
    task_id: str = Field(alias="taskId")
    objective: str
    evidence_refs: list[str] = Field(default_factory=list, alias="evidenceRefs")
    hypothesis_refs: list[str] = Field(default_factory=list, alias="hypothesisRefs")
    asset_refs: list[str] = Field(default_factory=list, alias="assetRefs")
    constraints: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = "low"
    role: ModelRole = "medium"
    context: dict[str, Any] = Field(default_factory=dict)


class FindingItem(BaseModel):
    """A finding returned by an agent."""
    statement: str
    claim_type: ClaimType = "fact"
    confidence: float = 0.0
    evidence_refs: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    domain: Optional[SourceDomain] = None


class ProposedAction(BaseModel):
    """A remediation/action proposed by an agent. Will be vetted by the policy
    engine before execution."""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = "low"
    rationale: str = ""
    reversibility: Reversibility = "reversible"
    requires_approval: bool = False
    approval_scope: ApprovalScope = "security"
    blast_radius: dict[str, Any] = Field(default_factory=dict)


class NextStep(BaseModel):
    """A next investigation step recommended by an agent."""
    objective: str
    agent: Optional[str] = None
    information_gain: float = 0.0
    cost: float = 0.0
    confidence_impact: float = 0.0
    risk_level: RiskLevel = "low"
    target_hypothesis_id: Optional[str] = None
    expected_evidence: list[str] = Field(default_factory=list)


class AgentOutput(BaseModel):
    """Typed output from an agent (§15). Reject malformed outputs."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    investigation_id: str = Field(alias="investigationId")
    task_id: str = Field(alias="taskId")
    agent_name: str = Field(alias="agentName")
    findings: list[FindingItem] = Field(default_factory=list)
    new_evidence: list[EvidenceDTO] = Field(default_factory=list, alias="newEvidence")
    new_hypotheses: list[HypothesisDTO] = Field(default_factory=list, alias="newHypotheses")
    confidence_delta: float = 0.0
    contradictions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[NextStep] = Field(default_factory=list, alias="recommendedNextSteps")
    proposed_actions: list[ProposedAction] = Field(default_factory=list, alias="proposedActions")
    completion: Literal["incomplete", "complete", "blocked"] = "incomplete"
    summary: str = ""
    metrics: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Policy / safety
# --------------------------------------------------------------------------- #

class PolicyDecision(BaseModel):
    decision: Literal["allow", "deny", "require_approval", "prohibited"] = "allow"
    reason: str = ""
    required_approvals: list[ApprovalScope] = Field(default_factory=list)
    risk_level: RiskLevel = "low"
    reversibility: Reversibility = "reversible"
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class OTSafetyAssessment(BaseModel):
    classification: OTSafetyClassification = "operationally_sensitive"
    cyber_risk: RiskLevel = "medium"
    operational_risk: RiskLevel = "medium"
    safety_dependency: Literal["none", "indirect", "direct", "unknown"] = "unknown"
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    physical_consequence: Optional[str] = None
    reversibility: Reversibility = "unknown"
    requires_human_ot_authority: bool = True
    rationale: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class BlastRadius(BaseModel):
    affected_assets: list[str] = Field(default_factory=list)
    dependent_assets: list[str] = Field(default_factory=list)
    affected_business_functions: list[str] = Field(default_factory=list)
    affected_processes: list[str] = Field(default_factory=list)
    safety_impacted: bool = False
    estimated_users_affected: int = 0
    reversibility: Reversibility = "unknown"


# --------------------------------------------------------------------------- #
# Model provider
# --------------------------------------------------------------------------- #

class ModelRequest(BaseModel):
    role: ModelRole = "medium"
    system_prompt: str = ""
    user_prompt: str = ""
    tools: list[dict[str, Any]] = Field(default_factory=list)
    max_tokens: int = 2000
    temperature: float = 0.0
    prefer_json: bool = False


class ModelResponse(BaseModel):
    text: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    model: str = ""
    provider: str = ""
    finish_reason: str = ""
