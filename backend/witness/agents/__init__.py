"""Aggregator that imports all agents to populate the registry."""
from .base import Agent, get_agent_class, list_agent_names, register_agent
from .orchestrator import OrchestratorAgent
from .specialized import (
    TriageAgent, PlannerAgent, EvidenceAnalystAgent, ThreatHunterAgent,
    IdentityAnalystAgent, EndpointAnalystAgent, NetworkAnalystAgent,
    CloudAnalystAgent, DFIRAnalystAgent, OTAnalystAgent,
    ThreatIntelAnalystAgent, AttackMapperAgent, HypothesisEngineAgent,
    ContradictionAnalystAgent, RiskAnalystAgent, ResponsePlannerAgent,
    VerificationAgent, ReportingAgent,
)

__all__ = [
    "Agent", "register_agent", "get_agent_class", "list_agent_names",
    "OrchestratorAgent", "TriageAgent", "PlannerAgent",
    "EvidenceAnalystAgent", "ThreatHunterAgent", "IdentityAnalystAgent",
    "EndpointAnalystAgent", "NetworkAnalystAgent", "CloudAnalystAgent",
    "DFIRAnalystAgent", "OTAnalystAgent", "ThreatIntelAnalystAgent",
    "AttackMapperAgent", "HypothesisEngineAgent", "ContradictionAnalystAgent",
    "RiskAnalystAgent", "ResponsePlannerAgent", "VerificationAgent",
    "ReportingAgent",
]
