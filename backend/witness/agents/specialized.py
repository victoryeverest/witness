"""Specialized analyst agents (§14).

To keep the codebase cohesive and the implementation testable, each agent:
1. Pulls relevant telemetry via the tool registry.
2. Produces evidence and findings grounded in that telemetry.
3. Updates hypotheses (support / contradict) via the HypothesisEngine.
4. Recommends next steps.

Agents are deliberately small and deterministic. They do NOT call the LLM
to "decide" — they apply rules to the tool output and update the typed
state. This makes the agent layer testable without an LLM and prevents
hallucination.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from .base import Agent, register_agent
from ..models import Evidence, Hypothesis, Asset
from ..core.hypothesis import HypothesisEngine
from functools import partial

from ..core.evidence import add_evidence as _add_evidence, list_evidence
from ..core.timeline import TimelineEngine
from ..schemas import (
    AgentInput, AgentOutput, FindingItem, NextStep,
    HypothesisDTO, ProposedAction,
)
from ..utils.time import utc_now, parse_iso

# Agents re-read the same fixed telemetry every iteration: re-observing a
# record must return the existing evidence row, never create another.
add_evidence = partial(_add_evidence, dedupe=True)


def _norm_user(u: Any) -> str:
    """'CORP\\alice' / 'alice@corp' / 'Alice' -> 'alice'."""
    u = str(u or "").strip().lower()
    u = u.rsplit("\\", 1)[-1]
    return u.split("@", 1)[0]


def _is_benign_hypothesis(h: Hypothesis) -> bool:
    """The 'legitimate activity' alternative carries no ATT&CK techniques."""
    return not (h.attackTechniques or []) and "legitimate" in (h.statement or "").lower()


def _hyps_by_category(session_hyps: list[Hypothesis], category: str) -> list[Hypothesis]:
    from ..core.counter_evidence import classify_hypothesis
    return [h for h in session_hyps if classify_hypothesis(h.statement) == category]


async def _get_hyps(session, investigation_id: str) -> list[Hypothesis]:
    res = await session.execute(
        select(Hypothesis).where(Hypothesis.investigationId == investigation_id)
    )
    return list(res.scalars().all())


async def _find_asset_by(session, *, hostname: str | None = None,
                         ip: str | None = None) -> Asset | None:
    if hostname:
        res = await session.execute(select(Asset).where(Asset.hostname == hostname))
        a = res.scalar_one_or_none()
        if a:
            return a
    if ip:
        res = await session.execute(select(Asset).where(Asset.ipAddress == ip))
        a = res.scalar_one_or_none()
        if a:
            return a
    return None


# --------------------------------------------------------------------------- #
# 1. Triage Agent
# --------------------------------------------------------------------------- #

@register_agent
class TriageAgent(Agent):
    name = "triage"
    description = "Performs initial triage on incoming signals (§14 #2)."
    default_role = "small"
    domain = "endpoint"

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Read the trigger evidence for the investigation.
        evs = await list_evidence(self.session, inp.investigation_id)
        findings: list[FindingItem] = []
        for ev in evs[:20]:
            nd = ev.normalizedData or {}
            # Detect obvious high-signal events.
            if nd.get("event_kind") == "process_exec" and any(
                tool in (nd.get("image") or "").lower()
                for tool in ["powershell", "cmd.exe", "wmic", "rundll32"]
            ):
                findings.append(FindingItem(
                    statement=f"PowerShell/shell execution observed on {ev.host} by {ev.user}",
                    claim_type="fact",
                    confidence=0.7,
                    evidence_refs=[ev.id],
                    attack_techniques=["T1059"],
                    domain="endpoint",
                ))
            if nd.get("event_kind") == "auth_event" and nd.get("outcome") == "failure":
                if nd.get("count", 0) >= 5:
                    findings.append(FindingItem(
                        statement=f"Multiple failed authentications for {nd.get('user')} on {ev.host}",
                        claim_type="fact",
                        confidence=0.6,
                        evidence_refs=[ev.id],
                        attack_techniques=["T1110"],
                        domain="identity",
                    ))
        return self._output(
            inp,
            findings=findings,
            summary=f"Triage produced {len(findings)} initial findings from {len(evs)} evidence items.",
            recommended_next_steps=[NextStep(
                objective="Hand findings to investigation planner",
                agent="planner", information_gain=0.5, cost=0.1,
                confidence_impact=0.3, risk_level="low",
            )],
        )


# --------------------------------------------------------------------------- #
# 2. Investigation Planner
# --------------------------------------------------------------------------- #

@register_agent
class PlannerAgent(Agent):
    name = "planner"
    description = "Decides what to investigate next (§12, §13)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        from ..core.info_gain import rank_steps
        from ..core.counter_evidence import build_plans

        hyps = await _get_hyps(self.session, inp.investigation_id)
        steps: list[NextStep] = []
        for h in hyps:
            if h.status in {"confirmed", "rejected"}:
                continue
            plans = build_plans(h)
            for s in plans.support_steps:
                steps.append(NextStep(
                    objective=s["objective"], agent=s.get("agent"),
                    information_gain=0.7, confidence_impact=0.6,
                    cost=0.4, risk_level="low",
                    target_hypothesis_id=h.id,
                    expected_evidence=[s.get("evidence_kind", "")],
                ))
            for s in plans.counter_steps:
                steps.append(NextStep(
                    objective=s["objective"], agent=s.get("agent"),
                    information_gain=0.8, confidence_impact=0.7,
                    cost=0.4, risk_level="low",
                    target_hypothesis_id=h.id,
                    expected_evidence=[s.get("evidence_kind", "")],
                ))
        ranked = rank_steps(steps)
        return self._output(
            inp,
            findings=[FindingItem(
                statement=f"Planner ranked {len(ranked)} candidate next steps",
                claim_type="inference", confidence=0.9,
                evidence_refs=[], attack_techniques=[], domain=None,
            )],
            recommended_next_steps=ranked[:8],
            summary=f"Planner returned {len(ranked)} ranked next steps.",
        )


# --------------------------------------------------------------------------- #
# 3. Evidence Analyst
# --------------------------------------------------------------------------- #

@register_agent
class EvidenceAnalystAgent(Agent):
    name = "evidence_analyst"
    description = "Cross-correlates evidence across sources (§14 #4)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        evs = await list_evidence(self.session, inp.investigation_id)
        # Group by host+user+minute.
        from collections import defaultdict
        buckets: dict[tuple, list[Evidence]] = defaultdict(list)
        for ev in evs:
            buckets[(ev.host, ev.user, ev.timestamp.replace(second=0, microsecond=0))].append(ev)

        findings: list[FindingItem] = []
        for (host, user, minute), group in buckets.items():
            if len(group) >= 3:
                kinds = {g.normalizedData.get("event_kind") for g in group}
                if {"process_exec", "process_access"} <= kinds or {
                        "auth_event", "process_exec"} <= kinds:
                    findings.append(FindingItem(
                        statement=f"Correlated activity burst on {host} by {user} at {minute.isoformat()}: {sorted(kinds)}",
                        claim_type="inference",
                        confidence=0.65,
                        evidence_refs=[g.id for g in group],
                        attack_techniques=[],
                        domain="endpoint",
                    ))
        return self._output(
            inp,
            findings=findings,
            summary=f"Evidence analyst found {len(findings)} correlated bursts.",
        )


# --------------------------------------------------------------------------- #
# 4. Threat Hunter
# --------------------------------------------------------------------------- #

@register_agent
class ThreatHunterAgent(Agent):
    name = "threat_hunter"
    description = "Hunt-mode agent (§30, §106)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Hunt = look across all telemetry for IOCs and anomalies.
        telemetry: list[dict[str, Any]] = self.ctx_state.get("telemetry", [])
        ti: list[dict[str, Any]] = self.ctx_state.get("threat_intel", [])
        ioc_hits: list[dict[str, Any]] = []
        for t in telemetry:
            for i in ti:
                ind = i.get("indicator")
                if not ind:
                    continue
                # Look for the indicator in common fields.
                for fld in ("dst_ip", "src_ip", "query", "url", "domain",
                            "image", "dst_host"):
                    if ind in str(t.get(fld, "")):
                        ioc_hits.append({"indicator": ind, "telemetry_id": t.get("id"), "field": fld})
                        break
        findings: list[FindingItem] = []
        if ioc_hits:
            # Record as evidence.
            for hit in ioc_hits[:10]:
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="threat_intel",
                    source_type="ti",
                    timestamp=utc_now(),
                    normalized_data={
                        "event_kind": "ioc_hit",
                        "domain": "network",
                        "indicator": hit["indicator"],
                        "telemetry_field": hit["field"],
                    },
                    reliability="medium",
                    confidence=0.6,
                )
                findings.append(FindingItem(
                    statement=f"Threat intel match: indicator {hit['indicator']} found in telemetry field {hit['field']}",
                    claim_type="fact", confidence=0.7,
                    evidence_refs=[ev.id],
                    attack_techniques=[],
                    domain="network",
                ))
        return self._output(
            inp, findings=findings,
            summary=f"Hunter found {len(ioc_hits)} IOC hits across {len(telemetry)} telemetry rows.",
        )


# --------------------------------------------------------------------------- #
# 5. Identity Analyst
# --------------------------------------------------------------------------- #

@register_agent
class IdentityAnalystAgent(Agent):
    name = "identity_analyst"
    description = "Investigates identity-related activity (§14 #6)."
    default_role = "medium"
    domain = "identity"

    async def run(self, inp: AgentInput) -> AgentOutput:
        findings: list[FindingItem] = []
        hyps = await _get_hyps(self.session, inp.investigation_id)
        cred_hyps = _hyps_by_category(hyps, "credential_compromise")

        # Look for SUCCESSFUL lateral logons (4624, type 3).
        result = await self.call_tool("search_windows_events",
                                      {"event_id": 4624, "limit": 50})
        events = result.get("data", {}).get("events", [])
        lateral = [e for e in events
                   if e.get("normalized_data", {}).get("logon_type") == 3
                   and e.get("normalized_data", {}).get("source_ip")]
        for h in cred_hyps:
            for e in lateral:
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="windows_event_log", source_type="log",
                    timestamp=parse_iso(e.get("timestamp", utc_now().isoformat())),
                    host=e.get("host"), user=e.get("user"),
                    normalized_data={"event_kind": "auth_lateral",
                                      "domain": "identity",
                                      "logon_type": 3,
                                      "source_ip": e.get("normalized_data", {}).get("source_ip"),
                                      "user": e.get("user")},
                    reliability="high", confidence=0.85,
                )
                await HypothesisEngine.add_support(
                    self.session, h.id, ev.id,
                    evidence_reliability=0.9, evidence_confidence=0.85,
                    reason=f"lateral_auth_{ev.id}")
                findings.append(FindingItem(
                    statement=f"Network logon (type 3) by {e.get('user')} from {e.get('normalized_data', {}).get('source_ip')} to {e.get('host')}",
                    claim_type="fact", confidence=0.8,
                    evidence_refs=[ev.id],
                    attack_techniques=["T1021"], domain="identity",
                ))
                await TimelineEngine.add_event(
                    self.session, inp.investigation_id,
                    timestamp=ev.timestamp,
                    domain="identity",
                    event_type="lateral_authentication",
                    title=f"Lateral auth: {e.get('user')} → {e.get('host')}",
                    asset_id=None, evidence_id=ev.id,
                    confidence=0.8,
                )

        # Also look for FAILED authentications (brute force / password guessing).
        fail_result = await self.call_tool("search_windows_events",
                                            {"event_id": 4625, "limit": 100})
        fail_events = fail_result.get("data", {}).get("events", [])
        # Group by user.
        from collections import defaultdict
        by_user: dict[str, list] = defaultdict(list)
        for e in fail_events:
            u = e.get("normalized_data", {}).get("user") or e.get("user")
            if u:
                by_user[u].append(e)
        for u, evs in by_user.items():
            if len(evs) >= 5:
                # Brute force pattern. Cap evidence creation at 10 events to
                # avoid noise — the pattern is the signal, not each event.
                bf_evidence_ids: list[str] = []
                for e in evs[:10]:
                    ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
                    ev = await add_evidence(
                        self.session, inp.investigation_id,
                        source="windows_event_log", source_type="log",
                        timestamp=ts, host=e.get("host"), user=u,
                        normalized_data={
                            "event_kind": "auth_failure", "domain": "identity",
                            "outcome": "failure", "user": u, "count": len(evs),
                            "source_ip": e.get("normalized_data", {}).get("source_ip"),
                            "host": e.get("host"),
                        },
                        reliability="high", confidence=0.85,
                    )
                    bf_evidence_ids.append(ev.id)
                    findings.append(FindingItem(
                        statement=f"Failed authentication #{len(evs)} for {u} on {e.get('host')} from {e.get('normalized_data', {}).get('source_ip')}",
                        claim_type="fact", confidence=0.85,
                        evidence_refs=[ev.id],
                        attack_techniques=["T1110"],
                        domain="identity",
                    ))
                    await TimelineEngine.add_event(
                        self.session, inp.investigation_id,
                        timestamp=ts, domain="identity",
                        event_type="auth_failure",
                        title=f"Failed auth {u}@{e.get('host')}",
                        evidence_id=ev.id, confidence=0.85,
                        attack_techniques=["T1110"],
                    )
                # Support credential_compromise hypotheses with the evidence
                # rows just created (never raw telemetry IDs, which are not evidence).
                for h in cred_hyps:
                    for ev_id in bf_evidence_ids:
                        await HypothesisEngine.add_support(
                            self.session, h.id, ev_id,
                            evidence_reliability=0.9, evidence_confidence=0.85,
                            reason=f"brute_force_{len(evs)}_attempts")
        # Remote-access logons (VPN) from infrastructure on a TI list.
        bad = {t.get("indicator") for t in self.ctx_state.get("threat_intel", [])}
        vpn = await self.call_tool("search_log_source", {"source": "vpn_log", "limit": 100})
        for e in vpn.get("data", {}).get("events", []):
            nd = dict(e.get("normalized_data", {}))
            if nd.get("outcome") != "success" or nd.get("source_ip") not in bad:
                continue
            nd["suspicious_source"] = True
            ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
            ev = await add_evidence(
                self.session, inp.investigation_id, source="vpn_log", source_type="log",
                timestamp=ts, host=e.get("host"), user=e.get("user"),
                raw_reference=e.get("id"), normalized_data=nd,
                reliability="high", confidence=0.85,
                synthetic=self.ctx_state.get("synthetic", True),
            )
            findings.append(FindingItem(
                statement=(f"Successful VPN logon as {nd.get('user')} from "
                           f"threat-intel-listed address {nd.get('source_ip')}"),
                claim_type="fact", confidence=0.85, evidence_refs=[ev.id],
                attack_techniques=["T1078.002"], domain="identity",
            ))
            await TimelineEngine.add_event(
                self.session, inp.investigation_id, timestamp=ts, domain="identity",
                event_type="suspicious_remote_logon",
                title=f"VPN logon {nd.get('user')} from {nd.get('source_ip')}",
                evidence_id=ev.id, confidence=0.85, attack_techniques=["T1078.002"],
            )
        return self._output(
            inp, findings=findings,
            summary=f"Identity analyst found {len(lateral)} lateral logons and {len(fail_events)} failed authentications.",
        )


# --------------------------------------------------------------------------- #
# 6. Endpoint Analyst
# --------------------------------------------------------------------------- #

@register_agent
class EndpointAnalystAgent(Agent):
    name = "endpoint_analyst"
    description = "Investigates endpoint activity (§14 #7)."
    default_role = "medium"
    domain = "endpoint"

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Search for suspicious PowerShell.
        result = await self.call_tool("search_sysmon",
                                      {"event_id": 1, "image": "powershell",
                                       "limit": 50})
        events = result.get("data", {}).get("events", [])
        findings: list[FindingItem] = []
        hyps = await _get_hyps(self.session, inp.investigation_id)
        ps_hyps = _hyps_by_category(hyps, "powershell_execution")
        for h in ps_hyps:
            for e in events:
                ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
                cmdline = e.get("normalized_data", {}).get("command_line", "")
                encoded = "-enc" in cmdline or "FromBase64String" in cmdline
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="sysmon", source_type="log",
                    timestamp=ts, host=e.get("host"), user=e.get("user"),
                    normalized_data={
                        "event_kind": "process_exec", "domain": "endpoint",
                        "image": e.get("image"), "command_line": cmdline,
                        "encoded": encoded, "user": e.get("user"),
                        **({"change_ticket": e["normalized_data"]["change_ticket"]}
                           if e.get("normalized_data", {}).get("change_ticket") else {}),
                    },
                    reliability="high", confidence=0.85,
                )
                await HypothesisEngine.add_support(
                    self.session, h.id, ev.id,
                    evidence_reliability=0.9, evidence_confidence=0.85,
                    reason="suspicious_powershell_exec")
                derived = await self._decode_powershell(inp, ev, cmdline)
                if derived is not None:
                    await HypothesisEngine.add_support(
                        self.session, h.id, derived.id,
                        evidence_reliability=0.95, evidence_confidence=0.9,
                        reason="decoded_command_references_known_bad_infrastructure")
                    findings.append(FindingItem(
                        statement=(f"Decoded PowerShell on {e.get('host')} references "
                                   f"known-bad {', '.join(derived.normalizedData['iocs'])}"),
                        claim_type="fact", confidence=0.9, evidence_refs=[derived.id, ev.id],
                        attack_techniques=["T1059.001", "T1105"], domain="endpoint",
                    ))
                findings.append(FindingItem(
                    statement=f"PowerShell execution on {e.get('host')} by {e.get('user')}: {cmdline[:80]}",
                    claim_type="fact", confidence=0.7 + 0.2 * encoded,
                    evidence_refs=[ev.id],
                    attack_techniques=["T1059.001"],
                    domain="endpoint",
                ))
                await TimelineEngine.add_event(
                    self.session, inp.investigation_id,
                    timestamp=ts, domain="endpoint",
                    event_type="process_exec",
                    title=f"PowerShell on {e.get('host')} by {e.get('user')}",
                    evidence_id=ev.id, confidence=0.8,
                    attack_techniques=["T1059.001"],
                )
        findings += await self._other_endpoint_activity(inp)
        return self._output(
            inp, findings=findings,
            summary=f"Endpoint analyst found {len(events)} PowerShell executions.",
        )

    async def _decode_powershell(self, inp: AgentInput, source_ev: Evidence,
                                 cmdline: str):
        """Decode `-enc` payloads (base64 of UTF-16LE) and check the result
        against threat intel. Returns derived evidence when it references a
        known-bad indicator, else None. Derived evidence records what it was
        derived from, so provenance stays traceable (§8)."""
        import base64
        import binascii
        m = re.search(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", cmdline, re.I)
        if not m:
            return None
        try:
            decoded = base64.b64decode(m.group(1), validate=True).decode("utf-16-le")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        indicators = [t.get("indicator") for t in self.ctx_state.get("threat_intel", [])
                      if t.get("indicator")]
        hits = sorted({i for i in indicators if i.lower() in decoded.lower()})
        if not hits:
            return None
        return await add_evidence(
            self.session, inp.investigation_id,
            source="witness:powershell_decoder", source_type="derived",
            timestamp=source_ev.timestamp, host=source_ev.host, user=source_ev.user,
            normalized_data={"event_kind": "decoded_command", "domain": "endpoint",
                             "derived_from": source_ev.id, "decoded": decoded[:500],
                             "iocs": hits},
            reliability="high", confidence=0.9, collection_method="derived",
            synthetic=self.ctx_state.get("synthetic", True),
        )

    async def _other_endpoint_activity(self, inp: AgentInput) -> list[FindingItem]:
        """LSASS access, service creation and phishing clicks. Evidence only:
        the ATT&CK mapper links it to whichever hypotheses claim the
        corresponding technique."""
        findings: list[FindingItem] = []
        synthetic = self.ctx_state.get("synthetic", True)
        lsass = await self.call_tool("search_sysmon", {"event_id": 10, "limit": 50})
        services = await self.call_tool("search_windows_events", {"event_id": 7045, "limit": 50})
        clicks = await self.call_tool("search_log_source", {"source": "email_gateway", "limit": 50})
        rows = ([("process_access", "sysmon", e) for e in lsass.get("data", {}).get("events", [])]
                + [("service_create", "windows_event_log", e)
                   for e in services.get("data", {}).get("events", [])]
                + [("email_click", "email_gateway", e)
                   for e in clicks.get("data", {}).get("events", [])])
        for kind, source, e in rows:
            nd = dict(e.get("normalized_data", {}))
            if nd.get("event_kind") != kind:
                continue
            if kind == "process_access" and "lsass" not in str(nd.get("target_image", "")).lower():
                continue
            ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
            ev = await add_evidence(
                self.session, inp.investigation_id, source=source, source_type="log",
                timestamp=ts, host=e.get("host") or nd.get("host"),
                user=e.get("user") or nd.get("user"), raw_reference=e.get("id"),
                normalized_data=nd, reliability="high", confidence=0.85,
                synthetic=synthetic,
            )
            label = {"process_access": f"LSASS memory accessed by {nd.get('image')}",
                     "service_create": f"Service '{nd.get('service_name')}' created",
                     "email_click": f"User clicked link {nd.get('url')}"}[kind]
            from ..attack.mapper import map_evidence_to_attack
            techs = map_evidence_to_attack(nd)
            findings.append(FindingItem(
                statement=f"{label} on {ev.host}", claim_type="fact", confidence=0.85,
                evidence_refs=[ev.id], attack_techniques=techs, domain="endpoint",
            ))
            await TimelineEngine.add_event(
                self.session, inp.investigation_id, timestamp=ts, domain="endpoint",
                event_type=kind, title=f"{label} on {ev.host}", evidence_id=ev.id,
                confidence=0.85, attack_techniques=techs,
            )
        return findings


# --------------------------------------------------------------------------- #
# 7. Network Analyst
# --------------------------------------------------------------------------- #

@register_agent
class NetworkAnalystAgent(Agent):
    name = "network_analyst"
    description = "Investigates network activity (§14 #8)."
    default_role = "medium"
    domain = "network"

    async def run(self, inp: AgentInput) -> AgentOutput:
        smb_result = await self.call_tool("query_zeek",
                                          {"log_type": "conn", "dst_port": 445,
                                           "limit": 100})
        conns_smb = smb_result.get("data", {}).get("events", [])
        dns_result = await self.call_tool("query_zeek",
                                          {"log_type": "dns", "limit": 100})
        dns = dns_result.get("data", {}).get("events", [])
        # All connections (for beaconing detection).
        all_conns_result = await self.call_tool("query_zeek",
                                                  {"log_type": "conn", "limit": 200})
        all_conns = all_conns_result.get("data", {}).get("events", [])
        findings: list[FindingItem] = []
        hyps = await _get_hyps(self.session, inp.investigation_id)
        lat_hyps = _hyps_by_category(hyps, "lateral_movement")
        for h in lat_hyps:
            for c in conns_smb:
                ts = parse_iso(c.get("timestamp", utc_now().isoformat()))
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="zeek", source_type="log", timestamp=ts,
                    host=c.get("src_ip"),
                    normalized_data={
                        "event_kind": "flow", "domain": "network",
                        "src_ip": c.get("src_ip"), "dst_ip": c.get("dst_ip"),
                        "dst_port": c.get("dst_port"), "proto": c.get("proto"),
                    },
                    reliability="high", confidence=0.85,
                )
                await HypothesisEngine.add_support(
                    self.session, h.id, ev.id,
                    reason=f"smb_connection_{ev.id}")
                findings.append(FindingItem(
                    statement=f"SMB connection {c.get('src_ip')} → {c.get('dst_ip')}:445",
                    claim_type="fact", confidence=0.7,
                    evidence_refs=[ev.id], attack_techniques=["T1021.002"],
                    domain="network",
                ))
                await TimelineEngine.add_event(
                    self.session, inp.investigation_id,
                    timestamp=ts, domain="network",
                    event_type="smb_connection",
                    title=f"SMB {c.get('src_ip')} → {c.get('dst_ip')}",
                    evidence_id=ev.id, confidence=0.8,
                    attack_techniques=["T1021.002"],
                )
        # Detect beaconing: many short connections to the same dst_ip.
        from collections import defaultdict
        by_dst: dict[str, list] = defaultdict(list)
        for c in all_conns:
            by_dst[c.get("dst_ip")].append(c)
        for dst, group in by_dst.items():
            if len(group) >= 3:
                # Beaconing pattern.
                for c in group[:5]:
                    ts = parse_iso(c.get("timestamp", utc_now().isoformat()))
                    ev = await add_evidence(
                        self.session, inp.investigation_id,
                        source="zeek", source_type="log", timestamp=ts,
                        host=c.get("src_ip"),
                        normalized_data={
                            "event_kind": "beacon_http", "domain": "c2",
                            "src_ip": c.get("src_ip"), "dst_ip": dst,
                            "dst_port": c.get("dst_port"), "proto": c.get("proto"),
                        },
                        reliability="high", confidence=0.7,
                    )
                    findings.append(FindingItem(
                        statement=f"Beacon: {c.get('src_ip')} → {dst}:{c.get('dst_port')} ({len(group)} connections)",
                        claim_type="fact", confidence=0.7,
                        evidence_refs=[ev.id], attack_techniques=["T1071.001"],
                        domain="c2",
                    ))
                    await TimelineEngine.add_event(
                        self.session, inp.investigation_id,
                        timestamp=ts, domain="network",
                        event_type="beacon",
                        title=f"Beacon {c.get('src_ip')} → {dst}",
                        evidence_id=ev.id, confidence=0.7,
                        attack_techniques=["T1071.001"],
                    )
        # DNS findings — check for newly-registered domains.
        nrd_indicators: list[dict[str, Any]] = self.ctx_state.get("threat_intel", [])
        nrd_indicators = [t for t in nrd_indicators
                          if t.get("indicator_type") == "ioc_domain"
                          and t.get("attributes", {}).get("newly_registered")]
        for d in dns:
            query = d.get("query", "")
            for ti in nrd_indicators:
                if query.endswith(ti["indicator"]):
                    ts = parse_iso(d.get("timestamp", utc_now().isoformat()))
                    ev = await add_evidence(
                        self.session, inp.investigation_id,
                        source="zeek", source_type="log", timestamp=ts,
                        normalized_data={
                            "event_kind": "dns_nrd", "domain": "network",
                            "query": query, "src_ip": d.get("src_ip"),
                        },
                        reliability="high", confidence=0.7,
                    )
                    findings.append(FindingItem(
                        statement=f"DNS resolution of newly-registered domain {query}",
                        claim_type="fact", confidence=0.7,
                        evidence_refs=[ev.id],
                        attack_techniques=["T1071.004"], domain="network",
                    ))
                    break
        return self._output(
            inp, findings=findings,
            summary=f"Network analyst found {len(conns_smb)} SMB and {len(dns)} DNS events.",
        )


# --------------------------------------------------------------------------- #
# 8. Cloud Analyst
# --------------------------------------------------------------------------- #

@register_agent
class CloudAnalystAgent(Agent):
    name = "cloud_analyst"
    description = "Investigates cloud audit logs (§14 #9)."
    default_role = "medium"
    domain = "cloud"

    async def run(self, inp: AgentInput) -> AgentOutput:
        result = await self.call_tool("query_cloud_audit", {"limit": 100})
        events = result.get("data", {}).get("events", [])
        findings: list[FindingItem] = []
        for e in events:
            nd = e.get("normalized_data", {})
            if nd.get("event_kind") == "iam_change":
                ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="cloud_audit", source_type="log", timestamp=ts,
                    user=e.get("user"),
                    normalized_data=nd, reliability="high", confidence=0.85,
                )
                findings.append(FindingItem(
                    statement=f"Cloud IAM change by {e.get('user')}: {nd.get('event_name')}",
                    claim_type="fact", confidence=0.8,
                    evidence_refs=[ev.id], attack_techniques=["T1098"], domain="cloud",
                ))
        return self._output(
            inp, findings=findings,
            summary=f"Cloud analyst processed {len(events)} audit events.",
        )


# --------------------------------------------------------------------------- #
# 9. DFIR Analyst
# --------------------------------------------------------------------------- #

@register_agent
class DFIRAnalystAgent(Agent):
    name = "dfir_analyst"
    description = "DFIR integrations: filesystem, registry, prefetch, memory (§14 #10)."
    default_role = "medium"
    domain = "dfir"

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Look for persistence evidence in registry.
        reg_result = await self.call_tool("registry_artifacts", {})
        regs = reg_result.get("data", {}).get("entries", [])
        findings: list[FindingItem] = []
        for r in regs:
            if "Run" in r.get("key_path", ""):
                ts = parse_iso(r.get("timestamp", utc_now().isoformat()))
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="registry", source_type="registry", timestamp=ts,
                    host=r.get("host"),
                    normalized_data={
                        "event_kind": "registry_persist", "domain": "persistence",
                        "key_path": r.get("key_path"), "value": r.get("value"),
                    },
                    reliability="high", confidence=0.85,
                )
                findings.append(FindingItem(
                    statement=f"Persistence in Run key on {r.get('host')}: {r.get('value')}",
                    claim_type="fact", confidence=0.8,
                    evidence_refs=[ev.id], attack_techniques=["T1547.001"],
                    domain="persistence",
                ))
        # Memory acquisition is approval-gated (§42). The agent *proposes*
        # acquisition for hosts where the evidence shows credential-access
        # behaviour, and a human decides.
        evs = await list_evidence(self.session, inp.investigation_id)
        mem_targets = sorted({
            ev.host for ev in evs
            if ev.host and (ev.normalizedData or {}).get("event_kind") == "process_access"
        })
        proposed: list[ProposedAction] = []
        for host in mem_targets[:3]:
            action = await self.propose_action(
                "memory_acquire", {"host": host},
                rationale=f"Credential-access behaviour on {host}; memory needed to confirm (§32)")
            proposed.append(ProposedAction(
                tool_name="memory_acquire", arguments={"host": host},
                risk_level=action.riskLevel, requires_approval=action.requiresApproval,
                rationale=f"Acquire memory from {host} (action {action.id}, status {action.status})",
            ))
        return self._output(
            inp, findings=findings, proposed_actions=proposed,
            summary=(f"DFIR analyst found {len(regs)} registry entries; proposed memory "
                     f"acquisition for {len(proposed)} host(s) pending approval."),
        )


# --------------------------------------------------------------------------- #
# 10. OT/ICS Analyst
# --------------------------------------------------------------------------- #

@register_agent
class OTAnalystAgent(Agent):
    name = "ot_analyst"
    description = "Investigates OT/ICS activity (§14 #11, §22, §26)."
    default_role = "medium"
    domain = "ot"

    async def run(self, inp: AgentInput) -> AgentOutput:
        result = await self.call_tool("query_ot_protocol", {"limit": 200})
        events = result.get("data", {}).get("events", [])
        proc_result = await self.call_tool("query_process_variables", {"limit": 200})
        proc_events = proc_result.get("data", {}).get("events", [])

        findings: list[FindingItem] = []
        hyps = await _get_hyps(self.session, inp.investigation_id)
        ot_hyps = _hyps_by_category(hyps, "ot_plc_compromise")

        # Detect unauthorized PLC writes from EWS.
        unauthorized_writes = [e for e in events
                                if e.get("normalized_data", {}).get("function") == "write_single_register"
                                and e.get("normalized_data", {}).get("authorized") is False]
        for h in ot_hyps:
            for e in unauthorized_writes[:20]:
                ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
                nd = e.get("normalized_data", {})
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="ot:modbus", source_type="ot", timestamp=ts,
                    host=e.get("src_device"),
                    normalized_data={
                        "event_kind": "plc_write", "domain": "ot",
                        "protocol": "modbus", "src_device": e.get("src_device"),
                        "dst_device": e.get("dst_device"),
                        "register": nd.get("register"), "value": nd.get("value"),
                    },
                    reliability="high", confidence=0.85,
                )
                await HypothesisEngine.add_support(
                    self.session, h.id, ev.id,
                    reason=f"unauthorized_plc_write_{ev.id}")
                findings.append(FindingItem(
                    statement=f"Unauthorized Modbus write to {e.get('dst_device')} register {nd.get('register')} from {e.get('src_device')}",
                    claim_type="fact", confidence=0.85,
                    evidence_refs=[ev.id],
                    attack_techniques=["T0855", "T0836"], domain="ot",
                ))
                await TimelineEngine.add_event(
                    self.session, inp.investigation_id,
                    timestamp=ts, domain="ot",
                    event_type="plc_write",
                    title=f"Modbus write {e.get('src_device')} → {e.get('dst_device')}",
                    evidence_id=ev.id, confidence=0.85,
                    attack_techniques=["T0855", "T0836"],
                )
        # Detect process variable deviation.
        for e in proc_events:
            nd = e.get("normalized_data", {})
            if nd.get("deviation") and nd.get("deviation") == "high":
                ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
                ev = await add_evidence(
                    self.session, inp.investigation_id,
                    source="process_variable", source_type="ot", timestamp=ts,
                    normalized_data={
                        "event_kind": "process_var_change", "domain": "process",
                        "asset": nd.get("asset"), "variable": nd.get("variable"),
                        "value": nd.get("value"), "expected": nd.get("expected"),
                    },
                    reliability="high", confidence=0.85,
                )
                findings.append(FindingItem(
                    statement=f"Process variable {nd.get('variable')} on {nd.get('asset')} deviated from expected range",
                    claim_type="fact", confidence=0.7,
                    evidence_refs=[ev.id], attack_techniques=["T0831"],
                    domain="process",
                ))
                for h in ot_hyps:
                    await HypothesisEngine.add_support(
                        self.session, h.id, ev.id,
                        reason=f"process_var_change_{ev.id}")
        # Safety/alarm system: suppressed alarms (inhibit response function).
        alarms = await self.call_tool("search_log_source", {"source": "alarm_system", "limit": 100})
        for e in alarms.get("data", {}).get("events", []):
            nd = dict(e.get("normalized_data", {}))
            if not nd.get("suppressed"):
                continue
            ts = parse_iso(e.get("timestamp", utc_now().isoformat()))
            ev = await add_evidence(
                self.session, inp.investigation_id, source="alarm_system", source_type="ot",
                timestamp=ts, host=nd.get("suppressed_by"), raw_reference=e.get("id"),
                normalized_data=nd, reliability="high", confidence=0.9,
                synthetic=self.ctx_state.get("synthetic", True),
            )
            findings.append(FindingItem(
                statement=(f"Alarm {nd.get('alarm_id')} on {nd.get('asset')} suppressed "
                           f"from {nd.get('suppressed_by')}"),
                claim_type="fact", confidence=0.9, evidence_refs=[ev.id],
                attack_techniques=["T0878"], domain="safety",
            ))
            await TimelineEngine.add_event(
                self.session, inp.investigation_id, timestamp=ts, domain="ot",
                event_type="alarm_suppressed", title=f"Alarm {nd.get('alarm_id')} suppressed",
                evidence_id=ev.id, confidence=0.9, attack_techniques=["T0878"],
            )
        return self._output(
            inp, findings=findings,
            summary=f"OT analyst found {len(unauthorized_writes)} unauthorized writes and {len(proc_events)} process events.",
        )


# --------------------------------------------------------------------------- #
# 11. Threat Intel Analyst
# --------------------------------------------------------------------------- #

@register_agent
class ThreatIntelAnalystAgent(Agent):
    name = "threat_intel_analyst"
    description = "Enriches evidence with threat intelligence (§14 #12)."
    default_role = "small"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        evs = await list_evidence(self.session, inp.investigation_id)
        findings: list[FindingItem] = []
        for ev in evs:
            nd = ev.normalizedData or {}
            # Look up any IPs/doms in TI.
            for fld in ("dst_ip", "src_ip", "query", "domain", "url"):
                v = nd.get(fld)
                if not v:
                    continue
                ti_result = await self.call_tool("search_threat_intel", {"indicator": v})
                items = ti_result.get("data", {}).get("items", [])
                if items:
                    findings.append(FindingItem(
                        statement=f"Evidence {ev.id} matched threat intel: {v} ({items[0].get('indicator_type')})",
                        claim_type="fact", confidence=0.7,
                        evidence_refs=[ev.id],
                        attack_techniques=items[0].get("attack_techniques", []),
                        domain="network",
                    ))
        return self._output(
            inp, findings=findings,
            summary=f"TI analyst enriched {len(evs)} evidence items.",
        )


# --------------------------------------------------------------------------- #
# 12. ATT&CK Mapper
# --------------------------------------------------------------------------- #

@register_agent
class AttackMapperAgent(Agent):
    name = "attack_mapper"
    description = "Maps observed behavior to MITRE ATT&CK Enterprise + ICS (§14 #13, §21, §27)."
    default_role = "small"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        from ..attack.mapper import map_evidence_to_attack
        evs = await list_evidence(self.session, inp.investigation_id)
        techniques: dict[str, list[str]] = {}
        findings: list[FindingItem] = []
        for ev in evs:
            techs = map_evidence_to_attack(ev.normalizedData or {})
            for t in techs:
                techniques.setdefault(t, []).append(ev.id)
        # Apply techniques to the most likely hypothesis.
        hyps = await _get_hyps(self.session, inp.investigation_id)
        for t, ev_ids in techniques.items():
            for h in hyps:
                if t in h.attackTechniques:
                    for ev_id in ev_ids:
                        await HypothesisEngine.add_support(
                            self.session, h.id, ev_id,
                            reason=f"attack_mapping_{t}_{ev_id}")
            findings.append(FindingItem(
                statement=f"ATT&CK technique {t} observed in {len(ev_ids)} evidence items",
                claim_type="inference", confidence=0.7,
                evidence_refs=ev_ids[:5], attack_techniques=[t],
                domain=None,
            ))
        return self._output(
            inp, findings=findings,
            summary=f"ATT&CK mapper mapped {len(techniques)} techniques.",
        )


# --------------------------------------------------------------------------- #
# 13. Hypothesis Engine Agent
# --------------------------------------------------------------------------- #

@register_agent
class HypothesisEngineAgent(Agent):
    name = "hypothesis_engine"
    description = "Generates new hypotheses from findings (§14 #14)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Generate counter-hypotheses for any confirmed hypothesis above a threshold.
        hyps = await _get_hyps(self.session, inp.investigation_id)
        from ..core.counter_evidence import generate_counter_hypothesis
        new_hyps: list[HypothesisDTO] = []
        for h in hyps:
            if h.status == "confirmed" and not h.counterHypothesis:
                ch = await generate_counter_hypothesis(
                    self.session, inp.investigation_id, h)
                new_hyps.append(HypothesisEngine.to_dto(ch))
        return self._output(
            inp, new_hypotheses=new_hyps,
            summary=f"Generated {len(new_hyps)} counter-hypotheses.",
        )


# --------------------------------------------------------------------------- #
# 14. Contradiction Analyst
# --------------------------------------------------------------------------- #

@register_agent
class ContradictionAnalystAgent(Agent):
    name = "contradiction_analyst"
    description = "Actively searches for disconfirming evidence (§14 #15, §7, §50)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        """Search for observations that would make each hypothesis wrong.

        Counter-evidence must be *about the same activity*: a change ticket
        contradicts a hypothesis only if it covers the user or host of that
        hypothesis's supporting evidence, inside the ticket's time window.
        (The original implementation let any ticket anywhere in the
        telemetry contradict every hypothesis.) Authorizing evidence also
        *supports* the benign alternative hypothesis.
        """
        from ..core.counter_evidence import build_plans
        hyps = await _get_hyps(self.session, inp.investigation_id)
        telemetry: list[dict[str, Any]] = self.ctx_state.get("telemetry", [])
        findings: list[FindingItem] = []
        contradictions: list[str] = []

        tickets = [t for t in telemetry
                   if t.get("source") == "change_management"
                   or t.get("normalized_data", {}).get("event_kind") == "change_ticket"]
        windows = [t for t in telemetry
                   if t.get("normalized_data", {}).get("event_kind") == "maintenance_window"]

        benign = [h for h in hyps if _is_benign_hypothesis(h)]
        for h in hyps:
            if h.status not in {"open", "probable", "confirmed"} or _is_benign_hypothesis(h):
                continue
            agents = {step.get("agent") for step in build_plans(h).counter_steps}
            support = [await self.session.get(Evidence, ev_id) for ev_id in h.supportEvidenceIds]
            support = [ev for ev in support if ev is not None]
            if not support:
                continue

            if "identity_analyst" in agents:
                for t in tickets:
                    nd = t.get("normalized_data", {})
                    covered = self._ticket_covers(nd, support)
                    if not covered:
                        continue
                    ev = await add_evidence(
                        self.session, inp.investigation_id,
                        source="change_management", source_type="log",
                        timestamp=parse_iso(t.get("timestamp", utc_now().isoformat())),
                        user=t.get("user") or nd.get("user"),
                        raw_reference=t.get("id"),
                        normalized_data={
                            "event_kind": "change_ticket", "domain": "identity",
                            "ticket_id": nd.get("ticket_id"),
                            "approver": nd.get("approver"),
                            "user": nd.get("user"), "host": nd.get("host"),
                            "window_start": nd.get("window_start"),
                            "window_end": nd.get("window_end"),
                        }, reliability="high", confidence=0.85,
                        synthetic=self.ctx_state.get("synthetic", True),
                    )
                    await HypothesisEngine.add_contradiction(
                        self.session, h.id, ev.id,
                        evidence_reliability=0.9, evidence_confidence=0.85,
                        reason=f"change_ticket_{nd.get('ticket_id')}_covers_{covered}")
                    for b in benign:
                        await HypothesisEngine.add_support(
                            self.session, b.id, ev.id,
                            evidence_reliability=0.9, evidence_confidence=0.85,
                            reason=f"authorized_change_{nd.get('ticket_id')}")
                        # Independent corroboration: the activity record itself
                        # cites this approved ticket by ID.
                        for sev in support:
                            if (sev.normalizedData or {}).get("change_ticket") == nd.get("ticket_id"):
                                await HypothesisEngine.add_support(
                                    self.session, b.id, sev.id,
                                    evidence_reliability=0.9, evidence_confidence=0.9,
                                    reason=f"activity_cites_ticket_{nd.get('ticket_id')}")
                    contradictions.append(
                        f"Evidence {ev.id} contradicts {h.id}: change ticket "
                        f"{nd.get('ticket_id')} approved by {nd.get('approver')} covers {covered}")

            if "ot_analyst" in agents:
                hosts = {ev.host for ev in support if ev.host} | {
                    (ev.normalizedData or {}).get(k) for ev in support
                    for k in ("asset", "dst_device", "src_device")}
                for w in windows:
                    nd = w.get("normalized_data", {})
                    if nd.get("asset") not in hosts:
                        continue
                    ev = await add_evidence(
                        self.session, inp.investigation_id,
                        source=w.get("source", "maintenance_log"), source_type="log",
                        timestamp=parse_iso(w.get("timestamp", utc_now().isoformat())),
                        raw_reference=w.get("id"),
                        normalized_data={"event_kind": "maintenance_window", "domain": "ot",
                                         "asset": nd.get("asset"),
                                         "scheduled": bool(nd.get("scheduled")),
                                         "engineer": nd.get("engineer")},
                        reliability="medium", confidence=0.8,
                        synthetic=self.ctx_state.get("synthetic", True),
                    )
                    if nd.get("scheduled"):
                        await HypothesisEngine.add_contradiction(
                            self.session, h.id, ev.id,
                            evidence_reliability=0.7, evidence_confidence=0.8,
                            reason=f"scheduled_maintenance_{nd.get('asset')}")
                        contradictions.append(
                            f"Evidence {ev.id} contradicts {h.id}: scheduled maintenance on {nd.get('asset')}")
                    else:
                        # An *unscheduled* maintenance entry is not an alibi —
                        # it is a claim of maintenance nobody authorized.
                        findings.append(FindingItem(
                            statement=(f"Maintenance entry for {nd.get('asset')} is NOT scheduled; "
                                       f"it does not explain the activity (not treated as counter-evidence)"),
                            claim_type="fact", confidence=0.8,
                            evidence_refs=[ev.id], attack_techniques=[], domain="ot",
                        ))
        return self._output(
            inp, findings=findings, contradictions=contradictions,
            summary=f"Contradiction analyst found {len(contradictions)} contradictions.",
        )

    @staticmethod
    def _ticket_covers(ticket: dict[str, Any], support: list[Evidence]) -> str | None:
        """Return what the ticket covers ('user:x' / 'host:y') or None."""
        t_user = _norm_user(ticket.get("user"))
        t_host = str(ticket.get("host") or "").lower()
        start = parse_iso(ticket["window_start"]) if ticket.get("window_start") else None
        end = parse_iso(ticket["window_end"]) if ticket.get("window_end") else None
        for ev in support:
            if start and ev.timestamp < start:
                continue
            if end and ev.timestamp > end:
                continue
            nd = ev.normalizedData or {}
            ev_user = _norm_user(ev.user or nd.get("user"))
            ev_host = str(ev.host or nd.get("host") or "").lower()
            if t_user and ev_user == t_user:
                return f"user:{t_user}"
            if t_host and ev_host == t_host:
                return f"host:{t_host}"
        return None


# --------------------------------------------------------------------------- #
# 15. Risk Analyst
# --------------------------------------------------------------------------- #

@register_agent
class RiskAnalystAgent(Agent):
    name = "risk_analyst"
    description = "Assesses risk to assets and processes (§110, §111)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        # Aggregate confirmed hypotheses and rank affected assets.
        hyps = await _get_hyps(self.session, inp.investigation_id)
        affected: dict[str, float] = {}
        for h in hyps:
            for ev_id in h.supportEvidenceIds:
                ev = await self.session.get(Evidence, ev_id)
                if ev and ev.host:
                    affected[ev.host] = affected.get(ev.host, 0) + h.currentConfidence
        ranked = sorted(affected.items(), key=lambda x: x[1], reverse=True)
        findings: list[FindingItem] = []
        for host, risk in ranked[:10]:
            findings.append(FindingItem(
                statement=f"Asset {host} risk score: {risk:.2f}",
                claim_type="inference", confidence=min(0.9, risk),
                evidence_refs=[], attack_techniques=[], domain=None,
            ))
        return self._output(
            inp, findings=findings,
            summary=f"Risk analyst ranked {len(ranked)} affected assets.",
        )


# --------------------------------------------------------------------------- #
# 16. Response Planner
# --------------------------------------------------------------------------- #

@register_agent
class ResponsePlannerAgent(Agent):
    name = "response_planner"
    description = "Proposes remediation actions (§14 #17, §37)."
    default_role = "medium"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        """Propose containment for what the evidence actually implicates.

        Targets come only from evidence supporting malicious hypotheses that
        reached `probable` or `confirmed` — not from every host and user that
        appears anywhere (which proposed disabling the accounts of the
        engineers whose change tickets cleared them). Every proposal goes
        through the policy engine and, for OT assets, the OT safety engine,
        and is recorded as an Action awaiting human approval.
        """
        hyps = await _get_hyps(self.session, inp.investigation_id)
        malicious = [h for h in hyps if h.status in {"probable", "confirmed"}
                     and not _is_benign_hypothesis(h)]
        support_ids = {ev_id for h in malicious for ev_id in h.supportEvidenceIds}
        support = [await self.session.get(Evidence, ev_id) for ev_id in sorted(support_ids)]
        support = [ev for ev in support if ev is not None]

        assets = self.ctx_state.get("assets", {})
        known_hosts = {a.get("hostname") or aid for aid, a in assets.items()} | set(assets)
        hosts = sorted({ev.host for ev in support if ev.host and ev.host in known_hosts})
        users = sorted({_norm_user(ev.user or (ev.normalizedData or {}).get("user"))
                        for ev in support if ev.user or (ev.normalizedData or {}).get("user")})
        indicators = {t.get("indicator") for t in self.ctx_state.get("threat_intel", [])
                      if t.get("indicator")}
        iocs = sorted({v for ev in support for k, v in (ev.normalizedData or {}).items()
                       if k in {"dst_ip", "query", "domain", "url"} and v in indicators})

        from ..ot.safety import OT_ASSET_KINDS
        plan: list[tuple[str, dict[str, Any], str]] = []
        findings: list[FindingItem] = []
        for host in hosts:
            asset = next((a for aid, a in assets.items()
                          if aid == host or a.get("hostname") == host), {})
            if (asset.get("kind") not in OT_ASSET_KINDS
                    and asset.get("criticality") in {"high", "safety_critical"}):
                # Isolating a domain controller or VPN gateway is an outage,
                # not containment. Flag it for a human-designed plan instead.
                findings.append(FindingItem(
                    statement=(f"{host} is critical infrastructure ({asset.get('name', host)}); "
                               f"network isolation not proposed — needs a manual containment plan"),
                    claim_type="recommendation", confidence=0.9,
                    evidence_refs=[ev.id for ev in support if ev.host == host][:5],
                    attack_techniques=[], domain=None,
                ))
                continue
            plan.append(("isolate_endpoint", {"host": host},
                         f"Contain {host}: supporting evidence for a probable/confirmed malicious hypothesis"))
        for user in users:
            plan.append(("disable_account", {"user": user},
                         f"Disable {user}: identity implicated by supporting evidence"))
            plan.append(("rotate_credentials", {"user": user},
                         f"Rotate {user} credentials: credentials may be compromised"))
        for ioc in iocs:
            plan.append(("block_ioc", {"ioc": ioc}, f"Block known-bad indicator {ioc}"))

        proposed: list[ProposedAction] = []
        for tool_name, args, why in plan:
            action = await self.propose_action(tool_name, args, rationale=why)
            scope = action.approvalScope or ""
            proposed.append(ProposedAction(
                tool_name=tool_name, arguments=args,
                risk_level=action.riskLevel,
                rationale=f"{why} (action {action.id}, status {action.status})",
                reversibility=action.reversibility,
                requires_approval=action.requiresApproval,
                approval_scope="multi" if "," in scope else (scope or "security"),
                blast_radius=action.blastRadius or {},
            ))
        return self._output(
            inp, proposed_actions=proposed, findings=findings,
            summary=(f"Response planner proposed {len(proposed)} action(s) for "
                     f"{len(hosts)} host(s), {len(users)} identity(ies), {len(iocs)} IOC(s)."),
        )


# --------------------------------------------------------------------------- #
# 17. Verification Agent
# --------------------------------------------------------------------------- #

@register_agent
class VerificationAgent(Agent):
    name = "verification"
    description = "Verifies remediation by re-checking telemetry (§38)."
    default_role = "verification"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        """Re-check the effect of every executed action (§38)."""
        from ..models import Investigation
        from ..tools.actions import verify_effect
        inv = await self.session.get(Investigation, inp.investigation_id)
        state = dict((inv.state if inv else None) or {})
        effects = {**self.ctx_state, **(state.get("effects") or {})}
        actions = list(state.get("executed_actions") or self.ctx_state.get("executed_actions") or [])
        results: list[FindingItem] = []
        verified = 0
        for a in actions:
            outcome = verify_effect(a.get("tool_name"), a.get("arguments", {}), effects)
            if outcome["verified"]:
                verified += 1
            for c in outcome["checks"]:
                results.append(FindingItem(
                    statement=f"Verification of {a.get('tool_name')}: {c['detail']} -> "
                              f"{'PASS' if c['passed'] else 'FAIL'}",
                    claim_type="inference", confidence=0.9,
                    evidence_refs=[], domain=None,
                ))
        return self._output(
            inp, findings=results,
            metrics={"actions_checked": len(actions), "actions_verified": verified},
            summary=f"Verification agent checked {len(actions)} actions; {verified} verified.",
        )


# --------------------------------------------------------------------------- #
# 18. Reporting Agent
# --------------------------------------------------------------------------- #

# Evidence kind -> kill-chain stage, for the staged reconstruction (§51, §91).
_STAGE_OF_EVENT = {
    "email_click": "initial_access",
    "process_exec": "execution",
    "process_access": "credential_access",
    "auth_failure": "credential_access",
    "auth_lateral": "lateral_movement",
    "service_create": "persistence",
    "registry_persist": "persistence",
    "beacon_http": "command_and_control",
    "dns_nrd": "command_and_control",
    "ioc_hit": "command_and_control",
    "plc_write": "ot_manipulation",
    "process_var_change": "process_impact",
    "alarm_event": "inhibit_response",
}

_AUDIENCE_SECTIONS = {
    "executive": ["what_happened", "risk", "containment", "known", "unknown", "decisions"],
    "ciso": ["what_happened", "risk", "containment", "known", "unknown", "decisions"],
    "analyst": ["stages", "hypotheses", "evidence", "unknown", "actions"],
    "ot_engineer": ["ot_impact", "stages", "actions", "unknown"],
    "auditor": ["provenance", "actions", "hypotheses"],
}


@register_agent
class ReportingAgent(Agent):
    name = "reporting"
    description = "Produces evidence-backed incident reports (§34, §114, §115, §116, §117, §118)."
    default_role = "strong"
    domain = None

    async def run(self, inp: AgentInput) -> AgentOutput:
        from collections import defaultdict
        from sqlalchemy import select as _select
        from ..attack.mapper import map_evidence_to_attack
        from ..core.coverage import compute_coverage
        from ..core.evidence import verify_chain
        from ..core.timeline import TimelineEngine
        from ..models import Action

        audience = inp.context.get("audience", "analyst")
        hyps = await _get_hyps(self.session, inp.investigation_id)
        coverage = await compute_coverage(self.session, inp.investigation_id)
        evs = await list_evidence(self.session, inp.investigation_id)
        ev_by_id = {e.id: e for e in evs}
        tl = await TimelineEngine.list_for_investigation(self.session, inp.investigation_id)
        actions = list((await self.session.execute(
            _select(Action).where(Action.investigationId == inp.investigation_id)
        )).scalars().all())
        integrity = await verify_chain(self.session, inp.investigation_id)

        malicious = [h for h in hyps if h.status in {"probable", "confirmed"}
                     and not _is_benign_hypothesis(h)]
        benign_winning = [h for h in hyps if _is_benign_hypothesis(h)
                          and h.status in {"probable", "confirmed"}]

        # Staged reconstruction, built only from evidence that supports a
        # probable/confirmed malicious hypothesis.
        stages: dict[str, dict[str, Any]] = {}
        for ev_id in sorted({i for h in malicious for i in h.supportEvidenceIds}):
            ev = ev_by_id.get(ev_id)
            if ev is None:
                continue
            nd = ev.normalizedData or {}
            stage = _STAGE_OF_EVENT.get(nd.get("event_kind"))
            if nd.get("event_kind") == "flow" and nd.get("dst_port") == 445:
                stage = "lateral_movement"
            if not stage:
                continue
            st = stages.setdefault(stage, {"stage": stage, "first_seen": ev.timestamp,
                                           "assets": set(), "techniques": set(), "evidence_ids": []})
            st["first_seen"] = min(st["first_seen"], ev.timestamp)
            for k in ("host", "asset", "dst_device"):
                v = ev.host if k == "host" else nd.get(k)
                if v:
                    st["assets"].add(v)
            st["techniques"].update(map_evidence_to_attack(nd))
            st["evidence_ids"].append(ev.id)
        staged = [{"stage": v["stage"], "first_seen": v["first_seen"].isoformat(),
                   "assets": sorted(v["assets"]), "techniques": sorted(v["techniques"]),
                   "evidence_ids": v["evidence_ids"]}
                  for v in sorted(stages.values(), key=lambda v: v["first_seen"])]

        # Techniques that are evidence-backed (claimed AND mapped from support).
        backed: dict[str, list[str]] = defaultdict(list)
        for h in malicious:
            for ev_id in h.supportEvidenceIds:
                ev = ev_by_id.get(ev_id)
                if ev is None:
                    continue
                for t in map_evidence_to_attack(ev.normalizedData or {}):
                    if t in (h.attackTechniques or []) and ev_id not in backed[t]:
                        backed[t].append(ev_id)

        gaps = [d for d, v in coverage.items() if d != "overall" and v < 0.5]
        pending = [a for a in actions if a.status == "proposed"]
        executed = [a for a in actions if a.status == "completed"]
        blocked = [a for a in actions if a.status in {"denied", "prohibited"}]
        ot_assets = sorted({a for st in staged if st["stage"] in
                            {"ot_manipulation", "process_impact", "inhibit_response"}
                            for a in st["assets"]})

        report_body = {
            "audience": audience,
            "sections": _AUDIENCE_SECTIONS.get(audience, _AUDIENCE_SECTIONS["analyst"]),
            "executive_summary": self._executive_summary(hyps, malicious, benign_winning, coverage),
            "incident_classification": (
                "Benign / authorized activity" if benign_winning and not malicious else
                "IT-to-OT intrusion" if any(t.startswith("T08") for h in malicious
                                            for t in (h.attackTechniques or []))
                else "Enterprise intrusion" if malicious else "Inconclusive"),
            "severity": self._severity(malicious),
            "confidence": self._confidence(hyps, malicious, coverage, tl, actions, staged),
            "affected_assets": sorted({ev.host for ev in evs if ev.host}),
            "affected_identities": sorted({_norm_user(ev.user) for ev in evs if ev.user}),
            "timeline_count": len(tl),
            "evidence_count": len(evs),
            "attack_techniques": sorted({t for h in malicious for t in h.attackTechniques}),
            "evidence_backed_techniques": {t: ids[:10] for t, ids in sorted(backed.items())},
            "attack_stages": staged,
            "hypotheses": [
                {
                    "id": h.id, "statement": h.statement,
                    "confidence": h.currentConfidence, "status": h.status,
                    "support": len(h.supportEvidenceIds),
                    "contradict": len(h.contradictEvidenceIds),
                } for h in hyps
            ],
            "evidence_coverage": coverage,
            "what_we_do_not_know": [f"No or weak evidence coverage for domain '{d}'" for d in gaps]
            + [f"Hypothesis '{h.statement}' is unresolved ({h.currentConfidence:.0%})"
               for h in hyps if h.status == "open" and h.supportEvidenceIds],
            "ot_impact": {
                "affected_ot_assets": ot_assets,
                "process_impact_observed": any(st["stage"] == "process_impact" for st in staged),
                "safety_function_inhibited": any(st["stage"] == "inhibit_response" for st in staged),
            },
            "recommended_actions": [
                {"id": a.id, "tool": a.toolName, "arguments": a.arguments, "status": a.status,
                 "risk_level": a.riskLevel, "approval_scope": a.approvalScope,
                 "rationale": (a.blastRadius or {}).get("rationale", "")}
                for a in actions],
            "decisions_required": [
                f"Approve or reject {a.toolName} {a.arguments} (needs: {a.approvalScope})"
                for a in pending],
            "actions_performed": [
                {"id": a.id, "tool": a.toolName, "arguments": a.arguments,
                 "verification": a.verification} for a in executed],
            "actions_refused_by_policy": [
                {"id": a.id, "tool": a.toolName, "status": a.status} for a in blocked],
            "containment_status": ("contained" if executed and all(
                (a.verification or {}).get("verified") for a in executed)
                else "partially_contained" if executed else "not_contained"),
            "provenance": {
                "evidence_chain_intact": integrity["intact"],
                "evidence_chain_head": integrity["head_hash"],
                "content_mismatches": len(integrity["content_mismatches"]),
                "chain_breaks": len(integrity["chain_breaks"]),
                "synthetic_evidence": sum(1 for e in evs if e.synthetic),
            },
            "remaining_risk": self._remaining_risk(malicious, gaps, pending, executed),
        }
        # Optional model-written narrative over the structured facts above.
        # Rejected (ungrounded) narratives are reported, never shown as fact.
        from ..core.model_assist import assist_enabled, write_narrative
        if assist_enabled():
            narrative, result = await write_narrative(self.session, inp.investigation_id, report_body)
            if narrative:
                report_body["narrative"] = narrative
            else:
                report_body["narrative_unavailable"] = result.reason
        return self._output(
            inp,
            findings=[FindingItem(
                statement=f"Report generated for audience={audience} with {len(hyps)} hypotheses and {len(evs)} evidence items",
                claim_type="inference", confidence=0.95,
                evidence_refs=[], attack_techniques=[], domain=None,
            )],
            summary=f"Report generated (audience={audience}).",
            metrics={"report": report_body},
        )

    @staticmethod
    def _executive_summary(hyps, malicious, benign_winning, coverage) -> str:
        if not hyps:
            return "No hypotheses were investigated; no conclusion can be drawn."
        cov = coverage.get("overall", 0.0)
        if malicious:
            top = max(malicious, key=lambda h: h.currentConfidence)
            lead = (f"Evidence supports the hypothesis: '{top.statement}' "
                    f"(confidence {top.currentConfidence:.0%}, {len(top.supportEvidenceIds)} "
                    f"supporting / {len(top.contradictEvidenceIds)} contradicting evidence items).")
        elif benign_winning:
            top = max(benign_winning, key=lambda h: h.currentConfidence)
            lead = (f"Evidence indicates authorized activity: '{top.statement}' "
                    f"(confidence {top.currentConfidence:.0%}). No malicious hypothesis "
                    f"reached 'probable'.")
        else:
            lead = "No hypothesis reached 'probable'; the investigation is inconclusive."
        return (f"{lead} Evidence coverage {cov:.0%}. {len(hyps)} hypotheses investigated: "
                f"{sum(h.status == 'confirmed' for h in hyps)} confirmed, "
                f"{sum(h.status == 'probable' for h in hyps)} probable, "
                f"{sum(h.status == 'rejected' for h in hyps)} rejected.")

    @staticmethod
    def _severity(malicious) -> str:
        if any(any(t.startswith("T08") for t in (h.attackTechniques or [])) for h in malicious):
            return "critical"
        if any(h.status == "confirmed" for h in malicious):
            return "high"
        if malicious:
            return "medium"
        return "low"

    @staticmethod
    def _confidence(hyps, malicious, coverage, timeline, actions, staged) -> dict[str, float]:
        """Every dimension is computed from investigation state. (The original
        returned constants — timeline 0.6, remediation 0.7, coverage 0.0 —
        which the report then presented as measured confidence.)"""
        if not hyps:
            return {"overall": 0.0}
        top = max((h.currentConfidence for h in malicious), default=0.0)
        tl_conf = (sum(t.confidence for t in timeline) / len(timeline)) if timeline else 0.0
        verified = [a for a in actions if a.status == "completed"]
        remediation = (sum(1 for a in verified if (a.verification or {}).get("verified"))
                       / len(verified)) if verified else 0.0
        with_tech = [h for h in malicious if h.attackTechniques]
        technique = max((h.currentConfidence for h in with_tech), default=0.0)
        impact_stages = {"ot_manipulation", "process_impact", "inhibit_response"}
        impact = top if any(st["stage"] in impact_stages for st in staged) else top * 0.5
        return {
            "overall": max(h.currentConfidence for h in hyps),
            "detection": top,
            "attribution": 0.0,  # WITNESS does not attribute actors; never claim otherwise.
            "timeline": round(tl_conf, 4),
            "technique": technique,
            "impact": impact,
            "remediation": round(remediation, 4),
            "evidence_coverage": coverage.get("overall", 0.0),
        }

    @staticmethod
    def _remaining_risk(malicious, gaps, pending, executed) -> dict[str, Any]:
        reasons = []
        if malicious and not executed:
            reasons.append("Malicious activity is supported by evidence and no containment has been executed.")
        if pending:
            reasons.append(f"{len(pending)} proposed action(s) await human approval.")
        if gaps:
            reasons.append(f"Evidence coverage is incomplete in: {', '.join(gaps)}.")
        level = ("high" if malicious and not executed else
                 "medium" if (pending or gaps) else "low")
        return {"level": level,
                "reason": " ".join(reasons) or "All key domains have evidence coverage.",
                "next_steps": [f"Collect {d} telemetry" for d in gaps]}
