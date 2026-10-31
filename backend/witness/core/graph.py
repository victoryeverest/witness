"""Evidence graph (§10, §29).

A derived graph view over evidence and asset relationships. We deliberately
use an in-memory adjacency representation rather than a graph database — the
graph is small (typically hundreds of nodes per investigation) and we need
flexible cross-domain traversal that a graph DB would not simplify materially.

Node types per §10: USER, ACCOUNT, HOST, PROCESS, FILE, HASH, IP, DOMAIN,
URL, PORT, CONNECTION, EVENT, SERVICE, TASK, REGISTRY_KEY, CREDENTIAL,
APPLICATION, CONTAINER, CLOUD_RESOURCE, PLC, RTU, HMI, SCADA_SERVER,
ENGINEERING_WORKSTATION, HISTORIAN, CONTROLLER, SENSOR, ACTUATOR,
PROCESS_VARIABLE, CONTROL_COMMAND, NETWORK_ZONE.

Edge types per §10: AUTHENTICATED_TO, SPAWNED, EXECUTED, CONNECTED_TO,
RESOLVED, DOWNLOADED, CREATED, MODIFIED, DELETED, PERSISTED_THROUGH,
ACCESSED, COMMUNICATED_WITH, LATERALLY_MOVED_TO, CONTROLLED, MONITORED,
CONFIGURED, CHANGED, TRIGGERED, OBSERVED.
"""
from __future__ import annotations

import uuid
from collections import defaultdict, deque
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import EvidenceRelationship, Asset, AssetRelationship


class GraphNode:
    __slots__ = ("id", "kind", "label", "attributes")
    def __init__(self, id: str, kind: str, label: str,
                 attributes: Optional[dict[str, Any]] = None):
        self.id = id
        self.kind = kind
        self.label = label
        self.attributes = attributes or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "label": self.label,
            "attributes": self.attributes,
        }


class GraphEdge:
    __slots__ = ("id", "src", "dst", "kind", "timestamp", "confidence",
                 "source_evidence_id", "attributes")
    def __init__(self, id: str, src: str, dst: str, kind: str,
                 timestamp, confidence: float = 1.0,
                 source_evidence_id: Optional[str] = None,
                 attributes: Optional[dict[str, Any]] = None):
        self.id = id
        self.src = src
        self.dst = dst
        self.kind = kind
        self.timestamp = timestamp
        self.confidence = confidence
        self.source_evidence_id = source_evidence_id
        self.attributes = attributes or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "src": self.src, "dst": self.dst, "kind": self.kind,
            "timestamp": self.timestamp.isoformat() if hasattr(self.timestamp, "isoformat") else str(self.timestamp),
            "confidence": self.confidence,
            "source_evidence_id": self.source_evidence_id,
            "attributes": self.attributes,
        }


class EvidenceGraph:
    """In-memory evidence graph for an investigation. Built from the
    evidence_relationships + asset_relationships tables."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.out_edges: dict[str, list[GraphEdge]] = defaultdict(list)
        self.in_edges: dict[str, list[GraphEdge]] = defaultdict(list)
        self.edges_by_kind: dict[str, list[GraphEdge]] = defaultdict(list)

    def add_node(self, id: str, kind: str, label: Optional[str] = None,
                 attributes: Optional[dict[str, Any]] = None) -> GraphNode:
        if id in self.nodes:
            return self.nodes[id]
        n = GraphNode(id=id, kind=kind, label=label or id, attributes=attributes or {})
        self.nodes[id] = n
        return n

    def add_edge(self, src: str, dst: str, kind: str, *,
                 timestamp=None, confidence: float = 1.0,
                 source_evidence_id: Optional[str] = None,
                 attributes: Optional[dict[str, Any]] = None) -> GraphEdge:
        e = GraphEdge(
            id=f"E-{uuid.uuid4().hex[:10].upper()}",
            src=src, dst=dst, kind=kind,
            timestamp=timestamp, confidence=confidence,
            source_evidence_id=source_evidence_id,
            attributes=attributes or {},
        )
        self.edges.append(e)
        self.out_edges[src].append(e)
        self.in_edges[dst].append(e)
        self.edges_by_kind[kind].append(e)
        return e

    def neighbors(self, node_id: str) -> list[str]:
        out = [e.dst for e in self.out_edges.get(node_id, [])]
        inn = [e.src for e in self.in_edges.get(node_id, [])]
        return list(dict.fromkeys(out + inn))

    def shortest_path(self, src: str, dst: str,
                      max_depth: int = 8) -> Optional[list[str]]:
        if src == dst:
            return [src]
        q: deque[tuple[str, list[str]]] = deque([(src, [src])])
        seen = {src}
        while q:
            cur, path = q.popleft()
            if len(path) > max_depth:
                continue
            for e in self.out_edges.get(cur, []):
                if e.dst in seen:
                    continue
                if e.dst == dst:
                    return path + [e.dst]
                seen.add(e.dst)
                q.append((e.dst, path + [e.dst]))
        return None

    def find_paths(self, src: str, dst: str,
                   max_depth: int = 6, max_results: int = 5) -> list[list[str]]:
        """Return up to `max_results` distinct paths from src to dst."""
        results: list[list[str]] = []
        q: deque[tuple[str, list[str]]] = deque([(src, [src])])
        seen_paths: set[tuple[str, ...]] = {(src,)}
        while q and len(results) < max_results:
            cur, path = q.popleft()
            if len(path) > max_depth:
                continue
            for e in self.out_edges.get(cur, []):
                npath = path + [e.dst]
                key = tuple(npath)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                if e.dst == dst:
                    results.append(npath)
                    continue
                q.append((e.dst, npath))
        return results

    def blast_radius(self, asset_id: str, *, max_depth: int = 4) -> dict[str, Any]:
        """BFS over the graph starting at `asset_id` to compute the set of
        assets reachable within `max_depth` hops. Used by the policy engine."""
        visited: dict[str, int] = {asset_id: 0}
        q: deque[tuple[str, int]] = deque([(asset_id, 0)])
        while q:
            cur, depth = q.popleft()
            if depth >= max_depth:
                continue
            for e in self.out_edges.get(cur, []):
                if e.dst not in visited:
                    visited[e.dst] = depth + 1
                    q.append((e.dst, depth + 1))
        # Categorize reachable nodes.
        by_kind: dict[str, list[str]] = defaultdict(list)
        for nid, depth in visited.items():
            by_kind[self.nodes[nid].kind if nid in self.nodes else "unknown"].append(nid)
        return {
            "affected_assets": list(visited.keys()),
            "by_kind": dict(by_kind),
            "max_depth_reached": max(visited.values()) if visited else 0,
            "total_reachable": len(visited) - 1,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


async def build_graph_for_investigation(
    session: AsyncSession, investigation_id: str
) -> EvidenceGraph:
    """Construct the EvidenceGraph for an investigation by combining
    asset relationships (static) and evidence relationships (observed)."""
    g = EvidenceGraph()

    # Load all assets — they become the base node set.
    res = await session.execute(select(Asset))
    for a in res.scalars().all():
        g.add_node(
            id=a.id, kind=a.kind, label=a.name,
            attributes={
                "hostname": a.hostname, "ip": a.ipAddress,
                "zone": a.zone, "criticality": a.criticality,
                "owner": a.owner,
                "business_function": a.businessFunction,
                "safety_classification": a.safetyClassification,
            },
        )

    # Static asset relationships.
    res = await session.execute(select(AssetRelationship))
    for ar in res.scalars().all():
        g.add_edge(
            ar.srcAssetId, ar.dstAssetId, ar.relation,
            confidence=ar.confidence,
            attributes=ar.attributes,
        )

    # Observed evidence relationships.
    res = await session.execute(
        select(EvidenceRelationship)
        .where(EvidenceRelationship.investigationId == investigation_id)
    )
    for er in res.scalars().all():
        if er.srcAssetId and er.dstAssetId:
            g.add_edge(
                er.srcAssetId, er.dstAssetId, er.relation,
                timestamp=er.timestamp,
                confidence=er.confidence,
                source_evidence_id=er.sourceEvidenceId,
                attributes=er.attributes,
            )
        elif er.srcEvidenceId and er.dstEvidenceId:
            g.add_edge(
                er.srcEvidenceId, er.dstEvidenceId, er.relation,
                timestamp=er.timestamp,
                confidence=er.confidence,
                source_evidence_id=er.sourceEvidenceId,
                attributes=er.attributes,
            )
    return g


async def record_observed_relationship(
    session: AsyncSession,
    investigation_id: str,
    *,
    relation: str,
    src_asset_id: Optional[str] = None,
    dst_asset_id: Optional[str] = None,
    src_evidence_id: Optional[str] = None,
    dst_evidence_id: Optional[str] = None,
    source_evidence_id: Optional[str] = None,
    confidence: float = 1.0,
    timestamp=None,
    attributes: Optional[dict[str, Any]] = None,
) -> EvidenceRelationship:
    er = EvidenceRelationship(
        id=f"ER-{uuid.uuid4().hex[:10].upper()}",
        investigationId=investigation_id,
        srcEvidenceId=src_evidence_id,
        dstEvidenceId=dst_evidence_id,
        srcAssetId=src_asset_id,
        dstAssetId=dst_asset_id,
        relation=relation,
        timestamp=timestamp,
        confidence=confidence,
        sourceEvidenceId=source_evidence_id,
        attributes=attributes or {},
    )
    session.add(er)
    await session.flush()
    return er
