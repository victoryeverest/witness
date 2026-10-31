"""In-memory ATT&CK index for fast technique-name lookup + RAG retrieval."""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from ..models import KnowledgeItem


_TOKEN_RE = re.compile(r"\w+")


def _tokenize(s: str) -> list[str]:
    return [w.lower() for w in _TOKEN_RE.findall(s or "")]


class AttackIndex:
    """A simple inverted index over ATT&CK techniques.

    For each technique, we tokenize the name + description and build a
    posting list of {token: set of external_id}. Retrieval returns techniques
    whose token overlap with the query exceeds a threshold.
    """
    def __init__(self, items: Iterable[KnowledgeItem]):
        self.by_id: dict[str, KnowledgeItem] = {}
        self.postings: dict[str, set[str]] = {}
        for it in items:
            self.by_id[it.externalId] = it
            text = f"{it.name} {it.body.get('description', '')} " \
                   f"{' '.join(it.body.get('tactics', []))}"
            for tok in set(_tokenize(text)):
                self.postings.setdefault(tok, set()).add(it.externalId)

    def technique_name(self, external_id: str) -> Optional[str]:
        it = self.by_id.get(external_id)
        return it.name if it else None

    def technique(self, external_id: str) -> Optional[dict[str, Any]]:
        it = self.by_id.get(external_id)
        if not it:
            return None
        return {
            "external_id": it.externalId,
            "name": it.name,
            "description": it.body.get("description", ""),
            "tactics": it.body.get("tactics", []),
            "matrix": it.body.get("matrix", ""),
            "deprecated": it.body.get("deprecated", False),
            "revoked": it.body.get("revoked", False),
            "version": getattr(it, "version", ""),
            "source": getattr(it, "source", ""),
        }

    def retrieve(self, query: str, *, top_k: int = 10) -> list[dict[str, Any]]:
        """Tokenize the query and return the top-K techniques by token overlap.

        This is a simple keyword-overlap retrieval. For real vector RAG, plug
        in a sentence-transformers model. The interface stays the same.
        """
        tokens = _tokenize(query)
        if not tokens:
            return []
        scores: dict[str, int] = {}
        for tok in tokens:
            for ext_id in self.postings.get(tok, set()):
                scores[ext_id] = scores.get(ext_id, 0) + 1
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        return [self.technique(eid) for eid, _ in ranked if eid in self.by_id]

    def all_techniques(self, kind: Optional[str] = None) -> list[dict[str, Any]]:
        out = []
        for it in self.by_id.values():
            if kind and getattr(it, "kind", "") != kind:
                continue
            out.append(self.technique(it.externalId))
        return [t for t in out if t]
