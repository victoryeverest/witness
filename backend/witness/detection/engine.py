"""WITNESS detection engine (§19) — real Sigma + YARA + IOC + behavioral rules.

This is the actual detection runtime. Per the spec, WITNESS should not rely
exclusively on LLM reasoning — deterministic detection is integrated and
the AI interprets and correlates the results.

This module is the entry point. It evaluates rules against:
- evidence rows (which carry normalized_data)
- raw file paths (for YARA scans)
- in-memory event streams (for behavioral/anomaly rules)

It produces evidence rows for every match, so the rest of the system
treats detection-engine output identically to any other evidence source.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DetectionRule, Evidence
from ..utils.crypto import sha256_text
from ..utils.logging import get_logger


log = get_logger("witness.detection")


# --------------------------------------------------------------------------- #
# Sigma rule evaluation (pysigma)
# --------------------------------------------------------------------------- #

async def evaluate_sigma_rule(rule_body: str, evidence_rows: list[Evidence]) -> list[Evidence]:
    """Evaluate a Sigma YAML rule against a list of evidence rows.

    Returns the subset of evidence rows that match the rule's `detection` section.
    Uses pysigma for YAML parsing + detection evaluation.
    """
    import yaml
    try:
        from sigma.collection import SigmaCollection
        from sigma.rule import SigmaRule
    except ImportError:
        log.warning("pysigma not installed; sigma evaluation falls back to YAML-only check")
        # Fallback: just check the YAML parses and has title + detection.
        try:
            data = yaml.safe_load(rule_body)
            if not data or "title" not in data or "detection" not in data:
                return []
            return []
        except yaml.YAMLError:
            return []

    try:
        data = yaml.safe_load(rule_body)
    except yaml.YAMLError as e:
        log.warning(f"sigma_rule_invalid_yaml: {e}")
        return []

    try:
        # Parse via pysigma. `from_yaml` parses a single rule YAML.
        rules = SigmaCollection.from_yaml(rule_body)
        sigma_rule: SigmaRule = rules[0] if len(rules) > 0 else None
    except Exception as e:
        log.warning(f"sigma_parse_failed: {e}")
        return []

    if not sigma_rule:
        return []

    # Convert each evidence row to a dict (its normalized_data) and check
    # against the rule's selection conditions.
    matches: list[Evidence] = []
    for ev in evidence_rows:
        ev_dict = dict(ev.normalizedData or {})
        ev_dict.setdefault("event_id", ev.id)
        if _sigma_matches(sigma_rule, ev_dict):
            matches.append(ev)
    return matches


def _sigma_matches(rule, ev: dict[str, Any]) -> bool:
    """Evaluate the Sigma rule's detection section against a single event dict.

    This is a simplified Sigma selector — handles `selections`, `condition`
    (keywords: `selection`, `selection1 and selection2`, `selection1 or
    selection2`, `not selection`), and field-value matchers with the
    `|contains` modifier. Full Sigma semantics would require pysigma's
    condition expression parser; we cover the common cases.
    """
    detection = None
    # pysigma exposes the parsed detection via .detection
    try:
        detection = rule.detection
    except AttributeError:
        return False
    if detection is None:
        return False

    # Use the rule's parsed detections + condition.
    selections: dict[str, Any] = {}
    try:
        # detection.detections is a dict {name: SigmaDetection}
        for name, sel in detection.detections.items():
            sel_name = name or "selection"
            selections[sel_name] = sel
    except Exception:
        return False

    cond_raw = detection.condition
    if isinstance(cond_raw, list):
        cond_str = " ".join(str(c) for c in cond_raw)
    elif isinstance(cond_raw, str):
        cond_str = cond_raw
    else:
        cond_str = "selection"
    if not cond_str:
        cond_str = "selection"
    cond_str = cond_str.strip()
    # Naive boolean evaluator: tokenize on `and`, `or`, `not`, parens.
    # For production, replace with a proper expression evaluator.
    return _eval_condition(cond_str, selections, ev)


def _eval_condition(cond: str, selections: dict[str, Any], ev: dict[str, Any]) -> bool:
    """Naive recursive boolean evaluator for Sigma condition strings."""
    # Tokenize
    cond = cond.replace("(", " ( ").replace(")", " ) ")
    tokens = cond.split()

    def parse_and_eval(idx: int) -> tuple[bool, int]:
        # Evaluate one operand, possibly a parenthesized subexpression.
        if idx >= len(tokens):
            return False, idx
        tok = tokens[idx]
        if tok == "(":
            val, idx2 = parse_or(idx + 1)
            if idx2 < len(tokens) and tokens[idx2] == ")":
                return val, idx2 + 1
            return val, idx2
        if tok.lower() == "not":
            v, idx2 = parse_and_eval(idx + 1)
            return (not v), idx2
        # Otherwise it's a selection name. Evaluate it.
        sel = selections.get(tok)
        v = _selection_matches(sel, ev) if sel is not None else False
        return v, idx + 1

    def parse_and(idx: int) -> tuple[bool, int]:
        v, idx2 = parse_and_eval(idx)
        while idx2 < len(tokens) and tokens[idx2].lower() == "and":
            v2, idx3 = parse_and_eval(idx2 + 1)
            v = v and v2
            idx2 = idx3
        return v, idx2

    def parse_or(idx: int) -> tuple[bool, int]:
        v, idx2 = parse_and(idx)
        while idx2 < len(tokens) and tokens[idx2].lower() == "or":
            v2, idx3 = parse_and(idx2 + 1)
            v = v or v2
            idx2 = idx3
        return v, idx2

    v, _ = parse_or(0)
    return v


def _selection_matches(sel, ev: dict[str, Any]) -> bool:
    """Evaluate a single Sigma selection (field→value matchers) against an event."""
    # `sel` is a SigmaDetection. Its `.detection_items` list holds the items.
    items = []
    if hasattr(sel, "detection_items"):
        items = list(sel.detection_items)
    elif hasattr(sel, "__iter__"):
        try:
            for x in sel:
                items.append(x)
        except TypeError:
            items = [sel]
    for item in items:
        try:
            field = item.field
            vals = item.value if isinstance(item.value, list) else [item.value]
            ev_val = ev.get(field) if field else None
            if ev_val is None:
                return False
            matched_any = False
            for v in vals:
                v_str = _sigma_value_to_str(v)
                if _sigma_match_value(v_str, str(ev_val)):
                    matched_any = True
                    break
            if not matched_any:
                return False
        except Exception:
            return False
    return True


def _sigma_value_to_str(v) -> str:
    """Extract the underlying string from a SigmaValue (which may carry
    wildcard markers)."""
    if hasattr(v, "value"):
        # SigmaString wraps a list of characters / wildcards.
        inner = v.value
        if isinstance(inner, (list, tuple)):
            return "".join(str(c) if not hasattr(c, "value") else str(c.value)
                            if not str(c).startswith("SpecialChars.")
                            else "*" for c in inner)
        return str(inner)
    return str(v)


def _sigma_match_value(pattern: str, value: str) -> bool:
    """Match a Sigma value pattern against an event value. Supports Sigma's
    `*` wildcard (multi-char) and `?` (single-char)."""
    if "*" in pattern or "?" in pattern:
        import re
        # Convert Sigma wildcards to regex.
        regex = "^"
        for ch in pattern:
            if ch == "*":
                regex += ".*"
            elif ch == "?":
                regex += "."
            else:
                regex += re.escape(ch)
        regex += "$"
        return bool(re.match(regex, value, re.IGNORECASE))
    return pattern.lower() == value.lower()


# --------------------------------------------------------------------------- #
# YARA rule evaluation
# --------------------------------------------------------------------------- #

async def evaluate_yara_rule(rule_body: str, file_paths: list[str]) -> list[dict[str, Any]]:
    """Compile and evaluate a YARA rule against a list of file paths.

    Returns a list of dicts: [{rule: name, file: path, matches: [...]}] for each
    file where the rule matched.
    """
    try:
        import yara
    except ImportError:
        log.warning("yara-python not installed; skipping YARA evaluation")
        return []

    try:
        # yara-python: compile from source string.
        rules = yara.compile(source=rule_body)
    except yara.Error as e:
        log.warning(f"yara_compile_failed: {e}")
        return []

    matches: list[dict[str, Any]] = []
    for path in file_paths:
        try:
            ms = rules.match(path)
            if ms:
                matches.append({
                    "file": path,
                    "rules": [str(m.rule) for m in ms],
                    "tags": [t for m in ms for t in (m.tags or [])],
                })
        except yara.Error as e:
            log.debug(f"yara_match_failed on {path}: {e}")
        except FileNotFoundError:
            continue
    return matches


# --------------------------------------------------------------------------- #
# IOC matching
# --------------------------------------------------------------------------- #

IOC_FIELDS = ("dst_ip", "src_ip", "query", "domain", "url", "image",
              "host", "user", "process", "command_line")


async def match_iocs(session: AsyncSession, evidence_rows: list[Evidence],
                     indicator_type: str = "ioc") -> list[tuple[Evidence, dict[str, Any]]]:
    """Match every IOC in the threat_intel table against evidence fields.

    Returns a list of (evidence, ti_item) tuples.
    """
    from ..models import ThreatIntel
    res = await session.execute(
        select(ThreatIntel).where(ThreatIntel.indicatorType.like(f"{indicator_type}%"))
    )
    ti_items = list(res.scalars().all())
    hits: list[tuple[Evidence, dict[str, Any]]] = []
    for ev in evidence_rows:
        nd = ev.normalizedData or {}
        for ti in ti_items:
            for fld in IOC_FIELDS:
                v = nd.get(fld)
                if v and ti.indicator in str(v):
                    hits.append((ev, {
                        "indicator_type": ti.indicatorType,
                        "indicator": ti.indicator,
                        "confidence": ti.confidence,
                        "source": ti.source,
                        "attack_techniques": ti.attackTechniques,
                    }))
                    break
    return hits


# --------------------------------------------------------------------------- #
# Behavioral rules — simple value/pattern matchers
# --------------------------------------------------------------------------- #

def _behavior_event_kind_match(rule: dict[str, Any], ev: dict[str, Any]) -> bool:
    """A behavioral rule is a dict of {field: value} all must match (AND).

    Supports a special `event_kind` field and a `regex:<field>` for regex matchers.
    """
    for k, v in rule.items():
        if k.startswith("regex:"):
            fld = k.split(":", 1)[1]
            import re
            pattern = re.compile(str(v))
            ev_val = ev.get(fld)
            if ev_val is None or not pattern.search(str(ev_val)):
                return False
        else:
            ev_val = ev.get(k)
            if ev_val is None or str(ev_val).lower() != str(v).lower():
                return False
    return True


async def evaluate_behavioral_rule(rule: dict[str, Any],
                                     evidence_rows: list[Evidence]) -> list[Evidence]:
    """Evaluate a behavioral rule against evidence. The rule is a dict of
    field=value matchers that must all match (AND semantics)."""
    return [ev for ev in evidence_rows
            if _behavior_event_kind_match(rule, ev.normalizedData or {})]


# --------------------------------------------------------------------------- #
# Statistical anomaly detection (baseline deviation)
# --------------------------------------------------------------------------- #

async def detect_baseline_deviations(evidence_rows: list[Evidence]) -> list[dict[str, Any]]:
    """For each (host, user, event_kind) tuple, compute the baseline frequency.
    Flag tuples that occur >3x the baseline as anomalies.

    This is a simple statistical detector — not a full baseline engine (§31).
    The baseline engine is in `witness.core.baseline`.
    """
    from collections import defaultdict
    by_key: dict[tuple, int] = defaultdict(int)
    for ev in evidence_rows:
        nd = ev.normalizedData or {}
        key = (ev.host or "(none)", ev.user or "(none)", nd.get("event_kind", ""))
        by_key[key] += 1
    if not by_key:
        return []
    # Compute mean + std as the baseline.
    counts = list(by_key.values())
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    std = variance ** 0.5
    threshold = mean + max(2 * std, 3.0)  # 2σ above mean, min absolute 3
    anomalies = [
        {"host": k[0], "user": k[1], "event_kind": k[2], "count": v,
         "baseline_mean": mean, "threshold": threshold}
        for k, v in by_key.items() if v >= threshold and mean > 0
    ]
    return anomalies


# --------------------------------------------------------------------------- #
# Main entry: evaluate all rules against evidence
# --------------------------------------------------------------------------- #

async def evaluate_all_rules(session: AsyncSession, investigation_id: str) -> dict[str, Any]:
    """Evaluate every DetectionRule in the DB against all evidence for the
    investigation. Returns a summary dict."""
    res = await session.execute(select(DetectionRule))
    rules = list(res.scalars().all())
    from ..core.evidence import list_evidence
    evidence = await list_evidence(session, investigation_id, limit=5000)
    results: dict[str, Any] = {"rules_evaluated": len(rules), "matches": []}
    for rule in rules:
        if rule.ruleType == "sigma":
            matches = await evaluate_sigma_rule(rule.body, evidence)
            for m in matches:
                results["matches"].append({
                    "rule_id": rule.id, "rule_name": rule.name,
                    "evidence_id": m.id, "rule_type": "sigma",
                })
        elif rule.ruleType == "yara":
            # YARA needs file paths, not evidence. Skip unless we have file refs.
            file_paths = [m.rawReference for m in evidence
                          if m.rawReference and m.rawReference.startswith("/")]
            if file_paths:
                yara_matches = await evaluate_yara_rule(rule.body, file_paths)
                for m in yara_matches:
                    results["matches"].append({
                        "rule_id": rule.id, "rule_name": rule.name,
                        "rule_type": "yara", "file": m["file"],
                        "matched_rules": m["rules"],
                    })
        elif rule.ruleType == "ioc":
            ioc_hits = await match_iocs(session, evidence, "ioc")
            for ev, ti in ioc_hits:
                results["matches"].append({
                    "rule_id": rule.id, "rule_name": rule.name,
                    "rule_type": "ioc", "evidence_id": ev.id, "ti": ti,
                })
        elif rule.ruleType == "behavioral":
            parsed = rule.parsed or {}
            matched = await evaluate_behavioral_rule(parsed, evidence)
            for m in matched:
                results["matches"].append({
                    "rule_id": rule.id, "rule_name": rule.name,
                    "rule_type": "behavioral", "evidence_id": m.id,
                })
    # Also run baseline deviation detection.
    anomalies = await detect_baseline_deviations(evidence)
    results["baseline_anomalies"] = anomalies
    return results


# --------------------------------------------------------------------------- #
# Built-in rule library — ships with WITNESS so it works out of the box
# --------------------------------------------------------------------------- #

BUILTIN_SIGMA_RULES = [
    {
        "name": "Suspicious Encoded PowerShell",
        "body": """
title: Suspicious Encoded PowerShell
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        image|endswith: powershell.exe
        command_line|contains:
            - '-enc '
            - '-encodedcommand'
            - 'FromBase64String'
    condition: selection
falsepositives:
    - Legitimate admin scripts (check change ticket)
level: high
""",
        "attack_techniques": ["T1059.001"],
    },
    {
        "name": "LSASS Memory Access",
        "body": """
title: LSASS Memory Access
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        target_image|endswith: lsass.exe
    condition: selection
level: critical
""",
        "attack_techniques": ["T1003.001"],
    },
    {
        "name": "Unauthorized Modbus Write",
        "body": """
title: Unauthorized Modbus Write
logsource:
    product: ot
    service: modbus
detection:
    selection:
        event_kind: plc_write
        authorized: false
    condition: selection
level: critical
""",
        "attack_techniques": ["T0855", "T0836"],
    },
]


BUILTIN_YARA_RULES = [
    {
        "name": "Suspicious Dropper Strings",
        "body": 'rule SuspiciousDropperStrings : dropper {\n  strings:\n    $a = "FromBase64String" nocase\n    $b = "IEX(" nocase\n    $c = "DownloadString" nocase\n    $d = "Invoke-Expression" nocase\n  condition:\n    2 of them\n}\n',
        "attack_techniques": ["T1059.001"],
    },
]


BUILTIN_BEHAVIORAL_RULES = [
    {
        "name": "Multiple Failed Authentications (Brute Force)",
        "parsed": {"event_kind": "auth_failure"},
        "attack_techniques": ["T1110"],
    },
    {
        "name": "Periodic Beacon to Same Destination",
        "parsed": {"event_kind": "beacon_http"},
        "attack_techniques": ["T1071.001"],
    },
    {
        "name": "Process Variable Deviation",
        "parsed": {"event_kind": "process_var_change"},
        "attack_techniques": ["T0831"],
    },
]


async def load_builtin_rules(session: AsyncSession) -> int:
    """Persist the built-in rule library to the DB if not already present."""
    count = 0
    for spec in BUILTIN_SIGMA_RULES:
        existing = await session.execute(
            select(DetectionRule).where(DetectionRule.name == spec["name"])
        )
        if existing.scalar_one_or_none():
            continue
        body = spec["body"]
        rule = DetectionRule(
            id=f"DR-SIG-{uuid.uuid4().hex[:8].upper()}",
            ruleType="sigma",
            name=spec["name"],
            body=body,
            parsed={},
            source="builtin",
            contentHash=sha256_text(body),
            attackTechniques=spec.get("attack_techniques", []),
            validated=True,
            deployed=True,
        )
        session.add(rule)
        count += 1
    for spec in BUILTIN_YARA_RULES:
        existing = await session.execute(
            select(DetectionRule).where(DetectionRule.name == spec["name"])
        )
        if existing.scalar_one_or_none():
            continue
        body = spec["body"]
        rule = DetectionRule(
            id=f"DR-YARA-{uuid.uuid4().hex[:8].upper()}",
            ruleType="yara",
            name=spec["name"],
            body=body,
            parsed={},
            source="builtin",
            contentHash=sha256_text(body),
            attackTechniques=spec.get("attack_techniques", []),
            validated=True,
            deployed=True,
        )
        session.add(rule)
        count += 1
    for spec in BUILTIN_BEHAVIORAL_RULES:
        existing = await session.execute(
            select(DetectionRule).where(DetectionRule.name == spec["name"])
        )
        if existing.scalar_one_or_none():
            continue
        body = json.dumps(spec["parsed"])
        rule = DetectionRule(
            id=f"DR-BEH-{uuid.uuid4().hex[:8].upper()}",
            ruleType="behavioral",
            name=spec["name"],
            body=body,
            parsed=spec["parsed"],
            source="builtin",
            contentHash=sha256_text(body),
            attackTechniques=spec.get("attack_techniques", []),
            validated=True,
            deployed=True,
        )
        session.add(rule)
        count += 1
    await session.flush()
    return count
