"""Tests for rule generation (§105) and NL→query (§47, §107)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import pytest_asyncio
from datetime import datetime, timezone

from witness.db import Base
from witness.config import settings
from witness.core.evidence import add_evidence
from witness.runtime.runtime import create_investigation
from witness.detection.rulegen import (
    generate_sigma_rule_from_pattern,
    generate_yara_rule_from_strings,
    propose_sigma_rule_from_evidence,
    propose_yara_rule_from_evidence,
    validate_rule, validate_all_pending,
)
from witness.core.nl_query import translate, StructuredQuery


@pytest_asyncio.fixture
async def db_session():
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


class TestRuleGeneration:
    def test_generate_sigma_rule_compiles(self):
        body = generate_sigma_rule_from_pattern(
            "Test Rule", {"image": "powershell.exe", "command_line": "-enc abc"},
            description="Test", attack_techniques=["T1059.001"],
        )
        assert "title: Test Rule" in body
        assert "powershell.exe" in body
        assert "attack.t1059_001" in body

    def test_generate_yara_rule_compiles(self):
        body = generate_yara_rule_from_strings(
            "Test YARA", ["IEX(", "DownloadString"], condition="2 of them",
            description="Test", attack_techniques=["T1059.001"],
        )
        assert "rule Test_YARA" in body
        assert "IEX(" in body
        assert "DownloadString" in body

    @pytest.mark.asyncio
    async def test_propose_sigma_rule_from_evidence(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        for i in range(5):
            await add_evidence(
                db_session, inv.id, source="sysmon", source_type="log",
                timestamp=datetime.now(timezone.utc),
                normalized_data={"event_kind": "process_exec",
                                  "image": "powershell.exe",
                                  "command_line": "-enc abc"},
            )
        rule = await propose_sigma_rule_from_evidence(
            db_session, inv.id, name="Auto PS Rule",
            event_kind="process_exec",
            matching_fields=["image", "command_line"],
            description="Auto-generated",
            attack_techniques=["T1059.001"],
        )
        assert rule.id
        assert rule.validated is False
        assert rule.deployed is False
        assert "powershell.exe" in rule.body

    @pytest.mark.asyncio
    async def test_propose_yara_rule_from_evidence(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        rule = await propose_yara_rule_from_evidence(
            db_session, inv.id, name="Auto YARA",
            suspicious_strings=["IEX(", "DownloadString", "Invoke-Expression"],
            description="Auto YARA from PowerShell abuse pattern",
            attack_techniques=["T1059.001"],
        )
        assert rule.id
        assert rule.validated is False
        assert "IEX(" in rule.body

    @pytest.mark.asyncio
    async def test_validate_rule_compiles_sigma(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        await add_evidence(
            db_session, inv.id, source="sysmon", source_type="log",
            timestamp=datetime.now(timezone.utc),
            normalized_data={"event_kind": "process_exec", "image": "powershell.exe"},
        )
        rule = await propose_sigma_rule_from_evidence(
            db_session, inv.id, name="Valid Rule",
            event_kind="process_exec", matching_fields=["image"],
        )
        ok, err = await validate_rule(rule)
        assert ok, err

    @pytest.mark.asyncio
    async def test_validate_rule_compiles_yara(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        rule = await propose_yara_rule_from_evidence(
            db_session, inv.id, name="Valid YARA",
            suspicious_strings=["test"],
        )
        ok, err = await validate_rule(rule)
        assert ok, err

    @pytest.mark.asyncio
    async def test_validate_all_pending(self, db_session):
        inv = await create_investigation(db_session, title="t", objective="o")
        # Add some evidence so the proposal succeeds.
        await add_evidence(
            db_session, inv.id, source="sysmon", source_type="log",
            timestamp=datetime.now(timezone.utc),
            normalized_data={"event_kind": "process_exec", "image": "powershell.exe"},
        )
        await propose_sigma_rule_from_evidence(
            db_session, inv.id, name="R1",
            event_kind="process_exec", matching_fields=["image"],
        )
        await propose_yara_rule_from_evidence(
            db_session, inv.id, name="R2", suspicious_strings=["abc"],
        )
        summary = await validate_all_pending(db_session)
        assert summary["validated"] >= 2


class TestNLQuery:
    def test_translate_recognizes_powershell(self):
        q = translate("Investigate suspicious PowerShell execution")
        # "powershell" keyword maps to "sysmon" source.
        assert "sysmon" in q.data_sources
        assert "T1059.001" in q.attack_techniques
        assert q.agent == "endpoint_analyst"

    def test_translate_recognizes_engineering_workstation(self):
        q = translate("Investigate unusual authentication into engineering workstations outside maintenance hours")
        assert "windows_event_log" in q.data_sources
        assert q.filters.get("host") == "EWS-01"
        assert "query_ot_protocol" in q.data_sources
        assert q.agent == "ot_analyst"

    def test_translate_recognizes_lateral_movement(self):
        q = translate("Find evidence of lateral movement")
        # lateral movement keyword maps to "zeek" (network) source.
        assert "zeek" in q.data_sources
        assert q.filters.get("dst_port") == 445
        assert "T1021.002" in q.attack_techniques
        assert q.agent == "network_analyst"

    def test_translate_recognizes_plc(self):
        q = translate("Hunt for unauthorized PLC writes to PLC-07")
        assert "query_ot_protocol" in q.data_sources
        assert "query_process_variables" in q.data_sources
        assert q.filters.get("dst_device") == "PLC-07"
        assert "T0855" in q.attack_techniques
        assert q.agent == "ot_analyst"

    def test_translate_recognizes_brute_force(self):
        q = translate("Investigate brute force authentication against DC-01")
        assert "windows_event_log" in q.data_sources
        assert q.filters.get("event_kind") == "auth_failure"
        assert "T1110" in q.attack_techniques
        assert q.agent == "identity_analyst"

    def test_translate_returns_read_only_query(self):
        q = translate("Show me all events")
        assert q.read_only is True

    def test_translate_assigns_default_agent(self):
        q = translate("Just investigate")
        assert q.agent != ""
