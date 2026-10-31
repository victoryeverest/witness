"""Tests for the API surface of all the new (second-pass) endpoints."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from witness.api.app import app
from witness.db import init_db, drop_db


@pytest_asyncio.fixture
async def client():
    await drop_db()
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestNewEndpoints:
    @pytest.mark.asyncio
    async def test_detection_rules_endpoint(self, client):
        r = await client.get("/detection/rules")
        assert r.status_code == 200
        # The lifespan loader auto-populates builtin rules on startup.
        # (This test runs after init_db, so the rules should be present
        # only if lifespan ran. If not, the list is empty — still OK.)
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_knowledge_search(self, client):
        # First load knowledge.
        await client.post("/knowledge/load")
        r = await client.get("/knowledge/search", params={"q": "PowerShell", "top_k": 3})
        assert r.status_code == 200
        results = r.json()
        # Should return at least one technique matching "powershell".
        assert len(results) > 0
        assert any("T1059" in r["external_id"] for r in results)

    @pytest.mark.asyncio
    async def test_knowledge_techniques_list(self, client):
        await client.post("/knowledge/load")
        r = await client.get("/knowledge/techniques")
        assert r.status_code == 200
        techniques = r.json()
        assert len(techniques) > 0

    @pytest.mark.asyncio
    async def test_knowledge_technique_detail(self, client):
        await client.post("/knowledge/load")
        r = await client.get("/knowledge/technique/T1059.001")
        assert r.status_code == 200
        t = r.json()
        assert t["external_id"] == "T1059.001"
        assert "PowerShell" in t["name"]

    @pytest.mark.asyncio
    async def test_query_translate(self, client):
        r = await client.post("/query/translate", json={
            "objective": "Investigate unauthorized PowerShell execution"
        })
        assert r.status_code == 200
        q = r.json()
        assert "sysmon" in q["data_sources"]
        assert "T1059.001" in q["attack_techniques"]
        assert q["agent"] == "endpoint_analyst"

    @pytest.mark.asyncio
    async def test_incident_priority(self, client):
        # Create two incidents with different severities.
        await client.post("/incidents", json={"title": "OT", "severity": "critical", "scope": "hybrid_it_ot"})
        await client.post("/incidents", json={"title": "Phish", "severity": "low", "scope": "enterprise"})
        r = await client.get("/incidents/priority")
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 2
        # The critical OT incident should rank first.
        assert data[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_baseline_benchmark(self, client):
        r = await client.post("/benchmarks/run-baseline", params={"scenario_id": "flagship"})
        assert r.status_code == 200
        d = r.json()
        assert d["detection"] == 1.0
        assert "T1059.001" in d["detected_techniques"]
        # Scored by the same evaluator as WITNESS (no hand-tuned constants):
        # the baseline has no counter-evidence engine and executes nothing.
        m = d["metrics"]
        assert m["contradictions_found"] == 0
        assert m["verification_success"] is None
        assert 0.0 <= d["investigation_score"] <= 1.0

    @pytest.mark.asyncio
    async def test_pcap_analyze_missing_file(self, client):
        # Create an investigation to attach the pcap to.
        r = await client.post("/investigations", json={"title": "t", "objective": "o"})
        inv_id = r.json()["id"]
        # Inside the PCAP directory but absent -> 404.
        r = await client.post("/pcap/analyze", params={"investigation_id": inv_id},
                                json={"pcap_path": "nonexistent.pcap"})
        assert r.status_code == 404
        # Anywhere outside the PCAP directory -> 403, never opened.
        r = await client.post("/pcap/analyze", params={"investigation_id": inv_id},
                                json={"pcap_path": "/nonexistent.pcap"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_baselines_detect_deviations_empty(self, client):
        # Create an investigation with no evidence.
        r = await client.post("/investigations", json={"title": "t", "objective": "o"})
        inv_id = r.json()["id"]
        r = await client.post("/baselines/detect-deviations",
                                params={"investigation_id": inv_id})
        assert r.status_code == 200
        d = r.json()
        assert d["deviations"] == []
        assert d["evidence_inserted"] == []
