"""Tests for the API surface (§67)."""
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
    """HTTP client connected to the FastAPI app, with a fresh DB."""
    await drop_db()
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["version"] == "1.0.0"
        assert body["auth_mode"] == "none"


class TestAgentsEndpoint:
    @pytest.mark.asyncio
    async def test_lists_all_19_agents(self, client):
        r = await client.get("/agents")
        assert r.status_code == 200
        agents = r.json()
        names = {a["name"] for a in agents}
        assert "orchestrator" in names
        assert "triage" in names
        assert "planner" in names
        assert "reporting" in names
        assert len(names) >= 19


class TestToolsEndpoint:
    @pytest.mark.asyncio
    async def test_lists_all_tools(self, client):
        r = await client.get("/tools")
        assert r.status_code == 200
        tools = r.json()
        names = {t["name"] for t in tools}
        assert "search_sysmon" in names
        assert "isolate_endpoint" in names
        assert "plc_control_action" in names


class TestScenarioLoading:
    @pytest.mark.asyncio
    async def test_load_flagship_scenario(self, client):
        r = await client.post("/scenarios/load", params={"scenario_key": "flagship"})
        assert r.status_code == 200
        body = r.json()
        assert body["name"] == "Flagship IT→OT Intrusion"
        assert body["telemetry_count"] > 0

    @pytest.mark.asyncio
    async def test_list_available_scenarios(self, client):
        r = await client.get("/scenarios/available")
        assert r.status_code == 200
        scenarios = r.json()
        keys = {s["key"] for s in scenarios}
        assert "flagship" in keys
        assert "brute_force" in keys
        assert "false_positive" in keys
        assert "silent_compromise" in keys


class TestFlagshipDemoEndpoint:
    @pytest.mark.asyncio
    async def test_flagship_demo_completes(self, client):
        r = await client.post("/demo/flagship", json={
            "max_iterations": 3
        })
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "completed"
        assert "investigation_id" in body
        assert "metrics" in body
        assert body["metrics"]["detection"] == 1.0


class TestBenchmarkEndpoint:
    @pytest.mark.asyncio
    async def test_run_single_benchmark(self, client):
        r = await client.post("/benchmarks/run", json={"scenario_id": "flagship"})
        assert r.status_code == 200
        body = r.json()
        assert body["runs"] == 1
        assert body["results"][0]["metrics"]["detection"] == 1.0


class TestOTSafetyEndpoint:
    @pytest.mark.asyncio
    async def test_plc_control_action_is_prohibited(self, client):
        r = await client.post("/ot/safety-assessment", json={
            "tool_name": "plc_control_action",
            "arguments": {"plc": "PLC-01", "command": "stop"},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["classification"] == "prohibited"
        assert body["reversibility"] == "irreversible"


class TestAttackMappingEndpoint:
    @pytest.mark.asyncio
    async def test_lists_attack_enterprise(self, client):
        r = await client.get("/attack/enterprise")
        assert r.status_code == 200
        body = r.json()
        assert "T1059.001" in body["techniques"]

    @pytest.mark.asyncio
    async def test_lists_attack_ics(self, client):
        r = await client.get("/attack/ics")
        assert r.status_code == 200
        body = r.json()
        assert "T0866" in body["techniques"]


class TestPolicyEnforcement:
    @pytest.mark.asyncio
    async def test_action_proposal_records_decision(self, client):
        # First load a scenario + create investigation.
        await client.post("/scenarios/load", params={"scenario_key": "flagship"})
        r = await client.post("/investigations", json={
            "title": "t", "objective": "o",
        })
        inv_id = r.json()["id"]
        # Propose an isolate endpoint action.
        r = await client.post("/actions/propose", params={"investigation_id": inv_id}, json={
            "tool_name": "isolate_endpoint",
            "arguments": {"host": "EWS-01"},
            "user_role": "responder",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["decision"]["decision"] == "require_approval"
        assert body["requires_approval"] is True
