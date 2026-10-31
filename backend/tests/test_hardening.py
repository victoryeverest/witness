"""Safety and correctness invariants.

Approval bypasses, evidence integrity, confidence idempotence, benchmark
honesty, path containment, auth and privacy mode.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from witness.api.app import app
from witness.config import settings
from witness.db import AsyncSessionLocal, drop_db, init_db
from witness.models import Evidence, Investigation
from witness.core.evidence import add_evidence, verify_chain, verify_integrity
from witness.core.hypothesis import HypothesisEngine, posterior_confidence
from witness.core.counter_evidence import classify_hypothesis, build_plans, _validate_template_agents
from witness.runtime.runtime import (
    create_investigation, run_investigation, resume_investigation,
    InvestigationStateError,
)
from witness.range.cyber_range import load_scenario_into_db, get_scenario_telemetry_state
from witness.tools.base import ToolContext, execute_tool
from witness.benchmark.bench import evaluate_investigation, run_baseline, compute_investigation_score

TS = datetime(2025, 9, 4, 14, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def session():
    await drop_db()
    await init_db()
    async with AsyncSessionLocal() as s:
        yield s
        await s.rollback()


@pytest_asyncio.fixture
async def client():
    await drop_db()
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _new_inv(c) -> str:
    return (await c.post("/investigations", json={"title": "t", "objective": "o"})).json()["id"]


async def _ev(session, inv_id, i=0, **kw):
    return await add_evidence(session, inv_id, source="sysmon", source_type="log",
                              timestamp=TS + timedelta(seconds=i),
                              normalized_data={"event_kind": "process_exec", "n": i}, **kw)


# --------------------------------------------------------------------------- #
# Policy & approvals
# --------------------------------------------------------------------------- #

class TestApprovalBypasses:
    @pytest.mark.asyncio
    async def test_prohibited_plc_command_can_never_be_approved_or_executed(self, client):
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "plc_control_action", "arguments": {"plc": "PLC-07", "command": "stop"},
            "user_role": "admin"})).json()
        assert r["decision"]["decision"] == "prohibited"
        assert r["status"] == "prohibited"
        for role in ("security", "ot_engineering", "process_owner"):
            a = await client.post("/actions/approve", json={
                "action_id": r["action_id"], "approver_id": f"u-{role}", "approver_role": role})
            assert a.status_code == 409
        e = await client.post("/actions/execute", json={"action_id": r["action_id"]})
        assert e.status_code == 409

    @pytest.mark.asyncio
    async def test_denied_action_is_terminal(self, client):
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "isolate_endpoint", "arguments": {"host": "WS-01"},
            "user_role": "viewer"})).json()
        assert r["status"] == "denied"
        a = await client.post("/actions/approve", json={
            "action_id": r["action_id"], "approver_id": "x", "approver_role": "security"})
        assert a.status_code == 409
        assert (await client.post("/actions/execute", json={"action_id": r["action_id"]})).status_code == 409

    @pytest.mark.asyncio
    async def test_ot_host_requires_three_distinct_approvers(self, client):
        await client.post("/scenarios/load?scenario_key=flagship")
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "isolate_endpoint", "arguments": {"host": "EWS-01"},
            "user_role": "admin", "proposed_by": "proposer"})).json()
        assert r["status"] == "proposed"
        assert r["approval_scope"] == "security,ot_engineering,process_owner"
        aid = r["action_id"]

        async def approve(who, role):
            return await client.post("/actions/approve", json={
                "action_id": aid, "approver_id": who, "approver_role": role})

        assert (await approve("proposer", "security")).status_code == 409   # self-approval
        assert (await approve("sec", "auditor")).status_code == 409          # not a required scope
        assert (await approve("sec", "security")).json()["status"] == "proposed"
        assert (await approve("sec", "ot_engineering")).status_code == 409   # same person, 2nd scope
        assert (await approve("sec2", "security")).status_code == 409        # scope already signed
        assert (await approve("eng", "ot_engineering")).json()["status"] == "proposed"
        final = (await approve("owner", "process_owner")).json()
        assert final["status"] == "approved"
        assert set(final["approved_by"].split(",")) == {"sec", "eng", "owner"}

    @pytest.mark.asyncio
    async def test_rejected_action_cannot_be_reapproved(self, client):
        await client.post("/scenarios/load?scenario_key=flagship")
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "block_ioc", "arguments": {"ioc": "1.2.3.4"}, "user_role": "admin"})).json()
        rej = await client.post("/actions/reject", json={
            "action_id": r["action_id"], "approver_id": "a", "approver_role": "security", "reason": "no"})
        assert rej.json()["status"] == "rejected"
        again = await client.post("/actions/approve", json={
            "action_id": r["action_id"], "approver_id": "b", "approver_role": "security"})
        assert again.status_code == 409

    @pytest.mark.asyncio
    async def test_approved_action_executes_once_and_is_verified(self, client):
        await client.post("/scenarios/load?scenario_key=flagship")
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "isolate_endpoint", "arguments": {"host": "WS-01"},
            "user_role": "security_engineer"})).json()
        assert r["approval_scope"] == "security"
        await client.post("/actions/approve", json={
            "action_id": r["action_id"], "approver_id": "sec", "approver_role": "security"})
        e = (await client.post("/actions/execute", json={"action_id": r["action_id"]})).json()
        assert e["status"] == "completed"
        assert e["verification"]["verified"] is True
        assert (await client.post("/actions/execute", json={"action_id": r["action_id"]})).status_code == 409
        detail = (await client.get(f"/investigations/{inv}")).json()
        assert detail["actions"][0]["verification"]["verified"] is True
        audit = (await client.get(f"/audit?investigation_id={inv}")).json()
        assert any(a["policy_decision"] == "approved" for a in audit)

    @pytest.mark.asyncio
    async def test_unknown_target_is_treated_conservatively(self, client):
        inv = await _new_inv(client)
        r = (await client.post(f"/actions/propose?investigation_id={inv}", json={
            "tool_name": "isolate_endpoint", "arguments": {"host": "NO-SUCH-HOST"},
            "user_role": "admin"})).json()
        assert "ot_engineering" in r["approval_scope"]


class TestToolRegistryGuard:
    @pytest.mark.asyncio
    async def test_argument_cannot_self_authorize(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ctx = ToolContext(investigation_id=inv.id, state={"synthetic": True})
        res = await execute_tool(session, "isolate_endpoint", {"host": "WS-01", "approved": True}, ctx)
        assert not res.success and res.error == "approval_required"
        assert "isolated_hosts" not in ctx.state

    @pytest.mark.asyncio
    async def test_dry_run_is_allowed_without_approval(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ctx = ToolContext(investigation_id=inv.id, state={"synthetic": True})
        res = await execute_tool(session, "isolate_endpoint", {"host": "WS-01", "dry_run": True}, ctx)
        assert res.success and res.data["dry_run"] is True

    @pytest.mark.asyncio
    async def test_prohibited_tool_refused_even_when_authorized(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ctx = ToolContext(investigation_id=inv.id, state={"synthetic": True},
                          authorized_action_id="AC-FAKE")
        res = await execute_tool(session, "plc_control_action", {"plc": "PLC-07", "command": "x"}, ctx)
        assert res.error == "prohibited_by_policy"

    @pytest.mark.asyncio
    async def test_yara_deploy_compiles_rules(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ctx = ToolContext(investigation_id=inv.id, state={"synthetic": True})
        bad = await execute_tool(session, "deploy_yara", {"rule": "rule x { condition: nope }",
                                                         "dry_run": True}, ctx)
        assert not bad.success and bad.error.startswith("invalid_yara_rule")
        good = await execute_tool(session, "deploy_yara", {
            "rule": 'rule ok { strings: $a = "evil" condition: $a }', "dry_run": True}, ctx)
        assert good.success and good.data["rules"] == ["ok"]


# --------------------------------------------------------------------------- #
# Evidence integrity
# --------------------------------------------------------------------------- #

class TestEvidenceIntegrity:
    @pytest.mark.asyncio
    async def test_integrity_survives_database_round_trip(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ids = [(await _ev(session, inv.id, i)).id for i in range(3)]
        await session.commit()
        async with AsyncSessionLocal() as fresh:  # reload from SQLite
            for ev_id in ids:
                assert await verify_integrity(fresh, ev_id)
            row = await fresh.get(Evidence, ids[0])
            assert row.timestamp.tzinfo is not None
            assert (await verify_chain(fresh, inv.id))["intact"]

    @pytest.mark.asyncio
    async def test_chain_detects_deleted_row(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        evs = [await _ev(session, inv.id, i) for i in range(4)]
        await session.execute(delete(Evidence).where(Evidence.id == evs[1].id))
        await session.flush()
        report = await verify_chain(session, inv.id)
        assert not report["intact"]
        assert any("sequence_gap" in b["problem"] for b in report["chain_breaks"])

    @pytest.mark.asyncio
    async def test_chain_detects_forged_link(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        evs = [await _ev(session, inv.id, i) for i in range(3)]
        evs[2].chainHash = "0" * 64
        await session.flush()
        report = await verify_chain(session, inv.id)
        assert any(b["problem"] == "chain_hash_mismatch" for b in report["chain_breaks"])

    @pytest.mark.asyncio
    async def test_integrity_endpoint(self, client):
        inv = await _new_inv(client)
        await client.post(f"/evidence?investigation_id={inv}", json={
            "source": "manual", "source_type": "manual", "timestamp": TS.isoformat()})
        r = (await client.get(f"/investigations/{inv}/integrity")).json()
        assert r["intact"] and r["chained_count"] == 1

    @pytest.mark.asyncio
    async def test_dedupe_by_source_record_but_not_by_content_alone(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        a = await _ev(session, inv.id, 0, raw_reference="rec-1")
        b = await _ev(session, inv.id, 0, raw_reference="rec-1")
        assert a.id == b.id
        c = await _ev(session, inv.id, 0)  # identical content, no record id
        d = await _ev(session, inv.id, 0)
        assert c.id != d.id


# --------------------------------------------------------------------------- #
# Confidence math
# --------------------------------------------------------------------------- #

class TestConfidence:
    @pytest.mark.asyncio
    async def test_reobserving_evidence_does_not_inflate_confidence(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        ev = await _ev(session, inv.id)
        h = await HypothesisEngine.create(session, inv.id, "x", prior=0.35)
        await HypothesisEngine.add_support(session, h.id, ev.id)
        once = h.currentConfidence
        for _ in range(10):
            await HypothesisEngine.add_support(session, h.id, ev.id)
        assert h.currentConfidence == once
        assert h.status != "confirmed"

    def test_order_independent_and_diminishing(self):
        a = posterior_confidence(0.35, [0.9, 0.5, 0.7], [0.4])
        b = posterior_confidence(0.35, [0.7, 0.9, 0.5], [0.4])
        assert a == b
        many = posterior_confidence(0.35, [1.0] * 50, [])
        assert many < 0.99  # correlated corroboration saturates below certainty

    @pytest.mark.asyncio
    async def test_cannot_cite_nonexistent_or_foreign_evidence(self, session):
        inv = await create_investigation(session, title="t", objective="o")
        other = await create_investigation(session, title="t2", objective="o")
        foreign = await _ev(session, other.id)
        h = await HypothesisEngine.create(session, inv.id, "x")
        with pytest.raises(ValueError):
            await HypothesisEngine.add_support(session, h.id, "EV-DOES-NOT-EXIST")
        with pytest.raises(ValueError):
            await HypothesisEngine.add_support(session, h.id, foreign.id)


class TestClassification:
    def test_whole_word_matching(self):
        assert classify_hypothesis("Rootkit installed on another host") != "ot_plc_compromise"
        assert classify_hypothesis("Observed process variable deviation indicates process impact") \
            == "ot_plc_compromise"

    def test_every_plan_step_routes_to_a_registered_agent(self):
        from witness.agents import list_agent_names
        _validate_template_agents()

        class H:
            id = "H-TEST"
            statement = "Something with no category at all"
        steps = build_plans(H()).support_steps + build_plans(H()).counter_steps
        assert all(s["agent"] in list_agent_names() for s in steps)


# --------------------------------------------------------------------------- #
# Investigations end to end
# --------------------------------------------------------------------------- #

async def _run(session, key, **kw):
    scn = await load_scenario_into_db(session, key)
    ctx = get_scenario_telemetry_state(scn)
    inv = await create_investigation(session, title=key, objective="Investigate.")
    inv = await run_investigation(session, inv.id, ctx_state=ctx, max_iterations=kw.get("n", 5))
    return scn, inv


class TestInvestigationBehaviour:
    @pytest.mark.asyncio
    async def test_flagship_reconstructs_chain_without_duplicates(self, session):
        _, inv = await _run(session, "flagship")
        evs = (await session.execute(select(Evidence).where(
            Evidence.investigationId == inv.id))).scalars().all()
        assert len(evs) == len({e.contentHash for e in evs})
        kinds = {(e.normalizedData or {}).get("event_kind") for e in evs}
        assert {"email_click", "process_access", "decoded_command", "alarm_event",
                "plc_write"} <= kinds
        assert (await verify_chain(session, inv.id))["intact"]

    @pytest.mark.asyncio
    async def test_false_positive_concludes_authorized_activity(self, session):
        _, inv = await _run(session, "false_positive")
        hyps = await HypothesisEngine.list_for_investigation(session, inv.id)
        benign = next(h for h in hyps if "legitimate" in h.statement)
        ps = next(h for h in hyps if "PowerShell" in h.statement)
        assert benign.status in {"probable", "confirmed"}
        assert ps.contradictEvidenceIds and ps.status not in {"probable", "confirmed"}

    @pytest.mark.asyncio
    async def test_change_ticket_for_someone_else_is_not_an_alibi(self, session):
        scn = await load_scenario_into_db(session, "flagship")
        ctx = get_scenario_telemetry_state(scn)
        ctx["telemetry"].append({
            "id": "UNRELATED-TICKET", "source": "change_management",
            "timestamp": TS.isoformat(), "user": "bob",
            "normalized_data": {"event_kind": "change_ticket", "ticket_id": "CHG-X",
                                "user": "bob", "host": "WEB-01", "approver": "x"}})
        inv = await create_investigation(session, title="f", objective="o")
        inv = await run_investigation(session, inv.id, ctx_state=ctx, max_iterations=5)
        hyps = await HypothesisEngine.list_for_investigation(session, inv.id)
        assert all(not h.contradictEvidenceIds for h in hyps)

    @pytest.mark.asyncio
    async def test_response_planner_never_isolates_critical_infrastructure(self, session):
        from witness.models import Action
        _, inv = await _run(session, "brute_force")
        acts = (await session.execute(select(Action).where(
            Action.investigationId == inv.id))).scalars().all()
        assert acts, "expected containment proposals"
        assert not any(a.toolName == "isolate_endpoint" and a.arguments.get("host") == "DC-01"
                       for a in acts)
        assert all(a.status == "proposed" for a in acts)  # nothing executes autonomously

    @pytest.mark.asyncio
    async def test_completed_investigation_cannot_rerun(self, session):
        _, inv = await _run(session, "silent_compromise")
        assert inv.status == "completed"
        with pytest.raises(InvestigationStateError):
            await run_investigation(session, inv.id, ctx_state={})

    @pytest.mark.asyncio
    async def test_pause_takes_effect_and_resume_continues(self, session, monkeypatch):
        from witness.agents.specialized import PlannerAgent
        original = PlannerAgent.run
        calls = {"n": 0}

        async def pausing_run(self, inp):
            calls["n"] += 1
            if calls["n"] == 1:  # simulate a pause request arriving mid-iteration
                inv = await self.session.get(Investigation, inp.investigation_id)
                inv.status = "paused"
            return await original(self, inp)

        monkeypatch.setattr(PlannerAgent, "run", pausing_run)
        scn = await load_scenario_into_db(session, "flagship")
        ctx = get_scenario_telemetry_state(scn)
        inv = await create_investigation(session, title="p", objective="o")
        inv = await run_investigation(session, inv.id, ctx_state=ctx, max_iterations=5)
        assert inv.status == "paused" and inv.iteration == 1
        inv = await resume_investigation(session, inv.id, ctx_state=ctx, max_iterations=5)
        assert inv.status == "completed" and inv.iteration >= 2

    @pytest.mark.asyncio
    async def test_background_run_completes(self, client):
        scn = (await client.post("/scenarios/load?scenario_key=silent_compromise")).json()
        inv = await _new_inv(client)
        r = await client.post(f"/investigations/{inv}/run", json={
            "scenario_id": scn["id"], "background": True, "max_iterations": 3})
        assert r.json()["status"] == "running"
        for _ in range(200):
            d = (await client.get(f"/investigations/{inv}")).json()
            if d["status"] == "completed" and not d["running"]:
                break
            await asyncio.sleep(0.05)
        assert d["status"] == "completed"
        assert d["evidence"]


# --------------------------------------------------------------------------- #
# Benchmark honesty
# --------------------------------------------------------------------------- #

class TestBenchmarkHonesty:
    def _snapshot(self, **kw):
        base = {"hypotheses": [], "evidence": [], "timeline": [], "claims": [],
                "findings": [], "tasks": [], "actions": [], "coverage": {}}
        base.update(kw)
        return base

    def test_dangling_evidence_reference_counts_as_hallucination(self):
        gt = {"attack_start": "x", "techniques": ["T1110"], "stages": []}
        snap = self._snapshot(
            evidence=[{"id": "EV-1", "attack_techniques": ["T1110"]}],
            hypotheses=[{"status": "probable", "attack_techniques": ["T1110"],
                         "support_evidence_ids": ["EV-1", "EV-GHOST"]}],
            findings=[{"claim_type": "fact", "evidence_refs": []}])
        m = evaluate_investigation(snap, None, gt)
        assert m["hallucination_rate"] == pytest.approx(2 / 3)

    def test_detection_metrics_are_distinct(self):
        gt = {"attack_start": "x", "techniques": ["T1110"], "stages": []}
        snap = self._snapshot(hypotheses=[{"status": "probable", "attack_techniques": ["T9999"],
                                           "support_evidence_ids": []}])
        m = evaluate_investigation(snap, None, gt)
        assert m["detection"] == 1.0 and m["detection_correct"] == 0.0

    def test_evidence_backed_requires_mapping_evidence(self):
        gt = {"attack_start": "x", "techniques": ["T1110"], "stages": []}
        snap = self._snapshot(
            evidence=[{"id": "EV-1", "attack_techniques": ["T1059.001"]}],
            hypotheses=[{"status": "probable", "attack_techniques": ["T1110"],
                         "support_evidence_ids": ["EV-1"]}])
        assert evaluate_investigation(snap, None, gt)["evidence_backed_accuracy"] == 0.0

    def test_baseline_scored_by_same_formula(self):
        b = run_baseline("flagship")
        assert b["investigation_score"] == compute_investigation_score(b["metrics"])
        assert run_baseline("false_positive")["detection"] == 0.0  # no counter-evidence engine


# --------------------------------------------------------------------------- #
# API hardening
# --------------------------------------------------------------------------- #

class TestApiHardening:
    @pytest.mark.asyncio
    async def test_assets_endpoint_serializes(self, client):
        await client.post("/scenarios/load?scenario_key=flagship")
        r = await client.get("/assets")
        assert r.status_code == 200
        assert any(a["id"] == "DC-01" for a in r.json())

    @pytest.mark.asyncio
    async def test_pcap_path_traversal_blocked(self, client):
        inv = await _new_inv(client)
        r = await client.post(f"/pcap/analyze?investigation_id={inv}",
                              json={"pcap_path": "../../config.py"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_pcap_upload_rejects_non_pcap(self, client):
        inv = await _new_inv(client)
        r = await client.post(f"/pcap/upload?investigation_id={inv}",
                              files={"file": ("x.pcap", b"not a capture", "application/octet-stream")})
        assert r.status_code == 415

    @pytest.mark.asyncio
    async def test_reset_disabled_in_production(self, client, monkeypatch):
        monkeypatch.setattr(settings, "environment", "production")
        assert (await client.post("/system/reset")).status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_investigation_is_404_not_500(self, client):
        assert (await client.post("/evidence?investigation_id=NOPE", json={
            "source": "m", "source_type": "m", "timestamp": TS.isoformat()})).status_code == 404
        assert (await client.post("/investigations/NOPE/pause")).status_code == 404


class TestTokenAuth:
    @pytest_asyncio.fixture
    async def token_client(self, client, monkeypatch):
        monkeypatch.setattr(settings, "auth_mode", "token")
        monkeypatch.setattr(settings, "api_tokens",
                            "tok-sec-0123456789abcdef:sec:security_engineer,"
                            "tok-view-0123456789abcde:viewer1:viewer")
        yield client

    @pytest.mark.asyncio
    async def test_requests_without_token_are_rejected(self, token_client):
        assert (await token_client.get("/investigations")).status_code == 401
        assert (await token_client.get("/health")).status_code == 200
        bad = await token_client.get("/investigations", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401

    @pytest.mark.asyncio
    async def test_identity_and_role_come_from_token_not_body(self, token_client):
        h = {"Authorization": "Bearer tok-view-0123456789abcde"}
        who = (await token_client.get("/auth/whoami", headers=h)).json()
        assert who == {"user_id": "viewer1", "role": "viewer", "authenticated": True,
                       "auth_mode": "token"}
        inv = (await token_client.post("/investigations", headers=h,
                                       json={"title": "t", "objective": "o"})).json()["id"]
        # Claims admin in the body; the token says viewer -> denied.
        r = (await token_client.post(f"/actions/propose?investigation_id={inv}", headers=h, json={
            "tool_name": "isolate_endpoint", "arguments": {"host": "WS-01"},
            "user_role": "admin"})).json()
        assert r["status"] == "denied"

    @pytest.mark.asyncio
    async def test_role_must_be_allowed_to_sign_scope(self, token_client):
        sec = {"Authorization": "Bearer tok-sec-0123456789abcdef"}
        view = {"Authorization": "Bearer tok-view-0123456789abcde"}
        await token_client.post("/scenarios/load?scenario_key=flagship", headers=sec)
        inv = (await token_client.post("/investigations", headers=sec,
                                       json={"title": "t", "objective": "o"})).json()["id"]
        aid = (await token_client.post(f"/actions/propose?investigation_id={inv}", headers=view, json={
            "tool_name": "block_ioc", "arguments": {"ioc": "9.9.9.9"}})).json()["action_id"]
        # viewer lacks WRITE_RESPONSE -> denied regardless; propose as security engineer instead
        aid = (await token_client.post(f"/actions/propose?investigation_id={inv}", headers=sec, json={
            "tool_name": "block_ioc", "arguments": {"ioc": "9.9.9.9"}})).json()["action_id"]
        r = await token_client.post("/actions/approve", headers=view, json={
            "action_id": aid, "approver_role": "security"})
        assert r.status_code == 403


class TestStartupAndMigration:
    def test_production_without_auth_refuses_to_start(self, monkeypatch):
        from witness.api.auth import check_startup_security
        monkeypatch.setattr(settings, "environment", "production")
        monkeypatch.setattr(settings, "auth_mode", "none")
        monkeypatch.setattr(settings, "allow_insecure_production", False)
        with pytest.raises(RuntimeError):
            check_startup_security()

    def test_malformed_tokens_rejected(self, monkeypatch):
        monkeypatch.setattr(settings, "api_tokens", "only:two")
        with pytest.raises(ValueError):
            settings.parsed_api_tokens()

    @pytest.mark.asyncio
    async def test_missing_columns_are_added_to_old_databases(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from witness.db import _add_missing_columns
        eng = create_async_engine(f"sqlite+aiosqlite:///{(tmp_path / 'old.db').as_posix()}")
        async with eng.begin() as conn:
            await conn.exec_driver_sql(
                "CREATE TABLE evidence (id VARCHAR PRIMARY KEY, investigationId VARCHAR NOT NULL, "
                "source VARCHAR NOT NULL, sourceType VARCHAR NOT NULL, timestamp DATETIME NOT NULL, "
                "contentHash VARCHAR NOT NULL)")
            added = await conn.run_sync(_add_missing_columns)
        await eng.dispose()
        assert "evidence.sequence" in added and "evidence.chainHash" in added


class TestPrivacyMode:
    def test_local_endpoints_allowed(self):
        from witness.models_layer.base import endpoint_is_local
        for ep in ("http://localhost:11434/v1", "http://127.0.0.1:8080", "http://10.1.2.3/v1",
                   "http://ollama:11434", "http://[::1]:8000"):
            assert endpoint_is_local(ep), ep
        for ep in ("https://api.openai.com/v1", "http://8.8.8.8", "https://models.example.com"):
            assert not endpoint_is_local(ep), ep

    def test_remote_endpoint_refused_under_local_only(self, monkeypatch):
        from witness.models_layer import base
        monkeypatch.setattr(settings, "model_provider", "openai_compatible")
        monkeypatch.setattr(settings, "model_endpoint", "https://api.openai.com/v1")
        monkeypatch.setattr(settings, "privacy_mode", "LOCAL_ONLY")
        monkeypatch.setattr(base, "_providers", {})
        with pytest.raises(base.PrivacyViolation):
            base.get_provider("medium")
        monkeypatch.setattr(settings, "privacy_mode", "ALLOW_EXTERNAL")
        assert base.get_provider("medium") is not None


class TestAttackCatalogueConsistency:
    def test_every_technique_used_is_in_the_catalogue(self):
        """Rules, hypothesis templates and ground truth may only use technique
        IDs the catalogue knows; otherwise model proposals citing them would be
        rejected as 'unknown'."""
        from witness.attack.mapper import _RULES, ENTERPRISE_TECHNIQUES, ICS_TECHNIQUES
        from witness.agents.orchestrator import HYPOTHESIS_TEMPLATES
        from witness.range.cyber_range import ALL_SCENARIOS
        known = set(ENTERPRISE_TECHNIQUES) | set(ICS_TECHNIQUES)
        used = {t for _, t in _RULES}
        used |= {t for h in HYPOTHESIS_TEMPLATES for t in h["attack"]}
        used |= {t for b in ALL_SCENARIOS.values() for t in b()["ground_truth"]["techniques"]}
        assert used <= known, sorted(used - known)

    def test_ics_ids_carry_their_mitre_names(self):
        from witness.attack.mapper import ICS_TECHNIQUES as ics
        assert ics["T0855"] == "Unauthorized Command Message"
        assert ics["T0831"] == "Manipulation of Control"
        assert ics["T0878"] == "Alarm Suppression"
        assert ics["T0834"] == "Native API"
        assert ics["T0877"] == "I/O Module Discovery"
