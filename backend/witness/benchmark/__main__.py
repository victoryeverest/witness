"""WITNESS-Bench from the command line.

    python -m witness.benchmark                  # all scenarios
    python -m witness.benchmark flagship -v      # one scenario, show hypotheses/actions
    python -m witness.benchmark --json           # machine-readable

Runs against a throwaway SQLite database (never your configured one) and
prints WITNESS next to the non-agent baseline, both scored by the same
evaluator.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile


def _isolate_database() -> None:
    tmp = tempfile.mkdtemp(prefix="witness-bench-")
    os.environ["WITNESS_DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp}/bench.db".replace("\\", "/")
    os.environ.setdefault("WITNESS_AUTOLOAD_ATTACK", "false")
    os.environ.setdefault("WITNESS_ENVIRONMENT", "test")


COLUMNS = [("investigation_score", "score"), ("detection", "detect"),
           ("detection_correct", "det_ok"), ("attack_technique_accuracy", "atk_acc"),
           ("evidence_backed_accuracy", "ev_back"), ("hallucination_rate", "halluc"),
           ("ot_safety_score", "ot_safe"), ("remediation_quality", "remed")]


async def _run(keys: list[str], verbose: bool) -> list[dict]:
    from sqlalchemy import select
    from ..db import AsyncSessionLocal, init_db
    from ..models import Action
    from ..core.hypothesis import HypothesisEngine
    from ..core.evidence import verify_chain
    from .bench import run_benchmark, run_baseline

    await init_db()
    rows = []
    for key in keys:
        async with AsyncSessionLocal() as s:
            run = await run_benchmark(s, key)
            await s.commit()
            row = {"scenario": key, "witness": run.metrics, "baseline": run_baseline(key)["metrics"],
                   "chain_intact": (await verify_chain(s, run.investigationId))["intact"]}
            if verbose:
                hyps = await HypothesisEngine.list_for_investigation(s, run.investigationId)
                row["hypotheses"] = [(h.currentConfidence, h.status, h.statement) for h in hyps]
                acts = (await s.execute(select(Action).where(
                    Action.investigationId == run.investigationId))).scalars().all()
                row["actions"] = [(a.toolName, a.arguments, a.status, a.approvalScope) for a in acts]
            rows.append(row)
    return rows


def _fmt(v) -> str:
    return "  n/a" if v is None else f"{float(v):5.2f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m witness.benchmark", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", help="scenario keys (default: all)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show hypotheses and actions")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    _isolate_database()
    logging.disable(logging.CRITICAL)
    from ..range.cyber_range import ALL_SCENARIOS
    keys = args.scenarios or list(ALL_SCENARIOS)
    unknown = [k for k in keys if k not in ALL_SCENARIOS]
    if unknown:
        ap.error(f"unknown scenario(s): {', '.join(unknown)}; choose from {', '.join(ALL_SCENARIOS)}")
    rows = asyncio.run(_run(keys, args.verbose))

    if args.json:
        json.dump(rows, sys.stdout, indent=2, default=str)
        print()
        return 0
    header = f"{'scenario':<18} {'system':<9}" + "".join(f"{label:>8}" for _, label in COLUMNS)
    print(header)
    print("-" * len(header))
    for r in rows:
        for system in ("witness", "baseline"):
            m = r[system]
            print(f"{r['scenario'] if system == 'witness' else '':<18} {system:<9}"
                  + "".join(f"{_fmt(m.get(k)):>8}" for k, _ in COLUMNS))
        print(f"{'':<18} evidence chain intact: {r['chain_intact']}")
        w = r["witness"]
        if w.get("model_calls"):
            print(f"{'':<18} model: {w['model_calls']} call(s), {w.get('model_outputs_accepted', 0)} "
                  f"accepted, {w.get('model_hypotheses', 0)} hypothesis(es) proposed, "
                  f"{w.get('tokens_used', 0)} tokens")
        for conf, status, stmt in r.get("hypotheses", []):
            print(f"{'':<20}{conf:.2f} {status:<9} {stmt}")
        for tool, a, status, scope in r.get("actions", []):
            print(f"{'':<20}action {tool} {a} -> {status} (approval: {scope or 'n/a'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
