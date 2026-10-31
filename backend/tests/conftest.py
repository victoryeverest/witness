"""Test bootstrap.

Runs before any `witness` module is imported, so settings pick these up:
- a throwaway SQLite database per test session (the suite calls drop_db(),
  so it must never touch the developer's `data/witness.db`).
- no MITRE download / autoload, test environment, a temp PCAP directory.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

_TMP = Path(tempfile.mkdtemp(prefix="witness-tests-"))
os.environ["WITNESS_DATABASE_URL"] = f"sqlite+aiosqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["WITNESS_ENVIRONMENT"] = "test"
os.environ["WITNESS_AUTOLOAD_ATTACK"] = "false"
os.environ["WITNESS_AUTH_MODE"] = "none"
os.environ["WITNESS_PCAP_DIR"] = str(_TMP / "pcaps")
os.environ.pop("WITNESS_API_TOKENS", None)


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP, ignore_errors=True)
