"""Time normalization utilities.

The timeline engine must reconcile telemetry from many sources with
different clocks (§11). We standardize on UTC ISO-8601 with offset metadata
so we can both sort deterministically and surface clock-skew to the analyst.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        # Naive datetime: assume the source's local clock. Tag it as UTC for
        # sorting purposes; the timeline engine will surface the assumption.
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso(s: str) -> datetime:
    """Parse an ISO-8601 string, accepting trailing 'Z'."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return to_utc(dt)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def iso(dt: datetime) -> str:
    return to_utc(dt).isoformat().replace("+00:00", "Z")


def clock_skew_seconds(a: datetime, b: datetime) -> float:
    """Return the signed skew in seconds between two timestamps (a - b)."""
    return (to_utc(a) - to_utc(b)).total_seconds()


def window_contains(start: Optional[datetime], end: Optional[datetime],
                    t: datetime) -> bool:
    if start and to_utc(t) < to_utc(start):
        return False
    if end and to_utc(t) > to_utc(end):
        return False
    return True
