"""WITNESS backend launcher.

Usage:
    python -m witness.backend    (or)
    uvicorn witness.api.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import uvicorn

from .config import settings


def main() -> None:
    uvicorn.run(
        "witness.api.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=settings.environment == "development",
    )


if __name__ == "__main__":
    main()
