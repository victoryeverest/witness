# WITNESS backend container — Python 3.12 + FastAPI + SQLite by default.
# Cross-platform: same image runs on Linux, macOS (Docker Desktop), and Windows (Docker Desktop).
# Build: docker build -t witness-backend -f docker/backend.Dockerfile backend/
# Run:   docker run -p 8000:8000 -v $(pwd)/data:/app/data witness-backend

FROM python:3.12-slim

# Install build deps for yara-python, scapy, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libyara-dev libpcap-dev git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for layer caching. requirements.txt is the single
# source of truth (it includes sqlalchemy[asyncio], which needs greenlet).
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the witness package
COPY witness ./witness
COPY tests ./tests

# Expose port + create data dir
EXPOSE 8000
RUN mkdir -p /app/data

# Bind to 0.0.0.0 so the host can reach it. Per spec §70 the backend must be
# containerized and the same image must work in dev / staging / production.
ENV WITNESS_HOST=0.0.0.0
ENV WITNESS_PORT=8000
# Four slashes = absolute path. With three, SQLite resolved it relative to
# WORKDIR (/app/app/data/...): outside the volume, and a directory that does
# not exist, so the database could not be opened.
ENV WITNESS_DATABASE_URL=sqlite+aiosqlite:////app/data/witness.db
ENV WITNESS_KNOWLEDGE_DIR=/app/data/knowledge
ENV WITNESS_PCAP_DIR=/app/data/pcaps

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "witness.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
