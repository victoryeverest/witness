# WITNESS Deployment Guide (§70)

## Deployment modes

### 1. Single-machine development (default)

```bash
# Backend
cd backend
pip install -r requirements.txt
python3 -m uvicorn witness.api.app:app --host 0.0.0.0 --port 8000

# Frontend
cd ..
bun install
bun run dev
```

- Backend: SQLite at `data/witness.db`
- Frontend: Next.js dev server on port 3000
- Gateway (docker compose): Caddy on port 80 → `/api/witness/*` to the backend (prefix stripped), everything else to the console

### 2. Production (single server)

```bash
# Use gunicorn + uvicorn workers for production
cd backend
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker witness.api.app:app --bind 0.0.0.0:8000

# Build the frontend
cd ..
bun run build
bun run start   # production Next.js server on port 3000
```

- Backend: PostgreSQL (`WITNESS_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/witness`)
- Frontend: production Next.js server
- Reverse proxy: nginx or Caddy → backend + frontend

### 3. Container deployment

```dockerfile
# docker-compose.yml
version: '3.8'
services:
  witness-backend:
    build: ./backend
    ports: ["8000:8000"]
    environment:
      - WITNESS_DATABASE_URL=postgresql+asyncpg://witness:witness@db:5432/witness
      - WITNESS_MODEL_PROVIDER=mock
      - WITNESS_PRIVACY_MODE=LOCAL_ONLY
    depends_on: [db]
  witness-frontend:
    build: .
    ports: ["3000:3000"]
    environment:
      - NEXT_PUBLIC_API_BASE=http://witness-backend:8000
  db:
    image: postgres:16
    environment:
      - POSTGRES_USER=witness
      - POSTGRES_PASSWORD=witness
      - POSTGRES_DB=witness
    volumes: [pgdata:/var/lib/postgresql/data]
volumes:
  pgdata:
```

Any reverse proxy works: forward `/api/witness/*` to the backend with the prefix stripped (see `docker/Caddyfile.prod`) and everything else to the console. Without a proxy, `next start` forwards `/api/witness/*` itself using `WITNESS_BACKEND_URL`.

### 4. Air-gapped deployment

Per §97, the tournament build remains functional without external AI APIs.

```bash
# On the air-gapped host:
export WITNESS_MODEL_PROVIDER=mock
export WITNESS_PRIVACY_MODE=LOCAL_ONLY
export WITNESS_DATABASE_URL=sqlite+aiosqlite:///data/witness.db

# (Optional) Pre-load MITRE ATT&CK knowledge packs via offline tarball
# (Optional) Pre-load threat intel via offline STIX bundle

# Start
python3 -m uvicorn witness.api.app:app --host 0.0.0.0 --port 8000
```

No outbound network calls. No external API keys. The `mock` provider is fully deterministic.

### 5. Local GPU deployment (with real LLM)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b

# Configure WITNESS to use Ollama
export WITNESS_MODEL_PROVIDER=ollama
export WITNESS_MODEL_ENDPOINT=http://localhost:11434
export WITNESS_MODEL_SMALL=qwen3:8b
export WITNESS_MODEL_MEDIUM=qwen3:8b
export WITNESS_MODEL_STRONG=qwen3:8b

# Start
python3 -m uvicorn witness.api.app:app --host 0.0.0.0 --port 8000
```

## Configuration

All settings are environment variables prefixed `WITNESS_`:

| Variable | Default | Production recommendation |
|---|---|---|
| `WITNESS_ENVIRONMENT` | `development` | `production` |
| `WITNESS_DATABASE_URL` | `sqlite+aiosqlite:///data/witness.db` | PostgreSQL with `asyncpg` driver |
| `WITNESS_MODEL_PROVIDER` | `mock` | `openai_compatible` or `ollama` for LLM-enabled |
| `WITNESS_MODEL_ENDPOINT` | `` | URL of LLM endpoint |
| `WITNESS_MODEL_API_KEY` | `` | API key for the LLM endpoint |
| `WITNESS_PRIVACY_MODE` | `LOCAL_ONLY` | Keep `LOCAL_ONLY` for sensitive environments |
| `WITNESS_REQUIRE_APPROVAL_HIGH_RISK` | `true` | Keep `true` — never disable in production |
| `WITNESS_OT_REQUIRES_DUAL_APPROVAL` | `true` | Keep `true` — non-negotiable per §69 |
| `WITNESS_INVESTIGATION_MAX_ITERATIONS` | `25` | Lower for faster demos; raise for deeper investigations |
| `WITNESS_INVESTIGATION_CONFIDENCE_THRESHOLD` | `0.75` | Lower for more cautious closure; raise for stricter |
| `WITNESS_INVESTIGATION_STEP_TIMEOUT_SECONDS` | `60` | Lower for faster failure; raise for slow LLMs |

## Health check

```bash
curl http://localhost:8000/health
# {"status": "ok", "version": "1.0.0", "model_provider": "mock", "model_assist": false, "privacy_mode": "LOCAL_ONLY", "auth_mode": "none"}
```

## Observability (§71)

WITNESS uses structured JSON logging via Python's `logging` module. The JSON formatter in `witness/utils/logging.py` adds:
- `ts` — ISO-8601 UTC timestamp
- `level` — log level
- `logger` — logger name
- `msg` — log message
- context fields: `investigation_id`, `incident_id`, `agent`, `tool`, `evidence_id`, `hypothesis_id`, `task_id`, `actor`

For production:
- Pipe stdout into your log aggregator (Loki, ELK, CloudWatch, Datadog).
- Add OpenTelemetry traces for the runtime loop (not included in the demo build).
- The `AuditLog` table is the authoritative audit trail — replicate it to a SIEM for long-term retention.

## Secrets

WITNESS does NOT store secrets in the DB:
- User password hashes are stored in `User.passwordHash` (use bcrypt/argon2).
- API keys for LLM endpoints live in env vars (`WITNESS_MODEL_API_KEY`), never in the DB.
- The audit log records arguments but the `redact()` helper in `witness/utils/crypto.py` can mask sensitive values before logging.

Never commit `.env` files. Use `.env.example` (provided) as a template.

## Database migrations

The demo build uses `Base.metadata.create_all()` at startup — no migrations needed for SQLite. For production with PostgreSQL:

```bash
# Install Alembic
pip install alembic

# Initialize
cd backend
alembic init alembic

# Configure alembic.ini to use the WITNESS_DATABASE_URL
# Configure env.py to import witness.models.Base.metadata

# Generate first migration
alembic revision --autogenerate -m "initial schema"

# Apply
alembic upgrade head
```

## Backup

```bash
# SQLite
cp data/witness.db data/witness-backup-$(date +%Y%m%d).db

# PostgreSQL
pg_dump -U witness -d witness > witness-backup-$(date +%Y%m%d).sql
```

The `Evidence.contentHash` and `chainOfCustody` fields make tampering with restored backups detectable.

## Release checklist (§125)

Before declaring completion:

- [ ] Fresh clone works
- [ ] Documentation builds
- [ ] Docker deployment works
- [ ] Database initializes
- [ ] Backend starts
- [ ] Frontend starts
- [ ] Model connects (or mock provider works)
- [ ] Agent executes
- [ ] Tools execute
- [ ] Evidence stored
- [ ] Graph works
- [ ] Timeline works
- [ ] ATT&CK mapping works
- [ ] OT simulation works
- [ ] Human approval works
- [ ] Audit works
- [ ] Reports work
- [ ] Benchmarks work
- [ ] Tests pass (`cd backend && python -m pytest`, 171 tests)
- [ ] `WITNESS_AUTH_MODE=token` with long random tokens; `WITNESS_ALLOW_INSECURE_PRODUCTION` unset
- [ ] `GET /investigations/{id}/integrity` reports `intact: true` for retained cases
- [ ] Security tests pass
- [ ] No secrets committed
- [ ] No fake functionality
- [ ] No critical TODOs

## Tournament submission materials (§145)

The proposal should emphasize:

> WITNESS does not make cybersecurity decisions by pretending uncertainty doesn't exist. It makes uncertainty explicit and investigates it.

Include:
- technical proposal (this docs/ directory)
- architecture (docs/ARCHITECTURE.md)
- demo (POST /demo/flagship)
- README.md
- benchmark results (POST /benchmarks/run)
- evaluation methodology (docs/BENCHMARK.md)
- security model (docs/THREAT_MODEL.md)
- OT safety model (docs/OT_SAFETY.md)
- model card (docs/MODEL_ARCHITECTURE.md)
- dataset card (docs/CYBER_RANGE.md)
- documentation (docs/)
- screenshots (the console at http://localhost)
- architecture diagrams (docs/ARCHITECTURE.md)
- demo video script (the flagship demo end-to-end with voiceover)
