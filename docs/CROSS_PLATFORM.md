# WITNESS Cross-Platform Setup Guide

WITNESS runs natively on Linux, macOS, and Windows. All paths use `pathlib.Path`, the database is SQLite (zero-config, cross-platform), and the backend binds to `0.0.0.0` so it's reachable through any reverse proxy.

## Prerequisites

| Component | Version | Linux | macOS | Windows |
|---|---|---|---|---|
| Python | 3.11+ | apt / dnf / pyenv | brew install python | python.org or Microsoft Store |
| Node.js (or Bun) | 18+ / latest | apt / nvm | brew install node | nodejs.org |
| Git | any | apt | brew install git | git-scm.com |
| Docker (optional) | latest | apt | Docker Desktop | Docker Desktop |

For Windows users: **Docker Desktop** (with WSL2) is the easiest path. The native install also works (Python + Node on Windows), but `yara-python` needs the pre-built Windows wheel (pip handles this automatically) and `scapy` benefits from `Npcap` for live capture (only needed if you want to capture live traffic — PCAP file parsing works without it).

## Quick start

### Linux / macOS (bash)

```bash
git clone https://github.com/victoryeverest/witness.git witness
cd witness
bash scripts/start.sh
# In a separate terminal:
bun install && bun run dev
```

### Windows (PowerShell)

```powershell
git clone https://github.com/victoryeverest/witness.git witness
cd witness
pwsh scripts/start.ps1
# In a separate terminal:
bun install ; bun run dev   # or: npm install ; npm run dev
```

### Windows (cmd.exe)

```cmd
git clone https://github.com/victoryeverest/witness.git witness
cd witness
scripts\start.bat
:: In a separate terminal:
bun install & bun run dev
```

### Docker Compose (any OS)

```bash
git clone https://github.com/victoryeverest/witness.git witness
cd witness
cp .env.example .env
docker compose up --build
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# Gateway: http://localhost
```

## Platform-specific notes

### Linux

- All Python deps install cleanly via pip. `yara-python` requires `libyara-dev`; the install script uses `apt` for this on Debian/Ubuntu.
- On RHEL/Fedora: `sudo dnf install yara-devel libpcap-devel`
- On Alpine: `apk add yara-dev libpcap-dev`

### macOS

- Use Homebrew: `brew install yara libpcap`
- Apple Silicon (M1/M2/M3): yara-python ships pre-built wheels for arm64.
- The Python venv path differs slightly (`bin/` vs `Scripts/`) but the start script handles it.

### Windows

- `yara-python`: pre-built wheels for Windows are on PyPI, no compile needed.
- `scapy`: PCAP file parsing works out of the box. For live capture, install [Npcap](https://npcap.com/) (the modern WinPcap replacement).
- Path handling: all WITNESS code uses `pathlib.Path`, so backslashes / forward slashes work interchangeably. The data dir defaults to `data/witness.db` relative to the project root on all OSes.
- For production, Docker Compose adds a Caddy gateway in front of the console and API.

## Database

Default: SQLite at `data/witness.db`. Cross-platform, zero-config, file-based. Suitable for development, demos, and small deployments.

For production: PostgreSQL. Set `WITNESS_DATABASE_URL=postgresql+asyncpg://user:pass@host/db` and `pip install asyncpg`. Everything else stays the same.

## Files / directories

| Path | Purpose | Cross-platform? |
|---|---|---|
| `data/witness.db` | SQLite database (default) | ✓ |
| `data/knowledge/` | MITRE ATT&CK STIX bundle cache | ✓ |
| `/tmp/witness-backend.log` | Backend log (Linux/macOS) | — |
| `%TEMP%\witness-backend.log` | Backend log (Windows) | — |
| `scripts/start.sh` | Linux/macOS start | ✓ |
| `scripts/start.bat` | Windows cmd start | ✓ |
| `scripts/start.ps1` | PowerShell 5.1 / 7+ start | ✓ |
| `docker-compose.yml` | Full-stack deployment | ✓ (Docker Desktop) |

## CI matrix (`.github/workflows/ci.yml`)

Runs on every push / pull request:

| OS | Python versions | What runs |
|---|---|---|
| ubuntu-latest | 3.11, 3.12 | full test suite + lint + coverage |
| macos-latest | 3.11, 3.12 | full test suite |
| windows-latest | 3.11, 3.12 | full test suite |

Plus: frontend lint + build, pip-audit security scan, Docker image build, end-to-end smoke test via docker compose.

## Troubleshooting

### `yara-python` install fails on Linux

```bash
sudo apt install build-essential libyara-dev
pip install yara-python --no-binary :all:
```

### `yara-python` install fails on macOS

```bash
brew install yara
pip install yara-python --no-binary :all:
```

### `scapy` errors on Windows when capturing live

Install Npcap: https://npcap.com/dist/

PCAP **file** parsing (using `dpkt`) works without Npcap. Npcap is only needed if you want `sniff()` for live capture.

### Backend not reachable through gateway

Make sure the backend binds to `0.0.0.0` (not `127.0.0.1`). The start scripts handle this; if you start uvicorn manually, pass `--host 0.0.0.0`.

### Port 8000 already in use

The start scripts attempt to kill any existing process on port 8000. If that fails:

- Linux/macOS: `lsof -ti:8000 | xargs kill -9`
- Windows: `netstat -ano | findstr :8000` (find the PID, then `taskkill /F /PID <pid>`)

### Database is locked

Delete `data/witness.db` and restart. The DB is recreated on next startup with all tables and the builtin detection rules + MITRE ATT&CK knowledge loaded.
