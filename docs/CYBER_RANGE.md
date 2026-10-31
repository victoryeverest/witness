# WITNESS Cyber Range (§53, §54, §55)

> Build a safe simulated industrial environment for evaluation. It must never connect to real industrial equipment.

## What's in the range

The cyber range ships with synthetic IT + OT assets, telemetry fixtures for each scenario, and hidden ground truth. Every asset is clearly marked `SYNTHETIC` in the UI and every evidence row has `synthetic=True`.

## Asset inventory

### IT assets (enterprise zone, 10.10.1.0/24)

| ID | Kind | Hostname | IP | Criticality |
|---|---|---|---|---|
| DC-01 | host | DC-01 | 10.10.1.10 | high |
| WEB-01 | host | WEB-01 | 10.10.1.20 | medium |
| FILE-01 | host | FILE-01 | 10.10.1.30 | medium |
| WS-01 | host (laptop) | WS-01 | 10.10.1.50 | low |
| WS-02 | host (laptop) | WS-02 | 10.10.1.51 | low |
| VPN-01 | host (gateway) | VPN-01 | 10.10.1.100 | high |

### OT assets (supervisory zone, 10.20.1.0/24; control zone, 10.30.1.0/24)

| ID | OT type | Hostname | IP | Criticality | Physical process | Safety impact |
|---|---|---|---|---|---|---|
| EWS-01 | engineering_workstation | EWS-01 | 10.20.1.10 | safety_critical | Reactor-A | serious |
| SCADA-01 | scada_server | SCADA-01 | 10.20.1.20 | safety_critical | Reactor-A | serious |
| HMI-01 | hmi | HMI-01 | 10.20.1.30 | high | Reactor-A | serious |
| HIST-01 | historian | HIST-01 | 10.20.1.40 | high | Reactor-A | minor |
| PLC-01 | plc | PLC-01 | 10.30.1.1 | safety_critical | Reactor-A | catastrophic |
| PLC-02 | plc | PLC-02 | 10.30.1.2 | safety_critical | Reactor-B | catastrophic |
| PLC-07 | plc | PLC-07 | 10.30.1.7 | high | Reactor-G | serious |

### Identities

| ID | Name | Domain |
|---|---|---|
| U-alice | Alice Chen | corporate |
| U-bob | Bob Smith | corporate |
| U-engineer | Engineering Account | supervisory |

## Static asset relationships (Purdue model)

```
Corporate IT (10.10.1.0/24)
     │
     │  Enterprise Firewall
     ▼
Industrial DMZ  (not modeled in range — out of scope)
     │
     │  OT Firewall
     ▼
Supervisory Network (10.20.1.0/24)
     │
     ├── EWS-01 ─── controls ──→ PLC-01, PLC-02, PLC-07
     ├── SCADA-01 ── controls ──→ PLC-01, PLC-02, PLC-07
     ├── HMI-01 ─── monitored_by ──→ SCADA-01
     └── HIST-01 ── monitored_by ──→ SCADA-01
     │
     ▼
Control Network (10.30.1.0/24)
     │
     ├── PLC-01 (Reactor-A, safety-critical)
     ├── PLC-02 (Reactor-B, safety-critical)
     └── PLC-07 (Reactor-G, NOT safety-critical by default)
     │
     ▼
Physical Process
```

The graph understands trust boundaries (§23). The OT safety engine uses these dependencies when classifying proposed actions.

## Telemetry sources

The range produces synthetic telemetry from:
- `email_gateway` — phishing email arrivals
- `sysmon` — EID 1 (process), 10 (process access)
- `windows_event_log` — EID 4624 (success auth), 4625 (failed auth), 7045 (service create)
- `vpn_log` — VPN authentication
- `zeek` — `conn` (network flows), `dns` (DNS queries)
- `ot:modbus` — Modbus read/write operations
- `process_variable` — sensor / setpoint values
- `alarm_system` — alarm events (with suppression flag)
- `maintenance_log` — scheduled maintenance windows
- `change_management` — change tickets

Each telemetry row has the same normalized shape that the production telemetry normalizers would produce — the tool registry treats range telemetry identically to production telemetry.

## Scenarios

### 1. Flagship IT→OT Intrusion (`flagship`)

```
t=0    : Alice (WS-01) receives phishing email with link to evil-c2.example.com
t=30   : Alice clicks link, encoded PowerShell runs (downloader)
t=45   : DNS resolution of evil-c2.example.com (newly-registered domain)
t=45   : HTTPS connection to 198.51.100.7 (download)
t=120  : LSASS memory access (procdump-style)
t=200  : VPN authentication as Alice from 198.51.100.7
t=300  : Lateral authentication to EWS-01 via SMB
t=300  : SMB connection WS-01 → EWS-01:445
t=310  : Service creation on EWS-01 (persistence)
t=420  : Engineering software launch on EWS-01
t=540  : Modbus write to PLC-07 register 40001, value 75, UNAUTHORIZED
t=540  : Process variable Reactor-Temp on PLC-07 deviates (92.0 vs expected 60-80)
t=545  : Alarm T-HIGH-7 suppressed by EWS-01
t=480  : Maintenance log shows scheduled=False — meaning the maintenance was NOT authorized
```

The agent must reason about the maintenance log: `scheduled=False` is itself evidence *against* benign maintenance, not for it.

**Hidden ground truth**: see `flagship_scenario()` in `witness/range/cyber_range.py`. The agent never sees this; the benchmark verifies its reconstruction.

### 2. Brute Force Authentication (`brute_force`)

20 failed authentications (EID 4625) for `admin` from `198.51.100.7`, followed by a successful auth. The identity analyst's brute-force detection should fire (≥5 failures grouped by user).

### 3. False Positive (`false_positive`)

An authorized engineer (`ot-engineer`) runs encoded PowerShell on EWS-01 during a scheduled maintenance window. A change ticket `CHG-2025-09-04-001` exists with approver `ot-lead`. The contradiction analyst should find this ticket and reject the malicious-PowerShell hypothesis.

### 4. Silent Compromise (`silent_compromise`)

Five periodic short connections from WS-01 to `198.51.100.7:443`. No initial alert. The network analyst's beaconing detection should fire (≥3 connections to the same dst_ip).

## Threat intel fixtures

The range ships with a small synthetic TI set:
- `evil-c2.example.com` (domain, newly-registered, T1071.004)
- `198.51.100.7` (IP, T1071.001)

These are TEST-NET-2 / documentation-reserved IPs and the `.example.com` domain — they will never resolve to real infrastructure.

## Using the range

```bash
# Load a scenario
curl -X POST 'http://localhost:8000/scenarios/load?scenario_key=flagship'

# List available scenarios
curl 'http://localhost:8000/scenarios/available'

# List loaded scenarios
curl 'http://localhost:8000/scenarios'

# Run a benchmark (loads + investigates + evaluates)
curl -X POST 'http://localhost:8000/benchmarks/run' \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id": "flagship"}'
```

## What the range is NOT

- **Not a packet generator** — the range produces pre-built telemetry fixtures. It does not simulate actual protocol traffic.
- **Not a PLC emulator** — the range does not execute real Modbus or ladder logic. The `plc_control_action` tool only writes to a simulated state dict.
- **Not connected to real equipment** — the range is isolated by design (§53).

## Adding a new scenario

1. Write a builder function in `witness/range/cyber_range.py` that returns `{name, scope, difficulty, telemetry, ground_truth}`.
2. Register it in `ALL_SCENARIOS`.
3. Add a test in `tests/test_witness.py::TestCyberRange` asserting the ground truth has the expected techniques.

The benchmark picks up new scenarios automatically via `ALL_SCENARIOS`.
