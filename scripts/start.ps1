#!/usr/bin/env pwsh
# Start the WITNESS backend (Windows PowerShell 5.1 or PowerShell 7+ on any OS),
# then print how to start the console.
#
#   pwsh scripts/start.ps1            # http://127.0.0.1:8000
#   $env:WITNESS_PORT = 8010; pwsh scripts/start.ps1

$ErrorActionPreference = 'Stop'
$ProjRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$Backend  = Join-Path $ProjRoot 'backend'
$Port     = if ($env:WITNESS_PORT) { $env:WITNESS_PORT } else { '8000' }
$TempDir  = [System.IO.Path]::GetTempPath()
$OutLog   = Join-Path $TempDir 'witness-backend.out.log'
$ErrLog   = Join-Path $TempDir 'witness-backend.log'
$PidFile  = Join-Path $TempDir 'witness-backend.pid'

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $Python) {
    Write-Error 'python not found in PATH. Install Python 3.11+ from https://python.org'
    exit 1
}
$Python = $Python.Source
Write-Host "Using $(& $Python --version 2>&1)"

# Install from requirements.txt (the single source of truth) if anything is missing.
& $Python -c 'import fastapi, sqlalchemy, greenlet, aiosqlite, pydantic_settings' 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Installing Python dependencies from backend/requirements.txt ...'
    & $Python -m pip install --quiet -r (Join-Path $Backend 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { Write-Error 'pip install failed'; exit 1 }
}

New-Item -ItemType Directory -Force -Path (Join-Path $ProjRoot 'data') | Out-Null

# Stop a previous instance started by this script.
if (Test-Path $PidFile) {
    $old = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($old -and (Get-Process -Id $old -ErrorAction SilentlyContinue)) {
        Write-Host "Stopping previous backend (PID $old)"
        Stop-Process -Id $old -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
}

$probe = New-Object System.Net.Sockets.TcpClient
try { $probe.Connect('127.0.0.1', [int]$Port); $busy = $true } catch { $busy = $false } finally { $probe.Close() }
if ($busy) {
    Write-Error "Port $Port is already in use by another program. Set WITNESS_PORT to a free port."
    exit 1
}

Write-Host "Starting WITNESS backend on http://127.0.0.1:$Port ..."
# stdout and stderr must go to different files (Start-Process refuses the same path).
$proc = Start-Process -FilePath $Python -WorkingDirectory $Backend `
    -ArgumentList '-m', 'uvicorn', 'witness.api.app:app', '--host', '0.0.0.0', '--port', $Port, '--log-level', 'warning' `
    -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -PassThru -NoNewWindow
$proc.Id | Set-Content $PidFile

for ($i = 0; $i -lt 40; $i++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
        Write-Host "Backend is up (PID $($proc.Id))."
        $health | ConvertTo-Json -Compress
        Write-Host ''
        Write-Host "Console (separate terminal):  cd $ProjRoot; bun install; bun run dev   # or npm"
        Write-Host "API docs:                     http://127.0.0.1:$Port/docs"
        Write-Host "Flagship demo:                Invoke-RestMethod -Method Post http://127.0.0.1:$Port/demo/flagship -ContentType application/json -Body '{""max_iterations"": 5}'"
        Write-Host "Benchmark (CLI):              cd $Backend; python -m witness.benchmark"
        Write-Host "Log:                          $ErrLog"
        Write-Host "Stop:                         Stop-Process -Id $($proc.Id)"
        exit 0
    } catch {
        if ($proc.HasExited) { break }
        Start-Sleep -Milliseconds 500
    }
}
Write-Host 'Backend did not come up. Last log lines:'
Get-Content $ErrLog -Tail 20 -ErrorAction SilentlyContinue
exit 1
