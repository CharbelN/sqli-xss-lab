<#
.SYNOPSIS
  Run the OWASP ZAP Automation Framework plan headless via Docker, scoped to the
  authorized lab host, and drop the HTML + JSON reports into evidence/zap/.

.DESCRIPTION
  Phase 1 of the lab, ZAP portion. Requires Docker Desktop to be running.
  The scan scope is pinned inside zap/automation-plan.yaml (single host), so this
  wrapper only has to mount the plan and the output directory.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\run_zap.ps1
#>

$ErrorActionPreference = "Stop"

# Resolve repo root (parent of this script's folder).
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ZapDir   = Join-Path $RepoRoot "zap"
$OutDir   = Join-Path $RepoRoot "evidence\zap"
$Image    = "ghcr.io/zaproxy/zaproxy:stable"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "[zap] checking Docker daemon..." -ForegroundColor Cyan
try {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { throw "daemon not reachable" }
} catch {
    Write-Host "[zap] ERROR: Docker daemon is not running." -ForegroundColor Red
    Write-Host "      Start Docker Desktop and wait until it says 'Engine running', then re-run this script." -ForegroundColor Yellow
    exit 1
}

Write-Host "[zap] pulling image $Image (first run only, ~1-2 min)..." -ForegroundColor Cyan
docker pull $Image

Write-Host "[zap] running Automation Framework plan (scoped to testaspnet.vulnweb.com)..." -ForegroundColor Cyan
# ZAP runs as uid 1000 inside the container; make the mounted dirs writable.
docker run --rm `
    -v "${ZapDir}:/zap/wrk:rw" `
    -v "${OutDir}:/zap/out:rw" `
    $Image zap.sh -cmd -autorun /zap/wrk/automation-plan.yaml

$code = $LASTEXITCODE
Write-Host "[zap] exit code: $code" -ForegroundColor Cyan
Write-Host "[zap] reports written to: $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -ErrorAction SilentlyContinue | Select-Object Name,Length | Format-Table
# ZAP exits non-zero when it finds alerts (that's expected here) or on plan warnings.
exit 0
