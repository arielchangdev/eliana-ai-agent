<#
.SYNOPSIS
  Package the six engines + integration layer into a flattened eliana-bundle/
  and zip it for RHEL VM deployment.

.DESCRIPTION
  Run on the local Windows machine. Collects sources scattered across the
  workspace into the /opt/eliana/ flattened layout so a single
  PYTHONPATH=/opt/eliana can import every top-level package on the VM.

  Flatten map:
    .kiro\app\                                          -> bundle\app\
    .kiro\eliana-personality\app\personality\           -> bundle\app\personality\
    .kiro\eliana_core\                                  -> bundle\eliana_core\
    .kiro\eliana-digital-wallet\eliana_digital_wallet\  -> bundle\eliana_digital_wallet\
    .kiro\eliana-learning-engine\src\                   -> bundle\src\
    .kiro\eliana-learning-engine\config.yaml            -> bundle\learning_config.yaml
    .kiro\eliana-integration\                           -> bundle\eliana-integration\
    .kiro\eliana-dashboard\                             -> bundle\eliana-dashboard\

  Excludes: secrets (.env*, *.db, keys, *.pem), caches (__pycache__,
            .pytest_cache, .hypothesis), tests\, and .git.

.EXAMPLE
  cd c:\Users\ariel\.kiro\eliana-integration
  pwsh -File deploy\bundle.ps1
  # or on Windows PowerShell 5.1:
  powershell -ExecutionPolicy Bypass -File deploy\bundle.ps1
#>

param(
    [string]$Root = "c:\Users\ariel\.kiro",
    [string]$OutDir = "c:\Users\ariel\.kiro\eliana-bundle",
    [switch]$IncludeTests
)

$ErrorActionPreference = "Stop"

$excludeDirs = @('__pycache__', '.pytest_cache', '.hypothesis', '.git', 'node_modules', 'dist', 'build')
if (-not $IncludeTests) { $excludeDirs += 'tests' }

$excludeFilePatterns = @('*.env', '.env', '.env.*', '*.db', '*.sqlite', '*.sqlite3',
                         '*.key', '*.pem', 'id_rsa*', 'id_ed25519*', '*.log', '*.pyc')

function Copy-Tree {
    param([string]$Src, [string]$Dst)
    if (-not (Test-Path $Src)) {
        Write-Host "[skip] source missing: $Src" -ForegroundColor Yellow
        return
    }
    Write-Host "[copy] $Src -> $Dst" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $Dst | Out-Null

    Get-ChildItem -Path $Src -Recurse -Force | ForEach-Object {
        $item = $_
        $skip = $false
        foreach ($d in $excludeDirs) {
            if ($item.FullName -match [regex]::Escape("\$d\") -or $item.Name -eq $d) { $skip = $true; break }
        }
        if ($skip) { return }

        $rel = $item.FullName.Substring($Src.Length).TrimStart('\')
        $target = Join-Path $Dst $rel

        if ($item.PSIsContainer) {
            New-Item -ItemType Directory -Force -Path $target | Out-Null
        }
        else {
            foreach ($pat in $excludeFilePatterns) {
                if ($item.Name -like $pat) { return }
            }
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            Copy-Item -Path $item.FullName -Destination $target -Force
        }
    }
}

if (Test-Path $OutDir) {
    Write-Host "[clean] removing old bundle: $OutDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "=== collecting engine sources ===" -ForegroundColor Green

# 1. bounty-hunter + other app submodules (app.bounty / app.services ...)
Copy-Tree -Src (Join-Path $Root "app") -Dst (Join-Path $OutDir "app")

# 2. personality (merge into app\personality)
Copy-Tree -Src (Join-Path $Root "eliana-personality\app\personality") `
          -Dst (Join-Path $OutDir "app\personality")

# 3. core-infra
Copy-Tree -Src (Join-Path $Root "eliana_core") -Dst (Join-Path $OutDir "eliana_core")

# 4. digital-wallet (inner package)
Copy-Tree -Src (Join-Path $Root "eliana-digital-wallet\eliana_digital_wallet") `
          -Dst (Join-Path $OutDir "eliana_digital_wallet")

# 5. learning-engine (inner src)
Copy-Tree -Src (Join-Path $Root "eliana-learning-engine\src") -Dst (Join-Path $OutDir "src")
$learnCfg = Join-Path $Root "eliana-learning-engine\config.yaml"
if (Test-Path $learnCfg) {
    Copy-Item $learnCfg (Join-Path $OutDir "learning_config.yaml") -Force
    Write-Host "[copy] learning config.yaml -> learning_config.yaml" -ForegroundColor Cyan
}

# 6. integration (includes run_server.py, deploy\)
Copy-Tree -Src (Join-Path $Root "eliana-integration") -Dst (Join-Path $OutDir "eliana-integration")

# 7. dashboard
Copy-Tree -Src (Join-Path $Root "eliana-dashboard") -Dst (Join-Path $OutDir "eliana-dashboard")

Write-Host "=== secret-leak check ===" -ForegroundColor Green
$leaks = Get-ChildItem -Path $OutDir -Recurse -Force -File | Where-Object {
    $_.Name -match '\.env' -or $_.Extension -in @('.db', '.sqlite', '.sqlite3', '.key', '.pem') `
        -or $_.Name -match 'id_rsa|id_ed25519'
}
if ($leaks) {
    Write-Host "[WARN] possible secret files found, please review:" -ForegroundColor Red
    $leaks | ForEach-Object { Write-Host "   $($_.FullName)" -ForegroundColor Red }
}
else {
    Write-Host "[ok] no secret files found" -ForegroundColor Green
}

$zipPath = "$OutDir.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Write-Host "=== zipping to $zipPath ===" -ForegroundColor Green
Compress-Archive -Path "$OutDir\*" -DestinationPath $zipPath -Force

$sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ("  bundle dir: {0}" -f $OutDir)
Write-Host ("  zip: {0} ({1} MB)" -f $zipPath, $sizeMB)
Write-Host ""
Write-Host "Next: copy the zip to RHEL VM (<ELIANA_HOST_IP>) and unzip to /opt/eliana/:"
Write-Host "  scp eliana-bundle.zip eliana@<ELIANA_HOST_IP>:/tmp/"
Write-Host "  # on the VM:"
Write-Host "  sudo mkdir -p /opt/eliana; sudo chown `$USER /opt/eliana"
Write-Host "  unzip /tmp/eliana-bundle.zip -d /opt/eliana"
Write-Host "  export PYTHONPATH=/opt/eliana"
