
<# 
  Sentinel Antivirus - Launcher Script
  Builds the C++ engine (if needed) and launches the WPF GUI as Administrator.
#>

$ErrorActionPreference = "Continue"
$projectRoot = "C:\Users\bhila\Desktop\S"
$engineExe   = "$projectRoot\build\bin\Release\antivirus.exe"
$guiProject  = "$projectRoot\AntivirusGUI"

# ── Colors ──
function Write-Header($msg) { Write-Host "`n  $msg" -ForegroundColor Cyan }
function Write-OK($msg)     { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Err($msg)    { Write-Host "  [!]  $msg" -ForegroundColor Red }
function Write-Step($msg)   { Write-Host "  ...  $msg" -ForegroundColor DarkGray }

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║       SENTINEL ANTIVIRUS LAUNCHER        ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan

# ── 1. Check Admin ──
Write-Header "Checking Administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "Not running as Admin. Relaunching elevated..."
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
Write-OK "Running as Administrator"

# ── 2. Build C++ Engine (if missing or outdated) ──
Write-Header "Checking C++ scan engine..."
$needsBuild = $false

if (-not (Test-Path $engineExe)) {
    Write-Step "Engine not found — building..."
    $needsBuild = $true
} else {
    # Check if any source file is newer than the exe
    $exeTime = (Get-Item $engineExe).LastWriteTime
    $newerSources = Get-ChildItem "$projectRoot\src","$projectRoot\include" -Recurse -File | 
        Where-Object { $_.LastWriteTime -gt $exeTime } | Select-Object -First 1
    if ($newerSources) {
        Write-Step "Source files changed — rebuilding..."
        $needsBuild = $true
    }
}

if ($needsBuild) {
    Write-Step "Configuring CMake..."
    $cmakeArgs = @(
        "-B", "$projectRoot\build",
        "-S", $projectRoot,
        "-DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake",
        "-DVCPKG_TARGET_TRIPLET=x64-windows-static",
        "-DENABLE_CUDA=ON",
        "-DCMAKE_CUDA_COMPILER=C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v13.1/bin/nvcc.exe"
    )
    & cmake @cmakeArgs 2>&1 | Out-Null
    
    Write-Step "Building Release..."
    & cmake --build "$projectRoot\build" --config Release 2>&1 | Out-Null
    
    if (Test-Path $engineExe) {
        Write-OK "Engine built successfully"
    } else {
        Write-Err "Engine build failed!"
        Write-Host "  Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
} else {
    Write-OK "Engine is up to date"
}

# ── 3. Verify signatures + rules ──
Write-Header "Checking resources..."
$sigDir   = "$projectRoot\build\bin\Release\signatures"
$rulesDir = "$projectRoot\build\bin\Release\rules"

if (Test-Path "$sigDir\malware_signatures.db") {
    $sigCount = (Get-Content "$sigDir\malware_signatures.db" | Where-Object { $_ -and $_ -notmatch '^\s*#' }).Count
    Write-OK "Signatures: $sigCount loaded"
} else {
    Write-Err "Signature database not found!"
}

if (Test-Path "$rulesDir\sentinel_rules.yar") {
    Write-OK "YARA rules present"
} else {
    Write-Step "YARA rules missing — copying from source..."
    if (Test-Path "$projectRoot\rules\sentinel_rules.yar") {
        New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
        Copy-Item "$projectRoot\rules\sentinel_rules.yar" "$rulesDir\" -Force
        Write-OK "YARA rules restored"
    }
}

# ── 4. Quick engine test ──
Write-Header "Testing engine..."
$statusOutput = & $engineExe status 2>&1 | Out-String
if ($statusOutput -match "Ready: Yes") {
    Write-OK "Engine ready"
    if ($statusOutput -match "GPU: (.+)") { Write-OK "GPU: $($Matches[1].Trim())" }
    if ($statusOutput -match "YARA: Compiled (\d+)") { Write-OK "YARA: $($Matches[1]) rules compiled" }
} else {
    Write-Err "Engine test failed — launching anyway"
}

# ── 5. Launch GUI ──
Write-Header "Launching Sentinel Antivirus GUI..."
Write-Host ""

Set-Location $guiProject
& dotnet run --configuration Release 2>&1

Write-Host "`n  Sentinel Antivirus closed." -ForegroundColor DarkGray
