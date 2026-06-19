# ARES Engine Air-Gapped Bootstrap Script (Windows)
# Run this script in an air-gapped environment to prepare tools and models.

param(
    [string]$ToolsDir = ".\ares_tools",
    [string]$ModelsDir = ".\ares_models",
    [string]$ManifestPath = ".\airgap-manifest.json",
    [switch]$GenerateManifest,
    [switch]$VerifyIntegrity
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "ARES Air-Gap Bootstrap"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ARES Engine - Air-Gap Bootstrap"      -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Ensure tools directory exists
if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
    Write-Host "[+] Created tools directory: $ToolsDir" -ForegroundColor Green
}

# Ensure models directory exists
if (-not (Test-Path $ModelsDir)) {
    New-Item -ItemType Directory -Path $ModelsDir -Force | Out-Null
    Write-Host "[+] Created models directory: $ModelsDir" -ForegroundColor Green
}

# Pre-approved tool list for air-gapped environments
$requiredTools = @(
    @{ Name = "nmap";     Url = "https://nmap.org/dist/nmap-7.95-win32.zip";    Binary = "nmap.exe" },
    @{ Name = "ffuf";     Url = "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_1.5.0_windows_amd64.zip"; Binary = "ffuf.exe" },
    @{ Name = "gobuster"; Url = "https://github.com/OJ/gobuster/releases/latest/download/gobuster_3.6.0_windows_amd64.zip"; Binary = "gobuster.exe" }
)

if (-not $GenerateManifest -and -not $VerifyIntegrity) {
    Write-Host "[*] This script prepares an air-gapped ARES deployment." -ForegroundColor Yellow
    Write-Host "[*] In an air-gapped environment, download these tool bundles" -ForegroundColor Yellow
    Write-Host "[*] on a connected machine and transfer them via secure media." -ForegroundColor Yellow
    Write-Host ""

    foreach ($tool in $requiredTools) {
        $toolPath = Join-Path $ToolsDir $tool.Binary
        if (Test-Path $toolPath) {
            Write-Host "  [OK] $($tool.Name) found at $toolPath" -ForegroundColor Green
        } else {
            Write-Host "  [--] $($tool.Name) not found. Download from: $($tool.Url)" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "[*] Recommended Ollama models for local LLM:" -ForegroundColor Cyan
    Write-Host "  - llama3.1:70b (primary reasoning)" -ForegroundColor White
    Write-Host "  - qwen2.5:14b  (attack generation)" -ForegroundColor White
    Write-Host "  - nomic-embed-text:v1.5 (embeddings)" -ForegroundColor White
    Write-Host ""
    Write-Host "[*] To download models in air-gap:" -ForegroundColor Cyan
    Write-Host "  1. On internet-connected machine: ollama pull llama3.1:70b" -ForegroundColor White
    Write-Host "  2. Export: & 'C:\Program Files\Ollama\ollama.exe' pull llama3.1:70b" -ForegroundColor White
    Write-Host "  3. Copy models from ~\.ollama\models to $ModelsDir" -ForegroundColor White
    Write-Host ""
    Write-Host "[*] Set environment variables:" -ForegroundColor Cyan
    Write-Host "  ARES_AIRGAP=true" -ForegroundColor White
    Write-Host "  ARES_ALLOWED_DOMAINS=localhost,127.0.0.1" -ForegroundColor White
    Write-Host "  ARES_LOCAL_MODELS_ONLY=true" -ForegroundColor White
    Write-Host "  ARES_DISABLE_TELEMETRY=true" -ForegroundColor White
    Write-Host "  ARES_AIRGAP_MANIFEST=$ManifestPath" -ForegroundColor White
}

if ($GenerateManifest) {
    Write-Host "[*] Generating air-gap manifest..." -ForegroundColor Cyan
    $tools = @{}
    foreach ($tool in $requiredTools) {
        $toolPath = Join-Path $ToolsDir $tool.Binary
        if (Test-Path $toolPath) {
            $hash = (Get-FileHash -Path $toolPath -Algorithm SHA256).Hash
            $tools[$tool.Name] = $toolPath
            Write-Host "  [HASH] $($tool.Name): $hash" -ForegroundColor Green
        }
    }

    # Call the Go tool via the engine if available
    Write-Host "[+] Manifest would be written to: $ManifestPath" -ForegroundColor Green
}

if ($VerifyIntegrity) {
    Write-Host "[*] Verifying tool integrity..." -ForegroundColor Cyan
    if (Test-Path $ManifestPath) {
        $manifest = Get-Content $ManifestPath | ConvertFrom-Json
        foreach ($toolEntry in $manifest.tools) {
            $toolPath = Join-Path $ToolsDir "$($toolEntry.name).exe"
            if (Test-Path $toolPath) {
                $actualHash = (Get-FileHash -Path $toolPath -Algorithm SHA256).Hash
                if ($actualHash -eq $toolEntry.sha256) {
                    Write-Host "  [OK] $($toolEntry.name) hash matches" -ForegroundColor Green
                } else {
                    Write-Host "  [FAIL] $($toolEntry.name) hash MISMATCH!" -ForegroundColor Red
                    Write-Host "         Expected: $($toolEntry.sha256)" -ForegroundColor Red
                    Write-Host "         Actual:   $actualHash" -ForegroundColor Red
                }
            } else {
                Write-Host "  [--] $($toolEntry.name) not found at $toolPath" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [--] Manifest not found at $ManifestPath" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Air-Gap Bootstrap Complete"             -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
