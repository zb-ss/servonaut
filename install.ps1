# Servonaut Installer for Windows
# Usage: irm https://github.com/zb-ss/servonaut/releases/latest/download/install.ps1 | iex
# Or: .\install.ps1
#
# Release candidate instead of the stable release:
#   $env:SERVONAUT_PRE = "1"; irm https://github.com/zb-ss/servonaut/releases/latest/download/install.ps1 | iex
# Or: .\install.ps1 -Pre
#
# Servonaut is installed from PyPI with pipx. When run from a clone of the
# repository, .\install.ps1 installs that checkout instead.

param(
    # Install the newest release candidate instead of the stable release
    [switch]$Pre
)

$ErrorActionPreference = "Stop"

# Oldest Python that Servonaut supports (requires-python in pyproject.toml)
$MinPythonMajor = 3
$MinPythonMinor = 10

$RepoUrl = "https://github.com/zb-ss/servonaut"
$TroubleshootingUrl = "$RepoUrl/blob/master/docs/troubleshooting.md#the-install-script-stops"

# Naming a pre-release in the version specifier lets pip choose a release
# candidate of Servonaut, or the stable release when that is newer. pip's
# --pre flag would also allow pre-release versions of every dependency.
$PreReleaseSpec = "servonaut>=0rc0"

function Write-Header {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host "   Servonaut Installer" -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
    Write-Host ""
}

function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Err { param([string]$Message) Write-Host "[X] $Message" -ForegroundColor Red }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Info { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor Cyan }

function Test-Command { param([string]$Name) return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

# True when -Pre or SERVONAUT_PRE asks for the newest release candidate
function Test-PreReleaseRequested {
    param([bool]$Switch)

    if ($Switch) { return $true }

    $value = "$env:SERVONAUT_PRE".Trim().ToLowerInvariant()
    if ($value -in @("", "0", "false", "no")) { return $false }
    if ($value -in @("1", "true", "yes")) { return $true }

    Write-Err "SERVONAUT_PRE must be 1 or 0, not '$env:SERVONAUT_PRE'"
    exit 2
}

function Test-PythonVersion {
    Write-Info "Checking Python installation..."

    $pythonCmd = $null
    foreach ($cmd in @("python3", "python", "py")) {
        if (Test-Command $cmd) {
            $pythonCmd = $cmd
            break
        }
    }

    if (-not $pythonCmd) {
        Write-Err "Python not found!"
        Write-Host ""
        Write-Host "Install Python $MinPythonMajor.$MinPythonMinor+ from: https://www.python.org/downloads/"
        Write-Host "  - Check 'Add Python to PATH' during installation"
        Write-Host ""
        Write-Host "Or via winget:"
        Write-Host "  winget install Python.Python.3.12" -ForegroundColor White
        exit 1
    }

    $version = & $pythonCmd -c "import sys; print('.'.join(map(str, sys.version_info[:2])))" 2>$null
    if (-not $version) {
        Write-Err "Could not determine Python version"
        exit 1
    }

    $parts = $version.Split(".")
    $major = [int]$parts[0]
    $minor = [int]$parts[1]

    if ($major -lt $MinPythonMajor -or ($major -eq $MinPythonMajor -and $minor -lt $MinPythonMinor)) {
        Write-Err "Python $version found, but Python $MinPythonMajor.$MinPythonMinor+ is required!"
        Write-Host "Download from: https://www.python.org/downloads/"
        exit 1
    }

    Write-Success "Python $version found"
    return $pythonCmd
}

function Install-Pipx {
    param([string]$PythonCmd)

    Write-Info "Checking pipx installation..."

    if (Test-Command "pipx") {
        $pipxVersion = & pipx --version 2>$null
        Write-Success "pipx already installed ($pipxVersion)"
        return
    }

    Write-Warn "pipx not found. Installing pipx..."

    try {
        & $PythonCmd -m pip install --user pipx 2>$null
        if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

        & $PythonCmd -m pipx ensurepath 2>$null
        # Refresh PATH for current session
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "User") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "Machine")

        if (Test-Command "pipx") {
            Write-Success "pipx installed"
        } else {
            Write-Warn "pipx installed but not in PATH"
            Write-Host ""
            Write-Host "Close and reopen PowerShell, then run this installer again."
            Write-Host "Or run: $PythonCmd -m pipx ensurepath" -ForegroundColor White
            exit 1
        }
    }
    catch {
        Write-Err "Failed to install pipx"
        Write-Host ""
        Write-Host "Try manually: $PythonCmd -m pip install --user pipx" -ForegroundColor White
        exit 1
    }
}

# Version of servonaut that pipx has installed, or "unknown"
function Get-InstalledVersion {
    try {
        $line = & pipx list --short | Where-Object { $_ -match '^servonaut\s' } | Select-Object -First 1
    }
    catch {
        return "unknown"
    }
    if ($line) { return ($line -split '\s+')[1] }
    return "unknown"
}

function Install-ReleaseCandidate {
    Write-Info "Installing the newest Servonaut release candidate from PyPI..."
    Write-Info "When no candidate is newer than the stable release, the stable release is installed."

    # --force also switches an existing installation over
    & pipx install --force $PreReleaseSpec
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Servonaut $(Get-InstalledVersion) installed from PyPI"
        return
    }

    Write-Err "Could not install a release candidate"
    Write-Host ""
    Write-Host "Try manually:" -ForegroundColor White
    Write-Host "  pipx install --force `"$PreReleaseSpec`""
    exit 1
}

function Install-Servonaut {
    param([bool]$Pre)

    if ($Pre) {
        Install-ReleaseCandidate
        return
    }

    Write-Info "Installing Servonaut..."

    # Strategy 1: Local repository
    if (Test-Path "pyproject.toml") {
        $content = Get-Content "pyproject.toml" -Raw -ErrorAction SilentlyContinue
        if ($content -match 'name = "servonaut"') {
            Write-Info "Installing from local repository..."
            & pipx install . --force 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Servonaut installed from local source"
                return
            }
            Write-Warn "Local install failed, trying PyPI..."
        }
    }

    # Strategy 2: PyPI
    Write-Info "Installing from PyPI..."
    & pipx install servonaut
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Servonaut installed from PyPI"
        return
    }

    # Never fall back to unreleased source: stop and say why
    Write-Err "Could not install Servonaut from PyPI (pipx's error is shown above)"
    Write-Host ""
    Write-Host "Fix the problem pipx reports and run the installer again, or install manually:"
    Write-Host "  pipx install servonaut" -ForegroundColor White
    Write-Host ""
    Write-Host "Troubleshooting: $TroubleshootingUrl"
    exit 1
}

function Test-AwsCli {
    Write-Info "Checking AWS CLI..."

    if (-not (Test-Command "aws")) {
        Write-Warn "AWS CLI not found"
        Write-Host ""
        Write-Host "Servonaut requires AWS CLI. Install from:"
        Write-Host "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        Write-Host ""
        Write-Host "Or via winget:"
        Write-Host "  winget install Amazon.AWSCLI" -ForegroundColor White
        Write-Host ""
        Write-Host "After installation, configure with:"
        Write-Host "  aws configure" -ForegroundColor White
        return
    }

    $awsVersion = & aws --version 2>&1 | Select-Object -First 1
    Write-Success "AWS CLI found: $awsVersion"

    Write-Info "Checking AWS configuration..."
    & aws sts get-caller-identity *>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "AWS credentials configured"
    }
    else {
        Write-Warn "AWS CLI not configured"
        Write-Host ""
        $response = Read-Host "Would you like to configure AWS now? (y/n)"
        if ($response -eq "y" -or $response -eq "Y") {
            & aws configure
        }
        else {
            Write-Host "Configure later with: aws configure" -ForegroundColor White
        }
    }
}

function Test-SshClient {
    Write-Info "Checking SSH client..."

    if (Test-Command "ssh") {
        Write-Success "SSH client found"
    }
    else {
        Write-Warn "SSH client not found"
        Write-Host ""
        Write-Host "Install OpenSSH via Settings > Apps > Optional Features > OpenSSH Client"
        Write-Host "Or via PowerShell (admin):"
        Write-Host "  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor White
    }
}

function Write-FinalMessage {
    param([bool]$Pre)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   Installation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Servonaut has been installed successfully!"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor White
    Write-Host "  servonaut"
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor White
    Write-Host "  1. Ensure AWS CLI is configured (aws configure)"
    Write-Host "  2. Run 'servonaut' to launch the interactive interface"
    Write-Host "  3. Use the menu to manage SSH keys and connect to instances"
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor White
    Write-Host "  $RepoUrl"
    Write-Host ""
    if ($Pre) {
        Write-Host "Release candidate:" -ForegroundColor White
        Write-Host "  Report problems at: $RepoUrl/issues"
        Write-Host "  Return to the stable release with: pipx install --force servonaut"
        Write-Host ""
    }
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "  Config: $env:USERPROFILE\.servonaut\config.json"
    Write-Host ""
}

# Main
$installPre = Test-PreReleaseRequested -Switch $Pre.IsPresent

Write-Header

$pythonCmd = Test-PythonVersion
Write-Host ""

Install-Pipx -PythonCmd $pythonCmd
Write-Host ""

Install-Servonaut -Pre $installPre
Write-Host ""

$response = Read-Host "Run setup wizard? (checks AWS CLI, SSH, configuration) (y/n)"
if ($response -eq "y" -or $response -eq "Y") {
    Write-Host ""
    Test-AwsCli
    Write-Host ""
    Test-SshClient
}

Write-FinalMessage -Pre $installPre
