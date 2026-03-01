# Servonaut Installer for Windows
# Usage: irm https://raw.githubusercontent.com/zb-ss/ec2-ssh/master/install.ps1 | iex
# Or: .\install.ps1

$ErrorActionPreference = "Stop"

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
        Write-Host "Install Python 3.8+ from: https://www.python.org/downloads/"
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

    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
        Write-Err "Python $version found, but Python 3.8+ is required!"
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

function Install-Servonaut {
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
    & pipx install servonaut 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Servonaut installed from PyPI"
        return
    }

    # Strategy 3: Clone and install
    Write-Warn "PyPI install failed, cloning repository..."

    if (-not (Test-Command "git")) {
        Write-Err "git is required to clone the repository"
        Write-Host ""
        Write-Host "Install git: https://git-scm.com/download/win"
        Write-Host "Or via winget: winget install Git.Git" -ForegroundColor White
        Write-Host ""
        Write-Host "Then try: pipx install servonaut" -ForegroundColor White
        exit 1
    }

    $cloneDir = Join-Path $env:TEMP "servonaut-install-$(Get-Random)"
    Write-Info "Cloning to: $cloneDir"

    try {
        & git clone --depth 1 https://github.com/zb-ss/ec2-ssh.git "$cloneDir\servonaut" 2>$null
        if ($LASTEXITCODE -eq 0) {
            & pipx install "$cloneDir\servonaut" --force 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Servonaut installed from repository"
                Remove-Item -Recurse -Force $cloneDir -ErrorAction SilentlyContinue
                return
            }
        }
    }
    catch {}

    Remove-Item -Recurse -Force $cloneDir -ErrorAction SilentlyContinue
    Write-Err "All installation methods failed"
    Write-Host ""
    Write-Host "Try manually:" -ForegroundColor White
    Write-Host "  git clone https://github.com/zb-ss/ec2-ssh.git"
    Write-Host "  cd ec2-ssh"
    Write-Host "  pipx install ."
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
    Write-Host "  https://github.com/zb-ss/ec2-ssh"
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "  Config: $env:USERPROFILE\.servonaut\config.json"
    Write-Host ""
}

# Main
Write-Header

$pythonCmd = Test-PythonVersion
Write-Host ""

Install-Pipx -PythonCmd $pythonCmd
Write-Host ""

Install-Servonaut
Write-Host ""

$response = Read-Host "Run setup wizard? (checks AWS CLI, SSH, configuration) (y/n)"
if ($response -eq "y" -or $response -eq "Y") {
    Write-Host ""
    Test-AwsCli
    Write-Host ""
    Test-SshClient
}

Write-FinalMessage
