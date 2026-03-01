#!/bin/sh
# Servonaut Installer
# Usage: curl -sSL https://raw.githubusercontent.com/zb-ss/ec2-ssh/master/install.sh | bash
# Or: ./install.sh

set -e

# Color codes for terminal output
# Use tput if available, otherwise fallback to ANSI codes
if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
    RED=$(tput setaf 1 2>/dev/null || echo '')
    GREEN=$(tput setaf 2 2>/dev/null || echo '')
    YELLOW=$(tput setaf 3 2>/dev/null || echo '')
    BLUE=$(tput setaf 4 2>/dev/null || echo '')
    BOLD=$(tput bold 2>/dev/null || echo '')
    RESET=$(tput sgr0 2>/dev/null || echo '')
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    RESET=''
fi

# Print functions
print_header() {
    echo ""
    echo "${BLUE}${BOLD}========================================${RESET}"
    echo "${BLUE}${BOLD}   Servonaut Installer${RESET}"
    echo "${BLUE}${BOLD}========================================${RESET}"
    echo ""
}

print_success() {
    echo "${GREEN}✓${RESET} $1"
}

print_error() {
    echo "${RED}✗${RESET} $1" >&2
}

print_warning() {
    echo "${YELLOW}⚠${RESET} $1"
}

print_info() {
    echo "${BLUE}→${RESET} $1"
}

# Check if a command exists
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python_version() {
    print_info "Checking Python installation..."

    # Try to find Python 3
    PYTHON_CMD=""
    for cmd in python3 python; do
        if check_command "$cmd"; then
            PYTHON_CMD="$cmd"
            break
        fi
    done

    if [ -z "$PYTHON_CMD" ]; then
        print_error "Python not found!"
        echo ""
        echo "Please install Python 3.8 or higher:"
        echo ""
        echo "  Ubuntu/Debian:  ${BOLD}sudo apt update && sudo apt install python3 python3-pip${RESET}"
        echo "  RHEL/CentOS:    ${BOLD}sudo yum install python3 python3-pip${RESET}"
        echo "  Arch Linux:     ${BOLD}sudo pacman -S python python-pip${RESET}"
        echo "  macOS:          ${BOLD}brew install python3${RESET}"
        echo ""
        echo "Or download from: https://www.python.org/downloads/"
        exit 1
    fi

    # Get Python version
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(".".join(map(str, sys.version_info[:2])))' 2>/dev/null || echo "0.0")
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    # Check if version is >= 3.8
    if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$PYTHON_MINOR" -lt 8 ]; then
        print_error "Python $PYTHON_VERSION found, but Python 3.8+ is required!"
        echo ""
        echo "Please upgrade Python to version 3.8 or higher."
        echo "Visit: https://www.python.org/downloads/"
        exit 1
    fi

    print_success "Python $PYTHON_VERSION found at $(command -v "$PYTHON_CMD")"
    echo "$PYTHON_CMD"
}

# Install pipx
install_pipx() {
    print_info "Checking pipx installation..."

    if check_command pipx; then
        PIPX_VERSION=$(pipx --version 2>/dev/null | head -n1 || echo "unknown")
        print_success "pipx already installed ($PIPX_VERSION)"
        return 0
    fi

    print_warning "pipx not found. Installing pipx..."

    PYTHON_CMD="$1"

    # Try to install pipx based on platform
    if [ "$(uname)" = "Darwin" ] && check_command brew; then
        print_info "Installing pipx via Homebrew..."
        if brew install pipx; then
            print_success "pipx installed via Homebrew"
        else
            print_error "Failed to install pipx via Homebrew"
            exit 1
        fi
    else
        print_info "Installing pipx via pip..."
        if $PYTHON_CMD -m pip install --user pipx; then
            print_success "pipx installed via pip"
        else
            print_error "Failed to install pipx via pip"
            echo ""
            echo "Please try manually:"
            echo "  ${BOLD}$PYTHON_CMD -m pip install --user pipx${RESET}"
            exit 1
        fi
    fi

    # Ensure pipx is in PATH
    print_info "Ensuring pipx is in PATH..."
    if ! check_command pipx; then
        print_warning "pipx installed but not in PATH"

        # Try to find pipx in common locations
        PIPX_PATH=""
        for path in "$HOME/.local/bin" "$HOME/Library/Python/*/bin" "/usr/local/bin"; do
            if [ -f "$path/pipx" ]; then
                PIPX_PATH="$path"
                break
            fi
        done

        if [ -n "$PIPX_PATH" ]; then
            print_info "Found pipx at: $PIPX_PATH"
            print_warning "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
            echo ""
            echo "  ${BOLD}export PATH=\"\$PATH:$PIPX_PATH\"${RESET}"
            echo ""
            # Temporarily add to PATH for this session
            PATH="$PATH:$PIPX_PATH"
            export PATH
        else
            print_error "Could not locate pipx binary"
            echo ""
            echo "Try running: ${BOLD}$PYTHON_CMD -m pipx ensurepath${RESET}"
            echo "Then restart your shell."
            exit 1
        fi
    fi

    # Run pipx ensurepath
    if check_command pipx; then
        pipx ensurepath >/dev/null 2>&1 || true
    fi
}

# Install servonaut
install_servonaut() {
    print_info "Installing Servonaut..."

    # Strategy 1: Local repository (if running ./install.sh from cloned repo)
    if [ -f "pyproject.toml" ] && grep -q "name = \"servonaut\"" pyproject.toml 2>/dev/null; then
        print_info "Installing from local repository..."
        if pipx install . --force; then
            print_success "Servonaut installed successfully from local source"
            return 0
        else
            print_warning "Local install failed, trying PyPI..."
        fi
    fi

    # Strategy 2: Install from PyPI
    print_info "Installing from PyPI..."
    if pipx install servonaut 2>/dev/null; then
        print_success "Servonaut installed successfully from PyPI"
        return 0
    fi

    # Strategy 3: Clone repo and install from source
    print_warning "PyPI install failed, cloning repository..."

    if ! check_command git; then
        print_error "git is required to clone the repository"
        echo ""
        echo "Install git and try again, or install manually:"
        echo "  ${BOLD}pipx install servonaut${RESET}"
        exit 1
    fi

    CLONE_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'servonaut')
    print_info "Cloning to temporary directory: $CLONE_DIR"

    if git clone --depth 1 https://github.com/zb-ss/ec2-ssh.git "$CLONE_DIR/servonaut" 2>/dev/null; then
        if pipx install "$CLONE_DIR/servonaut" --force; then
            print_success "Servonaut installed successfully from repository"
            rm -rf "$CLONE_DIR"
            return 0
        fi
    fi

    rm -rf "$CLONE_DIR"
    print_error "All installation methods failed"
    echo ""
    echo "Please try manually:"
    echo "  ${BOLD}git clone https://github.com/zb-ss/ec2-ssh.git${RESET}"
    echo "  ${BOLD}cd ec2-ssh${RESET}"
    echo "  ${BOLD}pipx install .${RESET}"
    exit 1
}

# Setup wizard
setup_wizard() {
    print_header
    echo "${BOLD}Setup Wizard${RESET}"
    echo ""

    # Check AWS CLI
    print_info "Checking AWS CLI installation..."
    if check_command aws; then
        AWS_VERSION=$(aws --version 2>&1 | head -n1 || echo "unknown")
        print_success "AWS CLI found: $AWS_VERSION"

        # Check if AWS is configured
        print_info "Checking AWS configuration..."
        if aws sts get-caller-identity >/dev/null 2>&1; then
            AWS_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null || echo "{}")
            AWS_ACCOUNT=$(echo "$AWS_IDENTITY" | grep -o '"Account": *"[^"]*"' | cut -d'"' -f4 || echo "unknown")
            AWS_USER=$(echo "$AWS_IDENTITY" | grep -o '"Arn": *"[^"]*"' | cut -d'"' -f4 | sed 's/.*\///' || echo "unknown")
            print_success "AWS configured (Account: $AWS_ACCOUNT, User: $AWS_USER)"
        else
            print_warning "AWS CLI not configured"
            echo ""
            echo "Would you like to configure AWS now? (y/n)"
            printf "> "
            read -r response
            if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
                print_info "Running 'aws configure'..."
                aws configure
            else
                print_info "Skipping AWS configuration"
                echo ""
                echo "You can configure AWS later by running:"
                echo "  ${BOLD}aws configure${RESET}"
            fi
        fi
    else
        print_warning "AWS CLI not found"
        echo ""
        echo "Servonaut requires AWS CLI to be installed and configured."
        echo ""
        echo "Install instructions:"
        echo ""
        echo "  Linux:   ${BOLD}https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html${RESET}"
        echo "  macOS:   ${BOLD}brew install awscli${RESET}"
        echo ""
        echo "After installation, configure it with:"
        echo "  ${BOLD}aws configure${RESET}"
    fi

    # Test AWS connectivity
    if check_command aws && aws sts get-caller-identity >/dev/null 2>&1; then
        print_info "Testing AWS connectivity..."
        TEST_REGION=$(aws ec2 describe-regions --query 'Regions[0].RegionName' --output text 2>/dev/null || echo "")
        if [ -n "$TEST_REGION" ]; then
            print_success "AWS connectivity verified (Test region: $TEST_REGION)"
        else
            print_warning "Could not verify AWS connectivity"
        fi
    fi

    # Create starter config
    echo ""
    echo "Would you like to create a starter configuration file? (y/n)"
    printf "> "
    read -r response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        create_starter_config
    else
        print_info "Skipping configuration file creation"
        echo ""
        echo "A default configuration will be created automatically when you first run servonaut."
    fi
}

# Create starter config file
create_starter_config() {
    CONFIG_FILE="$HOME/.servonaut/config.json"

    if [ -f "$CONFIG_FILE" ]; then
        print_warning "Configuration file already exists at: $CONFIG_FILE"
        echo ""
        echo "Would you like to overwrite it? (y/n)"
        printf "> "
        read -r response
        if [ "$response" != "y" ] && [ "$response" != "Y" ]; then
            print_info "Keeping existing configuration"
            return 0
        fi
    fi

    print_info "Creating starter configuration at: $CONFIG_FILE"

    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << 'EOF'
{
  "version": 2,
  "default_key": "",
  "instance_keys": {},
  "default_username": "ec2-user",
  "cache_ttl_seconds": 300,
  "default_scan_paths": ["~/shared/"],
  "scan_rules": [],
  "connection_profiles": [],
  "connection_rules": [],
  "terminal_emulator": "auto",
  "keyword_store_path": "~/.servonaut/keywords.json",
  "theme": "dark"
}
EOF

    if [ -f "$CONFIG_FILE" ]; then
        print_success "Configuration file created"
        echo ""
        echo "You can customize this file later to set:"
        echo "  - Default SSH key"
        echo "  - Default username"
        echo "  - Cache TTL"
        echo "  - And more..."
    else
        print_error "Failed to create configuration file"
    fi
}

# Print final success message
print_final_message() {
    echo ""
    echo "${GREEN}${BOLD}========================================${RESET}"
    echo "${GREEN}${BOLD}   Installation Complete!${RESET}"
    echo "${GREEN}${BOLD}========================================${RESET}"
    echo ""
    echo "Servonaut has been installed successfully!"
    echo ""
    echo "${BOLD}Usage:${RESET}"
    echo "  Run the following command to start:"
    echo ""
    echo "    ${BOLD}servonaut${RESET}"
    echo ""
    echo "${BOLD}Next Steps:${RESET}"
    echo "  1. Ensure AWS CLI is configured with your credentials"
    echo "  2. Run 'servonaut' to launch the interactive interface"
    echo "  3. Use the menu to manage SSH keys and connect to instances"
    echo ""
    echo "${BOLD}Documentation:${RESET}"
    echo "  https://github.com/zb-ss/ec2-ssh"
    echo ""
    echo "${BOLD}Configuration:${RESET}"
    echo "  Config dir:  ~/.servonaut/"
    echo "  Config file: ~/.servonaut/config.json"
    echo ""
}

# Main installation flow
main() {
    print_header

    # Check Python
    PYTHON_CMD=$(check_python_version)
    echo ""

    # Install pipx
    install_pipx "$PYTHON_CMD"
    echo ""

    # Install servonaut
    install_servonaut
    echo ""

    # Ask about setup wizard
    echo "Would you like to run the setup wizard? (y/n)"
    echo "(This will check AWS CLI installation and configuration)"
    printf "> "
    read -r response
    if [ "$response" = "y" ] || [ "$response" = "Y" ]; then
        echo ""
        setup_wizard
    else
        print_info "Skipping setup wizard"
    fi

    # Print final message
    print_final_message
}

# Run main function
main
