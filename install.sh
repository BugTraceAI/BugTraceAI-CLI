#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# BugTraceAI Installation Wizard
# ============================================================
# This script provides an interactive installation wizard for
# BugTraceAI with two modes:
# 1. Local installation (Python virtual environment)
# 2. Docker installation (with automatic port detection)
# ============================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Emoji support
CHECK="✓"
CROSS="✗"
ARROW="→"
ROCKET="🚀"
GEAR="⚙️"
DOCKER="🐳"
PYTHON="🐍"
ENV_FILE_CREATED=false
INSTALL_INTERFACE=""
INSTALL_RUNTIME=""
INSTALL_GLOBAL=""
INSTALLER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$INSTALLER_DIR" || exit 1
source "$INSTALLER_DIR/scripts/install_global_command.sh"
source "$INSTALLER_DIR/scripts/install_docker_runtime.sh"

# Persist only installation choices, never API keys. Read values without sourcing shell code.
load_install_choices() {
    [[ -f .bugtrace-install.env ]] || return 0
    INSTALL_INTERFACE=$(awk -F= '$1=="INTERFACE" {print $2}' .bugtrace-install.env)
    INSTALL_RUNTIME=$(awk -F= '$1=="RUNTIME" {print $2}' .bugtrace-install.env)
    INSTALL_GLOBAL=$(awk -F= '$1=="GLOBAL" {print $2}' .bugtrace-install.env)
    case "$INSTALL_GLOBAL" in yes|no) ;; *) INSTALL_GLOBAL=no ;; esac
    case "$INSTALL_INTERFACE" in tui|api|both) ;; *) INSTALL_INTERFACE="" ;; esac
    case "$INSTALL_RUNTIME" in local|docker) ;; *) INSTALL_RUNTIME="" ;; esac
}

save_install_choices() {
    printf 'INTERFACE=%s\nRUNTIME=%s\nGLOBAL=%s\n' "$INSTALL_INTERFACE" "$INSTALL_RUNTIME" "$INSTALL_GLOBAL" > .bugtrace-install.env
    chmod 600 .bugtrace-install.env
}

install_extras() {
    case "$INSTALL_INTERFACE" in
        tui) printf '.[tui]' ;; api) printf '.[api]' ;; both) printf '.[tui,api]' ;;
        *) return 1 ;;
    esac
}

show_launch_commands() {
    print_info "Installed: $INSTALL_INTERFACE / $INSTALL_RUNTIME"
    if [[ "$INSTALL_RUNTIME" == local ]]; then
        [[ "$INSTALL_INTERFACE" == api ]] || print_info "TUI: ./bugtraceai-cli tui (Provider/F7 configures the key)"
        [[ "$INSTALL_INTERFACE" == tui ]] || print_info "API: ./bugtraceai-cli serve --port 8000"
    elif [[ "$INSTALL_INTERFACE" == tui ]]; then
        print_info "TUI: $COMPOSE_CMD -f docker-compose.tui.yml run --rm scanner"
        print_info "No API server or exposed ports are started."
    else
        print_info "API: http://localhost:$(read_env_value CLI_PORT)"
        [[ "$INSTALL_INTERFACE" == api ]] || print_info "TUI: $COMPOSE_CMD exec api python3 -m bugtrace tui"
    fi
    print_info "Update/repair the same selection: ./install.sh --reuse"
}

# ============================================================
# Helper Functions
# ============================================================

print_header() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║              ${ROCKET}  BugTraceAI Setup Wizard  ${ROCKET}            ║"
    echo "║                                                            ║"
    echo "║         Advanced AI-powered Security Testing Tool         ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${BLUE}${GEAR} $1${NC}"
}

print_success() {
    echo -e "${GREEN}${CHECK} $1${NC}"
}

print_error() {
    echo -e "${RED}${CROSS} $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${CYAN}${ARROW} $1${NC}"
}

read_env_value() {
    local key=$1
    [ -f .env ] || return 0
    grep -E "^${key}=" .env 2>/dev/null | tail -n 1 | cut -d= -f2-
}

sed_inplace() {
    if sed --version &>/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

set_env_value() {
    local key=$1 value=$2
    if grep -qE "^${key}=" .env 2>/dev/null; then
        sed_inplace "s|^${key}=.*|${key}=${value}|" .env
    else
        if [ -s .env ] && [ -n "$(tail -c 1 .env)" ]; then
            echo "" >> .env
        fi
        echo "${key}=${value}" >> .env
    fi
}

# ============================================================
# Port Management Functions
# ============================================================

is_port_in_use() {
    local port=$1
    if command -v lsof &> /dev/null; then
        lsof -i:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    elif command -v netstat &> /dev/null; then
        netstat -tuln | grep -q ":$port "
    elif command -v ss &> /dev/null; then
        ss -tuln | grep -q ":$port "
    else
        # Fallback: try to bind to the port
        (echo >/dev/tcp/localhost/"$port") &>/dev/null
    fi
}

find_free_port() {
    local start_port=${1:-8000}
    local max_attempts=100
    local port=$start_port
    
    # This function is commonly used in command substitution; keep progress
    # messages off stdout so callers receive only the numeric port.
    print_step "Searching for available port starting from $start_port..." >&2
    
    for ((i=0; i<max_attempts; i++)); do
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done
    
    print_error "Could not find a free port after $max_attempts attempts"
    return 1
}

find_free_port_avoiding() {
    local start_port=${1:-8000}
    local avoid_port=${2:-}
    local max_attempts=100
    local port=$start_port

    for ((i=0; i<max_attempts; i++)); do
        if [ "$port" != "$avoid_port" ] && ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done

    print_error "Could not find a free port after $max_attempts attempts"
    return 1
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# ============================================================
# System Requirements Check
# ============================================================

check_command() {
    local cmd=$1
    local name=$2
    if command -v "$cmd" &> /dev/null; then
        print_success "$name is installed"
        return 0
    else
        print_error "$name is not installed"
        return 1
    fi
}

check_optional_command() {
    local cmd=$1
    local name=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        print_success "$name is installed"
        return 0
    fi
    print_warning "$name not found (optional for the local TUI)"
    return 1
}

run_privileged() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        print_error "Administrator privileges are required to install: $*"
        return 1
    fi
}

install_linux_packages() {
    local packages=("$@")
    [[ ${#packages[@]} -gt 0 ]] || return 0

    print_info "Installing system packages: ${packages[*]}"
    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update -qq && \
            run_privileged apt-get install -y --no-install-recommends "${packages[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y "${packages[@]}"
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y "${packages[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -S --needed --noconfirm "${packages[@]}"
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper install -y "${packages[@]}"
    else
        print_error "No supported system package manager was found."
        return 1
    fi
}

probe_python_venv() {
    local probe
    probe=$(mktemp -d "${TMPDIR:-/tmp}/bugtraceai-venv.XXXXXX")
    if python3 -m venv "$probe" >/dev/null 2>&1 && "$probe/bin/python3" -m pip --version >/dev/null 2>&1; then
        rm -rf "$probe"
        return 0
    fi
    rm -rf "$probe"
    return 1
}

prepare_local_requirements() {
    command -v python3 >/dev/null 2>&1 || {
        print_error "Python 3.10 or newer is required. Install Python and run the installer again."
        return 1
    }
    if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        print_error "Python 3.10 or newer is required. Upgrade Python and rerun the installer."
        return 1
    fi

    local need_python_packages=()
    local need_nmap=false

    if ! python3 -m pip --version >/dev/null 2>&1; then
        if python3 -m ensurepip --upgrade >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
            print_success "Bootstrapped pip with Python ensurepip"
        else
            need_python_packages+=(python3-pip)
        fi
    fi
    if ! probe_python_venv; then
        need_python_packages+=(python3-venv)
    fi
    command -v nmap >/dev/null 2>&1 || need_nmap=true

    if [[ ${#need_python_packages[@]} -eq 0 && "$need_nmap" == false ]]; then
        return 0
    fi

    print_info "Missing local tools detected; installing them now."

    if [[ "$need_nmap" == true ]]; then
        if [[ "$(uname -s)" == Darwin ]]; then
            local brew_bin=""
            if command -v brew >/dev/null 2>&1; then
                brew_bin="$(command -v brew)"
            elif [[ -x /opt/homebrew/bin/brew ]]; then
                brew_bin=/opt/homebrew/bin/brew
            elif [[ -x /usr/local/bin/brew ]]; then
                brew_bin=/usr/local/bin/brew
            fi
            if [[ -n "$brew_bin" ]]; then
                "$brew_bin" install nmap || print_warning "Could not install nmap; continuing without it."
            else
                print_warning "Homebrew is not installed; install nmap separately if you need it."
            fi
        else
            need_python_packages+=(nmap)
        fi
    fi

    if [[ ${#need_python_packages[@]} -gt 0 ]]; then
        if [[ "$(uname -s)" == Darwin ]]; then
            if command -v brew >/dev/null 2>&1; then
                brew install python || return 1
            else
                print_error "Python packaging tools are missing and Homebrew is not installed."
                return 1
            fi
        else
            install_linux_packages "${need_python_packages[@]}" || {
                print_error "Could not install the required Python tools automatically."
                return 1
            }
        fi
    fi

    if ! python3 -m pip --version >/dev/null 2>&1 || ! probe_python_venv; then
        print_error "Python pip/venv is still unavailable after installation."
        return 1
    fi
    return 0
}

check_local_requirements() {
    print_step "Checking local installation requirements..."
    echo ""
    
    local all_ok=true
    
    check_command python3 "Python 3" || all_ok=false
    
    if command -v python3 &> /dev/null; then
        local python_version=$(python3 --version | cut -d' ' -f2)
        print_info "Python version: $python_version"
    fi
    
    if python3 -m pip --version >/dev/null 2>&1; then
        print_success "pip (Python module) is installed"
    else
        print_error "pip is not installed"
        all_ok=false
    fi
    check_optional_command nmap "nmap" || true
    if command -v docker >/dev/null 2>&1; then
        print_success "Docker is installed"
    else
        print_info "Docker is optional for local TUI; choose the Docker runtime for container setup"
    fi
    
    echo ""
    
    if [ "$all_ok" = false ]; then
        print_error "Some required dependencies are missing"
        return 1
    fi
    
    return 0
}

check_docker_compose_works() {
    if docker_select_compose; then
        print_success "Docker Compose is ready ($COMPOSE_CMD)"
        return 0
    else
        print_error "Docker Compose is not installed or not working"
        return 1
    fi
}

check_docker_requirements() {
    print_step "Checking Docker installation requirements..."
    echo ""

    local all_ok=true

    check_command docker "Docker" || all_ok=false
    check_docker_compose_works || all_ok=false
    
    # Check if Docker daemon is running
    if "${DOCKER_RUN[@]}" info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_error "Docker daemon is not running"
        all_ok=false
    fi
    
    # Check Docker permissions
    if "${DOCKER_RUN[@]}" ps &> /dev/null; then
        print_success "Docker permissions OK"
    else
        print_error "Docker container access failed using ${DOCKER_RUN[*]}"
        all_ok=false
    fi
    
    echo ""
    
    if [ "$all_ok" = false ]; then
        print_error "Docker requirements not met"
        return 1
    fi
    
    return 0
}

api_health_ready() {
    local port=$1
    if command -v curl >/dev/null 2>&1; then
        curl -sf --max-time 2 "http://localhost:$port/health" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO /dev/null --timeout=2 --tries=1 "http://localhost:$port/health" >/dev/null 2>&1
    else
        print_error "curl or wget is required for the API health check."
        return 1
    fi
}

# ============================================================
# Environment Setup
# ============================================================

setup_env_file() {
    print_step "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            ENV_FILE_CREATED=true
            print_success "Created .env file from .env.example"
        else
            print_warning ".env.example not found, creating basic .env"
            cat > .env << 'EOF'
# BugTraceAI Environment Configuration
# Configure a key through Provider (F7) in the TUI.
# OPENROUTER_API_KEY=your-openrouter-api-key-here
BUGTRACE_CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:6869
EOF
            ENV_FILE_CREATED=true
        fi
        
        echo ""
        print_info "Local TUI: configure your provider and API key with Provider (F7)."
        print_info "Server/Docker: configure the provider and a real API key in .env before scanning."
        echo ""
    else
        print_info ".env file already exists"
    fi
}

# ============================================================
# Local Installation
# ============================================================

install_local() {
    print_header
    echo -e "${PYTHON} ${GREEN}Local Installation Mode${NC}"
    echo ""
    
    if ! prepare_local_requirements || ! check_local_requirements; then
        print_error "Local prerequisites could not be prepared. Installation cancelled."
        exit 1
    fi
    
    echo ""
    setup_env_file
    
    echo ""
    print_step "Creating Python virtual environment..."
    
    if [ -d .venv ]; then
        print_info "Refreshing the existing virtual environment without removing packages"
        python3 -m venv .venv
    else
        python3 -m venv .venv
        print_success "Virtual environment created"
    fi
    
    echo ""
    print_step "Activating virtual environment..."
    source .venv/bin/activate
    print_success "Virtual environment activated"
    
    echo ""
    print_step "Upgrading pip..."
    python3 -m pip install --upgrade pip
    
    echo ""
    print_step "Installing Python dependencies..."
    print_info "This may take several minutes (includes PyTorch CPU and other ML libraries)..."
    if [[ "$(uname -s)" == Linux ]]; then
        python3 -m pip install 'torch>=2.0.0' --index-url https://download.pytorch.org/whl/cpu
    fi
    python3 -m pip install -e "$(install_extras)"
    chmod +x bugtraceai-cli
    if [[ "$INSTALL_INTERFACE" != api ]]; then
        python3 -c "from bugtrace.core.ui.tui import BugTraceApp; print('TUI dependencies ready')"
    fi
    if [[ "$INSTALL_INTERFACE" != tui ]]; then
        python3 -c "import fastapi, uvicorn, mcp; print('API/MCP dependencies ready')"
    fi
    print_success "Engine and selected interface dependencies installed"

    echo ""
    print_step "Installing Playwright browsers..."
    playwright install chromium
    if [[ "$(uname -s)" == Linux ]]; then
        playwright install-deps chromium
    fi
    print_success "Playwright Chromium installed"
    
    echo ""
    print_step "Building Go fuzzers..."
    if [ -f tools/build_fuzzers.sh ]; then
        chmod +x tools/build_fuzzers.sh
        if command -v go >/dev/null 2>&1 && (cd tools && bash build_fuzzers.sh); then
            print_success "Go fuzzers built successfully"
        else
            print_warning "Go fuzzers were not prebuilt. Install Go to enable on-demand compilation."
        fi
    else
        print_warning "Go fuzzers build script not found (optional)"
    fi
    
    echo ""
    print_step "Creating required directories..."
    mkdir -p reports logs data
    print_success "Directories created"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║            ${CHECK} Local Installation Complete! ${CHECK}              ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    show_launch_commands

}

# ============================================================
# Docker Installation
# ============================================================

install_docker() {
    print_header
    echo -e "${DOCKER} ${GREEN}Docker Installation Mode${NC}"
    echo ""
    
    if ! prepare_docker_requirements || ! check_docker_requirements; then
        echo ""
        print_error "Cannot proceed with Docker installation"
        print_info "Docker setup failed. Resolve the error above or see:"
        print_info "  https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    echo ""
    setup_env_file
    
    # A terminal-only image is built on demand and has no listening services.
    if [[ "$INSTALL_INTERFACE" == tui ]]; then
        "${COMPOSE_ARGS[@]}" -f docker-compose.tui.yml config -q
        "${COMPOSE_ARGS[@]}" -f docker-compose.tui.yml build
        show_launch_commands
        return
    fi
    set_env_value BUGTRACE_INTERFACE "$INSTALL_INTERFACE"

    # Port configuration
    echo ""
    print_step "Configuring network ports..."
    
    local default_cli_port=8000
    local default_mcp_port=8001
    local selected_cli_port=$default_cli_port
    local selected_mcp_port=$default_mcp_port
    local existing_cli_port existing_mcp_port preserve_existing_ports=false

    existing_cli_port=$(read_env_value CLI_PORT || true)
    existing_mcp_port=$(read_env_value MCP_PORT || true)
    if "${DOCKER_RUN[@]}" ps --format '{{.Names}}' 2>/dev/null | grep -Eq '^(bugtrace_api|bugtrace_mcp)$'; then
        preserve_existing_ports=true
    fi

    if is_valid_port "$existing_cli_port" && {
        [ "$ENV_FILE_CREATED" = false ] || [ "$preserve_existing_ports" = true ];
    }; then
        selected_cli_port=$existing_cli_port
    elif is_port_in_use "$default_cli_port"; then
        selected_cli_port=$(find_free_port "$default_cli_port")
    fi

    if is_valid_port "$existing_mcp_port" && {
        [ "$ENV_FILE_CREATED" = false ] || [ "$preserve_existing_ports" = true ];
    }; then
        selected_mcp_port=$existing_mcp_port
    elif is_port_in_use "$default_mcp_port"; then
        selected_mcp_port=$(find_free_port "$default_mcp_port")
    fi

    if [ "$selected_cli_port" = "$selected_mcp_port" ]; then
        selected_mcp_port=$(find_free_port_avoiding "$((selected_mcp_port + 1))" "$selected_cli_port")
    fi

    echo ""
    print_info "Using CLI port: $selected_cli_port, MCP port: $selected_mcp_port"
    set_env_value CLI_PORT "$selected_cli_port"
    set_env_value MCP_PORT "$selected_mcp_port"
    
    echo ""
    print_step "Building Docker image..."
    print_info "This may take 5-10 minutes on first build..."
    
    if ! docker_select_compose; then
        print_error "Docker Compose not available"
        exit 1
    fi
    
    if ! "${COMPOSE_ARGS[@]}" config -q &>/dev/null; then
        print_error "Docker compose configuration is invalid"
        "${COMPOSE_ARGS[@]}" config
        exit 1
    fi
    "${COMPOSE_ARGS[@]}" build
    print_success "Docker image built successfully"
    
    echo ""
    print_step "Starting BugTraceAI container..."
    "${COMPOSE_ARGS[@]}" up -d
    print_success "Container started"
    
    echo ""
    print_step "Waiting for API to be ready..."
    local max_wait=60
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        if api_health_ready "$selected_cli_port"; then
            print_success "API is ready!"
            break
        fi
        sleep 2
        ((waited+=2))
        echo -n "."
    done
    echo ""
    
    if [ $waited -ge $max_wait ]; then
        print_error "API health check timed out; installation could not be verified."
        print_info "Check logs with: $COMPOSE_CMD logs -f"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║            ${CHECK} Docker Installation Complete! ${CHECK}             ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_info "BugTraceAI is now running at:"
    echo -e "  ${CYAN}http://localhost:$selected_cli_port${NC}"
    echo ""
    print_info "API Health Check:"
    echo -e "  ${CYAN}http://localhost:$selected_cli_port/health${NC}"
    echo ""
    print_info "API Documentation:"
    echo -e "  ${CYAN}http://localhost:$selected_cli_port/docs${NC}"
    echo ""
    show_launch_commands
    print_info "Useful commands:"
    echo -e "  ${CYAN}$COMPOSE_CMD logs -f${NC}         # View logs"
    echo -e "  ${CYAN}$COMPOSE_CMD stop${NC}            # Stop container"
    echo -e "  ${CYAN}$COMPOSE_CMD start${NC}           # Start container"
    echo -e "  ${CYAN}$COMPOSE_CMD restart${NC}         # Restart container"
    echo -e "  ${CYAN}$COMPOSE_CMD down${NC}            # Stop and remove container"
    echo ""
}

# ============================================================
# Main Menu
# ============================================================

main() {
    local reuse=false global_only=false requested_interface="" requested_runtime="" requested_global="" requested_launch="" choice
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --interface) [[ $# -ge 2 ]] || return 1; requested_interface="$2"; shift 2 ;;
            --runtime) [[ $# -ge 2 ]] || return 1; requested_runtime="$2"; shift 2 ;;
            --global-only) global_only=true; shift ;;
            --global) [[ $# -ge 2 ]] || return 1; requested_global="$2"; shift 2 ;;
            --launch) [[ $# -ge 2 ]] || return 1; requested_launch="$2"; shift 2 ;;
            --reuse) reuse=true; shift ;;
            --help|-h) echo "Usage: ./install.sh [--interface tui|api|both] [--runtime local|docker] [--global yes|no] [--launch yes|no] [--global-only] [--reuse]"; return ;;
            *) print_error "Unknown option: $1"; return 1 ;;
        esac
    done
    if $reuse; then
        load_install_choices
        [[ -n "$INSTALL_INTERFACE" && -n "$INSTALL_RUNTIME" ]] || { print_error "No saved choices. Run ./install.sh once."; return 1; }
    fi
    [[ -z "$requested_interface" ]] || INSTALL_INTERFACE="$requested_interface"
    [[ -z "$requested_runtime" ]] || INSTALL_RUNTIME="$requested_runtime"
    if [[ -z "$INSTALL_INTERFACE" ]]; then
        print_header
        echo "Which BugTraceAI CLI interfaces do you want?"
        echo "  1) Interactive terminal (TUI)"
        echo "  2) API server + MCP (WEB / integrations)"
        echo "  3) Both TUI and API/MCP"
        echo "  4) Cancel"
        read -r -p "Select interface [1-4]: " choice
        case "$choice" in 1) INSTALL_INTERFACE=tui ;; 2) INSTALL_INTERFACE=api ;; 3) INSTALL_INTERFACE=both ;; 4) return ;; *) print_error "Invalid interface"; return 1 ;; esac
    fi
    case "$INSTALL_INTERFACE" in tui|api|both) ;; *) print_error "Interface must be tui, api or both"; return 1 ;; esac
    case "$requested_launch" in ''|yes|no) ;; *) print_error "Launch choice must be yes or no"; return 1 ;; esac
    if [[ "$requested_launch" == yes ]]; then
        [[ "$INSTALL_INTERFACE" != api ]] || { print_error "Launching the TUI requires TUI or both interfaces."; return 1; }
        [[ -t 0 && -t 1 ]] || { print_error "--launch yes requires an interactive terminal. Use --launch no for automation."; return 1; }
    fi
    if [[ -z "$INSTALL_RUNTIME" ]]; then
        echo ""
        echo "Where should the selected CLI interfaces run?"
        echo ""
        echo "  1) Local Python virtual environment"
        echo "     -> The selected interfaces run in a local .venv"
        echo ""
        echo "  2) Docker containers"
        case "$INSTALL_INTERFACE" in
            tui) echo "     -> TUI runs in an interactive container; no API server is started" ;;
            api) echo "     -> API/MCP run as Compose services" ;;
            both) echo "     -> API/MCP run in Compose; the TUI opens inside the API container" ;;
        esac
        echo "     -> Missing Docker/Compose will be installed; sudo may be requested"
        echo ""
        echo "  3) Cancel"
        echo ""
        read -r -p "Select runtime [1-3]: " choice
        case "$choice" in 1) INSTALL_RUNTIME=local ;; 2) INSTALL_RUNTIME=docker ;; 3) return ;; *) print_error "Invalid runtime"; return 1 ;; esac
    fi
    case "$INSTALL_RUNTIME" in local|docker) ;; *) print_error "Runtime must be local or docker"; return 1 ;; esac
    [[ -z "$requested_global" ]] || INSTALL_GLOBAL="$requested_global"
    if [[ "$INSTALL_INTERFACE" == api ]]; then
        [[ "$INSTALL_GLOBAL" != yes ]] || { print_error "The global btai command requires TUI or both."; return 1; }
        INSTALL_GLOBAL=no
    elif [[ -z "$INSTALL_GLOBAL" ]]; then
        read -r -p "Install global btai command to open the TUI from any folder? [y/N]: " choice
        case "$choice" in y|Y|yes|YES) INSTALL_GLOBAL=yes ;; *) INSTALL_GLOBAL=no ;; esac
    fi
    case "$INSTALL_GLOBAL" in yes|no) ;; *) print_error "Global choice must be yes or no"; return 1 ;; esac
    if ! $global_only; then
        case "$INSTALL_RUNTIME" in
            local) install_local ;;
            docker) install_docker ;;
        esac
    fi
    # An optional command/PATH failure must not lose a completed installation's profile.
    save_install_choices
    if [[ "$INSTALL_GLOBAL" == yes ]]; then install_global_command; fi
    offer_tui_launch "$requested_launch" "$global_only"
}

# ============================================================
# Entry Point
# ============================================================

# Trap errors
trap 'print_error "Installation failed at line $LINENO"' ERR

# Run main function
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
