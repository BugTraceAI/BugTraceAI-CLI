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
    
    print_step "Searching for available port starting from $start_port..."
    
    for ((i=0; i<max_attempts; i++)); do
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        ((port++))
    done
    
    print_error "Could not find a free port after $max_attempts attempts"
    return 1
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

check_local_requirements() {
    print_step "Checking local installation requirements..."
    echo ""
    
    local all_ok=true
    
    check_command python3 "Python 3" || all_ok=false
    
    if command -v python3 &> /dev/null; then
        local python_version=$(python3 --version | cut -d' ' -f2)
        print_info "Python version: $python_version"
    fi
    
    check_command pip3 "pip3" || all_ok=false
    check_command nmap "nmap" || print_warning "nmap not found (optional, but recommended)"
    check_command docker "Docker" || print_warning "Docker not found (needed for some agents)"
    
    echo ""
    
    if [ "$all_ok" = false ]; then
        print_error "Some required dependencies are missing"
        return 1
    fi
    
    return 0
}

check_docker_requirements() {
    print_step "Checking Docker installation requirements..."
    echo ""
    
    local all_ok=true
    
    check_command docker "Docker" || all_ok=false
    check_command docker-compose "Docker Compose" || check_command "docker compose" "Docker Compose" || all_ok=false
    
    # Check if Docker daemon is running
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_error "Docker daemon is not running"
        all_ok=false
    fi
    
    # Check Docker permissions
    if docker ps &> /dev/null; then
        print_success "Docker permissions OK"
    else
        print_warning "Docker requires sudo (you may need to add your user to docker group)"
    fi
    
    echo ""
    
    if [ "$all_ok" = false ]; then
        print_error "Docker requirements not met"
        return 1
    fi
    
    return 0
}

# ============================================================
# Environment Setup
# ============================================================

setup_env_file() {
    print_step "Setting up environment configuration..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            print_success "Created .env file from .env.example"
        else
            print_warning ".env.example not found, creating basic .env"
            cat > .env << 'EOF'
# BugTraceAI Environment Configuration
OPENROUTER_API_KEY=your-openrouter-api-key-here
BUGTRACE_CORS_ORIGINS=http://localhost:3000,http://localhost:5173,http://localhost:6869
EOF
        fi
        
        echo ""
        print_warning "IMPORTANT: You need to configure your .env file!"
        print_info "Please edit .env and add your OPENROUTER_API_KEY"
        print_info "Get your API key from: https://openrouter.ai/keys"
        echo ""
        
        read -p "$(echo -e ${YELLOW}Press Enter to continue after configuring .env...${NC})"
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
    
    if ! check_local_requirements; then
        echo ""
        read -p "$(echo -e ${YELLOW}Continue anyway? [y/N]: ${NC})" continue_install
        if [[ ! "$continue_install" =~ ^[Yy]$ ]]; then
            print_error "Installation cancelled"
            exit 1
        fi
    fi
    
    echo ""
    setup_env_file
    
    echo ""
    print_step "Creating Python virtual environment..."
    
    if [ -d .venv ]; then
        print_info "Virtual environment already exists"
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
    pip install --upgrade pip
    
    echo ""
    print_step "Installing Python dependencies..."
    print_info "This may take several minutes (includes PyTorch CPU and other ML libraries)..."
    pip install -r requirements.txt
    print_success "Dependencies installed"
    
    echo ""
    print_step "Installing Playwright browsers..."
    playwright install chromium
    playwright install-deps chromium
    print_success "Playwright Chromium installed"
    
    echo ""
    print_step "Building Go fuzzers..."
    if [ -f tools/build_fuzzers.sh ]; then
        chmod +x tools/build_fuzzers.sh
        cd tools && bash build_fuzzers.sh && cd ..
        print_success "Go fuzzers built successfully"
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
    
    print_info "To start BugTraceAI:"
    echo -e "  ${CYAN}source .venv/bin/activate${NC}"
    echo -e "  ${CYAN}./bugtraceai-cli serve --port 8000${NC}"
    echo ""
    print_info "Or use the CLI directly:"
    echo -e "  ${CYAN}./bugtraceai-cli scan <target-url>${NC}"
    echo ""
}

# ============================================================
# Docker Installation
# ============================================================

install_docker() {
    print_header
    echo -e "${DOCKER} ${GREEN}Docker Installation Mode${NC}"
    echo ""
    
    if ! check_docker_requirements; then
        echo ""
        print_error "Cannot proceed with Docker installation"
        print_info "Please install Docker and Docker Compose first:"
        print_info "  https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    echo ""
    setup_env_file
    
    # Port configuration
    echo ""
    print_step "Configuring network ports..."
    
    local default_port=8000
    local selected_port=$default_port
    
    if is_port_in_use "$default_port"; then
        print_warning "Default port $default_port is already in use"
        
        local free_port
        free_port=$(find_free_port $default_port)
        
        if [ -n "$free_port" ]; then
            print_info "Found available port: $free_port"
            echo ""
            read -p "$(echo -e ${YELLOW}Use port $free_port? [Y/n]: ${NC})" use_free_port
            
            if [[ ! "$use_free_port" =~ ^[Nn]$ ]]; then
                selected_port=$free_port
            else
                read -p "$(echo -e ${YELLOW}Enter custom port: ${NC})" custom_port
                selected_port=${custom_port:-$default_port}
            fi
        else
            read -p "$(echo -e ${YELLOW}Enter custom port: ${NC})" custom_port
            selected_port=${custom_port:-$default_port}
        fi
    else
        print_success "Port $default_port is available"
    fi
    
    echo ""
    print_info "Using port: $selected_port"
    
    # Update docker-compose.yml with selected port
    if [ "$selected_port" != "$default_port" ]; then
        print_step "Updating docker-compose.yml with port $selected_port..."
        
        if [ -f docker-compose.yml ]; then
            # Create backup
            cp docker-compose.yml docker-compose.yml.bak
            
            # Update port mapping
            sed -i "s/- \"[0-9]*:8000\"/- \"$selected_port:8000\"/" docker-compose.yml
            print_success "Port configuration updated"
        fi
    fi
    
    echo ""
    print_step "Building Docker image..."
    print_info "This may take 5-10 minutes on first build..."
    
    # Check if docker-compose or docker compose is available
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    $COMPOSE_CMD build
    print_success "Docker image built successfully"
    
    echo ""
    print_step "Starting BugTraceAI container..."
    $COMPOSE_CMD up -d
    print_success "Container started"
    
    echo ""
    print_step "Waiting for API to be ready..."
    local max_wait=60
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
        if curl -sf "http://localhost:$selected_port/health" > /dev/null 2>&1; then
            print_success "API is ready!"
            break
        fi
        sleep 2
        ((waited+=2))
        echo -n "."
    done
    echo ""
    
    if [ $waited -ge $max_wait ]; then
        print_warning "API health check timeout, but container may still be starting..."
        print_info "Check logs with: $COMPOSE_CMD logs -f"
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║            ${CHECK} Docker Installation Complete! ${CHECK}             ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_info "BugTraceAI is now running at:"
    echo -e "  ${CYAN}http://localhost:$selected_port${NC}"
    echo ""
    print_info "API Health Check:"
    echo -e "  ${CYAN}http://localhost:$selected_port/health${NC}"
    echo ""
    print_info "API Documentation:"
    echo -e "  ${CYAN}http://localhost:$selected_port/docs${NC}"
    echo ""
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

show_menu() {
    print_header
    
    echo -e "Choose your installation method:"
    echo ""
    echo -e "  ${PYTHON} ${CYAN}1)${NC} Local Installation (Python Virtual Environment)"
    echo -e "     ${ARROW} Best for development and customization"
    echo -e "     ${ARROW} Requires Python 3.10+, pip, and system dependencies"
    echo ""
    echo -e "  ${DOCKER} ${CYAN}2)${NC} Docker Installation (Containerized)"
    echo -e "     ${ARROW} Best for production and isolated environments"
    echo -e "     ${ARROW} Requires Docker and Docker Compose"
    echo -e "     ${ARROW} Automatic port detection and configuration"
    echo ""
    echo -e "  ${CYAN}3)${NC} Exit"
    echo ""
}

main() {
    # Check if running from project root
    if [ ! -f "bugtraceai-cli" ] || [ ! -f "requirements.txt" ]; then
        print_error "Please run this script from the BugTraceAI project root directory"
        exit 1
    fi
    
    while true; do
        show_menu
        read -p "$(echo -e ${YELLOW}Select option [1-3]: ${NC})" choice
        echo ""
        
        case $choice in
            1)
                install_local
                break
                ;;
            2)
                install_docker
                break
                ;;
            3)
                print_info "Installation cancelled"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1, 2, or 3."
                echo ""
                sleep 2
                clear
                ;;
        esac
    done
}

# ============================================================
# Entry Point
# ============================================================

# Trap errors
trap 'print_error "Installation failed at line $LINENO"' ERR

# Run main function
main "$@"
