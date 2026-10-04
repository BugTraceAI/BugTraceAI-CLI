# Docker setup and access shared by the installer and the global TUI helper.
# Sourcing this file performs no installation or daemon operations.
DOCKER_RUN=(docker)
COMPOSE_ARGS=()

docker_resolve_access() {
    local runtime_bin
    DOCKER_RUN=(docker)
    if [[ "$(uname -s)" == Darwin ]] && ! command -v docker >/dev/null 2>&1; then
        for runtime_bin in /opt/homebrew/bin /usr/local/bin /Applications/Docker.app/Contents/Resources/bin; do
            [[ ! -x "$runtime_bin/docker" ]] || export PATH="$runtime_bin:$PATH"
        done
    fi
    if command docker info >/dev/null 2>&1; then
        return 0
    fi
    # Escalate only a local socket permission error, never a broken remote context.
    local diagnostic context
    diagnostic=$(command docker info 2>&1) || true
    if [[ "$(uname -s)" == Linux && "$diagnostic" == *"permission denied"* ]] && \
       [[ -z "${DOCKER_HOST:-}" ]] && command -v sudo >/dev/null 2>&1; then
        context=$(command docker context show 2>/dev/null) || context=default
        if [[ "$context" == default ]] && sudo docker info >/dev/null 2>&1; then
            DOCKER_RUN=(sudo docker)
            return 0
        fi
    fi
    return 1
}

docker_select_compose() {
    COMPOSE_ARGS=()
    COMPOSE_CMD=""
    if "${DOCKER_RUN[@]}" compose version >/dev/null 2>&1; then
        COMPOSE_ARGS=("${DOCKER_RUN[@]}" compose)
    elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
        if [[ "${DOCKER_RUN[0]}" == sudo ]]; then
            COMPOSE_ARGS=(sudo docker-compose)
        else
            COMPOSE_ARGS=(docker-compose)
        fi
    else
        return 1
    fi
    COMPOSE_CMD="${COMPOSE_ARGS[*]}"
}

docker_download() {
    local url=$1 destination=$2
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1 && [[ "$(uname -s)" == Linux ]]; then
        install_linux_packages curl || return 1
        hash -r
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 --connect-timeout 15 "$url" -o "$destination"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$destination" "$url"
    else
        print_error "curl or wget is required to download Docker's installer."
        return 1
    fi
}

install_linux_docker_engine() {
    # Do not rerun the convenience installer over an existing Docker installation.
    command -v docker >/dev/null 2>&1 && return 0
    if command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -S --needed --noconfirm docker docker-compose
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper install -y docker docker-compose
    else
        local script
        script=$(mktemp "${TMPDIR:-/tmp}/bugtraceai-docker.XXXXXX") || return 1
        if ! docker_download https://get.docker.com "$script"; then
            rm -- "$script"
            return 1
        fi
        local status=0
        run_privileged sh "$script" || status=$?
        rm -- "$script"
        [[ "$status" -eq 0 ]] || return "$status"
    fi
}

start_linux_docker() {
    # Respect configured remote/rootless/Desktop contexts; do not switch runtimes.
    local context
    context=$(command docker context show 2>/dev/null) || context=default
    if [[ -n "${DOCKER_HOST:-}" || "$context" != default ]]; then
        print_error "The selected Docker endpoint/context is unavailable: $context"
        print_info "Start that runtime and rerun the installer."
        return 1
    fi
    print_step "Starting Docker Engine..."
    if command -v systemctl >/dev/null 2>&1; then
        run_privileged systemctl start docker || {
            command -v service >/dev/null 2>&1 && run_privileged service docker start
        } || return 1
    elif command -v service >/dev/null 2>&1; then
        run_privileged service docker start || return 1
    else
        print_error "No supported service manager found; start Docker and rerun the installer."
        return 1
    fi
    local attempt
    for ((attempt=0; attempt<15; attempt++)); do
        docker_resolve_access && return 0
        sleep 2
    done
    print_error "Docker Engine did not become ready."
    return 1
}

install_linux_compose() {
    print_step "Installing Docker Compose..."
    # Prefer a managed package for existing Docker installations.
    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get install -y docker-compose-plugin || \
            run_privileged apt-get install -y docker-compose-v2 || true
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y docker-compose-plugin || true
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y docker-compose-plugin || true
    elif command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -S --needed --noconfirm docker-compose || true
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper install -y docker-compose || true
    fi
    docker_select_compose && return 0

    local arch plugin
    arch=$(uname -m)
    case "$arch" in x86_64|aarch64|armv7l|ppc64le|s390x|riscv64) ;; *)
        print_error "No automatic Compose download is available for $arch."
        return 1 ;;
    esac
    [[ "$arch" != armv7l ]] || arch=armv7
    plugin=$(mktemp "${TMPDIR:-/tmp}/bugtraceai-compose.XXXXXX") || return 1
    if ! docker_download "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$arch" "$plugin"; then
        rm -- "$plugin"
        return 1
    fi
    # Verify the completed download before installing it in Docker's plugin path.
    chmod 755 "$plugin"
    if ! "$plugin" version >/dev/null 2>&1; then
        print_error "The downloaded Compose executable could not run."
        rm -- "$plugin"
        return 1
    fi
    local status=0
    run_privileged install -D -m 755 "$plugin" /usr/local/lib/docker/cli-plugins/docker-compose || status=$?
    rm -- "$plugin"
    [[ "$status" -eq 0 ]] && docker_select_compose
}

ensure_macos_docker() {
    local brew_bin=""
    # Respect an existing Docker Desktop installation before choosing Colima.
    if [[ -d /Applications/Docker.app ]]; then
        export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
        open -a Docker || return 1
    else
        brew_bin=$(command -v brew) || brew_bin=""
        if [[ -z "$brew_bin" ]]; then
            for brew_bin in /opt/homebrew/bin/brew /usr/local/bin/brew; do
                [[ ! -x "$brew_bin" ]] || break
            done
            [[ -x "$brew_bin" ]] || {
                print_error "Homebrew is required for automatic Docker/Colima setup on macOS."
                print_info "Install Homebrew or Docker Desktop, then rerun the installer."
                return 1
            }
        fi
        export PATH="$(dirname "$brew_bin"):$PATH"
        print_step "Installing Docker, Compose and Colima with Homebrew..."
        "$brew_bin" install docker docker-compose colima || return 1
        if ! command docker info >/dev/null 2>&1; then
            colima start --runtime docker || return 1
        fi
    fi
    local attempt
    for ((attempt=0; attempt<30; attempt++)); do
        docker_resolve_access && break
        sleep 2
    done
    docker_resolve_access || { print_error "The macOS Docker runtime did not become ready."; return 1; }
    if ! docker_select_compose; then
        [[ -n "$brew_bin" ]] || brew_bin=$(command -v brew) || {
            print_error "Compose is missing; install it through Docker Desktop or Homebrew."
            return 1
        }
        "$brew_bin" install docker-compose || return 1
        docker_select_compose || { print_error "Docker Compose is still unavailable."; return 1; }
    fi
}

prepare_docker_requirements() {
    print_step "Preparing Docker runtime..."
    if docker_resolve_access && docker_select_compose; then
        return 0
    fi
    case "$(uname -s)" in
        Linux)
            if ! command -v docker >/dev/null 2>&1; then
                print_info "Docker is missing; installing Docker Engine from its official installer."
                install_linux_docker_engine || { print_error "Docker installation failed."; return 1; }
                hash -r
            fi
            docker_resolve_access || start_linux_docker || return 1
            docker_select_compose || install_linux_compose || {
                print_error "Docker Compose setup failed."
                return 1
            }
            ;;
        Darwin) ensure_macos_docker || return 1 ;;
        *) print_error "Automatic Docker setup supports Linux and macOS."; return 1 ;;
    esac
    if [[ "${DOCKER_RUN[0]}" == sudo ]]; then
        print_info "Docker needs administrator access; this installer and btai will use sudo."
    fi
}
