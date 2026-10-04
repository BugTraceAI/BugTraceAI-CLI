# Sourced by install.sh; install only a user-owned command, without sudo.
install_global_command() {
    local command_dir="$HOME/.local/bin" command_path="$HOME/.local/bin/btai" profile
    mkdir -p "$command_dir"
    if [[ -e "$command_path" || -L "$command_path" ]]; then
        if ! head -n 3 "$command_path" 2>/dev/null | grep -q '^# BugTraceAI global command$'; then
            print_error "A different btai command already exists at $command_path; it was kept."
            return 1
        fi
    fi
    (umask 077
        printf '#!/usr/bin/env bash\n# BugTraceAI global command\nexec bash %q "$@"\n' "$INSTALLER_DIR/btai" > "$command_path"
    )
    chmod 755 "$command_path"
    case ":$PATH:" in
        *":$command_dir:"*) ;;
        *)
            case "${SHELL:-/bin/bash}" in
                */zsh) profile="$HOME/.zshrc" ;;
                *) if [[ "$(uname -s)" == Darwin ]]; then profile="$HOME/.bash_profile"; else profile="$HOME/.bashrc"; fi ;;
            esac
            if ! grep -q '^# BugTraceAI user commands$' "$profile" 2>/dev/null; then
                printf '\n# BugTraceAI user commands\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$profile"
            fi
            print_info "Open a new terminal to use btai (PATH configured in $profile)."
            ;;
    esac
    print_success "Global TUI command installed: btai"
    print_info "It opens this installation from any folder; no sudo required."
}
