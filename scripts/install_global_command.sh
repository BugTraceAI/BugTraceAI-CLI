# Sourced by scripts/install-runtime.sh; install only a user-owned command, without sudo.
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
        *":$command_dir:"*) print_success "Global TUI command ready: btai" ;;
        *)
            case "${SHELL:-/bin/bash}" in
                */zsh) profile="$HOME/.zshrc" ;;
                *) if [[ "$(uname -s)" == Darwin ]]; then profile="$HOME/.bash_profile"; else profile="$HOME/.bashrc"; fi ;;
            esac
            if ! grep -q '^# BugTraceAI user commands$' "$profile" 2>/dev/null; then
                printf '\n# BugTraceAI user commands\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$profile"
            fi
            print_success "btai registered for new terminals"
            print_info "This terminal still needs its PATH refreshed."
            print_info "To enable it here, run this in your current shell:"
            printf '  export PATH="$HOME/.local/bin:$PATH"\n'
            print_info "Or open a new terminal (PATH configured in $profile)."
            ;;
    esac
    local quoted_command
    printf -v quoted_command '%q' "$command_path"
    print_info "Start the TUI immediately: $quoted_command"
    print_info "It opens this installation from any folder."
    if [[ "${INSTALL_RUNTIME:-local}" == docker ]]; then
        print_info "Global registration needs no sudo; Docker may ask for your sudo password at launch."
    fi
}

# Use the checkout path to launch; the parent shell may not have the new PATH yet.
offer_tui_launch() {
    local requested=${1:-no}
    [[ "$INSTALL_INTERFACE" != api && "$requested" == yes ]] || return 0
    print_step "Opening the BugTraceAI TUI..."
    if bash "$INSTALLER_DIR/btai"; then
        print_info "TUI closed. Your installation and saved profile are ready."
    else
        print_warning "The TUI did not open successfully; the installation and saved profile were kept."
        print_info "Retry with: ./btai"
    fi
    if [[ "$INSTALL_GLOBAL" == yes && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        print_info "To use btai by name in this terminal, run:"
        printf '  export PATH="$HOME/.local/bin:$PATH"\n'
    fi
}
