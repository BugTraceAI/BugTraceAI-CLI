#!/usr/bin/env bash
# The Launcher is the only guided installer. Explicit options remain compatible.
set -euo pipefail
installer_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
    '') exec bash "$installer_dir/scripts/launcher-bootstrap.sh" terminal ;;
    --help|-h)
        printf '%s\n' 'Usage: ./install.sh' \
            'Opens the universal Launcher with the terminal profile suggested.' \
            'Direct automation: ./scripts/install-runtime.sh --interface tui|api|both --runtime local|docker' \
            'Optional: --global yes|no --launch yes|no --global-only --reuse' \
            'Legacy explicit flags and --standalone [options] delegate to that backend.' \
            'The component has no separate setup wizard. See INSTALLATION.md.' ;;
    *) exec bash "$installer_dir/scripts/install-runtime.sh" "$@" ;;
esac
