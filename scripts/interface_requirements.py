"""Select interface dependencies for Docker; keep the shared engine unchanged."""
import re
import sys
from pathlib import Path

GROUPS = {"tui": {"textual"}, "api": {"fastapi", "uvicorn", "websockets", "mcp"}}


def select_requirements(content, interface):
    if interface not in {"tui", "api", "both"}:
        raise ValueError("Interface must be tui, api or both")
    excluded = GROUPS["api"] if interface == "tui" else GROUPS["tui"] if interface == "api" else set()
    lines = []
    for line in content.splitlines(keepends=True):
        match = re.match(r"\s*([\w.-]+)", line)
        if not match or match[1].lower() not in excluded:
            lines.append(line)
    return "".join(lines)


if __name__ == "__main__":
    Path(sys.argv[3]).write_text(select_requirements(Path(sys.argv[2]).read_text(), sys.argv[1]))
