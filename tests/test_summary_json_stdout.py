import json
import os
import subprocess
import sys
from pathlib import Path


def test_summary_json_stdout_is_machine_readable(tmp_path):
    report = (
        tmp_path
        / "reports"
        / "example.test_20261030_120000"
        / "specialists"
        / "results"
    )
    report.mkdir(parents=True)

    (report / "findings.json").write_text(
        json.dumps({
            "findings": [{
                "url": "http://example.test/",
                "parameter": "test",
                "type": "TEST_FINDING",
                "payload": "test",
                "severity": "LOW",
                "status": "VALIDATED_CONFIRMED",
            }]
        }),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["BUGTRACE_TEST_ROOT"] = str(tmp_path)

    result = subprocess.run(
        [sys.executable, "-m", "bugtrace", "summary", "--json"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr

    data = json.loads(result.stdout)

    assert data["total_findings"] == 1
    assert data["severity"]["low"] == 1
    assert data["by_type"]["TEST_FINDING"] == 1

    assert "Provider preset loaded" not in result.stdout
    assert "[aiohttp-patch]" not in result.stdout
