from __future__ import annotations

import subprocess
import sys


def test_cli_module_is_executable() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "threat_report_agent.cli", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()
