"""Tests for the argument and environment checks in .forgejo/desktop-ci.sh."""

import os
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / ".forgejo" / "desktop-ci.sh"


def run_script(**overrides):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("DESKTOP_CI_")
    }
    env.update(
        REF="main",
        SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
        REPO_TOKEN="token",
        SERVER_URL="https://forgejo.invalid",
        REPOSITORY="factory/muniment-core",
        RUNNER_TEMP="/nonexistent",
    )
    env.update(overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), "linux", "true"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class DesktopCiHost(unittest.TestCase):
    def test_unset_host_fails(self):
        result = run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DESKTOP_CI_HOST", result.stderr)

    def test_empty_host_fails(self):
        result = run_script(DESKTOP_CI_HOST="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DESKTOP_CI_HOST", result.stderr)


if __name__ == "__main__":
    unittest.main()
