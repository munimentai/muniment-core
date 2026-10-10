"""Tests for check-private-addresses.sh against throwaway git repositories."""

import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-private-addresses.sh"


def dotted(*parts):
    return ".".join(str(p) for p in parts)


class PrivateAddressCheck(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.git("init", "-q")

    def git(self, *args):
        subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            capture_output=True,
        )

    def run_check(self, relpath, content):
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.git("add", "-f", relpath)
        return subprocess.run(
            [str(SCRIPT), str(self.root)], capture_output=True, text=True
        )

    def assertRejected(self, relpath, content):
        result = self.run_check(relpath, content)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(relpath, result.stdout)

    def test_rejects_ten_network(self):
        self.assertRejected("a.txt", "host " + dotted(10, 1, 10, 10) + "\n")

    def test_rejects_172_range(self):
        for second in (16, 20, 31):
            with self.subTest(second=second):
                self.assertRejected("b.txt", "x=" + dotted(172, second, 4, 5))

    def test_accepts_outside_172_range(self):
        for second in (15, 32):
            with self.subTest(second=second):
                result = self.run_check("b.txt", dotted(172, second, 4, 5) + "\n")
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_rejects_192_168(self):
        self.assertRejected("c.txt", dotted(192, 168, 0, 1) + "\n")

    def test_accepts_documentation_address(self):
        result = self.run_check("d.txt", "host " + dotted(192, 0, 2, 10) + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_internal_domain(self):
        name = "box." + "roo" + "." + "run"
        self.assertRejected("e.txt", "ssh " + name + "\n")

    def test_ignores_third_party(self):
        result = self.run_check(
            "third-party/lib/f.txt", dotted(10, 1, 10, 10) + "\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ignores_lockfiles(self):
        addr = dotted(10, 1, 10, 10) + "\n"
        for name in ("Cargo.lock", "x.lock", "x.lock.json", "pins/packages.bun.lock"):
            with self.subTest(name=name):
                result = self.run_check(name, addr)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_check_files_hold_no_literal_host(self):
        files = [SCRIPT, Path(__file__).resolve()]
        repo = self.root
        for path in files:
            dest = repo / path.name
            dest.write_bytes(path.read_bytes())
            self.git("add", "-f", path.name)
        result = subprocess.run(
            [str(SCRIPT), str(repo)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reports_offending_line(self):
        addr = dotted(10, 1, 10, 10)
        result = self.run_check("g.txt", "ok\nbad " + addr + "\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("g.txt:2:bad " + addr, result.stdout)


if __name__ == "__main__":
    unittest.main()
