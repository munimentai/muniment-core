"""Tests for the version rules in scripts/release.py."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class Level(unittest.TestCase):
    def test_prefixes_pick_the_bump(self):
        cases = {
            "feat: add pins": 2,
            "feat(router): add a pool": 2,
            "fix: keep the digest": 1,
            "perf: reuse the agent": 1,
            "feat!: drop the shim": 3,
            "fix(core)!: change the journal": 3,
            "chore: update CI": 0,
            "docs: explain pins": 0,
            "test: cover the lookup": 0,
            "refactor: split the module": 0,
            "Merge pull request #1": 0,
            "feature: not a prefix": 0,
            "feat:missing space": 0,
        }
        for subject, expected in cases.items():
            self.assertEqual(release.level(subject, ""), expected, subject)

    def test_breaking_change_trailer_is_major(self):
        self.assertEqual(release.level("chore: rename", "Body.\n\nBREAKING CHANGE: paths move"), 3)
        self.assertEqual(release.level("fix: x", "BREAKING-CHANGE: y"), 3)
        self.assertEqual(release.level("fix: x", "Mentions BREAKING CHANGE: inline"), 1)

    def test_bump_resets_lower_parts(self):
        self.assertEqual(release.bump((1, 2, 3), 3), (2, 0, 0))
        self.assertEqual(release.bump((1, 2, 3), 2), (1, 3, 0))
        self.assertEqual(release.bump((1, 2, 3), 1), (1, 2, 4))


if __name__ == "__main__":
    unittest.main()
