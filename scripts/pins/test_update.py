#!/usr/bin/env python3
"""Tests for the pin update selection and publishing in `update.py`."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import update  # noqa: E402

PASS = {"passed": True, "steps": []}


def fail(output):
    return {"passed": False, "steps": [{"name": "Pi, extension, and bridge checks", "passed": False,
                                        "output": output}]}


def report(pi="1.0.2", mcp="5.0.0", claude="2.1.289"):
    return {
        "pi": {"current": "0.87.1", "latest": pi, "newer": pi != "0.87.1"},
        "packages": [
            {"name": "pi-web-access", "current": "0.31.0", "latest": "0.31.0", "newer": False},
            {"name": "pi-mcp-adapter", "current": "2.37.0", "latest": mcp, "newer": mcp != "2.37.0"},
        ],
        "claude_code": {"current": "2.1.282", "latest": claude, "newer": claude != "2.1.282"},
        "updates": True,
    }


class FakePins:
    """Records bumps. `outcomes` maps a frozenset of bumped components to a compat result."""

    def __init__(self, check, outcomes):
        self.report = check
        self.outcomes = outcomes
        self.current = []

    def check(self):
        return self.report

    def restore(self):
        self.current = []

    def bump(self, args):
        names = []
        changes = []
        for flag, value in zip(args[::2], args[1::2]):
            if flag == "--pi":
                names.append("Pi")
                changes.append({"component": "Pi", "from": "0.87.1", "to": value})
            elif flag == "--claude-code":
                names.append("Claude Code")
                changes.append({"component": "Claude Code", "from": "2.1.282", "to": value})
            else:
                name, version = value.rsplit("@", 1)
                names.append(name)
                changes.append({"component": name, "from": "old", "to": version})
        self.current = names
        return {"changes": changes, "title": "feat: update " + ", ".join(names) if names else None}

    def compat(self, _name):
        return self.outcomes.get(frozenset(self.current), PASS)


class Recorder:
    def __init__(self, issues=()):
        self.issues = list(issues)
        self.calls = []

    def open_issues(self):
        return self.issues

    def create_issue(self, title, text):
        self.calls.append(("create", title))

    def comment(self, number, text):
        self.calls.append(("comment", number))

    def close(self, number, text):
        self.calls.append(("close", number))

    def pull_request(self, title, text):
        self.calls.append(("pr", title))


class SelectTest(unittest.TestCase):
    def test_current_pins_change_nothing(self):
        check = report(pi="0.87.1", mcp="2.37.0", claude="2.1.282")
        result = update.select(FakePins(check, {}), workspace_tests=False)
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["blocked"], [])

    def test_a_passing_full_bump_keeps_everything(self):
        result = update.select(FakePins(report(), {}), workspace_tests=False)
        self.assertEqual([c["component"] for c in result["changes"]], ["Pi", "pi-mcp-adapter", "Claude Code"])
        self.assertEqual(result["passed"], ["Pi", "pi-mcp-adapter", "Claude Code"])

    def test_a_failing_pin_is_blocked_and_the_rest_ship(self):
        everything = frozenset({"Pi", "pi-mcp-adapter", "Claude Code"})
        outcomes = {everything: fail("all"), frozenset({"Pi"}): fail("Pi broke the RPC frames")}
        result = update.select(FakePins(report(), outcomes), workspace_tests=False)
        self.assertEqual([c["component"] for c in result["changes"]], ["pi-mcp-adapter", "Claude Code"])
        self.assertEqual([b["title"] for b in result["blocked"]], ["Pin update blocked: Pi 1.0.2"])
        self.assertIn("Pi broke the RPC frames", result["blocked"][0]["output"])

    def test_pins_that_fail_together_are_added_one_at_a_time(self):
        outcomes = {
            frozenset({"Pi", "pi-mcp-adapter", "Claude Code"}): fail("all"),
            frozenset({"Pi", "pi-mcp-adapter"}): fail("Pi and the adapter conflict"),
        }
        result = update.select(FakePins(report(), outcomes), workspace_tests=False)
        self.assertEqual(result["passed"], ["Pi", "Claude Code"])
        self.assertEqual([b["component"] for b in result["blocked"]], ["pi-mcp-adapter"])


class PublishTest(unittest.TestCase):
    def result(self, blocked=()):
        return {
            "changes": [{"component": "Claude Code", "from": "2.1.282", "to": "2.1.289"}],
            "title": "fix: update Claude Code to 2.1.289",
            "passed": ["Claude Code"],
            "blocked": [{"component": "Pi", "version": "1.0.2", "title": "Pin update blocked: Pi 1.0.2",
                         "output": "boom"} for _ in blocked],
        }

    def test_issues_are_deduplicated_by_title(self):
        github = Recorder([{"number": 7, "title": "Pin update blocked: Pi 1.0.2"}])
        commits = []
        actions = update.publish(self.result(blocked=[1]), PASS, github, commits.append)
        self.assertEqual(commits, ["fix: update Claude Code to 2.1.289"])
        self.assertIn(("comment", 7), github.calls)
        self.assertNotIn(("create", "Pin update blocked: Pi 1.0.2"), github.calls)
        self.assertIn(("pr", "fix: update Claude Code to 2.1.289"), actions)

    def test_a_new_blocked_pin_opens_an_issue(self):
        github = Recorder()
        update.publish(self.result(blocked=[1]), PASS, github, lambda title: None)
        self.assertIn(("create", "Pin update blocked: Pi 1.0.2"), github.calls)

    def test_a_shipped_pin_closes_its_old_blocked_issue(self):
        github = Recorder([{"number": 3, "title": "Pin update blocked: Claude Code 2.1.285"}])
        update.publish(self.result(), PASS, github, lambda title: None)
        self.assertIn(("close", 3), github.calls)

    def test_a_macos_failure_blocks_the_pull_request(self):
        github = Recorder()
        commits = []
        update.publish(self.result(), fail("darwin archive"), github, commits.append)
        self.assertEqual(commits, [])
        self.assertEqual(github.calls, [("create", "Pin update blocked: Claude Code 2.1.289")])

    def test_candidates_list_only_newer_pins(self):
        groups = update.candidates(report(mcp="2.37.0"))
        self.assertEqual([(c, v) for c, v, _ in groups], [("Pi", "1.0.2"), ("Claude Code", "2.1.289")])


if __name__ == "__main__":
    unittest.main()
