#!/usr/bin/env python3
"""Daily pin update: pick the newest versions that pass the compatibility suite.

`select` checks for newer releases, bumps every newer pin at once, and runs
`muniment-pins compat`. When that fails it tries each newer pin alone, keeps
the ones that pass, and records the others as blocked. The kept pins also pass
the workspace tests. The result goes to `update.json`, and the bumped files stay
in the working tree.

`publish` reads `update.json` and the macOS compat report. It opens or updates
the `pins/update` pull request with auto-merge, opens or comments on one
`Pin update blocked: <component> <version>` issue per blocked pin, and closes
blocked issues for pins that now pass.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRANCH = "pins/update"
PIN_FILES = ["pins/pins.toml", "pins/packages.bun.lock"]
BLOCKED = "Pin update blocked: "
OUTPUT_TAIL = 20000
WORKSPACE_TESTS = ["cargo", "test", "--workspace", "--locked",
                   "--features", "muniment-core/network-tests,muniment-pins/cli",
                   "--", "--test-threads=1"]


def run(argv, check=True, capture=True, **kwargs):
    print("+", " ".join(argv), file=sys.stderr, flush=True)
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=capture, **kwargs)
    if capture and result.stderr:
        sys.stderr.write(result.stderr[-OUTPUT_TAIL:])
    if check and result.returncode != 0:
        raise SystemExit(f"{argv[0]} exited {result.returncode}\n{(result.stdout or '')[-4000:]}")
    return result


def tail(text, limit=OUTPUT_TAIL):
    return text[-limit:]


def candidates(report):
    """The newer pins in `check` output, one bump argument list per component."""
    groups = []
    if report["pi"]["newer"]:
        groups.append(("Pi", report["pi"]["latest"], ["--pi", report["pi"]["latest"]]))
    for package in report["packages"]:
        if package["newer"]:
            spec = f"{package['name']}@{package['latest']}"
            groups.append((package["name"], package["latest"], ["--package", spec]))
    if report["claude_code"]["newer"]:
        latest = report["claude_code"]["latest"]
        groups.append(("Claude Code", latest, ["--claude-code", latest]))
    return groups


def issue_title(component, version):
    return f"{BLOCKED}{component} {version}"


def failure_text(report):
    """The failing steps of a compat report, with their output tails."""
    parts = []
    for step in report.get("steps", []):
        if not step["passed"]:
            parts.append(f"### {step['name']}\n\n```\n{step['output'].strip()}\n```")
    return "\n\n".join(parts) or "The compatibility suite failed before it ran a step."


class Pins:
    """Drives the `muniment-pins` binary in a checkout."""

    def __init__(self, binary, cache):
        self.binary = str(binary)
        self.cache = str(cache)

    def check(self):
        return json.loads(run([self.binary, "check", "--root", str(ROOT)]).stdout)

    def restore(self):
        run(["git", "checkout", "--", *PIN_FILES])

    def bump(self, args):
        result = run([self.binary, "bump", "--root", str(ROOT), "--cache", self.cache, *args])
        return json.loads(result.stdout)

    def compat(self, name):
        path = Path(self.cache) / f"compat-{name}.json"
        path.unlink(missing_ok=True)
        result = run([self.binary, "compat", "--root", str(ROOT), "--cache", self.cache,
                      "--report", str(path)], check=False)
        if path.exists():
            return json.loads(path.read_text())
        return {"passed": False, "steps": [{"name": "compat", "passed": False,
                                            "output": tail(result.stdout + result.stderr)}]}


def select(pins, workspace_tests=True):
    report = pins.check()
    groups = candidates(report)
    result = {"check": report, "changes": [], "title": None, "blocked": [], "passed": []}
    if not groups:
        return result
    everything = [arg for _, _, args in groups for arg in args]
    pins.restore()
    bumped = pins.bump(everything)
    outcome = pins.compat("all")
    kept = groups if outcome["passed"] else []
    if not outcome["passed"]:
        failures = {}
        for component, version, args in groups:
            pins.restore()
            pins.bump(args)
            alone = pins.compat(component.replace(" ", "-"))
            if alone["passed"]:
                kept.append((component, version, args))
            else:
                failures[component] = (version, alone)
        # Passing pins can still fail together. Add them one at a time.
        accepted = []
        for group in kept:
            pins.restore()
            trial = accepted + [group]
            pins.bump([arg for _, _, args in trial for arg in args])
            together = pins.compat("together")
            if together["passed"]:
                accepted.append(group)
            else:
                failures[group[0]] = (group[1], together)
        kept = accepted
        for component, (version, failed) in failures.items():
            result["blocked"].append({"component": component, "version": version,
                                      "title": issue_title(component, version),
                                      "output": failure_text(failed)})
        pins.restore()
        bumped = pins.bump([arg for _, _, args in kept for arg in args]) if kept else {"changes": []}
    if kept and workspace_tests:
        tests = run(WORKSPACE_TESTS, check=False)
        if tests.returncode != 0:
            output = f"### workspace tests\n\n```\n{tail(tests.stdout + tests.stderr).strip()}\n```"
            for component, version, _ in kept:
                result["blocked"].append({"component": component, "version": version,
                                          "title": issue_title(component, version), "output": output})
            pins.restore()
            kept, bumped = [], {"changes": []}
    result["changes"] = bumped["changes"]
    result["title"] = bumped.get("title")
    result["passed"] = [component for component, _, _ in kept]
    return result


def body(result):
    lines = ["Daily pin update from `scripts/pins/update.py`.", "", "| Pin | From | To |", "| --- | --- | --- |"]
    lines += [f"| {c['component']} | {c['from']} | {c['to']} |" for c in result["changes"]]
    lines += ["", "`muniment-pins compat` passed on Linux and macOS, and the workspace tests passed on Linux."]
    if result["blocked"]:
        lines += ["", "Blocked pins stay at their current versions:", ""]
        lines += [f"- {b['component']} {b['version']}" for b in result["blocked"]]
    return "\n".join(lines) + "\n"


class GitHub:
    """The `gh` calls `publish` makes. Tests replace it with a recorder."""

    def open_issues(self):
        out = run(["gh", "issue", "list", "--state", "open", "--search", f'"{BLOCKED}" in:title',
                   "--limit", "200", "--json", "number,title"]).stdout
        return json.loads(out)

    def create_issue(self, title, text):
        run(["gh", "issue", "create", "--title", title, "--body", text])

    def comment(self, number, text):
        run(["gh", "issue", "comment", str(number), "--body", text])

    def close(self, number, text):
        run(["gh", "issue", "close", str(number), "--comment", text])

    def pull_request(self, title, text):
        run(["git", "push", "--force", "origin", f"HEAD:refs/heads/{BRANCH}"])
        found = json.loads(run(["gh", "pr", "list", "--head", BRANCH, "--state", "open",
                                "--json", "number"]).stdout)
        if found:
            number = str(found[0]["number"])
            run(["gh", "pr", "edit", number, "--title", title, "--body", text])
        else:
            run(["gh", "pr", "create", "--base", "main", "--head", BRANCH, "--title", title, "--body", text])
            number = BRANCH
        merged = run(["gh", "pr", "merge", number, "--auto", "--squash"], check=False)
        if merged.returncode != 0:
            print("Auto-merge is unavailable. The pull request waits for a manual merge.", file=sys.stderr)


def publish(result, darwin, github, commit):
    """Opens the pull request and files issues. Returns the issue and PR actions taken."""
    blocked = list(result["blocked"])
    changes = result["changes"]
    if changes and darwin is not None and not darwin.get("passed"):
        output = "### macOS compat\n\n" + failure_text(darwin)
        by_component = {c["component"]: c["to"] for c in changes}
        for component in result["passed"]:
            version = by_component.get(component)
            if version:
                blocked.append({"component": component, "version": version,
                                "title": issue_title(component, version), "output": output})
        changes = []
    actions = []
    if changes:
        commit(result["title"])
        github.pull_request(result["title"], body(result))
        actions.append(("pr", result["title"]))
    existing = github.open_issues()
    for item in blocked:
        text = (f"`muniment-pins compat` failed for {item['component']} {item['version']}. "
                f"The current pins stay in place.\n\n{item['output']}")
        match = next((issue for issue in existing if issue["title"] == item["title"]), None)
        if match:
            github.comment(match["number"], text)
            actions.append(("comment", match["number"]))
        else:
            github.create_issue(item["title"], text)
            actions.append(("issue", item["title"]))
    shipped = {c["component"]: c["to"] for c in changes}
    for issue in existing:
        for component, version in shipped.items():
            if issue["title"].startswith(f"{BLOCKED}{component} "):
                github.close(issue["number"], f"{component} {version} passes the compatibility suite.")
                actions.append(("close", issue["number"]))
    return actions


def commit(title):
    run(["git", "add", *PIN_FILES])
    run(["git", "commit", "-m", title])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    chooser = sub.add_parser("select")
    chooser.add_argument("--bin", default=str(ROOT / "target/release/muniment-pins"))
    chooser.add_argument("--cache", default=str(ROOT / "target/muniment-pins"))
    chooser.add_argument("--out", default="update.json")
    chooser.add_argument("--skip-workspace-tests", action="store_true")
    publisher = sub.add_parser("publish")
    publisher.add_argument("--result", default="update.json")
    publisher.add_argument("--darwin", help="the macOS compat report")
    args = parser.parse_args()
    if args.command == "select":
        result = select(Pins(args.bin, args.cache), workspace_tests=not args.skip_workspace_tests)
        Path(args.out).write_text(json.dumps(result, indent=2))
        print(json.dumps({"title": result["title"], "blocked": [b["title"] for b in result["blocked"]]}))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as out:
                out.write(f"changed={'true' if result['changes'] else 'false'}\n")
                out.write(f"blocked={'true' if result['blocked'] else 'false'}\n")
    else:
        result = json.loads(Path(args.result).read_text())
        darwin = json.loads(Path(args.darwin).read_text()) if args.darwin and Path(args.darwin).exists() else None
        if result["changes"] and darwin is None:
            darwin = {"passed": False, "steps": [{"name": "macOS compat", "passed": False,
                                                  "output": "The macOS job produced no report."}]}
        for action in publish(result, darwin, GitHub(), commit):
            print(*action)


if __name__ == "__main__":
    main()
