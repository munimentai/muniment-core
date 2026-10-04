#!/usr/bin/env python3
"""Tag the next release from conventional commit prefixes since the last tag.

`feat:` is minor, `fix:` and `perf:` are patch, a `!` before the colon or a
`BREAKING CHANGE:` trailer is major, and every other commit cuts no release.
Without `--publish` the script prints the plan and changes nothing.
"""

import argparse
import re
import subprocess
import sys
import tempfile

TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
SUBJECT = re.compile(r"(?P<type>[a-z]+)(?:\([^)]*\))?(?P<bang>!)?: \S")
BREAKING = re.compile(r"^BREAKING[ -]CHANGE: ", re.M)
LEVELS = {"feat": 2, "fix": 1, "perf": 1}
RECORD, FIELD = "\x1e", "\x1f"


def git(*args):
    return subprocess.check_output(["git", *args], text=True)


def last_tag(revision):
    tags = git("tag", "--merged", revision, "--list", "v*").split()
    versions = [tuple(map(int, m.groups())) for t in tags if (m := TAG.fullmatch(t))]
    return max(versions, default=None)


def level(subject, body):
    """Returns 3 for major, 2 for minor, 1 for patch, and 0 for no release."""
    match = SUBJECT.match(subject)
    if match and match["bang"] or BREAKING.search(body):
        return 3
    return LEVELS.get(match["type"], 0) if match else 0


def bump(version, change):
    major, minor, patch = version
    if change == 3:
        return (major + 1, 0, 0)
    if change == 2:
        return (major, minor + 1, 0)
    return (major, minor, patch + 1)


def commits(base, revision):
    log = git("log", "--no-merges", f"--format=%h{FIELD}%s{FIELD}%b{RECORD}",
              f"{base}..{revision}")
    for record in log.split(RECORD):
        if record.strip():
            short, subject, body = record.strip("\n").split(FIELD, 2)
            yield short, subject, body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--publish", action="store_true",
                        help="push the tag and create the GitHub release")
    parser.add_argument("--asset", action="append", default=[],
                        help="a file to attach to the release")
    args = parser.parse_args()

    version = last_tag(args.revision)
    if version is None:
        print("No v* tag exists. Create the first release tag by hand.")
        return
    base = "v%d.%d.%d" % version
    entries = list(commits(base, args.revision))
    change = max((level(s, b) for _, s, b in entries), default=0)
    if change == 0:
        print(f"No release: no feat, fix, perf, or breaking commit since {base}.")
        return
    tag = "v%d.%d.%d" % bump(version, change)
    notes = "".join(f"- {subject} ({short})\n" for short, subject, _ in entries)
    print(f"{base} -> {tag}\n{notes}", end="")
    if not args.publish:
        return
    revision = git("rev-parse", args.revision).strip()
    subprocess.run(["git", "tag", tag, revision], check=True)
    subprocess.run(["git", "push", "origin", f"refs/tags/{tag}"], check=True)
    with tempfile.NamedTemporaryFile("w", suffix=".md") as file:
        file.write(f"Changes since {base}:\n\n{notes}")
        file.flush()
        subprocess.run(["gh", "release", "create", tag, "--title", tag,
                        "--notes-file", file.name, "--verify-tag", *args.asset],
                       check=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(f"Release failed: {error}", file=sys.stderr)
        sys.exit(1)
