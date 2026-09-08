#!/usr/bin/env python3
"""ANTUMBRA merge-rail policy gate (policy-as-code).

The change routing rules of CONTRIBUTING.md ("The rails"), executed
on every pull request instead of trusted to memory:

* The consensus surface is everything under code/crates/ — every
  crate in the workspace is consensus-relevant by construction
  (primitives and encodings, the Veil, the ordering layer, the Ring,
  Kleos). A pull request that touches it must carry the `rail-c`
  label, and whenever crate *sources* change (*/src/*), the same
  pull request must also touch spec/adr/: no consensus behavior
  change without an architecture decision record, per the hygiene
  rules of the repository.

* A rail-B pull request (tooling label) that touches the consensus
  surface is refused: the rails are disjoint, a diff declares its
  rail once, and the merge predicate checks files against rails.

Direct pushes to main are not routed here: branch protection
governs how main accepts commits, and the same labels and ADR
discipline apply at review time. This script fails closed: any API
error is a red check, not a warning.

Usage: python3 ci/merge_rails.py
Environment (injected by the workflow):
  GITHUB_TOKEN         read token, pull-requests scope
  RAILS_EVENT          pull_request | push | anything else
  RAILS_PR_NUMBER      pull request number (pull_request only)
  RAILS_REPOSITORY     owner/name of the repository
"""

import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
CONSENSUS_PREFIX = "code/crates/"
CONSENSUS_SRC_MARK = "/src/"
ADR_PREFIX = "spec/adr/"
LABEL_CONSENSUS = "rail-c"
LABEL_TOOLING = "rail-b"
TIMEOUT_SECONDS = 30


def github_get(path: str, token: str):
    request = urllib.request.Request(
        f"{API}/repos/{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def pull_request_files(repository: str, number: int, token: str):
    files: list[str] = []
    page = 1
    while True:
        batch = github_get(f"{repository}/pulls/{number}/files?per_page=100&page={page}", token)
        files.extend(entry["filename"] for entry in batch)
        if len(batch) < 100:
            return files
        page += 1


def pull_request_labels(repository: str, number: int, token: str):
    payload = github_get(f"{repository}/issues/{number}/labels", token)
    return {entry["name"] for entry in payload}


def main() -> int:
    event = os.environ.get("RAILS_EVENT", "")
    if event != "pull_request":
        print(f"merge rails: event '{event or 'unknown'}' carries no pull request to route; passing.")
        return 0

    repository = os.environ.get("RAILS_REPOSITORY", "")
    number = os.environ.get("RAILS_PR_NUMBER", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repository or not number or not token:
        print("merge rails: missing RAILS_REPOSITORY, RAILS_PR_NUMBER or GITHUB_TOKEN", file=sys.stderr)
        return 1
    if not str(number).isdigit():
        print(f"merge rails: RAILS_PR_NUMBER is not a number: {number!r}", file=sys.stderr)
        return 1

    try:
        files = pull_request_files(repository, int(number), token)
        names = pull_request_labels(repository, int(number), token)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
        print(f"merge rails: GitHub API error (fail closed): {error}", file=sys.stderr)
        return 1

    consensus = [f for f in files if f.startswith(CONSENSUS_PREFIX)]
    sources = [f for f in consensus if CONSENSUS_SRC_MARK in f]
    decisions = [f for f in files if f.startswith(ADR_PREFIX)]

    print(f"merge rails: {len(files)} file(s) in the diff")
    for name in sorted(files):
        print(f"  {name}")
    print(f"merge rails: labels on the pull request: {sorted(names) or 'none'}")

    problems: list[str] = []

    if consensus and LABEL_CONSENSUS not in names:
        problems.append(
            f"the diff touches the consensus surface ({len(consensus)} file(s) under "
            f"{CONSENSUS_PREFIX}) but the pull request does not carry the "
            f"'{LABEL_CONSENSUS}' label: consensus changes are rail-C merges"
        )

    if consensus and LABEL_TOOLING in names:
        problems.append(
            f"the pull request declares itself '{LABEL_TOOLING}' (tooling) but touches "
            f"the consensus surface: a rail-B merge may never modify {CONSENSUS_PREFIX}"
        )

    if sources and not decisions:
        problems.append(
            f"consensus sources change ({len(sources)} file(s) under {CONSENSUS_PREFIX}*"
            f"{CONSENSUS_SRC_MARK}*) without any change under {ADR_PREFIX}: every "
            "consensus behavior change travels with an architecture decision record"
        )

    if problems:
        for problem in problems:
            print(f"RAILS FAIL: {problem}", file=sys.stderr)
        print("merge rails: refused. See CONTRIBUTING.md, 'The rails'.", file=sys.stderr)
        return 1

    verdict = "rail-C consensus merge, ADR in the diff" if consensus else "no consensus surface touched"
    print(f"merge rails: OK ({verdict}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
