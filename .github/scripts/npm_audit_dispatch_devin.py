#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import annotations

# ruff: noqa: S310,TID251
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

JsonObject = dict[str, object]

DEVIN_TRIGGER_LABEL = "devin-remediate"
SOURCE_LABEL = "npm-audit"
DEVIN_SESSION_MARKER = "<!-- devin-session:"


@dataclass(frozen=True)
class IssueContext:
    number: str
    title: str
    body: str
    state: str
    html_url: str
    labels: set[str]


class GitHubClient:
    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.token = token

    def request(self, method: str, path: str, body: JsonObject | None = None) -> object:
        url = f"https://api.github.com/repos/{self.repo}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "superset-npm-audit-devin-dispatch",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
                return json.loads(response_body) if response_body else {}
        except urllib.error.HTTPError as error:
            error_body = error.read().decode("utf-8")
            message = f"GitHub API {method} {path} failed: {error.code} {error_body}"
            raise RuntimeError(message) from error

    def paginated(self, path: str) -> list[JsonObject]:
        page = 1
        results: list[JsonObject] = []
        separator = "&" if "?" in path else "?"
        while True:
            response = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            if not isinstance(response, list):
                raise RuntimeError(f"Expected list response from GitHub API for {path}")
            items = [item for item in response if isinstance(item, dict)]
            results.extend(items)
            if len(response) < 100:
                return results
            page += 1

    def issue(self, issue_number: str) -> JsonObject:
        response = self.request("GET", f"/issues/{issue_number}")
        issue = as_mapping(response)
        if not issue:
            raise RuntimeError(f"Issue #{issue_number} was not found")
        return issue

    def comments(self, issue_number: str) -> list[JsonObject]:
        return self.paginated(f"/issues/{issue_number}/comments")

    def comment(self, issue_number: str, body: str) -> None:
        self.request("POST", f"/issues/{issue_number}/comments", {"body": body})


class DevinClient:
    def __init__(self, org_id: str, api_key: str) -> None:
        self.org_id = org_id
        self.api_key = api_key

    def create_session(self, prompt: str) -> JsonObject:
        url = f"https://api.devin.ai/v3/organizations/{self.org_id}/sessions"
        request = urllib.request.Request(
            url,
            data=json.dumps({"prompt": prompt}).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "superset-npm-audit-devin-dispatch",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return as_mapping(json.loads(response.read().decode("utf-8")))
        except urllib.error.HTTPError as error:
            error_body = error.read().decode("utf-8")
            message = f"Devin API create session failed: {error.code} {error_body}"
            raise RuntimeError(message) from error


def as_mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, int | float):
        return str(value)
    return ""


def label_names(issue: JsonObject) -> set[str]:
    names: set[str] = set()
    for raw_label in as_list(issue.get("labels")):
        label = as_mapping(raw_label)
        name = text(label.get("name"))
        if name:
            names.add(name)
    return names


def issue_context(issue: JsonObject) -> IssueContext:
    number = text(issue.get("number"))
    if not number:
        raise RuntimeError("Issue payload is missing a number")
    return IssueContext(
        number=number,
        title=text(issue.get("title")),
        body=text(issue.get("body")),
        state=text(issue.get("state")),
        html_url=text(issue.get("html_url")),
        labels=label_names(issue),
    )


def load_event_issue(client: GitHubClient) -> IssueContext:
    if issue_number := os.environ.get("ISSUE_NUMBER", ""):
        return issue_context(client.issue(issue_number))

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        raise RuntimeError("ISSUE_NUMBER or GITHUB_EVENT_PATH is required")
    with open(event_path, encoding="utf-8") as event_file:
        event = as_mapping(json.load(event_file))
    return issue_context(as_mapping(event.get("issue")))


def event_label_name() -> str:
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        return ""
    with open(event_path, encoding="utf-8") as event_file:
        event = as_mapping(json.load(event_file))
    return text(as_mapping(event.get("label")).get("name"))


def has_devin_marker(issue: IssueContext, comments: list[JsonObject]) -> bool:
    bodies = [issue.body]
    bodies.extend(text(comment.get("body")) for comment in comments)
    return any(
        DEVIN_SESSION_MARKER in body
        or "app.devin.ai/sessions/" in body
        or "api.devin.ai/v3/organizations/" in body
        for body in bodies
    )


def load_playbook() -> str:
    playbook_path = os.environ.get(
        "PLAYBOOK_PATH",
        ".github/devin-playbooks/npm-audit-remediation.md",
    )
    with open(playbook_path, encoding="utf-8") as playbook_file:
        return playbook_file.read().strip()


def build_prompt(repo: str, issue: IssueContext, playbook: str) -> str:
    return f"""You are Devin working in GitHub repository `{repo}`.

Remediate this npm audit security issue and open a pull request:

Issue: {issue.html_url}
Title: {issue.title}
Issue number: #{issue.number}

Issue body:
{issue.body}

Follow this source-controlled playbook:

{playbook}

Additional instructions:
- This issue may contain multiple advisories for one package. Remediate the
  full set of advisories in a single PR.
- Make the smallest safe dependency/security fix that resolves all listed
  advisories.
- Avoid `npm audit fix --force` unless you justify why it is necessary.
- Inspect `superset-frontend/package-lock.json` and any package changes after
  automated fixes.
- Run relevant install, lint/typecheck, and targeted tests where practical.
- Open a PR back to this repository and explain the validation performed.
- IMPORTANT: The PR description MUST include `Closes #{issue.number}` so that
  GitHub automatically links the PR to the issue and closes it on merge.
  Do NOT merely mention the issue number — use the `Closes #N` keyword.
"""


def session_identifier(response: JsonObject) -> str:
    for key in ("url", "web_url", "app_url", "session_url", "devin_url"):
        value = text(response.get(key))
        if value:
            return value
    for key in ("devin_id", "session_id", "id"):
        value = text(response.get(key))
        if value:
            suffix = value.removeprefix("devin-")
            return f"https://app.devin.ai/sessions/{suffix}"
    return json.dumps(response, sort_keys=True)


def session_marker(response: JsonObject) -> str:
    for key in (
        "devin_id",
        "session_id",
        "id",
        "url",
        "web_url",
        "app_url",
        "session_url",
    ):
        value = text(response.get(key))
        if value:
            return value
    return "created"


def validate_trigger(issue: IssueContext) -> bool:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name == "issues" and event_label_name() != DEVIN_TRIGGER_LABEL:
        print("Skipping: labeled event is not for devin-remediate")
        return False
    if issue.state != "open":
        print(f"Skipping issue #{issue.number}: issue is {issue.state}")
        return False
    if SOURCE_LABEL not in issue.labels:
        print(f"Skipping issue #{issue.number}: missing {SOURCE_LABEL} label")
        return False
    if DEVIN_TRIGGER_LABEL not in issue.labels:
        print(f"Skipping issue #{issue.number}: missing {DEVIN_TRIGGER_LABEL} label")
        return False
    return True


SEVERITY_RANK = {"critical": 0, "high": 1}
DRY_RUN_SEVERITIES = {"high", "critical"}


def parse_audit_for_dry_run(audit_path: str) -> list[IssueContext]:
    """Parse a real npm audit JSON file into simulated IssueContext objects."""
    with open(audit_path, encoding="utf-8") as f:
        report = as_mapping(json.load(f))

    vulnerabilities = as_mapping(report.get("vulnerabilities"))
    packages: dict[str, list[dict[str, str]]] = {}
    package_fix: dict[str, str] = {}

    for package_name, raw_vuln in vulnerabilities.items():
        vuln = as_mapping(raw_vuln)
        pkg_severity = text(vuln.get("severity")).lower()
        pkg_range = text(vuln.get("range"))
        fix_available = vuln.get("fixAvailable")

        fix_str = "Not reported"
        if isinstance(fix_available, bool):
            fix_str = "Yes" if fix_available else "No"
        elif isinstance(fix_available, dict):
            name = text(fix_available.get("name"))
            version = text(fix_available.get("version"))
            major = " (semver-major)" if fix_available.get("isSemVerMajor") else ""
            if name and version:
                fix_str = f"Upgrade `{name}` to `{version}`{major}"
            elif version:
                fix_str = f"Upgrade to `{version}`{major}"

        for raw_advisory in as_list(vuln.get("via")):
            advisory = as_mapping(raw_advisory)
            if not advisory:
                continue
            severity = text(advisory.get("severity")).lower() or pkg_severity
            if severity not in DRY_RUN_SEVERITIES:
                continue
            adv_id = (
                text(advisory.get("source"))
                or text(advisory.get("url"))
                or text(advisory.get("title"))
            )
            if not adv_id:
                continue
            adv_range = text(advisory.get("range")) or pkg_range or "Not reported"
            adv_url = text(advisory.get("url"))
            adv_title = text(advisory.get("title")) or package_name
            if package_name not in packages:
                packages[package_name] = []
            existing_ids = {a["id"] for a in packages[package_name]}
            if adv_id not in existing_ids:
                packages[package_name].append({
                    "id": adv_id,
                    "title": adv_title,
                    "severity": severity,
                    "range": adv_range,
                    "url": adv_url,
                })
            package_fix[package_name] = fix_str

    issues: list[IssueContext] = []
    for pkg_name in sorted(packages):
        advisories = sorted(
            packages[pkg_name],
            key=lambda a: (SEVERITY_RANK.get(a["severity"], 99), a["id"]),
        )
        count = len(advisories)
        highest = "high"
        for adv in advisories:
            if SEVERITY_RANK.get(adv["severity"], 99) < SEVERITY_RANK.get(highest, 99):
                highest = adv["severity"]

        plural = "advisories" if count != 1 else "advisory"
        title = f"[npm audit] {highest}: {pkg_name} - {count} high/critical {plural}"

        ranges = []
        seen_ranges: dict[str, None] = {}
        for adv in advisories:
            if adv["range"] not in seen_ranges:
                seen_ranges[adv["range"]] = None
                ranges.append(adv["range"])
        ranges_display = ", ".join(f"`{r}`" for r in ranges)
        fix = package_fix.get(pkg_name, "Not reported")

        body_lines = [
            f"<!-- devin-fingerprint: npm-audit|package={pkg_name} -->",
            "# npm audit finding",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Package | `{pkg_name}` |",
            f"| Highest severity | `{highest}` |",
            f"| Advisory count | {count} |",
            f"| Vulnerable ranges | {ranges_display} |",
            f"| Recommended fix | {fix} |",
            "",
            "## Advisories",
            "",
            "| Severity | Advisory | Vulnerable range | Title |",
            "| --- | --- | --- | --- |",
        ]
        for adv in advisories:
            link = adv["url"] if adv["url"] else adv["id"]
            body_lines.append(
                f"| `{adv['severity']}` | {link} | `{adv['range']}` | {adv['title']} |"
            )
        body_lines.extend([
            "",
            "## Remediation",
            "",
            "This issue was generated from `npm audit --json` in the "
            "`superset-frontend` package-lock context.",
        ])

        issues.append(IssueContext(
            number=str(len(issues) + 1),
            title=title,
            body="\n".join(body_lines) + "\n",
            state="open",
            html_url=f"https://github.com/owner/repo/issues/{len(issues) + 1}",
            labels={"npm-audit", "security", "devin-remediate"},
        ))

    return issues


def main() -> None:
    dry_run = os.environ.get("DRY_RUN", "").lower() == "true"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    devin_api_key = os.environ.get("DEVIN_API_KEY", "")
    devin_org_id = os.environ.get("DEVIN_ORG_ID", "")

    if dry_run:
        repo = repo or "owner/repo"
        audit_path = os.environ.get("NPM_AUDIT_JSON", "")
        if audit_path:
            issues = parse_audit_for_dry_run(audit_path)
        else:
            issues = []

        if not issues:
            print("DRY RUN: no npm audit JSON provided or no high/critical findings.")
            print("  Hint: set NPM_AUDIT_JSON=/path/to/npm-audit.json to use real data.")
            return

        playbook = load_playbook()
        for issue in issues:
            print(f"DRY RUN: simulating dispatch for issue #{issue.number}")
            print(f"  Title: {issue.title}")
            print(f"  Labels: {sorted(issue.labels)}")
            print(f"  State: {issue.state}")
            print()
            prompt = build_prompt(repo, issue, playbook)
            print("=" * 72)
            print(f"PROMPT THAT WOULD BE SENT TO DEVIN (issue #{issue.number}):")
            print("=" * 72)
            print(prompt)
            print("=" * 72)
            print()

        print(
            f"DRY RUN complete. {len(issues)} issue(s) would dispatch Devin sessions."
            " No API calls were made."
        )
        return

    if not repo or not github_token:
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN are required")
    if not devin_api_key or not devin_org_id:
        raise SystemExit("DEVIN_API_KEY and DEVIN_ORG_ID are required")

    github = GitHubClient(repo, github_token)
    issue = load_event_issue(github)
    if not validate_trigger(issue):
        return

    comments = github.comments(issue.number)
    if has_devin_marker(issue, comments):
        print(f"Skipping issue #{issue.number}: Devin session marker already exists")
        return

    prompt = build_prompt(repo, issue, load_playbook())
    response = DevinClient(devin_org_id, devin_api_key).create_session(prompt)
    session_url = session_identifier(response)
    marker = session_marker(response)
    github.comment(
        issue.number,
        f"<!-- devin-session: {marker} -->\n"
        "Devin remediation session started.\n\n"
        f"Session: {session_url}\n\n"
        "Status: created",
    )
    print(f"Created Devin session for issue #{issue.number}: {session_url}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise
