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
import urllib.parse
import urllib.request
from dataclasses import dataclass

JsonObject = dict[str, object]

REQUIRED_LABELS: dict[str, tuple[str, str]] = {
    "npm-audit": ("5319e7", "Issue created from npm audit scan output."),
    "security": ("b60205", "Security or dependency vulnerability remediation."),
    "devin-remediate": ("0e8a16", "Route this issue to Devin for remediation."),
}
SEVERITIES = {"high", "critical"}
SEVERITY_RANK = {"critical": 0, "high": 1}
FINGERPRINT_PREFIX = "<!-- devin-fingerprint: "


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    title: str
    severity: str
    vulnerable_range: str
    url: str


@dataclass(frozen=True)
class PackageFinding:
    package_name: str
    advisories: tuple[Advisory, ...]
    fix_available: str

    @property
    def fingerprint(self) -> str:
        return f"npm-audit|package={self.package_name}"

    @property
    def highest_severity(self) -> str:
        best = "high"
        for adv in self.advisories:
            if SEVERITY_RANK.get(adv.severity, 99) < SEVERITY_RANK.get(best, 99):
                best = adv.severity
        return best

    @property
    def advisory_count(self) -> int:
        return len(self.advisories)

    @property
    def all_vulnerable_ranges(self) -> list[str]:
        seen: dict[str, None] = {}
        for adv in self.advisories:
            if adv.vulnerable_range not in seen:
                seen[adv.vulnerable_range] = None
        return list(seen)


class GitHubClient:
    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        body: JsonObject | None = None,
        ignored_statuses: set[int] | None = None,
    ) -> object:
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
                "User-Agent": "superset-npm-audit-devin-automation",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read().decode("utf-8")
                return json.loads(response_body) if response_body else {}
        except urllib.error.HTTPError as error:
            if ignored_statuses and error.code in ignored_statuses:
                return {}
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


def as_mapping(value: object) -> JsonObject:
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return ""


def render_fix_available(value: object) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    fix = as_mapping(value)
    if not fix:
        return "Not reported"
    name = text(fix.get("name"))
    version = text(fix.get("version"))
    major = " (semver-major)" if fix.get("isSemVerMajor") is True else ""
    if name and version:
        return f"Upgrade `{name}` to `{version}`{major}"
    if version:
        return f"Upgrade to `{version}`{major}"
    return json.dumps(fix, sort_keys=True)


def extract_package_findings(report: object) -> list[PackageFinding]:
    vulnerabilities = as_mapping(as_mapping(report).get("vulnerabilities"))
    packages: dict[str, list[Advisory]] = {}
    package_fix: dict[str, str] = {}

    for package_name, raw_vulnerability in vulnerabilities.items():
        vulnerability = as_mapping(raw_vulnerability)
        package_severity = text(vulnerability.get("severity")).lower()
        package_range = text(vulnerability.get("range"))
        fix_available = render_fix_available(vulnerability.get("fixAvailable"))

        for raw_advisory in as_list(vulnerability.get("via")):
            advisory = as_mapping(raw_advisory)
            if not advisory:
                continue
            severity = text(advisory.get("severity")).lower() or package_severity
            if severity not in SEVERITIES:
                continue
            advisory_id = (
                text(advisory.get("source"))
                or text(advisory.get("url"))
                or text(advisory.get("title"))
            )
            if not advisory_id:
                continue
            adv = Advisory(
                advisory_id=advisory_id,
                title=text(advisory.get("title")) or package_name,
                severity=severity,
                vulnerable_range=(
                    text(advisory.get("range")) or package_range or "Not reported"
                ),
                url=text(advisory.get("url")),
            )
            if package_name not in packages:
                packages[package_name] = []
            existing_ids = {a.advisory_id for a in packages[package_name]}
            if advisory_id not in existing_ids:
                packages[package_name].append(adv)
            package_fix[package_name] = fix_available

    findings: list[PackageFinding] = []
    for pkg_name in sorted(packages):
        advisories = sorted(
            packages[pkg_name],
            key=lambda a: (SEVERITY_RANK.get(a.severity, 99), a.advisory_id),
        )
        findings.append(
            PackageFinding(
                package_name=pkg_name,
                advisories=tuple(advisories),
                fix_available=package_fix.get(pkg_name, "Not reported"),
            )
        )

    return findings


def fingerprint_marker(finding: PackageFinding) -> str:
    return f"{FINGERPRINT_PREFIX}{finding.fingerprint} -->"


def truncate_title(title: str, limit: int = 220) -> str:
    return title if len(title) <= limit else f"{title[: limit - 1]}…"


def issue_title(finding: PackageFinding) -> str:
    count = finding.advisory_count
    severity = finding.highest_severity
    plural = "advisories" if count != 1 else "advisory"
    return truncate_title(
        f"[npm audit] {severity}: {finding.package_name}"
        f" - {count} high/critical {plural}"
    )


def issue_body(finding: PackageFinding) -> str:
    ranges_display = ", ".join(f"`{r}`" for r in finding.all_vulnerable_ranges)
    lines = [
        fingerprint_marker(finding),
        "# npm audit finding",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Package | `{finding.package_name}` |",
        f"| Highest severity | `{finding.highest_severity}` |",
        f"| Advisory count | {finding.advisory_count} |",
        f"| Vulnerable ranges | {ranges_display} |",
        f"| Recommended fix | {finding.fix_available} |",
        "",
        "## Advisories",
        "",
        "| Severity | Advisory | Vulnerable range | Title |",
        "| --- | --- | --- | --- |",
    ]
    for adv in finding.advisories:
        advisory_link = adv.url if adv.url else adv.advisory_id
        lines.append(
            f"| `{adv.severity}` | {advisory_link}"
            f" | `{adv.vulnerable_range}` | {adv.title} |"
        )
    lines.extend(
        [
            "",
            "## Remediation",
            "",
            "This issue was generated from `npm audit --json` in the "
            "`superset-frontend` package-lock context. The issue covers all "
            "high/critical advisories for this package. The remediation should "
            "make the smallest safe dependency/security change that resolves "
            "the full set of advisories in one PR.",
            "",
            "The scanner deduplicates by the hidden fingerprint comment above. "
            "If an open issue with the same fingerprint exists, the scanner "
            "updates it. If only a closed issue has the same fingerprint, the "
            "scanner skips creating a new issue so human closure decisions are "
            "respected; reopen the closed issue manually if renewed remediation "
            "is desired.",
        ]
    )
    return "\n".join(lines) + "\n"


def label_names(issue: JsonObject) -> set[str]:
    names: set[str] = set()
    for raw_label in as_list(issue.get("labels")):
        label = as_mapping(raw_label)
        name = text(label.get("name"))
        if name:
            names.add(name)
    return names


def ensure_labels(client: GitHubClient) -> None:
    for name, label_config in REQUIRED_LABELS.items():
        color, description = label_config
        client.request(
            "POST",
            "/labels",
            {"name": name, "color": color, "description": description},
            ignored_statuses={422},
        )


def load_existing_issues(client: GitHubClient) -> dict[str, list[JsonObject]]:
    label = urllib.parse.quote("npm-audit")
    issues = client.paginated(f"/issues?state=all&labels={label}")
    by_fingerprint: dict[str, list[JsonObject]] = {}
    for issue in issues:
        body = text(issue.get("body"))
        if "pull_request" in issue:
            continue
        for line in body.splitlines():
            if line.startswith(FINGERPRINT_PREFIX) and line.endswith(" -->"):
                fingerprint = line.removeprefix(FINGERPRINT_PREFIX).removesuffix(" -->")
                by_fingerprint.setdefault(fingerprint, []).append(issue)
    return by_fingerprint


def update_issue(
    client: GitHubClient, issue: JsonObject, finding: PackageFinding
) -> None:
    issue_number = text(issue.get("number"))
    if not issue_number:
        raise RuntimeError("Matched issue is missing a number")
    labels = sorted(label_names(issue) | set(REQUIRED_LABELS))
    client.request(
        "PATCH",
        f"/issues/{issue_number}",
        {"title": issue_title(finding), "body": issue_body(finding), "labels": labels},
    )
    print(f"Updated issue #{issue_number} for {finding.fingerprint}")


def create_issue(client: GitHubClient, finding: PackageFinding) -> None:
    response = client.request(
        "POST",
        "/issues",
        {
            "title": issue_title(finding),
            "body": issue_body(finding),
            "labels": sorted(REQUIRED_LABELS),
        },
    )
    issue = as_mapping(response)
    print(f"Created issue #{text(issue.get('number'))} for {finding.fingerprint}")


def process_findings(
    findings: list[PackageFinding], client: GitHubClient, dry_run: bool
) -> None:
    total_advisories = sum(f.advisory_count for f in findings)
    print(
        f"Found {total_advisories} high/critical advisories"
        f" across {len(findings)} packages"
    )
    if dry_run:
        for finding in findings:
            print(
                f"DRY RUN {finding.fingerprint}"
                f" ({finding.advisory_count} advisories,"
                f" highest={finding.highest_severity})"
            )
        return

    ensure_labels(client)
    existing = load_existing_issues(client)
    for finding in findings:
        matches = existing.get(finding.fingerprint, [])
        open_matches = [
            issue for issue in matches if text(issue.get("state")) == "open"
        ]
        if open_matches:
            update_issue(client, open_matches[0], finding)
            continue
        if matches:
            issue_numbers = ", ".join(
                f"#{text(issue.get('number'))}" for issue in matches
            )
            print(
                "Skipped "
                f"{finding.fingerprint}; matching closed issue exists: {issue_numbers}"
            )
            continue
        create_issue(client, finding)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: npm_audit_create_issues.py <npm-audit-json>")

    with open(sys.argv[1], encoding="utf-8") as audit_file:
        report = json.load(audit_file)

    findings = extract_package_findings(report)
    dry_run = os.environ.get("DRY_RUN", "").lower() == "true"
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not dry_run and (not token or not repo):
        raise SystemExit(
            "GITHUB_TOKEN and GITHUB_REPOSITORY are required unless DRY_RUN=true"
        )

    process_findings(findings, GitHubClient(repo, token), dry_run)


if __name__ == "__main__":
    main()
