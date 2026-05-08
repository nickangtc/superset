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
import html
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

JsonObject = dict[str, object]

SOURCE_LABEL = "npm-audit"
SECURITY_LABEL = "security"
TRIGGER_LABEL = "devin-remediate"
HUMAN_REMEDIATION_MINUTES = 65
DEVIN_HUMAN_INVOLVEMENT_MINUTES = 5
MINUTES_SAVED_PER_CLOSED_PR = (
    HUMAN_REMEDIATION_MINUTES - DEVIN_HUMAN_INVOLVEMENT_MINUTES
)
MEDIAN_ENGINEER_MONTHLY_SALARY_SGD = 6750
WORK_HOURS_PER_YEAR = 2080
ENGINEER_HOURLY_WAGE_SGD = (
    MEDIAN_ENGINEER_MONTHLY_SALARY_SGD * 12 / WORK_HOURS_PER_YEAR
)

TIMEFRAMES: list[tuple[str, int | str]] = [
    ("30 days", 30),
    ("60 days", 60),
    ("90 days", 90),
    ("180 days", 180),
    ("365 days", 365),
    ("Year to date", "ytd"),
]


@dataclass(frozen=True)
class IssueSummary:
    number: str
    title: str
    state: str
    created_at: str
    html_url: str


@dataclass(frozen=True)
class PRSummary:
    number: str
    state: str
    merged: bool
    html_url: str
    created_at: str


@dataclass(frozen=True)
class IssueOutcome:
    issue: IssueSummary
    prs: list[PRSummary]
    status: str


class GitHubClient:
    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.token = token

    def request(self, method: str, path: str) -> object:
        url = f"https://api.github.com/repos/{self.repo}{path}"
        request = urllib.request.Request(
            url,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "superset-devin-metrics",
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

    def timeline(self, issue_number: str) -> list[JsonObject]:
        return self.paginated(f"/issues/{issue_number}/timeline")


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


def label_names(issue: JsonObject) -> set[str]:
    names: set[str] = set()
    for raw_label in as_list(issue.get("labels")):
        label = as_mapping(raw_label)
        name = text(label.get("name"))
        if name:
            names.add(name)
    return names


def fetch_devin_issues(client: GitHubClient) -> list[IssueSummary]:
    labels = urllib.parse.quote(f"{SOURCE_LABEL},{SECURITY_LABEL},{TRIGGER_LABEL}")
    raw_issues = client.paginated(f"/issues?state=all&labels={labels}")
    issues: list[IssueSummary] = []
    for raw in raw_issues:
        if "pull_request" in raw:
            continue
        issues.append(
            IssueSummary(
                number=text(raw.get("number")),
                title=text(raw.get("title")),
                state=text(raw.get("state")),
                created_at=text(raw.get("created_at")),
                html_url=text(raw.get("html_url")),
            )
        )
    return issues


def find_linked_prs(client: GitHubClient, issue_number: str) -> list[PRSummary]:
    events = client.timeline(issue_number)
    prs: list[PRSummary] = []
    seen: set[str] = set()
    for event in events:
        source = as_mapping(event.get("source"))
        if not source:
            continue
        pr_raw = as_mapping(source.get("issue"))
        if not pr_raw or "pull_request" not in pr_raw:
            continue
        pr_number = text(pr_raw.get("number"))
        if not pr_number or pr_number in seen:
            continue
        seen.add(pr_number)
        pr_detail = as_mapping(pr_raw.get("pull_request"))
        merged = text(pr_detail.get("merged_at")) != ""
        prs.append(
            PRSummary(
                number=pr_number,
                state=text(pr_raw.get("state")),
                merged=merged,
                html_url=text(pr_raw.get("html_url")),
                created_at=text(pr_raw.get("created_at")),
            )
        )
    return prs


def classify_issue(issue: IssueSummary, prs: list[PRSummary]) -> str:
    if not prs:
        return "no_pr"
    if any(pr.merged for pr in prs):
        return "merged"
    if all(pr.state == "closed" for pr in prs):
        return "closed"
    return "open"


STATUS_LABELS = {
    "merged": "PR merged",
    "closed": "PR closed (not merged)",
    "open": "PR open (in progress)",
    "no_pr": "No PR created",
}

STATUS_COLORS = {
    "merged": "#2da44e",
    "closed": "#cf222e",
    "open": "#bf8700",
    "no_pr": "#656d76",
}


def build_outcomes(
    client: GitHubClient, issues: list[IssueSummary]
) -> list[IssueOutcome]:
    outcomes: list[IssueOutcome] = []
    total = len(issues)
    for idx, issue in enumerate(issues, 1):
        print(f"  Fetching timeline for issue #{issue.number} ({idx}/{total})")
        prs = find_linked_prs(client, issue.number)
        status = classify_issue(issue, prs)
        outcomes.append(IssueOutcome(issue=issue, prs=prs, status=status))
    return outcomes


def parse_iso(date_str: str) -> datetime:
    cleaned = date_str.replace("Z", "+00:00")
    return datetime.fromisoformat(cleaned)


def cutoff_for_timeframe(frame_value: int | str, now: datetime) -> datetime:
    if frame_value == "ytd":
        return datetime(now.year, 1, 1, tzinfo=timezone.utc)
    if isinstance(frame_value, int):
        return now - timedelta(days=frame_value)
    return now - timedelta(days=365)


def filter_outcomes(
    outcomes: list[IssueOutcome], frame_value: int | str, now: datetime
) -> list[IssueOutcome]:
    cutoff = cutoff_for_timeframe(frame_value, now)
    return [o for o in outcomes if parse_iso(o.issue.created_at) >= cutoff]


def count_statuses(outcomes: list[IssueOutcome]) -> dict[str, int]:
    counts: dict[str, int] = {"merged": 0, "closed": 0, "open": 0, "no_pr": 0}
    for outcome in outcomes:
        counts[outcome.status] = counts.get(outcome.status, 0) + 1
    return counts


def count_closed_prs(outcomes: list[IssueOutcome]) -> int:
    closed_pr_numbers: set[str] = set()
    for outcome in outcomes:
        for pr in outcome.prs:
            if pr.state == "closed":
                closed_pr_numbers.add(pr.number)
    return len(closed_pr_numbers)


def format_hours(hours: float) -> str:
    if hours.is_integer():
        return f"{int(hours):,}"
    return f"{hours:,.1f}"


def format_sgd(amount: float) -> str:
    return f"S${amount:,.2f}"


def load_template() -> str:
    tpl = pathlib.Path(__file__).parent / "devin_metrics_template.html"
    return tpl.read_text(encoding="utf-8")


def _pr_state(pr: PRSummary) -> str:
    if pr.merged:
        return "merged"
    return pr.state


def _build_tab_data(
    outcomes: list[IssueOutcome],
    now: datetime,
) -> list[dict[str, object]]:
    tab_data: list[dict[str, object]] = []
    for label, value in TIMEFRAMES:
        filtered = filter_outcomes(outcomes, value, now)
        counts = count_statuses(filtered)
        closed_pr_count = count_closed_prs(filtered)
        hours_saved = closed_pr_count * MINUTES_SAVED_PER_CLOSED_PR / 60
        labour_cost_saved = hours_saved * ENGINEER_HOURLY_WAGE_SGD
        issues_list = [
            {
                "number": o.issue.number,
                "title": html.escape(o.issue.title),
                "url": o.issue.html_url,
                "status": o.status,
                "status_label": (STATUS_LABELS[o.status]),
                "prs": [
                    {
                        "number": pr.number,
                        "url": pr.html_url,
                        "state": _pr_state(pr),
                    }
                    for pr in o.prs
                ],
            }
            for o in filtered
        ]
        tab_data.append(
            {
                "label": label,
                "counts": counts,
                "closed_pr_count": closed_pr_count,
                "hours_saved": format_hours(hours_saved),
                "labour_cost_saved": format_sgd(labour_cost_saved),
                "total": len(filtered),
                "issues": issues_list,
            }
        )
    return tab_data


def build_html(
    outcomes: list[IssueOutcome],
    repo: str,
    generated_at: str,
) -> str:
    now = datetime.now(tz=timezone.utc)
    tab_data = _build_tab_data(outcomes, now)
    template = load_template()
    result = template.replace("{{TAB_DATA}}", json.dumps(tab_data))
    result = result.replace(
        "{{STATUS_LABELS}}",
        json.dumps(STATUS_LABELS),
    )
    result = result.replace(
        "{{STATUS_COLORS}}",
        json.dumps(STATUS_COLORS),
    )
    result = result.replace("{{REPO}}", html.escape(repo))
    result = result.replace(
        "{{GENERATED_AT}}",
        html.escape(generated_at),
    )
    return result


def main() -> None:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    output = os.environ.get("OUTPUT_PATH", "devin-metrics.html")

    if not repo or not token:
        raise SystemExit("GITHUB_REPOSITORY and GITHUB_TOKEN are required")

    print(f"Fetching Devin remediation issues for {repo}...")
    client = GitHubClient(repo, token)
    issues = fetch_devin_issues(client)
    print(
        "Found "
        f"{len(issues)} issues with labels "
        f"{SOURCE_LABEL}+{SECURITY_LABEL}+{TRIGGER_LABEL}"
    )

    if not issues:
        print("No issues found. Generating empty report.")

    print("Fetching linked PRs via timeline events...")
    outcomes = build_outcomes(client, issues)

    now = datetime.now(tz=timezone.utc)
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")
    report = build_html(outcomes, repo, generated_at)

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"Report written to {output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        raise
