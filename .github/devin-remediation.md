<!--
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements.  See the NOTICE file distributed with
this work for additional information regarding copyright ownership.
The ASF licenses this file to You under the Apache License, Version 2.0
(the "License"); you may not use this file except in compliance with
the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Devin npm audit remediation automation

This repository contains a GitHub Actions automation loop for high and critical npm audit findings in `superset-frontend`:

1. `.github/workflows/npm-audit-scan.yml` runs `npm audit --json --audit-level=high` in the `superset-frontend` package-lock context.
2. `.github/scripts/npm_audit_create_issues.py` parses the audit report and creates or updates one GitHub issue per vulnerable **package**, grouping all high/critical advisories for that package into a single issue.
3. Issues receive the labels `npm-audit`, `security`, and `devin-remediate`.
4. `.github/workflows/npm-audit-devin-dispatch.yml` listens for `issues: labeled` events where the added label is `devin-remediate`, verifies the issue is a scanner-created open npm audit issue, and starts a Devin API v3 session.
5. Devin follows `.github/devin-playbooks/npm-audit-remediation.md`, remediates the dependency vulnerability, and opens a PR.

## Required repository configuration

- `DEVIN_API_KEY`: GitHub Actions secret containing a Devin API v3 service-user key.
- `DEVIN_ORG_ID`: GitHub Actions variable containing the Devin organization ID. The dispatch workflow also supports a secret with the same name for repositories that prefer storing it as a secret.

Optional:

- `ISSUE_BOT_TOKEN`: a fine-grained Personal Access Token (PAT) with:
  - **Repository access**: this fork only
  - **Permissions**: Issues (read/write), Metadata (read)

  This is recommended for the fully automated `scheduled scan -> issue -> labeled event -> Devin` loop because events created by the default `GITHUB_TOKEN` do not trigger downstream workflows (such as the `issues.labeled` dispatch workflow). Without this token, scanner-created issues still appear, but the Devin dispatch workflow will need to be run manually. The scan workflow picks it up via:
  ```yaml
  GITHUB_TOKEN: ${{ secrets.ISSUE_BOT_TOKEN || secrets.GITHUB_TOKEN }}
  ```

## Label taxonomy

- `npm-audit`: source label. The issue was created or maintained from npm audit scan output.
- `security`: category label. The issue is a security/dependency vulnerability remediation task for human filtering and reporting.
- `devin-remediate`: routing label. This is the operational trigger for the Devin dispatch workflow.

The dispatch workflow treats `devin-remediate` as the trigger label, requires `npm-audit` to be present, and ignores `security` by itself.

## Schedule

GitHub Actions cron expressions run in UTC. The scan workflow schedules both `03:00 UTC` and `04:00 UTC`, then gates scheduled runs with `TZ=Europe/Berlin date +%H` so only the run that corresponds to 5am Berlin time performs the scan. `workflow_dispatch` runs bypass the time gate.

## Deduplication strategy

Each package uses a stable fingerprint:

```text
npm-audit|package=<package-name>
```

The issue body includes the exact fingerprint as an HTML comment:

```html
<!-- devin-fingerprint: npm-audit|package=<package-name> -->
```

The scanner does not rely on GitHub full-text issue search. It uses the GitHub Issues REST API to list issues with label `npm-audit` and `state=all`, then inspects raw issue bodies locally for the exact fingerprint comment.

Behavior:

- If an open issue with the same fingerprint exists, the scanner updates that issue title, body, and labels.
- If only closed issues with the same fingerprint exist, the scanner creates a new issue. Closed generated issues are treated as historical records. If the same package appears in a future scan and no open issue exists, the scanner creates a new issue rather than reopening the old one.
- If no issue with the fingerprint exists (including deleted issues, which do not appear in the API), the scanner creates a new issue listing all high/critical advisories for the package, including severity, vulnerable ranges, advisory links, and fix metadata.

## Devin dispatch safeguards

The dispatch workflow launches Devin only when all of these are true:

- the event is an `issues: labeled` event for the `devin-remediate` label, or a manual `workflow_dispatch` for a specific issue
- the issue is open
- the issue has the `npm-audit` label
- the issue has the `devin-remediate` label
- the issue body and comments do not already contain a Devin session marker or Devin session URL

When a session is created, the workflow comments back on the issue with a hidden marker:

```html
<!-- devin-session: <session-id-or-url> -->
```

That marker prevents duplicate Devin sessions for the same issue.

## Manual demo steps

1. Run **NPM Audit Scan** from the Actions tab with `workflow_dispatch`.
2. Confirm that high or critical findings create/update issues with labels `npm-audit`, `security`, and `devin-remediate`.
3. If `ISSUE_BOT_TOKEN` is configured, confirm that adding `devin-remediate` starts **NPM Audit Devin Dispatch** automatically. If not, run **NPM Audit Devin Dispatch** manually and provide the issue number.
4. Confirm the issue receives a Devin session comment.
5. Confirm Devin opens a PR and the PR explains the dependency/security change and validation performed.
