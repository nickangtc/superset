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

# npm audit Devin automation - Local Docker simulation

This directory provides a **local simulation harness** for the npm audit Devin
automation. It lets you run and inspect the automation scripts without requiring
GitHub Actions, API keys, or a live Devin integration.

> **Important:** Docker is only a local simulation/development harness. The real
> automation runs in GitHub Actions. See [Limitations](#limitations) below.

---

## Architecture overview

```
                     GitHub Actions (event bus)
                              |
               +--------------+--------------+
               |                             |
   npm-audit-scan.yml              npm-audit-devin-dispatch.yml
   (scheduled / manual)            (issues.labeled trigger)
               |                             |
               v                             v
   npm_audit_create_issues.py      npm_audit_dispatch_devin.py
   (parse audit -> GitHub Issues)  (create Devin API session)
               |                             |
               v                             v
     GitHub Issues                   Devin session -> PR
     (remediation queue)
```

**Components:**

| Component | Role |
|-----------|------|
| GitHub Actions | Event bus and scanner runtime |
| GitHub Issues | Remediation queue (one issue per vulnerable package) |
| Labels | Route work: `npm-audit` (source), `security` (category), `devin-remediate` (trigger) |
| Devin | Async engineer that remediates vulnerabilities and opens PRs |

**Flow:**

1. Scheduled/manual scan runs `npm audit --json --audit-level=high` in `superset-frontend`.
2. Python script parses findings, groups by package, and creates/updates GitHub issues.
3. Issues receive labels: `npm-audit`, `security`, `devin-remediate`.
4. The `devin-remediate` label triggers a dispatch workflow.
5. Dispatch workflow validates the issue and starts a Devin API session with the playbook.
6. Devin follows the playbook, remediates the vulnerability, and opens a PR.

---

## Required GitHub repository setup (for real deployment)

### Secrets

| Secret | Purpose |
|--------|---------|
| `DEVIN_API_KEY` | Devin API v3 service-user key |
| `DEVIN_ORG_ID` | Devin organization ID (can also be a repository variable) |
| `ISSUE_BOT_TOKEN` | Fine-grained PAT for creating issues that trigger downstream workflows |

### About `ISSUE_BOT_TOKEN`

The default `GITHUB_TOKEN` in GitHub Actions cannot trigger other workflows.
For the fully automated `scan -> issue -> labeled event -> Devin` loop,
`ISSUE_BOT_TOKEN` should be a **fine-grained Personal Access Token** with:

- **Repository access:** the fork only
- **Permissions:** Issues (read/write), Metadata (read)

Without this token, scanner-created issues still appear, but the Devin dispatch
workflow must be triggered manually.

---

## Local Docker simulation

### Prerequisites

- Docker (with BuildKit)
- Repository cloned locally

### Quick start

From the **repository root**:

```bash
# Run all simulations (audit + issues + dispatch + validate)
bash .github/npm-audit-simulation/simulate.sh all

# Or run individual commands:
bash .github/npm-audit-simulation/simulate.sh audit      # npm audit scan
bash .github/npm-audit-simulation/simulate.sh issues     # issue creation (dry-run)
bash .github/npm-audit-simulation/simulate.sh dispatch   # Devin dispatch (dry-run)
bash .github/npm-audit-simulation/simulate.sh validate   # Python syntax check
```

### Manual Docker commands

```bash
# Build the image
docker build -f .github/npm-audit-simulation/Dockerfile -t npm-audit-sim .

# Run npm audit
docker run --rm npm-audit-sim -c \
  "cd /workspace/superset-frontend && npm audit --json --audit-level=high"

# Run issue creation in dry-run mode
docker run --rm npm-audit-sim -c \
  "cd /workspace/superset-frontend && \
   npm audit --json --audit-level=high > /tmp/npm-audit.json 2>/dev/null || true && \
   DRY_RUN=true python3 /workspace/scripts/npm_audit_create_issues.py /tmp/npm-audit.json"

# Run Devin dispatch in dry-run mode (uses real audit data from superset-frontend)
docker run --rm \
  -e DRY_RUN=true \
  -e PLAYBOOK_PATH=/workspace/playbooks/npm-audit-remediation.md \
  -e NPM_AUDIT_JSON=/tmp/npm-audit.json \
  npm-audit-sim -c \
  "cd /workspace/superset-frontend && \
   npm audit --json --audit-level=high > /tmp/npm-audit.json 2>/dev/null || true && \
   python3 /workspace/scripts/npm_audit_dispatch_devin.py"

# Validate Python syntax
docker run --rm npm-audit-sim -c \
  "python3 -m py_compile /workspace/scripts/npm_audit_create_issues.py && \
   python3 -m py_compile /workspace/scripts/npm_audit_dispatch_devin.py && \
   echo 'All scripts OK'"
```

### Using docker-compose

```bash
cd .github/npm-audit-simulation

# Build
docker compose build

# Run interactively
docker compose run --rm npm-audit-sim

# Inside the container you can run any command manually
```

### What to expect

| Command | Output |
|---------|--------|
| `audit` | Raw JSON output from `npm audit` showing vulnerabilities in `superset-frontend` |
| `issues` | List of packages with high/critical advisories that would become GitHub issues |
| `dispatch` | The full Devin prompt (with playbook) built from real audit findings that would be sent to the Devin API |
| `validate` | Confirmation that all Python scripts have valid syntax |

### Simulated vs real

| Aspect | Docker simulation | Real GitHub Actions |
|--------|-------------------|---------------------|
| npm audit scan | Real scan of `superset-frontend` lockfile | Same |
| Issue grouping/parsing | Real parsing logic, printed to stdout | Creates/updates GitHub issues |
| GitHub API calls | Skipped (DRY_RUN=true) | Creates issues, adds labels, comments |
| Devin dispatch | Builds and prints prompt only | Calls Devin API, starts session |
| Webhook triggers | Not simulated | `issues.labeled` triggers dispatch |
| PR lifecycle | Not simulated | Devin opens PR, CI runs |

---

## Limitations

This Docker simulation **cannot** reproduce:

- **GitHub `issues.labeled` webhooks** - the event-driven dispatch trigger
- **GitHub Actions token behavior** - `GITHUB_TOKEN` permissions and scoping
- **Devin's GitHub integration** - repository access, branch creation, PR opening
- **PR/CI lifecycle** - automated testing, review, and merge workflows
- **Issue deduplication** - requires the GitHub Issues API to check existing issues

The real end-to-end demo **must** be run in the forked GitHub repository using
GitHub Actions.

---

## Recommended end-to-end demo path

To run the full automation in your GitHub fork:

1. **Ensure Devin GitHub integration** has access to the fork.
2. **Configure repository secrets:** `DEVIN_API_KEY`, `DEVIN_ORG_ID`, `ISSUE_BOT_TOKEN`.
3. **Close existing npm-audit issues** if replaying the demo (to avoid deduplication conflicts).
4. **Manually run `NPM Audit Scan`** from the GitHub Actions tab (workflow_dispatch).
5. **Confirm grouped issues** are created with labels `npm-audit`, `security`, `devin-remediate`.
6. **Wait for `NPM Audit Devin Dispatch`** to trigger from the label event.
   - If `ISSUE_BOT_TOKEN` is not configured, run the dispatch workflow manually with the issue number.
7. **Wait ~20 minutes** for Devin to complete remediation.
8. **Inspect** the Devin session comment on the issue and the PR created by Devin.

---

## File reference

| File | Purpose |
|------|---------|
| `.github/workflows/npm-audit-scan.yml` | Scheduled/manual npm audit scan workflow |
| `.github/workflows/npm-audit-devin-dispatch.yml` | Label-triggered Devin dispatch workflow |
| `.github/scripts/npm_audit_create_issues.py` | Parse audit JSON, create/update GitHub issues |
| `.github/scripts/npm_audit_dispatch_devin.py` | Validate issue, build prompt, call Devin API |
| `.github/devin-playbooks/npm-audit-remediation.md` | Source-controlled playbook for Devin |
| `.github/devin-remediation.md` | Architecture documentation |
| `.github/npm-audit-simulation/Dockerfile` | Docker image for local simulation |
| `.github/npm-audit-simulation/docker-compose.yml` | Compose config for simulation |
| `.github/npm-audit-simulation/simulate.sh` | Wrapper script for common simulation commands |
