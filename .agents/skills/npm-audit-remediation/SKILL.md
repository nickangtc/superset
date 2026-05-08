---
name: npm-audit-remediation
description: >
  Remediate high and critical npm audit issues in Superset frontend by triaging
  package risk, making the smallest safe dependency fix, validating the result,
  and opening a linked PR.
---

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

# npm audit remediation

Use this skill when a Devin session is launched from an `npm-audit` issue with the `devin-remediate` routing label.

## Contextual triage

Treat `npm audit` as input, not truth. Before making changes, assess the vulnerable package in this repository's context.

For the package named in the issue:

1. Determine whether it is direct or transitive.
2. Determine whether it is under `dependencies`, `devDependencies`, `peerDependencies`, or `optionalDependencies`.
3. Identify the dependency path and parent package using commands such as:
   - `npm explain <package>`
   - `npm ls <package>`
4. Determine likely execution context:
   - production runtime
   - browser bundle
   - build pipeline
   - CI/CD
   - test/lint/storybook/dev-server tooling
   - unused or unclear
5. Do not dismiss devDependencies automatically. Build and CI dependencies may matter if they process contributor input, build production artifacts, or run with secrets.
6. For frontend code, do not assume every dependency ships to users. Check whether the package is imported by production source or appears likely to be bundled.
7. Assess realistic risk:
   - Is vulnerable functionality likely called?
   - Is attacker-controlled input plausibly passed to it?
   - Is this production risk, build-pipeline risk, local-dev risk, or likely noise?
8. State confidence briefly:
   - high confidence real risk
   - medium confidence potential risk
   - low confidence / likely noise
   - needs human review

## Guardrails

1. Each npm-audit GitHub issue covers **one package** and may list **multiple advisories**. The goal is to remediate the full set of advisories for that package in a single PR.
2. Prefer the smallest safe dependency/security change that resolves all reported high or critical advisories for the package.
3. Start in `superset-frontend`, because the audit scan runs against that package-lock context.
4. Inspect the advisory metadata in the GitHub issue: the summary table shows the package, highest severity, advisory count, vulnerable ranges, and recommended fix. The **Advisories** table lists each advisory with its severity, advisory link, vulnerable range, and title.
5. Prefer targeted package updates or safe `npm audit fix` changes. Avoid `npm audit fix --force` unless the advisories cannot be remediated safely another way and the PR explains why a force upgrade is justified.
6. After any automated audit fix, inspect the diff before committing. Check `superset-frontend/package.json`, `superset-frontend/package-lock.json`, and workspace package changes for unrelated upgrades.
7. Run dependency installation or lockfile refresh commands needed for a consistent lockfile.
8. Run relevant validation before opening the PR:
   - install or lockfile verification command used for the change
   - frontend lint or typecheck when touched packages can affect compiled code
   - targeted tests for impacted packages when practical
   - leave broad/full test-suite execution to CI when local runtime cost is excessive
9. Open a single pull request covering all advisories for the package. Include the remediation summary, advisory details, and validation performed.
10. **Link the PR to its GitHub issue.** The PR description **must** contain `Closes #<issue_number>` (using the issue number from the triggering npm-audit issue) so that GitHub automatically links the PR to the issue and closes it when the PR is merged. This ensures the issue timeline shows "linked a pull request that will close this issue" instead of just "mentioned this".
11. If the dependency fix is risky, blocked, or requires a semver-major upgrade, explain the tradeoff in the PR and keep the diff minimal.

## Fix strategy

Recommend and implement the least disruptive safe fix.

Prefer, in order:

1. non-breaking upgrade of the direct dependency
2. upgrade of the parent dependency that introduces the vulnerable package
3. semver-safe `npm audit fix`
4. targeted override/resolution if compatible and justified
5. removal of unused dependency

Avoid `npm audit fix --force` unless the PR explains why a breaking upgrade is necessary and acceptable.
Do not suppress an advisory unless the exploit path is not applicable, no fix exists, or compensating controls are documented.

## PR explanation

In the PR body, include a concise security note:

- vulnerable package
- dependency path / parent package
- execution context
- realistic risk assessment
- confidence
- remediation chosen
- validation performed
