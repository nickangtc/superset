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

# npm audit remediation playbook

Use this playbook when a Devin session is launched from an `npm-audit` issue with the `devin-remediate` routing label.

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
