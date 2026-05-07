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

1. Prefer the smallest safe dependency/security change that resolves the reported high or critical advisory.
2. Start in `superset-frontend`, because the audit scan runs against that package-lock context.
3. Inspect the advisory metadata in the GitHub issue and confirm the vulnerable package, advisory ID or URL, severity, vulnerable range, and recommended fix.
4. Prefer targeted package updates or safe `npm audit fix` changes. Avoid `npm audit fix --force` unless the advisory cannot be remediated safely another way and the PR explains why a force upgrade is justified.
5. After any automated audit fix, inspect the diff before committing. Check `superset-frontend/package.json`, `superset-frontend/package-lock.json`, and workspace package changes for unrelated upgrades.
6. Run dependency installation or lockfile refresh commands needed for a consistent lockfile.
7. Run relevant validation before opening the PR:
   - install or lockfile verification command used for the change
   - frontend lint or typecheck when touched packages can affect compiled code
   - targeted tests for impacted packages when practical
   - leave broad/full test-suite execution to CI when local runtime cost is excessive
8. Open a pull request with the remediation summary, advisory details, and validation performed.
9. If the dependency fix is risky, blocked, or requires a semver-major upgrade, explain the tradeoff in the PR and keep the diff minimal.
