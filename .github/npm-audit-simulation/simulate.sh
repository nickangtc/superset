#!/usr/bin/env bash
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

# Local simulation harness for the npm audit Devin automation.
# Run from the repository root:
#   bash .github/npm-audit-simulation/simulate.sh [command]
#
# Commands:
#   audit       Run npm audit --json against superset-frontend (default)
#   issues      Run the issue-creation script in dry-run mode
#   dispatch    Run the Devin dispatch script in dry-run mode
#   validate    Run Python syntax checks on all automation scripts
#   all         Run audit + issues + dispatch + validate

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="npm-audit-sim"

cd "${REPO_ROOT}"

build_image() {
    echo "=== Building Docker image '${IMAGE_NAME}' ==="
    docker build -f .github/npm-audit-simulation/Dockerfile -t "${IMAGE_NAME}" .
    echo
}

run_audit() {
    echo "=== Running npm audit --json in superset-frontend ==="
    docker run --rm "${IMAGE_NAME}" -c \
        "cd /workspace/superset-frontend && npm audit --json --audit-level=high 2>/dev/null | python3 -m json.tool | head -100; echo; echo '... (truncated for readability)'"
    echo
}

run_issues() {
    echo "=== Running issue-creation script (DRY_RUN=true) ==="
    docker run --rm "${IMAGE_NAME}" -c \
        "cd /workspace/superset-frontend && npm audit --json --audit-level=high > /tmp/npm-audit.json 2>/dev/null || true; DRY_RUN=true python3 /workspace/scripts/npm_audit_create_issues.py /tmp/npm-audit.json"
    echo
}

run_dispatch() {
    echo "=== Running Devin dispatch script (DRY_RUN=true) ==="
    docker run --rm -e DRY_RUN=true -e PLAYBOOK_PATH=/workspace/playbooks/npm-audit-remediation.md "${IMAGE_NAME}" -c \
        "python3 /workspace/scripts/npm_audit_dispatch_devin.py"
    echo
}

run_validate() {
    echo "=== Validating Python syntax ==="
    docker run --rm "${IMAGE_NAME}" -c \
        "python3 -m py_compile /workspace/scripts/npm_audit_create_issues.py && echo 'OK: npm_audit_create_issues.py' && python3 -m py_compile /workspace/scripts/npm_audit_dispatch_devin.py && echo 'OK: npm_audit_dispatch_devin.py'"
    echo
}

COMMAND="${1:-all}"

build_image

case "${COMMAND}" in
    audit)
        run_audit
        ;;
    issues)
        run_issues
        ;;
    dispatch)
        run_dispatch
        ;;
    validate)
        run_validate
        ;;
    all)
        run_audit
        run_issues
        run_dispatch
        run_validate
        echo "=== All simulations complete ==="
        ;;
    *)
        echo "Usage: $0 {audit|issues|dispatch|validate|all}"
        exit 1
        ;;
esac
