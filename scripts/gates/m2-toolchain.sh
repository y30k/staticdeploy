#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 TOOLCHAIN_EVIDENCE SECURITY_EVIDENCE_DIRECTORY OUTPUT" >&2
  exit 2
fi

rm -f \
  "$2/normalized-findings.json" \
  "$2/vulnerability-evaluation.json" \
  "$2/normalized-license-inventory.json" \
  "$2/license-evaluation.json"
node scripts/security-policy.mjs evaluate "$2"
node scripts/verify-m2-gate.mjs "$1" "$2" "$3"
