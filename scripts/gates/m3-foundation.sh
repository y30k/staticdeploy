#!/usr/bin/env bash
set -uo pipefail

component="${1:-full}"
report="${M3_EVIDENCE_PATH:-reports/m3-foundation-evidence.json}"
mkdir -p "$(dirname "$report")"
results="$(mktemp)"
trap 'rm -f "$results"' EXIT
failed=0
actual_major="unknown"

record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$results"
}

run_case() {
  local id="$1"
  local command="$2"
  if bash -o pipefail -c "$command"; then
    record "$id" passed "$command"
  else
    record "$id" failed "$command"
    failed=1
  fi
}

write_report() {
  local gate_status="PASSED"
  if [[ "$failed" -ne 0 ]]; then gate_status="FAILED"; fi
  if [[ "$component" != "authorization" ]]; then gate_status="BLOCKED-LOCAL"; fi
  node - "$results" "$report" "$gate_status" "$actual_major" "$component" <<'NODE'
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const [resultsPath, reportPath, status, postgresMajor, component] = process.argv.slice(2);
const cases = fs.readFileSync(resultsPath, "utf8").trim().split("\n")
  .filter(Boolean)
  .map(line => {
    const [id, caseStatus, command] = line.split("\t");
    return { id, status: caseStatus, command };
  });
let commit = "unknown";
let dirty = true;
try {
  commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  dirty = execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim() !== "";
} catch {}
const evidence = {
  schemaVersion: 1,
  gate: component === "authorization" ? "M3-07-focused" : "G-M3",
  status,
  commit,
  dirty,
  environment: {
    expectedPostgresMajor: process.env.EXPECTED_POSTGRES_MAJOR ?? null,
    attestedPostgresMajor: postgresMajor,
    nodeVersion: process.version,
  },
  cases,
  blockedLocal: ["M3-08", "M3-09", "M3-10", "M3-11", "M3-GATE"],
  blockedExternal: ["B-OKTA", "B-PG"],
  generatedAt: new Date().toISOString(),
};
fs.writeFileSync(reportPath, JSON.stringify(evidence, null, 2) + "\n");
process.stdout.write(JSON.stringify(evidence) + "\n");
NODE
}

if [[ "$component" != "authorization" ]]; then
  record "M3-08..M3-11" blocked "remaining local M3 stories"
  write_report
  exit 1
fi

if [[ -z "${POSTGRES_TEST_URL:-}" || -z "${EXPECTED_POSTGRES_MAJOR:-}" ]]; then
  record "ENVIRONMENT" failed "POSTGRES_TEST_URL and EXPECTED_POSTGRES_MAJOR are required"
  failed=1
else
  actual_major="$(node - "$POSTGRES_TEST_URL" <<'NODE' 2>/dev/null || true
const { Client } = require("pg");
(async () => {
  const client = new Client({ connectionString: process.argv[2] });
  await client.connect();
  const result = await client.query("show server_version_num");
  await client.end();
  process.stdout.write(String(Math.floor(Number(result.rows[0].server_version_num) / 10000)));
})().catch(() => process.exit(1));
NODE
)"
  if [[ "$actual_major" == "$EXPECTED_POSTGRES_MAJOR" ]]; then
    record "POSTGRES-MAJOR" passed "query server_version_num"
  else
    record "POSTGRES-MAJOR" failed "query server_version_num"
    failed=1
  fi

  # Compile first so migration-backed tests always execute this checkout's
  # migration 07 rather than any ignored/stale lib output.
  run_case "COMPILE-WORKSPACES" "corepack yarn compile"
  run_case "SCHEMA" "corepack yarn workspace @staticdeploy/pg-s3-storages test:postgres"
  for auth_case in AUTH-01 AUTH-02 AUTH-03 AUTH-04 AUTH-05; do
    run_case "$auth_case" "corepack yarn workspace @staticdeploy/pg-s3-storages test:v2-sessions -- --grep '$auth_case'"
  done
  run_case "AUTHZ-01" "corepack yarn workspace @staticdeploy/pg-s3-storages test:v2-authorization -- --grep 'AUTHZ-01'"
  run_case "TM-AUD-01" "corepack yarn workspace @staticdeploy/pg-s3-storages test:v2-authorization -- --grep 'TM-AUD-01'"
  run_case "CORE-AUTHZ" "corepack yarn workspace @staticdeploy/core test -- --grep 'V2Authorizer|ReplaceV2Bindings'"
  run_case "STATIC-INTEGRATION" "corepack yarn workspace @staticdeploy/staticdeploy test -- --grep 'M3-07|AUTHZ-01'"
fi

write_report
exit "$failed"
