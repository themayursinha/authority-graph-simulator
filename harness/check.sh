#!/usr/bin/env bash
# Authority Graph Simulator harness gate.
#
# Runs format check, vet, unit/CLI tests, race tests, and both golden fixture
# comparisons, then writes a gitignored evidence manifest under
# evidence/harness/<UTC timestamp>/manifest.md.
set -uo pipefail

cd "$(dirname "$0")/.."
export PATH="/usr/local/go/bin:$PATH"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="evidence/harness/${STAMP}"
mkdir -p "${EVIDENCE_DIR}"
MANIFEST="${EVIDENCE_DIR}/manifest.md"

FAILURES=0

record() {
  local name="$1"
  shift
  echo "### ${name}" >> "${MANIFEST}"
  echo '```' >> "${MANIFEST}"
  if "$@" >> "${MANIFEST}" 2>&1; then
    echo '```' >> "${MANIFEST}"
    echo "PASS: ${name}" >> "${MANIFEST}"
  else
    echo '```' >> "${MANIFEST}"
    echo "FAIL: ${name}" >> "${MANIFEST}"
    FAILURES=$((FAILURES + 1))
  fi
}

{
  echo "# Authority Graph Simulator harness"
  echo
  echo "Timestamp: $(date -u -Is)"
  echo "Go: $(go version)"
  echo
} > "${MANIFEST}"

record "gofmt" bash -c 'test "$(gofmt -l . | wc -l)" -eq 0'
record "go vet ./..." go vet ./...
record "go test ./... -count=1" go test ./... -count=1
record "go test -race ./... -count=1" go test -race ./... -count=1
record "fixture deny-transitive" bash -c 'go run ./cmd/authority-graph-simulator testdata/deny-transitive.json > /tmp/authority-deny.json && diff -u testdata/deny-transitive.expected.json /tmp/authority-deny.json'
record "fixture allow-legitimate" bash -c 'go run ./cmd/authority-graph-simulator testdata/allow-legitimate.json > /tmp/authority-allow.json && diff -u testdata/allow-legitimate.expected.json /tmp/authority-allow.json'

echo >> "${MANIFEST}"
if [ "${FAILURES}" -eq 0 ]; then
  echo "RESULT: PASS" >> "${MANIFEST}"
  echo "RESULT: PASS"
  exit 0
else
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >> "${MANIFEST}"
  echo "RESULT: FAIL (${FAILURES} command(s) failed)" >&2
  exit 1
fi
