#!/usr/bin/env bash
#
# mayhem/test.sh — RUNS upstream's base64/base62/json/mn_socket self-tests plus known-answer probes, all built
# by mayhem/build.sh. Fails if a self-test case fails or reports fewer cases than it should, or if the
# probe output differs from the expected values (so a neutered binary cannot pass).
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/mayhem/build/test"
passed=0 failed=0

# <suite binary> <expected number of [pass] lines>
run_suite() {
  local name="$1" want="$2" out p f
  if [ ! -x "$T/$name.bin" ]; then
    echo "missing $T/$name.bin (build.sh should have produced it)" >&2
    failed=$((failed + 1))
    return
  fi
  out="$("$T/$name.bin" 2>&1)"
  rc=$?
  echo "$out"
  p=$(printf '%s\n' "$out" | grep -c '^\[pass\]')
  f=$(printf '%s\n' "$out" | grep -c '^\[FAIL\]')
  passed=$((passed + p))
  failed=$((failed + f))
  if [ "$rc" -ne 0 ] || [ "$p" -ne "$want" ]; then
    echo "$name: rc=$rc, $p passes (expected $want)" >&2
    failed=$((failed + 1))
  fi
}

run_suite base64_selftest 5
run_suite base62_selftest 3
run_suite json_selftest 3
# inet_pton_test, inet6_pton_test, inet_ntop_test; upstream's 4th case, socket_tests, is a
# TEST_CASE_TASK that needs the OS scheduler (and test_sem), which the mayhem shim aborts on.
run_suite mn_socket_selftest 3

EXPECTED=$(cat <<'EOF'
b64enc 16 TWF5aGVtIGZ1enoh
b64enc 4 YWI=
b64dec 12 Mayhem fuzz!
b64declen 2
b64bad -1
hex 5 deadbeef01
b62enc 0 48
b62dec 0 4 ffffffff
ll -1234 ok
ll 31 ok
ll 0 einval
ull 300 erange
bool 1 ok
bool 1 erange
bytes 0 4 deadbeef
ip6net 0 64 fe80...01
ip6net 1
pton4 1 10.1.2.250
pton6 1 2001:db8:0:0:0:0:0:ff
json 0 -42 1 hi 3 6
json-badattr 3
EOF
)

if [ ! -x "$T/kat.bin" ]; then
  echo "missing $T/kat.bin (build.sh should have produced it)" >&2
  failed=$((failed + 1))
else
  ACTUAL="$("$T/kat.bin" 2>&1)"
  # one probe per expected line, so the counts reflect what was verified
  while IFS= read -r line; do
    if printf '%s\n' "$ACTUAL" | grep -qxF -- "$line"; then
      passed=$((passed + 1))
    else
      echo "KAT mismatch: expected '$line'" >&2
      failed=$((failed + 1))
    fi
  done <<< "$EXPECTED"
  echo "$ACTUAL"
fi

emit_ctrf "mynewt-selftests" "$passed" "$failed" 0
