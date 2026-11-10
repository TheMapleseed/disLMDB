#!/usr/bin/env bash
# Compare e2e_runner output against golden expected files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ $# -ge 1 && -n "$1" ]]; then
  BIN="$1"
  [[ "$BIN" = /* ]] || BIN="$ROOT/$BIN"
else
  BIN="$ROOT/build/bin/e2e_runner"
fi
SCEN_DIR="$ROOT/tests/e2e/scenarios"
EXP_DIR="$ROOT/tests/e2e/expected"
OUT_DIR="${TMPDIR:-/tmp}/dislmdb_e2e_out_$$"

mkdir -p "$OUT_DIR" "$ROOT/build/e2e_work"
cd "$ROOT/build"

fail=0
ran=0

normalize() {
  # Drop absolute paths / host noise; keep structured tags
  sed -E \
    -e 's#/.*/e2e_work/#./e2e_work/#g' \
    -e 's/[[:space:]]+$//'
}

if [[ ! -x "$BIN" ]]; then
  echo "e2e_runner missing: $BIN" >&2
  exit 2
fi

shopt -s nullglob
for scen in "$SCEN_DIR"/*.in; do
  name="$(basename "$scen" .in)"
  exp="$EXP_DIR/${name}.out"
  got="$OUT_DIR/${name}.out"
  ran=$((ran + 1))

  rm -rf "./e2e_work/${name}" "./e2e_workdir" 2>/dev/null || true
  # Scenarios use path=./e2e_work/... relative to CWD (build/)
  mkdir -p ./e2e_work

  if ! "$BIN" "$scen" >"$got.raw" 2>"$OUT_DIR/${name}.err"; then
    # Runner may exit non-zero on EXPECT failures — still compare output
    true
  fi
  normalize <"$got.raw" >"$got"

  if [[ ! -f "$exp" ]]; then
    echo "MISSING golden: $exp (writing candidate)"
    mkdir -p "$EXP_DIR"
    cp "$got" "$exp"
    echo "  wrote $exp — review and commit"
    fail=$((fail + 1))
    continue
  fi

  if ! diff -u "$exp" "$got" >"$OUT_DIR/${name}.diff"; then
    echo "FAIL $name"
    cat "$OUT_DIR/${name}.diff"
    fail=$((fail + 1))
  else
    echo "PASS $name"
  fi
done

echo "E2E summary: $((ran - fail))/$ran passed"
rm -rf "$OUT_DIR"
exit "$fail"
