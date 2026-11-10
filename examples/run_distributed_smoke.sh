#!/usr/bin/env bash
# Two-node smoke for distributed_example (HMAC + AEAD + BOTH).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/build/bin/distributed_example"
WORK="${ROOT}/build/example_smoke"
PORT_A="${DISLMDB_SMOKE_PORT_A:-30710}"
PORT_B="${DISLMDB_SMOKE_PORT_B:-30711}"

die() { echo "smoke-example: $*" >&2; exit 1; }
[[ -x "$BIN" ]] || die "missing $BIN — run 'make examples' first"

rm -rf "$WORK"
mkdir -p "$WORK/a" "$WORK/b"
export DISLMDB_SMOKE=1
# 64 hex chars (32 bytes) — demo key for local smoke only
export DISLMDB_CLUSTER_KEY="${DISLMDB_CLUSTER_KEY:-$(printf 'aa%.0s' {1..32})}"

export DYLD_LIBRARY_PATH="${ROOT}/build/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="${ROOT}/build/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

"$BIN" "$WORK/a" seed-a "$PORT_A" 1 >"$WORK/a.log" 2>&1 &
PID_A=$!
sleep 1
"$BIN" "$WORK/b" node-b "$PORT_B" 0 "127.0.0.1:${PORT_A}" >"$WORK/b.log" 2>&1 &
PID_B=$!

cleanup() {
  kill "$PID_A" "$PID_B" 2>/dev/null || true
  wait "$PID_A" "$PID_B" 2>/dev/null || true
}
trap cleanup EXIT

ok=0
for i in $(seq 1 60); do
  if grep -q 'Smoke mode: shutting down after commit' "$WORK/a.log" 2>/dev/null &&
     grep -q 'Smoke mode: shutting down after commit' "$WORK/b.log" 2>/dev/null; then
    ok=1
    break
  fi
  # Prefer exit status if processes already finished
  if ! kill -0 "$PID_A" 2>/dev/null && ! kill -0 "$PID_B" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

wait "$PID_A" && EA=0 || EA=$?
wait "$PID_B" && EB=0 || EB=$?
trap - EXIT

if [[ "$EA" -eq 0 && "$EB" -eq 0 ]]; then
  echo "distributed_example smoke: PASS (seed-a + node-b)"
  exit 0
fi

echo "distributed_example smoke: FAIL ea=$EA eb=$EB" >&2
tail -40 "$WORK/a.log" >&2 || true
tail -40 "$WORK/b.log" >&2 || true
exit 1
