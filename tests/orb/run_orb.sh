#!/usr/bin/env bash
# Bring up the OrbStack/Docker cluster described by tests/orb/cluster.kdl and
# run join / spawn / replicate / shard scenarios. Requires docker (OrbStack ok).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${DISLMDB_ORB_IMAGE:-dislmdb-orb:local}"
NET="${DISLMDB_ORB_NET:-dislmdb-orb-net}"
PREFIX="${DISLMDB_ORB_PREFIX:-dislmdb-orb}"
CTL="${ORB_CTL:-}"

die() { echo "orb: $*" >&2; exit 1; }
log() { echo ">>>> $*"; }

need_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    die "docker not found (install OrbStack or Docker Desktop)"
  fi
}

admin_addr() {
  # Published host ports: n0→29876, n1→29877, n2→29878, n3→29879
  case "$1" in
    n0) echo "127.0.0.1:29876" ;;
    n1) echo "127.0.0.1:29877" ;;
    n2) echo "127.0.0.1:29878" ;;
    n3) echo "127.0.0.1:29879" ;;
    *) die "unknown node $1" ;;
  esac
}

host_admin_port() {
  case "$1" in
    n0) echo 29876 ;;
    n1) echo 29877 ;;
    n2) echo 29878 ;;
    n3) echo 29879 ;;
  esac
}

ctl() {
  local node="$1"; shift
  local addr
  addr="$(admin_addr "$node")"
  [[ -n "$CTL" && -x "$CTL" ]] || die "orb_ctl missing (run: make orb-bins)"
  "$CTL" "$addr" "$@"
}

wait_ping() {
  local node="$1" ms="${2:-15000}" w=0
  while (( w < ms )); do
    if ctl "$node" PING >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
    w=$((w + 250))
  done
  die "timeout waiting for $node admin"
}

wait_get() {
  local node="$1" key="$2" expect="$3" ms="${4:-8000}" w=0
  while (( w < ms )); do
    ctl "$node" SYNC >/dev/null 2>&1 || true
    local out
    if out="$(ctl "$node" GET "$key" 2>/dev/null)"; then
      if [[ "$out" == "OK $expect"* ]] || [[ "$out" == "OK $expect" ]]; then
        return 0
      fi
    fi
    sleep 0.25
    w=$((w + 250))
  done
  die "wait_get $node $key!=$expect"
}

rm_node() {
  docker rm -f "${PREFIX}-$1" >/dev/null 2>&1 || true
}

start_node() {
  local id="$1" seed_flag="$2" join="${3:-}"
  local hap
  hap="$(host_admin_port "$id")"
  rm_node "$id"
  local transport="${DISLMDB_ORB_TRANSPORT:-both}"
  local args=(
    run -d --name "${PREFIX}-${id}"
    --network "$NET"
    --hostname "$id"
    -p "${hap}:19876"
    -v "${PREFIX}-${id}-data:/data"
    "$IMAGE"
    --id "$id" --data /data --peer-port 9876 --admin-port 19876
    --transport "$transport"
  )
  if [[ "$seed_flag" == "1" ]]; then
    args+=(--seed)
  fi
  if [[ -n "$join" ]]; then
    args+=(--join "$join")
  fi
  docker "${args[@]}" >/dev/null
  wait_ping "$id"
  log "started $id (admin localhost:${hap})"
}

cleanup() {
  log "teardown"
  for id in n0 n1 n2 n3; do
    rm_node "$id"
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
}

build_image() {
  log "building $IMAGE"
  docker build -f "$ROOT/tests/orb/Dockerfile" -t "$IMAGE" "$ROOT"
}

ensure_net() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
}

scenario_replicate() {
  log "scenario replicate"
  ctl n0 PUT alpha omega | grep -q '^OK' || die "put failed"
  wait_get n1 alpha omega 8000
  wait_get n2 alpha omega 8000
  echo "  PASS  replicate"
}

scenario_join_spawn() {
  log "scenario join_spawn"
  start_node n3 0 "n0:9876"
  # Seed learns about n3; n3 already joined seed via --join
  ctl n0 JOIN n3 9876 n3 | grep -q '^OK' || die "join n3 failed"
  sleep 1
  ctl n0 PUT joined yes | grep -q '^OK' || die "put joined failed"
  wait_get n3 joined yes 12000
  echo "  PASS  join_spawn"
}

scenario_shard_affinity() {
  log "scenario shard_affinity (prefix convention)"
  ctl n0 PUT "shardA/item1" a1 | grep -q '^OK' || die "shardA put"
  ctl n0 PUT "shardB/item1" b1 | grep -q '^OK' || die "shardB put"
  wait_get n1 "shardA/item1" a1 8000
  wait_get n2 "shardB/item1" b1 8000
  echo "  PASS  shard_affinity"
}

DO_CLEAN=1

main() {
  need_docker
  local cmd="${1:-all}"
  case "$cmd" in
    build) build_image; exit 0 ;;
    cleanup) cleanup; exit 0 ;;
    keep) DO_CLEAN=0; cmd=all ;;
  esac

  trap '[[ ${DO_CLEAN:-1} -eq 1 ]] && cleanup' EXIT

  build_image
  ensure_net

  # Prefer host-built ctl when available (faster than docker run --network host)
  if [[ -z "$CTL" && -x "$ROOT/build/bin/orb_ctl" ]]; then
    CTL="$ROOT/build/bin/orb_ctl"
  fi

  start_node n0 1
  start_node n1 0 "n0:9876"
  start_node n2 0 "n0:9876"
  # Mutual membership from seed
  ctl n0 JOIN n1 9876 n1 | grep -q '^OK' || die "join n1"
  ctl n0 JOIN n2 9876 n2 | grep -q '^OK' || die "join n2"
  sleep 1

  scenario_replicate
  scenario_join_spawn
  scenario_shard_affinity

  log "Orb cluster scenarios PASSED"
}

main "$@"
