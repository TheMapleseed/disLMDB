# DisLMDB TODO

Last updated: 2026-11-11

## Status

Working system: Raft + Enhanced-PBFT, TCP/UDP/BOTH/QUIC, mTLS 1.3, DQGM v3, shard map,
leave/membership, outbox, ACL, bytecode compress, sandbox/integration/orb lanes green.

Membership/network peer tables are **heap-growable**; `DISLMDB_MAX_NODES` is an initial
size hint only. Soft cap via `max_peers` / `DISLMDB_MAX_PEERS` (0 = unlimited). Regional
Raft + learners bound voter fan-out; latency / RTT budgets still apply.

**KV note:** keys/values are opaque `MDB_val` blobs — UUIDv7 (16-byte binary or ASCII)
works as a general KV key. Shard `key_prefix` is a NUL-terminated C string; prefer
textual prefixes and put UUIDs in the key body/suffix.

## Green (do not regress)

| Lane | Status |
| --- | --- |
| `make check-sandbox` | Pass |
| `make check-integration` | Pass |
| `make check-orb` | Pass |
| `make check-stress` | Pass (soak; flake-prone cells repeated) |
| PBFT / Raft matrix + leave / membership / shard | Pass |
| DQGM v3 + CID rebind + pkt_num + ACK + peer-restart | Pass |
| Per-peer outbox + sock buffers | Pass |
| raft_matrix + connect_churn + auth_reject + chaos rig | Pass |
| Phase J coverage (`system_surface`, `raft_learner`, e2e ACL/topo) | Pass |
| Phase K/L/M ITs (`index_*`, `acl` RBAC, e2e 05–06, rust bindings) | Pass |
| Phase N Go binding surface (query + RBAC; soft-skip if no `go`) | Pass |

---

## Durability today (honest)

| What | Where | Disk? |
| --- | --- | --- |
| User KV / LMDB pages | `mdb.c` mmap (`data.mdb` / lockfile) | **Yes** — mmap’d B+tree; commit syncs meta (not a Postgres-style WAL) |
| Meta: view, seq, replica list, shard_map | `dislmdb_persist.c` → meta DBI | **Yes** when `persist_state` |
| Optional cluster key | meta DBI | Only if `persist_cluster_key` |
| Raft hard state + log + snap meta | `__dislmdb_raft__` via `raft_wal.c` | **Yes** when Raft + `persist_state` (`raft_wal_sync_every`) |
| matchIndex / volatile Raft | `Enhanced-Raft-mechanism/raft.c` | RAM — rebuilt from WAL + catch-up |
| Network outbox / DQGM counters | `dislmdb_network.c` | RAM |
| Checkpoint / `dislmdb_force_sync` | LMDB `mdb_env_sync` + persist_save + WAL compact | Explicit flush to disk |

So: **data is not “all RAM”** — LMDB is disk-backed mmap; Raft durable state lives in
`__dislmdb_raft__`. “Cooldown to disk” ≈ sync interval + checkpoint + WAL sync policy.

---

## Phases A–J — complete (archived)

Scale/region/topo (A–E), Raft WAL/FSM (F), I/O + QUIC stack (G), product surface
(H: compress/ACL/bindings/metrics), harden (I), system-wide tests (J). Optional
commit/push of session work remains when asked — not a product gap.

---

## Phase K — Honest product gaps (closed 2026-11-11)

Roadmap A–J shipped a working distributed KV. Phase K gaps below are checked off;
re-measure SLOs on new CI hosts via `make measure-slos`.

### Data model & consistency

- [x] Secondary index helpers + query (`index_put`/`del`/`get`/`scan`;
      `docs/kv_and_txn.kdl`; ITs `test_index_versioned`, `test_index_query`)
- [x] Clarify multi-key ACID across named DBIs under consensus apply
      (`docs/kv_and_txn.kdl` + README; IT `test_multikey_txn` — one oplog, one apply txn)
- [x] Richer mirror conflict policy: `DISLMDB_MIRROR_CLIENT_TIMESTAMP` +
      `dislmdb_put/get_versioned` LWW (env `DISLMDB_MIRROR_CONFLICT=client_timestamp|lww`)

### Transport & scale

- [x] QUIC in `check-stress` (5× `test_raft_quic`) + soak gate doc (`docs/soak_slos.kdl`)
- [x] QUIC connect_churn (`test_connect_churn_quic`) + live CA mismatch (`test_quic_pki_reject`)
- [x] QUIC long soak target (`make check-quic-soak`, `DISLMDB_QUIC_SOAK_ROUNDS`)
- [x] Geo-scale **playbook** (`docs/geo_playbook.kdl` + README) — hubs/learners/modes/secrets
- [x] Multi-region IT (`test_geo_regions`: east hub + west learner + REGION_PRIORITY)

### Security & bindings

- [x] Fine-grained ACL + RBAC: prefix grants + roles (global/prefix-scoped);
      `docs/acl.kdl`; IT `test_acl`
- [x] Language bindings: Rust (`bindings/rust`) + Go (`bindings/go`, query/RBAC parity)

### Operations

- [x] Backup/restore **playbook** (`docs/ops_backup.kdl` — cold copy + checkpoint/sync)
- [x] Production admin CLI (`tools/dislmdb_admin.c` / `make tools`) — offline metrics/
      checkpoint/sync/leader (orb_ctl remains test-only)
- [x] Published soak **gates** (`docs/soak_slos.kdl` — CI commands)
- [x] Measured hub/leaf latency baseline (`test_slo_baseline` / `make measure-slos`;
      `docs/soak_slos.kdl` `measured{}` + soft `budgets{}`) — re-run on target CI hosts

## Implementation order (recommended)

1. ~~Document multi-key / txn + UUID/shard key conventions~~ (`docs/kv_and_txn.kdl`)
2. ~~Ops backup/restore + geo playbook~~ (`docs/ops_backup.kdl`, `docs/geo_playbook.kdl`)
3. ~~QUIC soak / churn hardening~~
4. ~~Mirror conflict hooks + secondary index helpers + ACL prefix depth~~
5. ~~Bindings maturity + admin CLI + QUIC long soak target~~
6. ~~Measured soak SLOs (`make measure-slos`)~~ — refresh on new hardware as needed

---

## Phase L — Harden & lock-in (closed 2026-11-11)

Phase K closed the product gaps. L locked them into CI, raised soak bar, and shipped
the former “deferred” query + RBAC surfaces.

- [x] e2e scenarios for index / versioned LWW / prefix ACL (`05_index_versioned_acl`)
- [x] Raise `check-stress` QUIC repeats to **20×** (mTLS parity; verified local 20/20)
- [x] Live metrics scrape file (`DISLMDB_METRICS_FILE` + `dislmdb_export_metrics_file`;
      `dislmdb_admin cat-metrics`) — refreshes on sync/checkpoint
- [x] Go cgo binding sketch (`bindings/go`; `make go-bindings` when Go toolchain present)
- [x] Secondary query layer: `dislmdb_index_get` + `dislmdb_index_scan` (`test_index_query`)
- [x] RBAC: roles (global + prefix-scoped), assign/unassign, persist (`docs/acl.kdl`, `test_acl`)

---

## Phase M — Surface lock-in (closed 2026-11-11)

Bring e2e goldens + Rust bindings up to the Phase L C ABI (query + RBAC).

- [x] e2e: `INDEX_GET` / `INDEX_SCAN` + RBAC role commands + scenario 06
- [x] Rust: `index_get` / `index_scan` + role APIs + tests (`OpenOptions.enable_acl`)
- [x] Green table notes Phase K/L ITs; e2e 01–06 pass

---

## Phase N — Go surface parity (closed 2026-11-11)

Bring the Go cgo sketch up to the same query + ACL/RBAC surface as Rust.

- [x] Go: `IndexGet` / `IndexScan`, versioned put/get, ACL prefix + RBAC APIs + tests
- [x] `make go-bindings` soft-skips when the Go toolchain is absent
- [x] README roadmap → Phases A–N
