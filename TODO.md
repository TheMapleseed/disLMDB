# DisLMDB TODO

Last updated: 2026-11-10

## Status

Working system: Raft + Enhanced-PBFT, TCP/UDP/BOTH, mTLS 1.3, DQGM v3, shard map,
leave/membership, outbox buffers, sandbox/integration/orb/stress lanes green.

Membership/network peer tables are **heap-growable**; `DISLMDB_MAX_NODES` is an initial
size hint only. Soft cap via `max_peers` / `DISLMDB_MAX_PEERS` (0 = unlimited). Practical
scale still bounded by **latency / full-mesh fan-out** until Phase B hierarchy lands.

## Green (do not regress)

| Lane | Status |
| --- | --- |
| `make check-sandbox` | Pass |
| `make check-integration` | Pass |
| `make check-orb` | Pass |
| `make check-stress` | Pass (target) |
| PBFT / Raft matrix + leave / membership / shard | Pass |
| DQGM v3 + CID rebind + pkt_num + ACK + peer-restart | Pass |
| Per-peer outbox + sock buffers | Pass |
| raft_matrix + connect_churn + auth_reject + chaos rig | Pass |

---

## Durability today (honest)

| What | Where | Disk? |
| --- | --- | --- |
| User KV / LMDB pages | `mdb.c` mmap (`data.mdb` / lockfile) | **Yes** — mmap’d B+tree; commit syncs meta (not a Postgres-style WAL) |
| Meta: view, seq, replica list, shard_map | `dislmdb_persist.c` → meta DBI | **Yes** when `persist_state` |
| Optional cluster key | meta DBI | Only if `persist_cluster_key` |
| Raft log / matchIndex | `Enhanced-Raft-mechanism/raft.c` | **RAM only today** — restart rebuilds via catch-up / HELLO |
| Network outbox / DQGM counters | `dislmdb_network.c` | RAM |
| Checkpoint / `dislmdb_force_sync` | LMDB `mdb_env_sync` + persist_save | Explicit flush to disk |

So: **data is not “all RAM”** — LMDB is disk-backed mmap with sync/checkpoint.
Consensus **log** still needs a durable Raft WAL for crash-safe leadership at scale.
“Cooldown to disk” ≈ sync interval + checkpoint + (future) Raft snapshot/WAL.

---

## Roadmap — uncapped scale + regional membership

### Phase A — Remove hard caps (dynamic structures)

Goal: membership/network grow with topology; only latency/RTT budgets constrain size.

- [x] Replace fixed arrays (`connections`, Raft peer/index tables) with growable heap
- [x] Cap policy becomes **soft**: `max_peers` / `DISLMDB_MAX_PEERS` (0 = unlimited)
- [x] Persist replica set without fixed N packing limits (REPL v2 length-prefixed stream)
- [x] Unit: `test_raft_peer_growth` past 64; IT: `test_topo_env`
- [ ] Rig soak spawn to N≫64 / hash map peer id → slot

### Phase B — Hierarchical consensus (latency-bound, not N² mesh)

Goal: thousands of nodes via **regions**, not one global voter set.

```
                    [global / mirror coordinators]     optional
                           │
          ┌────────────────┼────────────────┐
     [region-east]    [region-west]    [region-eu]     Raft (small N)
          │                │                │
     local nodes      local nodes      local nodes    gossip / leaf
```

- [x] **Local Raft group per region** (voters = same-region peers; cross → learner or absent)
- [x] **Cross-region**: mirror/hybrid → learners; shard → not in Raft (ownership local)
- [x] Prefer nearest peer: RTT probe + region affinity for dial/HELLO
- [x] Heartbeats / AE only inside the local voter set; dedicated cross-region learner AE lane (`learner_ae_ms`, default 4× HB)

### Phase C — Regional / localization secrets via env

Membership and crypto scoped by deployment env (never commit secrets).

| Variable | Role |
| --- | --- |
| **`DISLMDB_VOTING`** | **`on`/`1` (default) or `off`/`0`** — keep voting as a first-class function; disable for large-cluster leaves/learners |
| `DISLMDB_REGION` | e.g. `us-east`, `eu-west` — local voter set id |
| `DISLMDB_LOCALITY` | finer zone / rack / AZ |
| `DISLMDB_REGION_SECRET` | HMAC/AEAD key material for **intra-region** traffic |
| `DISLMDB_CROSS_REGION_SECRET` | separate key for inter-region mirror/shard sync |
| `DISLMDB_TOPOLOGY_MODE` | `mirror` \| `shard` \| `hybrid` |
| `DISLMDB_SEED_REGIONAL` | seed list for closest-region join |
| `DISLMDB_RTT_BUDGET_MS` | soft admit/reject for “too far” peers |

**Voting model**

- Voting remains the normal path for regional hubs / small groups (`enable_voting=true`).
- Large edge fleets set `DISLMDB_VOTING=off` (or `consensus.enable_voting=false`): node is a
  **learner** — replicates AppendEntries, never campaigns, never grants votes; learners are
  excluded from commit quorum (`raft_add_learner` / `raft_set_peer_voting`).
- Only latency and hub voter-set size constrain scale — not “every node votes.”

- [x] `consensus.enable_voting` + Raft learner quorum + `DISLMDB_VOTING` env overlay
- [x] Load region/locality/secrets/topo mode/RTT/max_peers from env at `env_open`
- [x] Persist region/locality/topo_mode in meta DBI + public getters
- [x] Derive traffic keys per plane (local vs cross) — fail closed on mismatch
- [x] Nearest-peer selection (v1): region/locality dial backoff + HELLO topo trailer
- [x] RTT EWMA on TX/RX + soft reject when `rtt_budget_ms` exceeded
- [x] Cross-region / non-voting HELLO peers → Raft learners on voting hubs
- [x] Document secret rotation without full cluster outage (README)
- [x] Dedicated IT: `test_topo_plane` (cross-region key plane + RTT reject)

### Phase D — Topology modes: mirror vs shard

- [x] **`mirror`**: full KV; put/del unrestricted; cross-region Raft learners (AE)
- [x] **`shard`**: write gate via `dislmdb_topo_key_writable` / shard owner;
      cross-region peers excluded from Raft
- [x] **`hybrid`**: `DISLMDB_SHARD_FLAG_MIRRORED` prefixes free; others owner-gated
- [x] IT: `test_topo_modes` (mirror/shard/hybrid + flag persist)
- [x] Owner resolve API (`dislmdb_topo_resolve_owner`) for app-level redirect
- [x] Forward writes to owner: `dislmdb_topo_forward_put` / `_del` + FORWARD RPC (IT: `test_topo_forward`)
- [ ] Proxy/redirect reads; auto-forward inside `dislmdb_put` when rejected (explicit API shipped)
- [ ] Orb scenarios for mirror vs shard across “fake regions” (containers + env)
- [ ] Explicit conflict policy for mirror (last-write / region priority)

### Phase E — Dedicated DB namespace for regional metadata

Store topology in LMDB (not only env), so peers learn maps after join:

- [x] Meta plane `peer_topo`: id + region/locality/host/port per peer (+ local region fields)
- [x] Replicate topo updates via consensus (`dislmdb_topo_map_publish` / TOPO blob)
- [x] Stored under meta DBI key `peer_topo` (apps use named DBI / avoid collision)
- [x] On boot: restore peer_topo + REPL stream into node table
- [ ] Persist RTT EWMA samples in peer_topo (optional next)

### Phase F — Durability for large / crashy clusters

- [x] **Raft WAL + snapshots** in LMDB DBI `__dislmdb_raft__` (hard state, per-index entries, snap meta)
- [x] Load WAL before `raft_start`; checkpoint → snapshot + compact (`log_base`)
- [x] IT: `test_raft_wal` (reopen restores term/commit; post-reopen propose)
- [x] Configurable sync: `raft_wal_sync_every` (1 = every append; 0 = checkpoint/close only; hard-state always syncs)
- [x] InstallSnapshot RPC (metadata): align `log_base` when follower `last_applied >= included`; reject if FSM dump still needed
- [x] Chaos IT: `test_raft_wal_chaos` (checkpoint → kill leader → reelect → revive → catch-up)
- [x] Full FSM blob on InstallSnapshot: `kv` DBI dump/restore hooks (`raft_set_fsm_hooks`)
- [ ] Expand FSM snapshot beyond `kv` (multi-DBI / unnamed)

### Phase G — Concurrency (supports Phases A–B)

- [x] Raft inbound queue: ELECTION + SYNC_REQUEST handled off the net thread
- [x] mTLS handshake worker pool (`handshake_workers`, default 2; inline fallback)
- [ ] Parallel per-peer send without starving net-thread RX
- [ ] io_uring / kqueue path where available
- [ ] Full QUIC / WebTransport (TLS 1.3 over UDP) atop DQGM

---

## Implementation order (recommended)

1. **A** dynamic peer tables (uncap arrays) + tests past 64  
2. **C** env region/locality/secrets + nearest dial  
3. **E** topo DBI in LMDB  
4. **D** mirror vs shard modes wired to topo  
5. **B** regional Raft groups (drop global full mesh)  
6. **F** Raft WAL/snapshots  
7. **G** I/O parallelism + QUIC  

## Smaller follow-ups

- [ ] Migrate remaining `raft_*` ITs onto `it_cluster.h`
- [ ] Commit / push session work
- [ ] Full QUIC stack (also under Phase G)

## Done this pass (reference)

- Raft/PBFT membership, leave, view-change, shard map, op status  
- DQGM v3, peer-restart, outbox, BOTH+mTLS flake fixes  
- Test expansion: matrix, connect_churn, auth_reject, chaos spawn/kill, check-stress  
- Env topo + soft uncap; growable net connections + Raft peer heap; `test_topo_env` /
  `test_raft_peer_growth`
- Raft WAL + safe compact + InstallSnapshot (meta) + `test_raft_wal_chaos`
- Heartbeat catch-up fix; voter vs learner AE lanes (`learner_ae_ms`)
- Shard owner forward RPC (`dislmdb_topo_forward_put`/`_del`, `test_topo_forward`)
- InstallSnapshot FSM dump/restore for `kv` (`raft_set_fsm_hooks`)
- Phase G: Raft inbound queue (ELECTION/SYNC off net thread)
- Phase G: mTLS handshake worker pool (`network.handshake_workers`)
