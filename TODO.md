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
- [ ] Persist replica set without fixed N packing limits (length-prefixed stream)
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

- [ ] **Local Raft group per region** (voters = regional peers only)
- [ ] **Cross-region**: async mirror *or* sharded ownership (config mode)
- [ ] Prefer nearest peer: RTT probe + region affinity for dial/HELLO
- [ ] Heartbeats / AE only inside the local voter set; cross-region on a separate lane

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
- [ ] Derive traffic keys per plane (local vs cross) — fail closed on mismatch
  (extends `test_auth_reject`)
- [x] Nearest-peer selection (v1): `node_addr.region/locality` + dial backoff prefers
      same region/locality (RTT probe still TODO)
- [ ] RTT EWMA probe tied to `DISLMDB_RTT_BUDGET_MS` admit/reject
- [ ] Auto-register cross-region peers as learners when `DISLMDB_VOTING=off` on the edge
- [ ] Document secret rotation without full cluster outage

### Phase D — Topology modes: mirror vs shard

- [ ] **`mirror`**: every region holds full KV; cross-region async replicate
      (eventual; conflict policy explicit — last-write / region priority)
- [ ] **`shard`**: key → region/owner via shard map (existing `dislmdb_shard_map_*`);
      redirects / proxy reads to owner region
- [ ] **`hybrid`**: hot prefixes mirrored; cold prefixes sharded
- [ ] Orb scenarios for mirror vs shard across “fake regions” (containers + env)

### Phase E — Dedicated DB namespace for regional metadata

Store topology in LMDB (not only env), so peers learn maps after join:

- [ ] Meta / dedicated DBI e.g. `dislmdb_topo`:
      region id, locality, endpoints, RTT EWMA, mode, generation
- [ ] Replicate topo updates via consensus (SMAP-like `TOPO` opcode) or regional
      gossip with signed envelopes
- [ ] Optional: reserve key-prefix `~topo/` or named DBI so apps never collide
- [ ] On boot: env secrets seed → merge with persisted topo → dial nearest

### Phase F — Durability for large / crashy clusters

- [ ] **Raft WAL + snapshots** to LMDB or sidecar log (term, vote, log entries)
- [ ] Configurable sync: sync-every-N / group-commit / NOSYNC+cooldown timer
- [ ] Catch-up from snapshot + WAL after regional rejoin
- [ ] Chaos IT: kill leader mid-commit; verify no silent divergence after WAL

### Phase G — Concurrency (supports Phases A–B)

- [ ] Net thread = bytes only; handshake + consensus on worker pool
- [ ] Parallel per-peer send (pipelined AE)
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
