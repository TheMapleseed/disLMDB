# DisLMDB TODO

Last updated: 2026-11-11

## Status

Working system: Raft + Enhanced-PBFT, TCP/UDP/BOTH/QUIC, mTLS 1.3, DQGM v3, shard map,
leave/membership, outbox, ACL, bytecode compress, sandbox/integration/orb lanes green.

Membership/network peer tables are **heap-growable**; `DISLMDB_MAX_NODES` is an initial
size hint only. Soft cap via `max_peers` / `DISLMDB_MAX_PEERS` (0 = unlimited). Regional
Raft + learners (Phase B) bound voter fan-out; latency / RTT budgets still apply.

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

## Roadmap — uncapped scale + regional membership

### Phase A — Remove hard caps (dynamic structures)

Goal: membership/network grow with topology; only latency/RTT budgets constrain size.

- [x] Replace fixed arrays (`connections`, Raft peer/index tables) with growable heap
- [x] Cap policy becomes **soft**: `max_peers` / `DISLMDB_MAX_PEERS` (0 = unlimited)
- [x] Persist replica set without fixed N packing limits (REPL v2 length-prefixed stream)
- [x] Unit: `test_raft_peer_growth` past 64; IT: `test_topo_env`
- [x] Rig soak spawn to N≫64 (`test_raft_peer_growth` 512 peers)

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
- [x] Auto-forward inside `dislmdb_put`/`dislmdb_del` when write-gated (`enable_auto_forward`, default on; requires connected owner)
- [x] Proxy/redirect reads: `dislmdb_topo_forward_get` / `dislmdb_topo_get` (FWD_OP_GET)
- [x] Orb scenarios for mirror vs shard across “fake regions” (`region_mirror` + `DISLMDB_REGION` in `run_orb.sh`)
- [x] Explicit conflict policy for mirror (`DISLMDB_MIRROR_LAST_WRITE` / `REGION_PRIORITY` + primary region)

### Phase E — Dedicated DB namespace for regional metadata

Store topology in LMDB (not only env), so peers learn maps after join:

- [x] Meta plane `peer_topo`: id + region/locality/host/port per peer (+ local region fields)
- [x] Replicate topo updates via consensus (`dislmdb_topo_map_publish` / TOPO blob)
- [x] Stored under meta DBI key `peer_topo` (apps use named DBI / avoid collision)
- [x] On boot: restore peer_topo + REPL stream into node table
- [x] Persist RTT EWMA samples in peer_topo (v2 records + restore via `set_rtt_ewma`)

### Phase F — Durability for large / crashy clusters

- [x] **Raft WAL + snapshots** in LMDB DBI `__dislmdb_raft__` (hard state, per-index entries, snap meta)
- [x] Load WAL before `raft_start`; checkpoint → snapshot + compact (`log_base`)
- [x] IT: `test_raft_wal` (reopen restores term/commit; post-reopen propose)
- [x] Configurable sync: `raft_wal_sync_every` (1 = every append; 0 = checkpoint/close only; hard-state always syncs)
- [x] InstallSnapshot RPC (metadata): align `log_base` when follower `last_applied >= included`; reject if FSM dump still needed
- [x] Chaos IT: `test_raft_wal_chaos` (checkpoint → kill leader → reelect → revive → catch-up)
- [x] Full FSM blob on InstallSnapshot: `kv` DBI dump/restore hooks (`raft_set_fsm_hooks`)
- [x] Expand FSM snapshot beyond `kv` (unnamed + all non-`__*` named DBIs)

### Phase G — Concurrency (supports Phases A–B)

- [x] Raft inbound queue: ELECTION + SYNC_REQUEST handled off the net thread
- [x] mTLS handshake worker pool (`handshake_workers`, default 2; inline fallback)
- [x] Fair multi-peer outbox drain (round-robin, capped) — net-safe; no RX-starving worker join
- [x] Net thread uses `poll()` (past `FD_SETSIZE`); per-fd wait helpers on `poll` too
- [x] Darwin/BSD `kqueue` wait path (EV_ONESHOT rebuild; poll fallback)
- [x] Linux `io_uring` POLL_ADD wait backend (`dislmdb_iouring_*`); net thread prefers it on Linux
- [x] QUIC substrate: long-header parse/encode, CID map, version-negotiation on UDP probes
- [x] `dislmdb_quic_stack_ready()` gates `TRANSPORT_QUIC` open (fail closed); unit `test_quic_substrate`
- [x] QUIC Initial: HKDF secrets, AES-128-GCM AEAD, AES-ECB header protection, CRYPTO frames
- [x] QUIC TLS 1.3 ClientHello/ServerHello + X25519 + Handshake/1-RTT key schedule
- [x] QUIC Certificate/Finished verify + Handshake-plane AEAD packet path (open still gated)
- [x] QUIC CertificateVerify (ECDSA P-256) encode/sign/verify
- [x] QUIC server Initial driver on UDP path (SH + Handshake crypto flight)
- [x] QUIC client handshake complete + 1-RTT short-header CRYPTO AEAD
- [x] QUIC server session table on net thread (Initial store + 1-RTT open)
- [x] 1-RTT CRYPTO → DQGM framed receive path + `client_start` dial helper
- [x] QUIC 1-RTT send path (DQGM wrap when session exists)
- [x] Client dial on net connect path + flip `stack_ready`
- [x] QUIC CA/PKI CertificateVerify (X.509 PEM / self-signed; TOFU without CA)

### Phase H — Product surface (post scale/QUIC)

- [x] `DISLMDB_BYTECODE_COMPRESS` (zlib store/get; VERIFY hashes plaintext)
- [x] Access-control layer (enable_acl + principal grants; put/write/admin gates)
- [x] Language bindings (`bindings/ABI.kdl` + pkg-config + Rust crate `bindings/rust`)
- [x] Metrics: sidecar-only forever (`dislmdb_format_metrics`; no embedded scrape HTTP)
- [x] QUIC IT: multi-node `TRANSPORT_QUIC` Raft smoke (`test_raft_quic`, 2-node)

### Phase I — Harden product surface

- [x] Persist ACL grants in meta DBI across reopen (`acl_grants`; `test_acl` reopen)
- [x] Ignore IT leftover dirs in `.gitignore` (`it_*`, cert scratch)
- [x] README/TODO status honesty after Phase H
- [x] QUIC 3-node Raft IT (`test_raft_quic` mesh + compress bytecode)
- [ ] Optional: commit / push Phase H+I session work (when asked)

### Phase J — System-wide test coverage

Goal: close gaps so unit/IT/e2e exercise the full product surface (not only happy paths).

- [x] Soft `max_peers` reject (`add_node` / `reconfigure` / open) — `test_system_surface`
- [x] `DISLMDB_VOTING=off` + live metrics/format + multi named-DBI persist
- [x] Mirror `LAST_WRITE` vs `REGION_PRIORITY` (`test_topo_modes` + system surface)
- [x] Raft hub + non-voting learner AE IT (`test_raft_learner`)
- [x] WAL `raft_wal_sync_every=0` + named DBI across checkpoint/reopen (`test_raft_wal`)
- [x] QUIC strict-CA reject vs TOFU (`test_quic_substrate`)
- [x] E2E ACL + topo getters (`04_acl_topo`)
- [ ] Optional: commit / push Phase J coverage (when asked)

---

## Implementation order (recommended)

1. **A** dynamic peer tables (uncap arrays) + tests past 64  
2. **C** env region/locality/secrets + nearest dial  
3. **E** topo DBI in LMDB  
4. **D** mirror vs shard modes wired to topo  
5. **B** regional Raft groups (drop global full mesh)  
6. **F** Raft WAL/snapshots  
7. **G** I/O parallelism + QUIC  
8. **H** bytecode compress → ACL → bindings → scrape  
9. **I** ACL persist → hygiene → optional QUIC 3-node  
10. **J** system-wide test coverage expansion  

## Smaller follow-ups

- [x] Migrate integration `raft_*` ITs onto `it_cluster.h` (tcp/udp/both/mtls/fault/stage/membership/leave)
- [x] Commit / push session work (Phase G QUIC + I/O)
- [x] QUIC cert/Finished + Handshake packet AEAD (CH/SH + key schedule shipped)
- [x] QUIC CertificateVerify (ECDSA P-256)
- [x] Wire QUIC server Initial reply into net UDP path
- [x] Client complete handshake + 1-RTT short-header packets
- [x] Net-thread QUIC session table (server)
- [x] DQGM-over-1-RTT receive + client_start
- [x] QUIC 1-RTT send (DQGM wrap when session exists)
- [x] Wire client dial into connect + flip `stack_ready`
- [x] QUIC X.509 CertificateVerify (PEM load + self-signed + RSA/ECDSA)

## Done this pass (reference)

- Raft/PBFT membership, leave, view-change, shard map, op status  
- DQGM v3, peer-restart, outbox, BOTH+mTLS flake fixes  
- Test expansion: matrix, connect_churn, auth_reject, chaos spawn/kill, check-stress  
- Env topo + soft uncap; growable net connections + Raft peer heap; `test_topo_env` /
  `test_raft_peer_growth`
- Raft WAL + safe compact + InstallSnapshot (meta) + `test_raft_wal_chaos`
- Heartbeat catch-up fix; voter vs learner AE lanes (`learner_ae_ms`)
- Shard owner forward RPC (`dislmdb_topo_forward_put`/`_del`, `test_topo_forward`)
- Auto-forward in `dislmdb_put`/`del` (`enable_auto_forward`, connected owner)
- Shard read proxy (`dislmdb_topo_get` / `forward_get`, FWD_OP_GET)
- Multi-DBI FSM snapshot; fair outbox drain; peer_topo RTT v2; mirror region_priority
- Orb fake-region scenario; Raft peer soak 512; QUIC transport reserved
- Net thread `poll()` (no `select`/`FD_SETSIZE`); mTLS wait on `poll` too
- Darwin/BSD `kqueue` net wait (ONESHOT); integration `raft_*` ITs on `it_cluster.h`
- QUIC open fail-closed + `lmdb_opened` so failed `env_open` is safely closeable
- QUIC substrate module + UDP version-negotiation responder; `test_quic_substrate`
- QUIC Initial AEAD/HP/CRYPTO + TLS1.3 CH/SH + HS/1-RTT keys; Linux io_uring wait
- QUIC EE/Certificate/Finished verify + Handshake long-header AEAD/HP packet path
- QUIC CertificateVerify (ECDSA-P256-SHA256) sign/verify + content builder
- QUIC `server_handle_initial` + UDP hook; TRANSPORT_QUIC opens UDP when ready
- QUIC client_complete_handshake + 1-RTT short-header build/open
- QUIC server session table on UDP path (store after Initial, open 1-RTT)
- 1-RTT CRYPTO → DQGM framed RX; `dislmdb_quic_client_start`
- QUIC client dial on connect; `stack_ready` true (ephemeral ECDSA CV)
- QUIC X.509 CertificateVerify (PEM / self-signed; strict CA when configured)
- `DISLMDB_BYTECODE_COMPRESS` zlib pack/unpack + VERIFY-on-plaintext; `-lz`
- QUIC simultaneous-open tie-break + Initial retransmit; `test_raft_quic`
- ACL `enable_acl` + grant/revoke/require; `test_acl`
- Metrics scrape: documented sidecar-only (no in-process HTTP)
- Bindings: `ABI.kdl` + `dislmdb.pc.in` + Rust `bindings/rust` (`make rust-bindings`)
- Test coverage: ACL admin/bytecode/off; compress probe/overflow/big; Raft TCP+QUIC
  compress apply; matrix `quic` cell; e2e `opts=compress,verify`
- ACL grant table persisted in meta (`acl_grants`) + reopen IT
- InstallSnapshot FSM dump/restore for `kv` (`raft_set_fsm_hooks`)
- Phase G: Raft inbound queue (ELECTION/SYNC off net thread)
- Phase G: mTLS handshake worker pool (`network.handshake_workers`)
- Phase J: system_surface + raft_learner + e2e ACL/topo; QUIC CA/TOFU
- Close-path deadlock fix: unlock around Raft apply; persist snapshot before LMDB;
  raft_sync_peers without holding nodes_mutex across raft_add_*
