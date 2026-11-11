# DisLMDB: Distributed Lightning Memory-Mapped Database

DisLMDB extends [LMDB](https://symas.com/lmdb/) with multi-node replication: Raft or Enhanced-PBFT consensus, TCP/UDP/BOTH transports, mTLS 1.3, and HMAC/AEAD cluster crypto. Storage remains LMDB’s mmap’d B+tree; consensus logs are in-memory today (see durability notes below).

Proprietary software — The Mapleseed Inc. Commercial license required.

## What works today

| Area | Status |
| --- | --- |
| **Consensus** | Enhanced-PBFT and Raft (`DISLMDB_CONSENSUS_*`), joint-consensus membership, graceful leave |
| **Voting** | First-class; `DISLMDB_VOTING=off` / `enable_voting=false` → learner (no campaign / no vote grant) |
| **Transports** | TCP, UDP (DQGM v3: pkt_num, cumulative ACK, CID rebind, peer-restart), **BOTH** (UDP signalling + TCP data) |
| **Crypto** | Cluster key HMAC + AEAD payload encryption; portable mTLS 1.3 via vendored Mbed TLS |
| **Topology** | Env: `DISLMDB_REGION` / `LOCALITY` / `TOPOLOGY_MODE` / secrets / `MAX_PEERS`; persisted region + peer_topo; same-region dial preference |
| **Topo modes** | `mirror` (full replicate / learners), `shard` (owner write-gate; cross-region out of Raft), `hybrid` (`DISLMDB_SHARD_FLAG_MIRRORED`) |
| **Scale** | Heap-growable peer + connection tables; soft `max_peers` (0 = unlimited). Regional voters; voter HB vs learner AE lanes |
| **Shard map** | `dislmdb_shard_map_*` + SMAP v2 (flags); longest-prefix owner lookup; `dislmdb_topo_key_writable` |
| **Bytecode** | Consensus-replicated (or SOLO) store/get; `DISLMDB_BYTECODE_VERIFY` (SHA-256 on disk). Compress flag reserved (`NOT_IMPLEMENTED`) |
| **Metrics** | `dislmdb_get_metrics` + `dislmdb_format_metrics` (Prometheus text). Covers commits, consensus, Raft term/commit, DQGM, outbox |
| **Ops status** | `dislmdb_consensus_get_operation_status` / `get_last_op_id` via local oplog ring |
| **Discovery** | HELLO/JOIN mesh engage before Raft elections |

## Durability (honest)

| What | Durable? |
| --- | --- |
| User KV / LMDB pages | **Yes** — mmap + commit / `dislmdb_force_sync` / checkpoint |
| Meta (view, replicas, shard map, region) | **Yes** when `persist_state` |
| Raft log / hard state | **Yes** when `persist_state` — `__dislmdb_raft__` WAL + snapshot compact |
| PBFT view/seq | **Yes** when `persist_state` (meta DBI) |
| Network outbox / DQGM counters | RAM |

Local ACID properties of LMDB still apply per node. Cross-node linearizability depends on the consensus path completing before the client sees success.

## Not done / not claimed

- FSM InstallSnapshot beyond the `kv` DBI (hooks ship `kv` dump/restore today)
- Shard owner read proxy; auto-forward inside `dislmdb_put` (explicit `dislmdb_topo_forward_put`/`_del` shipped)
- `DISLMDB_BYTECODE_COMPRESS`
- Access-control layer / language bindings / full QUIC stack
- Built-in Prometheus HTTP scrape port (format text yourself and expose)

## Requirements

- C23 compiler (GCC 13+ or Clang 16+)
- Vendored Mbed TLS (`third_party/mbedtls`) for mTLS 1.3
- OpenSSL *libcrypto* (non-Apple) or Apple CommonCrypto
- `uuid` on Linux; POSIX OS
- Makefile primary; CMake 3.16+ optional

## Build & test

```bash
make                 # build + sandbox-safe suite
make check-sandbox   # unit + rigs (no LMDB mmap — agent/sandbox safe)
make check-integration
make check-orb       # Docker/OrbStack
make check           # sandbox + unit + integration
make lib
```

| Layer | Location | Role |
| --- | --- | --- |
| Unit | `tests/unit/` | Raft, crypto, metrics format, transport |
| Rig | `tests/rig/` | In-memory multi-node / fault (no LMDB mmap) |
| Integration | `tests/integration/` | LMDB cluster, mTLS, matrix, topo env |
| Orb | `tests/orb/` | Container join / shard |
| E2E | `tests/e2e/` | Scenario scripts vs golden outputs |

Agent sandboxes block LMDB `mmap` — use `check-sandbox` there; run `check-integration` on a normal host shell.

## Quick start (solo)

```c
#include <dislmdb.h>

int main(void) {
    DISLMDB_env *env = NULL;
    DISLMDB_env_config config;
    dislmdb_env_config_init(&config);
    config.path = "./testdb";
    config.mapsize = 10 * 1024 * 1024;
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;

    if (dislmdb_env_create(&env) || dislmdb_env_open(env, &config)) {
        return 1;
    }

    DISLMDB_txn *txn = NULL;
    if (dislmdb_txn_begin(env, NULL, 0, &txn)) {
        dislmdb_env_close(env);
        return 1;
    }
    MDB_dbi dbi;
    MDB_txn *mt = dislmdb_get_lmdb_txn(txn);
    mdb_dbi_open(mt, "kv", MDB_CREATE, &dbi);
    MDB_val k = {.mv_size = 5, .mv_data = "hello"};
    MDB_val v = {.mv_size = 5, .mv_data = "world"};
    mdb_put(mt, dbi, &k, &v, 0);
    dislmdb_txn_commit(txn);

    DISLMDB_metrics m;
    char buf[4096];
    size_t n = 0;
    dislmdb_get_metrics(env, &m);
    dislmdb_format_metrics(&m, buf, sizeof(buf), &n);
    /* ship buf to your scrape endpoint / log */

    dislmdb_env_close(env);
    return 0;
}
```

Multi-node deployments **must** set a shared cluster key (`dislmdb_set_cluster_key` / `network.has_cluster_key`) or open fails closed. Prefer Raft for crashy LANs; PBFT when Byzantine tolerance matters. See `examples/`.

## Topology env (large / regional fleets)

| Variable | Role |
| --- | --- |
| `DISLMDB_VOTING` | `on`/`off` — hubs vote; edges can be learners |
| `DISLMDB_REGION` / `DISLMDB_LOCALITY` | Affinity for dial preference + persist |
| `DISLMDB_REGION_SECRET` / `DISLMDB_CROSS_REGION_SECRET` | Intra- / inter-region key material |
| `DISLMDB_TOPOLOGY_MODE` | `mirror` (default) \| `shard` \| `hybrid` — gates writes + Raft peer role |
| `DISLMDB_MAX_PEERS` | Soft membership cap (`0` = unlimited) |
| `DISLMDB_RTT_BUDGET_MS` | Soft RTT budget (admit policy evolving) |
| `DISLMDB_SEED_REGIONAL` | Comma-separated `host:port` seeds |

### Secret rotation (no full outage)

Plane keys are process-local (`DISLMDB_REGION_SECRET` / `DISLMDB_CROSS_REGION_SECRET` or `dislmdb_network_set_plane_keys`). Rotate without a cluster restart by rolling nodes:

1. Deploy the **new** key as an additional candidate on receivers first (set both old and new via a short dual-key window — today the cross plane is a single key, so overlap means briefly configuring the new key cluster-wide before dropping the old).
2. Flip senders to the new key (`set_plane_keys` / env + process reload) region-by-region.
3. Remove the old key after every peer has advanced.

Mismatched cross-region keys fail closed (`plane_auth_fail`); intra-region traffic keeps using the region/cluster key. Prefer rotating **cross** keys before **region** keys so local quorum is undisturbed.

`dislmdb_topo_map_publish` replicates peer endpoints after join; `dislmdb_topo_resolve_owner` lets apps redirect shard writes when this node is not the owner.

## Architecture

1. **Core API** — LMDB transactions + distributed helpers (`include/dislmdb.h`)
2. **Consensus** — `Enhanced-Raft-mechanism/` or `Enhanced-PBFT-mechanism/` via adapters
3. **Network** — framed messages, DQGM UDP, outbox, mTLS (`src/network/`)
4. **Storage** — LMDB mmap + meta DBI persist (`src/utils/dislmdb_persist.c`)

## Metrics

```c
DISLMDB_metrics m;
dislmdb_get_metrics(env, &m);
/* m.raft_term, m.dqgm_packets_rx, m.outbox_dropped, … */

char text[8192];
size_t n = 0;
dislmdb_format_metrics(&m, text, sizeof(text), &n);
```

No embedded scrape HTTP server — expose `text` from your process supervisor or sidecar.

## Attribution

See [TRIBUTE_HOWARD_CHU.md](TRIBUTE_HOWARD_CHU.md).

## Roadmap

Tracked in [TODO.md](TODO.md): multi-DBI FSM snapshots, put auto-forward, parallel send (net-safe), QUIC / io_uring.

## License

Commercial proprietary — The Mapleseed Inc. Unauthorized use prohibited.  
Copyright 2025–2026 David Harmon, The Mapleseed Inc.

## Contributing

CLA required. Contact us before submitting contributions.
