# OrbStack / Docker multi-node lane

Real LMDB (`mmap`), real peer TCP, real process-per-node. Use this for
**join**, **spawn**, **replicate**, and **shard-prefix** scenarios that the
in-process sandbox `cluster_rig` cannot cover.

Requires [OrbStack](https://orbstack.dev) or Docker. Not run inside the Cursor
agent sandbox.

## Layout

| Piece | Role |
| --- | --- |
| `cluster.kdl` | Topology + scenarios (source of truth; no YAML) |
| `node_agent.c` | DisLMDB node + test admin TCP (`PUT`/`GET`/`JOIN`/…) |
| `orb_ctl.c` | Admin client |
| `Dockerfile` | Linux image (`OpenSSL` + Mbed TLS mTLS stack) |
| `run_orb.sh` | Build → network → nodes → scenarios → teardown |

## Commands

```bash
# From repo root (OrbStack / Docker available)
make orb-bins          # host ctl (optional) + agent for image build context
make check-orb         # full container cluster scenarios (default transport=both)
DISLMDB_ORB_TRANSPORT=tcp  make check-orb
DISLMDB_ORB_TRANSPORT=udp  make check-orb
./tests/orb/run_orb.sh build
./tests/orb/run_orb.sh cleanup
./tests/orb/run_orb.sh keep   # leave containers up after pass
```

`both` listens on TCP + UDP: HELLO/HEARTBEAT/ELECTION prefer UDP; consensus data prefers TCP, each falling back if needed.

Admin ports on the host: `n0=29876`, `n1=29877`, `n2=29878`, `n3=29879`.

```bash
./build/bin/orb_ctl 127.0.0.1:29876 STATUS
./build/bin/orb_ctl 127.0.0.1:29876 PUT k v
```

## Three-lane test system

| Lane | Target | What it proves |
| --- | --- | --- |
| `make check-sandbox` | Agent / CI without mmap | Consensus logic, mTLS crypto, fault bus |
| `make check-integration` | Host with mmap | LMDB durability, HELLO, in-process multi-env |
| `make check-orb` | OrbStack/Docker | Join, spawn, cross-host TCP, shard-prefix reads |

`make check` stays sandbox + host integration. Orb is opt-in until CI has Docker.

## Sharding note

`shard_affinity` uses a **key-prefix convention** (`shardA/…`, `shardB/…`) until a
native shard map API exists. Join/spawn already exercise `dislmdb_add_node` and
live container lifecycle.
