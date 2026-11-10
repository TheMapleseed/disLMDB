# Sandbox-safe multi-node test rigs

Cursor’s agent sandbox blocks LMDB `mmap`, so full `DISLMDB_env` integration
tests fail with `Operation not permitted` even when the code is fine.

## Layout

| Piece | Role |
| --- | --- |
| `cluster_rig.{h,c}` | Shared in-memory cluster: KV + Raft + message bus + kill/revive |
| `test_cluster_rig` | Scenarios: multinode, UDP substrate, **mixed** signal/data lanes, Raft elect, f=1 |
| `test_mtls_tcp_rig` | Real TCP + mTLS 1.3 (no LMDB) |
| `test_raft_bus_rig` | Focused 3-node Raft bus (subset of cluster_rig) |

`cluster_rig` is the stand-in for `tests/integration/test_{multinode,udp,raft_udp,fault_tolerance,mtls_cluster}` **logic** (consensus + replicate + fault). mTLS crypto stays on the dedicated TCP rig; LMDB durability stays on `make check-integration`.

```bash
make check-sandbox        # unit + all rigs — safe in agent sandbox
make check-integration    # real LMDB cluster/e2e — normal shell only
make check-orb            # OrbStack/Docker: join, spawn, shard-prefix
make check                # sandbox + integration (orb is opt-in)
```

For process-per-node join/spawn against real LMDB, see [`tests/orb/`](../orb/).
