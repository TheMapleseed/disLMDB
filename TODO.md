# DisLMDB TODO

Last updated: 2026-11-10

## Open (blocking full `make check-integration`)

_None._

## Green (do not regress)

| Lane | Status |
| --- | --- |
| `make check-sandbox` | Pass |
| `make check-integration` | Pass |
| `make check-orb` | Pass |
| PBFT / Raft matrix + leave / membership / shard | Pass |
| DQGM v3 + CID rebind + pkt_num + cumulative ACK + stats | Pass |
| Op status ring + `get_last_op_id` | Pass |
| PBFT view-change IT | Pass |
| Makefile `-MMD` header deps | Pass |
| UDP peer-restart catch-up | Pass |

## Done this pass

- [x] Raft / PBFT membership, leave, view-change, shard map, op status
- [x] DQGM v2 packet numbers + peer CID bind
- [x] **DQGM session rebind** — `CID_RESET` / `pkt_num==1` rebinds after peer restart
- [x] **Makefile header deps** (`-MMD -MP`)
- [x] **DQGM counters on `DISLMDB_metrics`**
- [x] **UDP peer-restart catch-up** — pure-UDP revive (not BOTH); HELLO re-engage; IT
- [x] **`make check-orb`** — replicate + join_spawn + shard_affinity
- [x] **DQGM v3 cumulative ACK** — `ack_num` in envelope; `dqgm_ack_rx` / `dqgm_ack_advance`
- [x] Header `-Wnewline-eof` fixes (`dislmdb_network.h`, `dislmdb_internal.h`, `dislmdb_consensus.h`)

## Still unfinished — product / deferred

- [ ] **Full QUIC / WebTransport stack** — TLS 1.3 over UDP (ngtcp2/quiche); DQGM is framing + CID + pkt_num + ACK + rebind + peer-restart
- [ ] **raft_mtls occasional CONSENSUS_FAILED (1008)** — intermittent under sequential suite load; usually green on retry

## Hygiene

- [ ] Commit / push session work (local changes uncommitted)
