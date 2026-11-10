# DisLMDB TODO

Last updated: 2026-11-10

## Open (blocking full `make check-integration`)

_None._

## Green (do not regress)

| Lane | Status |
| --- | --- |
| `make check-sandbox` | Pass |
| `make check-integration` | Pass |
| PBFT / Raft matrix + leave / membership / shard | Pass |
| DQGM v2 envelope + CID bind + pkt_num replay drop | Pass |
| Op status ring + `get_last_op_id` | Pass |
| PBFT view-change IT (`test_pbft_viewchange`) | Pass |
| `make smoke-example` | Pass |

## Done this pass

- [x] Raft joint-consensus membership + reconfigure
- [x] Native shard map + SMAP consensus
- [x] Graceful LEAVE + Raft shrink / view-change triggers
- [x] Op status ring + `get_last_op_id`
- [x] DQGM peer CID bind/validate
- [x] **DQGM v2 packet numbers** — outbound counter, receive replay/stale drop; v1 still accepted
- [x] PBFT view-change IT

## Still unfinished — product / deferred

- [ ] **Full QUIC / WebTransport stack** — TLS 1.3 over UDP (ngtcp2/quiche); DQGM is framing + CID + pkt_num only
- [ ] **Confirm `make check-orb`** when Docker/OrbStack daemon is available (currently stopped)

## Hygiene

- [ ] Commit / push session work (local changes uncommitted)
- [ ] Makefile header deps (stale `.o` after `DISLMDB_env` layout changes can silently corrupt fields)
