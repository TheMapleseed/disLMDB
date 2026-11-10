# Enhanced PBFT mechanism (C port)

C23 port of [TheMapleseed/Enhanced-PBFT-mechanism](https://github.com/TheMapleseed/Enhanced-PBFT-mechanism) for DisLMDB.

## Alignment with the Rust original

| Component | Source |
|-----------|--------|
| PBFT phases | `pre-prepare` → `prepare` → `commit`, quorum `2f+1`, reduced view-change |
| Digests | **Time-Variant BLAKE3** over `(view, sequence)` IV ∥ payload |
| BLAKE3 | In-tree reference (BLAKE3-team reference_impl, CC0) |
| Transport | Not included — DisLMDB network layer + optional HMAC framing |

## Time-Variant BLAKE3

Specification: [TheMapleseed/Time-VariantBlake3](https://github.com/TheMapleseed/Time-VariantBlake3) (TeX/PDF).

Consensus profile uses **deterministic** timestamps derived from `(view, sequence)` so all honest replicas compute the same digest (safety does not depend on wall-clock time).

## Files

- `blake3_ref.c` / `.h` — BLAKE3 reference hasher
- `time_variant_blake3.c` / `.h` — IV pipeline + `hash_payload`
- `security_manager.c` / `.h` — `hash_consensus(view, sequence, data)`
- `epdft.c` / `.h` — `ConsensusCore` state machine
- `messaging.c` / `.h` — commit fan-out channel
