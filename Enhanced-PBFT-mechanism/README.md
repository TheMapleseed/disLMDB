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

### Proper compression binding (TeX §4)

The paper defines \(G'(h,m,t)=G(h\oplus IV(t), m, t)\). Digests use that binding: the BLAKE3 chaining value is initialized to `BLAKE3_IV ⊕ TV-IV(view,seq)`, then the payload is hashed (not the older `BLAKE3(IV‖payload)` approximation; that remains as `tvb3_hash_payload_prefixed` for comparison tests).

### Wire authenticity

When a shared cluster key is installed, every PBFT message carries a **keyed TV-BLAKE3 MAC** (`auth`): BLAKE3 keyed mode with key-words XOR'd by the same TV-IV, over a canonical encoding of `(type, from, view, seq, digest, last_stable, data)`. `verify_signatures` rejects inbound messages with a missing or bad MAC once a key is present.

## Files

- `blake3_ref.c` / `.h` — BLAKE3 reference hasher (incl. keyed / derive_key / CV-XOR init)
- `time_variant_blake3.c` / `.h` — IV pipeline, proper `hash_payload`, `tvb3_mac`
- `security_manager.c` / `.h` — digests + PBFT sign/verify
- `epdft.c` / `.h` — `ConsensusCore` state machine
- `messaging.c` / `.h` — commit fan-out channel
