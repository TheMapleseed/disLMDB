/**
 * @file time_variant_blake3.h
 * @brief Time-Variant BLAKE3 per TheMapleseed/Time-VariantBlake3 (TeX)
 *
 * Digests use the paper's compression binding:
 *   G'(h, m, t) = G(h ⊕ IV(t), m, t)
 * (chaining value XOR'd with the TV-IV, then BLAKE3 over the payload).
 *
 * Message authentication uses keyed BLAKE3 with the same IV XOR into the
 * keyed chaining value (cluster-secret MAC for PBFT wire authenticity).
 */

#ifndef EPDFT_TIME_VARIANT_BLAKE3_H
#define EPDFT_TIME_VARIANT_BLAKE3_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TimeVariantBlake3Config {
    uint64_t nu_cpu_hz; /**< ν_cpu in Hz (§1.1); default 3e9 */
} TimeVariantBlake3Config;

typedef struct ConsensusTemporal {
    uint64_t view;
    uint64_t sequence;
} ConsensusTemporal;

TimeVariantBlake3Config tvb3_config_default(void);

/** t_i for i in 1..8 (paper index). Returns 0 if i invalid. */
uint64_t tvb3_t_i(ConsensusTemporal temporal, uint8_t i);

/** IV ∈ F_2^32 ^ 8 */
void tvb3_iv_words(ConsensusTemporal temporal,
                   const TimeVariantBlake3Config *cfg,
                   uint32_t out_iv[8]);

/**
 * Proper consensus digest: BLAKE3 with CV = BLAKE3_IV ⊕ TV-IV(t), then payload.
 * Matches TeX §4 (not the IV‖payload prefix approximation).
 */
void tvb3_hash_payload(ConsensusTemporal temporal,
                       const TimeVariantBlake3Config *cfg,
                       const uint8_t *payload,
                       size_t payload_len,
                       uint8_t out[32]);

/**
 * Legacy prefix binding BLAKE3(IV_bytes ‖ payload) — for migration/tests only.
 */
void tvb3_hash_payload_prefixed(ConsensusTemporal temporal,
                                const TimeVariantBlake3Config *cfg,
                                const uint8_t *payload,
                                size_t payload_len,
                                uint8_t out[32]);

/**
 * Authenticate `msg` under `key` with keyed BLAKE3 whose key-words are
 * XOR'd with TV-IV(view,sequence). Output is a 32-byte MAC.
 */
void tvb3_mac(ConsensusTemporal temporal,
              const TimeVariantBlake3Config *cfg,
              const uint8_t key[32],
              const uint8_t *msg,
              size_t msg_len,
              uint8_t out[32]);

/** Constant-time MAC verify. */
bool tvb3_mac_verify(ConsensusTemporal temporal,
                     const TimeVariantBlake3Config *cfg,
                     const uint8_t key[32],
                     const uint8_t *msg,
                     size_t msg_len,
                     const uint8_t expect[32]);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_TIME_VARIANT_BLAKE3_H */
