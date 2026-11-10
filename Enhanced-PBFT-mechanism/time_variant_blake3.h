/**
 * @file time_variant_blake3.h
 * @brief Time-Variant BLAKE3 IV + payload digest (TeX / Enhanced-PBFT Rust port)
 *
 * Spec: https://github.com/TheMapleseed/Time-VariantBlake3
 * Implementation aligned with Enhanced-PBFT-mechanism (Rust) time_variant_blake3.rs
 *
 * For PBFT agreement, timestamps are derived deterministically from (view, sequence).
 */

#ifndef EPDFT_TIME_VARIANT_BLAKE3_H
#define EPDFT_TIME_VARIANT_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

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

/** t_i for i in 1..8 (paper index). Returns 0 and sets errno-like via out_ok=false if i invalid. */
uint64_t tvb3_t_i(ConsensusTemporal temporal, uint8_t i);

/** IV ∈ F_2^32 ^ 8 */
void tvb3_iv_words(ConsensusTemporal temporal,
                   const TimeVariantBlake3Config *cfg,
                   uint32_t out_iv[8]);

/** BLAKE3(IV_bytes || payload) — consensus digest */
void tvb3_hash_payload(ConsensusTemporal temporal,
                       const TimeVariantBlake3Config *cfg,
                       const uint8_t *payload,
                       size_t payload_len,
                       uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_TIME_VARIANT_BLAKE3_H */
