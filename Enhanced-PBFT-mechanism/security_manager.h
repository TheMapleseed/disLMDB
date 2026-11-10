/**
 * @file security_manager.h
 * @brief Consensus digests via Time-Variant BLAKE3 (Rust Enhanced-PBFT SecurityManager)
 */

#ifndef EPDFT_SECURITY_MANAGER_H
#define EPDFT_SECURITY_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "time_variant_blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECURITY_DIGEST_LEN 32

typedef struct SecurityConfig {
    TimeVariantBlake3Config tvb3;
} SecurityConfig;

typedef struct SecurityManager {
    TimeVariantBlake3Config tvb3;
} SecurityManager;

SecurityConfig security_config_default(void);
SecurityManager *security_manager_create(const SecurityConfig *config);
void security_manager_destroy(SecurityManager *sm);

/** PBFT request digest: TV-B3 IV from (view, sequence), then BLAKE3(IV || data). */
void security_manager_hash_consensus(SecurityManager *sm,
                                     uint64_t view,
                                     uint64_t sequence,
                                     const uint8_t *data,
                                     size_t size,
                                     uint8_t out[SECURITY_DIGEST_LEN]);

/** Convenience: hash_consensus(0, 0, data) */
void security_manager_hash(SecurityManager *sm,
                           const uint8_t *data,
                           size_t size,
                           uint8_t out[SECURITY_DIGEST_LEN]);

bool security_manager_digest_eq(const uint8_t a[SECURITY_DIGEST_LEN],
                                const uint8_t b[SECURITY_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_SECURITY_MANAGER_H */
