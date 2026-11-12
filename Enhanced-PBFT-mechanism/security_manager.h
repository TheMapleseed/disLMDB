/**
 * @file security_manager.h
 * @brief Consensus digests + TV-BLAKE3 MACs (proper TeX §4 binding)
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
#define SECURITY_AUTH_LEN   32

typedef struct SecurityConfig {
    TimeVariantBlake3Config tvb3;
    uint8_t cluster_key[32];
    bool has_cluster_key;
} SecurityConfig;

typedef struct SecurityManager {
    TimeVariantBlake3Config tvb3;
    uint8_t cluster_key[32];
    uint8_t mac_key[32]; /**< derived via blake3_derive_key */
    bool has_cluster_key;
} SecurityManager;

SecurityConfig security_config_default(void);
SecurityManager *security_manager_create(const SecurityConfig *config);
void security_manager_destroy(SecurityManager *sm);

/** Install / rotate the shared cluster key (derives MAC key). */
void security_manager_set_cluster_key(SecurityManager *sm, const uint8_t key[32]);

bool security_manager_has_key(const SecurityManager *sm);

/** PBFT request digest: CV = BLAKE3_IV ⊕ TV-IV(view,seq), then payload. */
void security_manager_hash_consensus(SecurityManager *sm,
                                     uint64_t view,
                                     uint64_t sequence,
                                     const uint8_t *data,
                                     size_t size,
                                     uint8_t out[SECURITY_DIGEST_LEN]);

bool security_manager_digest_eq(const uint8_t a[SECURITY_DIGEST_LEN],
                                const uint8_t b[SECURITY_DIGEST_LEN]);

/**
 * MAC over canonical PBFT fields (type, from, view, seq, digest, last_stable, data).
 * Requires cluster key. Returns false if no key configured.
 */
bool security_manager_sign_pbft(SecurityManager *sm,
                                uint8_t type,
                                const char *from,
                                uint64_t view,
                                uint64_t sequence,
                                const uint8_t digest[SECURITY_DIGEST_LEN],
                                uint64_t last_stable_seq,
                                const uint8_t *data,
                                size_t data_len,
                                uint8_t out_auth[SECURITY_AUTH_LEN]);

bool security_manager_verify_pbft(SecurityManager *sm,
                                  uint8_t type,
                                  const char *from,
                                  uint64_t view,
                                  uint64_t sequence,
                                  const uint8_t digest[SECURITY_DIGEST_LEN],
                                  uint64_t last_stable_seq,
                                  const uint8_t *data,
                                  size_t data_len,
                                  const uint8_t auth[SECURITY_AUTH_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_SECURITY_MANAGER_H */
