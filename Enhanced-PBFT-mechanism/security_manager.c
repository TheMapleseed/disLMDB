/**
 * @file security_manager.c
 * @brief Port of Enhanced-PBFT Rust security.rs
 */

#include "security_manager.h"

#include <stdlib.h>
#include <string.h>

SecurityConfig security_config_default(void)
{
    SecurityConfig cfg;
    cfg.tvb3 = tvb3_config_default();
    return cfg;
}

SecurityManager *security_manager_create(const SecurityConfig *config)
{
    SecurityManager *sm = calloc(1, sizeof(*sm));
    if (!sm) {
        return NULL;
    }
    sm->tvb3 = config ? config->tvb3 : tvb3_config_default();
    return sm;
}

void security_manager_destroy(SecurityManager *sm)
{
    free(sm);
}

void security_manager_hash_consensus(SecurityManager *sm,
                                     uint64_t view,
                                     uint64_t sequence,
                                     const uint8_t *data,
                                     size_t size,
                                     uint8_t out[SECURITY_DIGEST_LEN])
{
    ConsensusTemporal t = {.view = view, .sequence = sequence};
    tvb3_hash_payload(t, sm ? &sm->tvb3 : NULL, data, size, out);
}

void security_manager_hash(SecurityManager *sm,
                           const uint8_t *data,
                           size_t size,
                           uint8_t out[SECURITY_DIGEST_LEN])
{
    security_manager_hash_consensus(sm, 0, 0, data, size, out);
}

bool security_manager_digest_eq(const uint8_t a[SECURITY_DIGEST_LEN],
                                const uint8_t b[SECURITY_DIGEST_LEN])
{
    if (!a || !b) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < SECURITY_DIGEST_LEN; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}
