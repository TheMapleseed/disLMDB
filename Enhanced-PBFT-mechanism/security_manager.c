/**
 * @file security_manager.c
 * @brief TV-BLAKE3 digests (TeX §4) + keyed MACs for PBFT messages
 */

#include "security_manager.h"
#include "blake3_ref.h"
#include "dislmdb_crypto.h"

#include <stdlib.h>
#include <string.h>

static const char *MAC_CONTEXT = "DisLMDB|Enhanced-PBFT|TV-B3-MAC|v1";

SecurityConfig security_config_default(void)
{
    SecurityConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.tvb3 = tvb3_config_default();
    return cfg;
}

static void refresh_mac_key(SecurityManager *sm)
{
    if (!sm->has_cluster_key) {
        memset(sm->mac_key, 0, sizeof(sm->mac_key));
        return;
    }
    blake3_derive_key(MAC_CONTEXT, sm->cluster_key, 32, sm->mac_key);
}

SecurityManager *security_manager_create(const SecurityConfig *config)
{
    SecurityManager *sm = calloc(1, sizeof(*sm));
    if (!sm) {
        return NULL;
    }
    sm->tvb3 = config ? config->tvb3 : tvb3_config_default();
    if (config && config->has_cluster_key) {
        memcpy(sm->cluster_key, config->cluster_key, 32);
        sm->has_cluster_key = true;
        refresh_mac_key(sm);
    }
    return sm;
}

void security_manager_destroy(SecurityManager *sm)
{
    if (sm) {
        memset(sm, 0, sizeof(*sm));
        free(sm);
    }
}

void security_manager_set_cluster_key(SecurityManager *sm, const uint8_t key[32])
{
    if (!sm || !key) {
        return;
    }
    memcpy(sm->cluster_key, key, 32);
    sm->has_cluster_key = true;
    refresh_mac_key(sm);
}

bool security_manager_has_key(const SecurityManager *sm)
{
    return sm && sm->has_cluster_key;
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

static size_t encode_pbft_mac_input(uint8_t type,
                                    const char *from,
                                    uint64_t view,
                                    uint64_t sequence,
                                    const uint8_t digest[SECURITY_DIGEST_LEN],
                                    uint64_t last_stable_seq,
                                    const uint8_t *data,
                                    size_t data_len,
                                    uint8_t **out)
{
    size_t from_len = from ? strnlen(from, 64) : 0;
    size_t total = 1 + 8 + 8 + 32 + 1 + from_len + 8 + 4 + data_len;
    uint8_t *buf = malloc(total);
    if (!buf) {
        *out = NULL;
        return 0;
    }
    size_t o = 0;
    buf[o++] = type;
    dislmdb_write_u64(buf + o, view); o += 8;
    dislmdb_write_u64(buf + o, sequence); o += 8;
    memcpy(buf + o, digest, 32); o += 32;
    buf[o++] = (uint8_t)from_len;
    if (from_len > 0) {
        memcpy(buf + o, from, from_len);
        o += from_len;
    }
    dislmdb_write_u64(buf + o, last_stable_seq); o += 8;
    dislmdb_write_u32(buf + o, (uint32_t)data_len); o += 4;
    if (data_len > 0 && data) {
        memcpy(buf + o, data, data_len);
        o += data_len;
    }
    *out = buf;
    return o;
}

bool security_manager_sign_pbft(SecurityManager *sm,
                                uint8_t type,
                                const char *from,
                                uint64_t view,
                                uint64_t sequence,
                                const uint8_t digest[SECURITY_DIGEST_LEN],
                                uint64_t last_stable_seq,
                                const uint8_t *data,
                                size_t data_len,
                                uint8_t out_auth[SECURITY_AUTH_LEN])
{
    if (!sm || !sm->has_cluster_key || !digest || !out_auth) {
        return false;
    }
    uint8_t *input = NULL;
    size_t n = encode_pbft_mac_input(type, from, view, sequence, digest,
                                     last_stable_seq, data, data_len, &input);
    if (!input) {
        return false;
    }
    ConsensusTemporal t = {.view = view, .sequence = sequence};
    tvb3_mac(t, &sm->tvb3, sm->mac_key, input, n, out_auth);
    free(input);
    return true;
}

bool security_manager_verify_pbft(SecurityManager *sm,
                                  uint8_t type,
                                  const char *from,
                                  uint64_t view,
                                  uint64_t sequence,
                                  const uint8_t digest[SECURITY_DIGEST_LEN],
                                  uint64_t last_stable_seq,
                                  const uint8_t *data,
                                  size_t data_len,
                                  const uint8_t auth[SECURITY_AUTH_LEN])
{
    if (!sm || !sm->has_cluster_key || !digest || !auth) {
        return false;
    }
    uint8_t *input = NULL;
    size_t n = encode_pbft_mac_input(type, from, view, sequence, digest,
                                     last_stable_seq, data, data_len, &input);
    if (!input) {
        return false;
    }
    ConsensusTemporal t = {.view = view, .sequence = sequence};
    bool ok = tvb3_mac_verify(t, &sm->tvb3, sm->mac_key, input, n, auth);
    free(input);
    return ok;
}
