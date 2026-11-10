/**
 * @file test_tvb3.c
 * @brief Unit tests for proper Time-Variant BLAKE3 (TeX §4 + keyed MAC)
 */
#include "../harness/test_harness.h"
#include "time_variant_blake3.h"
#include "blake3_ref.h"
#include <stdio.h>
#include <string.h>

static void hex_of(const uint8_t *b, size_t n, char *out)
{
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 0xf];
    }
    out[n * 2] = '\0';
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/tvb3");

    TimeVariantBlake3Config cfg = tvb3_config_default();
    ConsensusTemporal t = {.view = 1, .sequence = 1};

    EXPECT_TRUE(&ctx, "t_i_1_nonzero", tvb3_t_i(t, 1) != 0);
    EXPECT_EQ_INT(&ctx, "t_i_0_invalid", (long long)tvb3_t_i(t, 0), 0);
    EXPECT_EQ_INT(&ctx, "t_i_9_invalid", (long long)tvb3_t_i(t, 9), 0);

    uint32_t iv1[8], iv2[8];
    tvb3_iv_words(t, &cfg, iv1);
    tvb3_iv_words(t, &cfg, iv2);
    EXPECT_MEMEQ(&ctx, "iv_stable", iv1, iv2, sizeof(iv1));

    ConsensusTemporal t2 = {.view = 2, .sequence = 1};
    uint32_t iv3[8];
    tvb3_iv_words(t2, &cfg, iv3);
    EXPECT_TRUE(&ctx, "iv_view_sensitive", memcmp(iv1, iv3, sizeof(iv1)) != 0);

    uint8_t d1[32], d2[32], d3[32], d_pref[32];
    char hex[65];
    tvb3_hash_payload(t, &cfg, (const uint8_t *)"", 0, d1);
    tvb3_hash_payload(t, &cfg, (const uint8_t *)"", 0, d2);
    EXPECT_MEMEQ(&ctx, "digest_stable", d1, d2, 32);
    hex_of(d1, 32, hex);
    printf("  INFO  proper-empty@(1,1) digest=%s\n", hex);

    tvb3_hash_payload_prefixed(t, &cfg, (const uint8_t *)"", 0, d_pref);
    EXPECT_TRUE(&ctx, "proper_ne_prefixed", memcmp(d1, d_pref, 32) != 0);

    tvb3_hash_payload(t, &cfg, (const uint8_t *)"hello", 5, d3);
    EXPECT_TRUE(&ctx, "digest_payload_sensitive", memcmp(d1, d3, 32) != 0);

    uint8_t d4[32];
    tvb3_hash_payload(t2, &cfg, (const uint8_t *)"hello", 5, d4);
    EXPECT_TRUE(&ctx, "digest_temporal_sensitive", memcmp(d3, d4, 32) != 0);

    /* Keyed TV-B3 MAC */
    uint8_t key[32];
    memset(key, 0x5a, sizeof(key));
    uint8_t mac1[32], mac2[32], mac_bad[32];
    const char *msg = "pre-prepare|payload";
    tvb3_mac(t, &cfg, key, (const uint8_t *)msg, strlen(msg), mac1);
    tvb3_mac(t, &cfg, key, (const uint8_t *)msg, strlen(msg), mac2);
    EXPECT_MEMEQ(&ctx, "mac_stable", mac1, mac2, 32);
    EXPECT_TRUE(&ctx, "mac_verify_ok",
                tvb3_mac_verify(t, &cfg, key, (const uint8_t *)msg, strlen(msg), mac1));
    tvb3_mac(t2, &cfg, key, (const uint8_t *)msg, strlen(msg), mac_bad);
    EXPECT_TRUE(&ctx, "mac_temporal_sensitive", memcmp(mac1, mac_bad, 32) != 0);
    EXPECT_TRUE(&ctx, "mac_verify_reject",
                !tvb3_mac_verify(t, &cfg, key, (const uint8_t *)msg, strlen(msg), mac_bad));

    /* derive_key smoke */
    uint8_t dk[32];
    blake3_derive_key("test-context", key, 32, dk);
    EXPECT_TRUE(&ctx, "derive_key_nonzero", memcmp(dk, key, 32) != 0);

    return test_end(&ctx);
}
