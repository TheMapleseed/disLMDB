/**
 * @file test_crypto.c
 * @brief Unit tests for crypto, AEAD, and wire endian helpers
 */
#include "../harness/test_harness.h"
#include "dislmdb_crypto.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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
    test_begin(&ctx, "unit/crypto");

    /* NIST SHA-256 empty string */
    {
        uint8_t dig[32];
        char hex[65];
        int rc = dislmdb_crypto_sha256("", 0, dig);
        hex_of(dig, 32, hex);
        EXPECT_EQ_INT(&ctx, "sha256_empty_rc", rc, 0);
        EXPECT_STREQ(&ctx, "sha256_empty", hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    /* SHA-256("abc") */
    {
        uint8_t dig[32];
        char hex[65];
        int rc = dislmdb_crypto_sha256("abc", 3, dig);
        hex_of(dig, 32, hex);
        EXPECT_EQ_INT(&ctx, "sha256_abc_rc", rc, 0);
        EXPECT_STREQ(&ctx, "sha256_abc", hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /* HMAC-SHA256 RFC 4231 test case 1 */
    {
        uint8_t key[20];
        memset(key, 0x0b, sizeof(key));
        uint8_t out[32];
        char hex[65];
        int rc = dislmdb_crypto_hmac_sha256(key, sizeof(key), "Hi There", 8, out);
        hex_of(out, 32, hex);
        EXPECT_EQ_INT(&ctx, "hmac_rc", rc, 0);
        EXPECT_STREQ(&ctx, "hmac_rfc4231_1", hex,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    /* secure_eq */
    {
        uint8_t a[4] = {1, 2, 3, 4};
        uint8_t b[4] = {1, 2, 3, 4};
        uint8_t c[4] = {1, 2, 3, 5};
        EXPECT_TRUE(&ctx, "secure_eq_match", dislmdb_crypto_secure_eq(a, b, 4));
        EXPECT_TRUE(&ctx, "secure_eq_mismatch", !dislmdb_crypto_secure_eq(a, c, 4));
    }

    /* random bytes nonempty + non-constant */
    {
        uint8_t r1[32], r2[32];
        EXPECT_EQ_INT(&ctx, "rand1", dislmdb_crypto_random_bytes(r1, 32), 0);
        EXPECT_EQ_INT(&ctx, "rand2", dislmdb_crypto_random_bytes(r2, 32), 0);
        EXPECT_TRUE(&ctx, "rand_diff", memcmp(r1, r2, 32) != 0);
    }

    /* endian helpers round-trip */
    {
        uint8_t buf[8];
        dislmdb_write_u16(buf, 0xABCD);
        EXPECT_EQ_INT(&ctx, "u16", dislmdb_read_u16(buf), 0xABCD);
        dislmdb_write_u32(buf, 0xDEADBEEFu);
        EXPECT_EQ_INT(&ctx, "u32", dislmdb_read_u32(buf), 0xDEADBEEFu);
        dislmdb_write_u64(buf, 0x0123456789ABCDEFull);
        EXPECT_EQ_INT(&ctx, "u64", (long long)dislmdb_read_u64(buf),
                      (long long)0x0123456789ABCDEFull);
    }

    /* AEAD seal/open round-trip */
    {
        uint8_t key[32];
        memset(key, 0x42, sizeof(key));
        const char *plain = "dislmdb-aead-payload";
        uint8_t *sealed = NULL, *opened = NULL;
        size_t sealed_len = 0, opened_len = 0;
        int rc = dislmdb_aead_seal(key, (const uint8_t *)plain, strlen(plain),
                                   &sealed, &sealed_len);
        EXPECT_EQ_INT(&ctx, "aead_seal_rc", rc, 0);
        EXPECT_TRUE(&ctx, "aead_sealed_len", sealed && sealed_len > strlen(plain));
        rc = dislmdb_aead_open(key, sealed, sealed_len, &opened, &opened_len);
        EXPECT_EQ_INT(&ctx, "aead_open_rc", rc, 0);
        EXPECT_EQ_INT(&ctx, "aead_open_len", (int)opened_len, (int)strlen(plain));
        EXPECT_TRUE(&ctx, "aead_roundtrip",
                    opened && memcmp(opened, plain, opened_len) == 0);
        /* tamper */
        if (sealed && sealed_len > 20) {
            sealed[20] ^= 0x01;
            uint8_t *bad = NULL;
            size_t bad_len = 0;
            rc = dislmdb_aead_open(key, sealed, sealed_len, &bad, &bad_len);
            EXPECT_TRUE(&ctx, "aead_tamper_reject", rc != 0);
            free(bad);
        }
        free(sealed);
        free(opened);
    }

    return test_end(&ctx);
}
