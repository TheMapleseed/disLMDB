/**
 * @file dislmdb_crypto.c
 * @brief Crypto primitives — CommonCrypto on Apple, OpenSSL elsewhere when available
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include "dislmdb_crypto.h"

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#if defined(__APPLE__)
#include <machine/endian.h>
#ifndef htonll
#include <libkern/OSByteOrder.h>
#define htonll(x) OSSwapHostToBigInt64(x)
#define ntohll(x) OSSwapBigToHostInt64(x)
#endif
#endif

#if defined(DISLMDB_USE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <Security/SecRandom.h>
#else
#error "No crypto backend: define DISLMDB_USE_OPENSSL or build on Apple with CommonCrypto"
#endif

#include <stdlib.h>

int dislmdb_crypto_sha256(const void *data, size_t size, uint8_t out[DISLMDB_SHA256_DIGEST_LENGTH])
{
    if ((!data && size > 0) || !out) {
        return EINVAL;
    }

#if defined(DISLMDB_USE_OPENSSL)
    unsigned int out_len = DISLMDB_SHA256_DIGEST_LENGTH;
    if (EVP_Digest(data, size, out, &out_len, EVP_sha256(), NULL) != 1) {
        return EIO;
    }
    return 0;
#else
    CC_SHA256(data, (CC_LONG)size, out);
    return 0;
#endif
}

int dislmdb_crypto_hmac_sha256(const void *key, size_t key_len,
                               const void *data, size_t data_len,
                               uint8_t out[DISLMDB_HMAC_SHA256_LENGTH])
{
    if ((!key && key_len > 0) || (!data && data_len > 0) || !out) {
        return EINVAL;
    }

#if defined(DISLMDB_USE_OPENSSL)
    unsigned int out_len = DISLMDB_HMAC_SHA256_LENGTH;
    if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) == NULL) {
        return EIO;
    }
    return 0;
#else
    CCHmac(kCCHmacAlgSHA256, key, key_len, data, data_len, out);
    return 0;
#endif
}

int dislmdb_crypto_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return EINVAL;
    }

#if defined(DISLMDB_USE_OPENSSL)
    if (RAND_bytes(buf, (int)len) != 1) {
        return EIO;
    }
    return 0;
#else
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess) {
        return EIO;
    }
    return 0;
#endif
}

bool dislmdb_crypto_secure_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

uint16_t dislmdb_htons(uint16_t v) { return htons(v); }
uint16_t dislmdb_ntohs(uint16_t v) { return ntohs(v); }
uint32_t dislmdb_htonl(uint32_t v) { return htonl(v); }
uint32_t dislmdb_ntohl(uint32_t v) { return ntohl(v); }

uint64_t dislmdb_htonll(uint64_t v)
{
#if defined(__APPLE__)
    return (uint64_t)htonll(v);
#else
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xffffffffu));
    return ((uint64_t)lo << 32) | hi;
#endif
}

uint64_t dislmdb_ntohll(uint64_t v)
{
#if defined(__APPLE__)
    return (uint64_t)ntohll(v);
#else
    uint32_t hi = ntohl((uint32_t)(v >> 32));
    uint32_t lo = ntohl((uint32_t)(v & 0xffffffffu));
    return ((uint64_t)lo << 32) | hi;
#endif
}

void dislmdb_write_u16(uint8_t *buf, uint16_t v)
{
    uint16_t n = htons(v);
    memcpy(buf, &n, sizeof(n));
}

void dislmdb_write_u32(uint8_t *buf, uint32_t v)
{
    uint32_t n = htonl(v);
    memcpy(buf, &n, sizeof(n));
}

void dislmdb_write_u64(uint8_t *buf, uint64_t v)
{
    uint64_t n = dislmdb_htonll(v);
    memcpy(buf, &n, sizeof(n));
}

uint16_t dislmdb_read_u16(const uint8_t *buf)
{
    uint16_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohs(n);
}

uint32_t dislmdb_read_u32(const uint8_t *buf)
{
    uint32_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohl(n);
}

uint64_t dislmdb_read_u64(const uint8_t *buf)
{
    uint64_t n;
    memcpy(&n, buf, sizeof(n));
    return dislmdb_ntohll(n);
}

int dislmdb_aead_seal(const uint8_t key[32],
                      const uint8_t *plain, size_t plain_len,
                      uint8_t **out, size_t *out_len)
{
    if (!key || !out || !out_len || (!plain && plain_len > 0)) {
        return EINVAL;
    }
    uint8_t iv[16];
    if (dislmdb_crypto_random_bytes(iv, sizeof(iv)) != 0) {
        return EIO;
    }
    const uint8_t *aes_key = key;          /* first 16 bytes */
    const uint8_t *mac_key = key + 16;     /* second 16 bytes */

#if defined(DISLMDB_USE_OPENSSL)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ENOMEM;
    int outl = 0, fin = 0;
    size_t max = plain_len + 32;
    uint8_t *buf = malloc(16 + max + 32);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return ENOMEM; }
    memcpy(buf, iv, 16);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, buf + 16, &outl, plain, (int)plain_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, buf + 16 + outl, &fin) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(buf); return EIO;
    }
    EVP_CIPHER_CTX_free(ctx);
    size_t ct_len = (size_t)(outl + fin);
    uint8_t mac[32];
    if (dislmdb_crypto_hmac_sha256(mac_key, 16, buf, 16 + ct_len, mac) != 0) {
        free(buf); return EIO;
    }
    memcpy(buf + 16 + ct_len, mac, 32);
    *out = buf;
    *out_len = 16 + ct_len + 32;
    return 0;
#else
    size_t max = plain_len + kCCBlockSizeAES128;
    uint8_t *buf = malloc(16 + max + 32);
    if (!buf) return ENOMEM;
    memcpy(buf, iv, 16);
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                 aes_key, kCCKeySizeAES128, iv,
                                 plain, plain_len, buf + 16, max, &moved);
    if (st != kCCSuccess) { free(buf); return EIO; }
    uint8_t mac[32];
    if (dislmdb_crypto_hmac_sha256(mac_key, 16, buf, 16 + moved, mac) != 0) {
        free(buf); return EIO;
    }
    memcpy(buf + 16 + moved, mac, 32);
    *out = buf;
    *out_len = 16 + moved + 32;
    return 0;
#endif
}

int dislmdb_aead_open(const uint8_t key[32],
                      const uint8_t *sealed, size_t sealed_len,
                      uint8_t **out, size_t *out_len)
{
    if (!key || !sealed || !out || !out_len || sealed_len < 16 + 32) {
        return EINVAL;
    }
    const uint8_t *aes_key = key;
    const uint8_t *mac_key = key + 16;
    size_t body = sealed_len - 32;
    uint8_t expect[32];
    if (dislmdb_crypto_hmac_sha256(mac_key, 16, sealed, body, expect) != 0) {
        return EIO;
    }
    if (!dislmdb_crypto_secure_eq(expect, sealed + body, 32)) {
        return EPERM;
    }
    const uint8_t *iv = sealed;
    const uint8_t *ct = sealed + 16;
    size_t ct_len = body - 16;

#if defined(DISLMDB_USE_OPENSSL)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ENOMEM;
    uint8_t *buf = malloc(ct_len + 32);
    if (!buf) { EVP_CIPHER_CTX_free(ctx); return ENOMEM; }
    int outl = 0, fin = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, buf, &outl, ct, (int)ct_len) != 1 ||
        EVP_DecryptFinal_ex(ctx, buf + outl, &fin) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(buf); return EIO;
    }
    EVP_CIPHER_CTX_free(ctx);
    *out = buf;
    *out_len = (size_t)(outl + fin);
    return 0;
#else
    uint8_t *buf = malloc(ct_len + kCCBlockSizeAES128);
    if (!buf) return ENOMEM;
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                 aes_key, kCCKeySizeAES128, iv,
                                 ct, ct_len, buf, ct_len + kCCBlockSizeAES128, &moved);
    if (st != kCCSuccess) { free(buf); return EIO; }
    *out = buf;
    *out_len = moved;
    return 0;
#endif
}
