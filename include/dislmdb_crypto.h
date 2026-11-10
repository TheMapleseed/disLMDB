/**
 * @file dislmdb_crypto.h
 * @brief Platform crypto primitives for DisLMDB (CommonCrypto or OpenSSL)
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#ifndef DISLMDB_CRYPTO_H
#define DISLMDB_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DISLMDB_SHA256_DIGEST_LENGTH 32
#define DISLMDB_HMAC_SHA256_LENGTH   32

/**
 * @brief SHA-256 digest
 * @return 0 on success, non-zero on error
 */
int dislmdb_crypto_sha256(const void *data, size_t size, uint8_t out[DISLMDB_SHA256_DIGEST_LENGTH]);

/**
 * @brief HMAC-SHA256
 * @return 0 on success, non-zero on error
 */
int dislmdb_crypto_hmac_sha256(const void *key, size_t key_len,
                               const void *data, size_t data_len,
                               uint8_t out[DISLMDB_HMAC_SHA256_LENGTH]);

/**
 * @brief Cryptographically secure random bytes
 * @return 0 on success, non-zero on error
 */
int dislmdb_crypto_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Constant-time comparison of digests
 * @return true if equal
 */
bool dislmdb_crypto_secure_eq(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief Network-endian helpers for wire format
 */
uint16_t dislmdb_htons(uint16_t v);
uint16_t dislmdb_ntohs(uint16_t v);
uint32_t dislmdb_htonl(uint32_t v);
uint32_t dislmdb_ntohl(uint32_t v);
uint64_t dislmdb_htonll(uint64_t v);
uint64_t dislmdb_ntohll(uint64_t v);

/**
 * @brief Write / read fixed-width integers in network byte order
 */
void dislmdb_write_u16(uint8_t *buf, uint16_t v);
void dislmdb_write_u32(uint8_t *buf, uint32_t v);
void dislmdb_write_u64(uint8_t *buf, uint64_t v);
uint16_t dislmdb_read_u16(const uint8_t *buf);
uint32_t dislmdb_read_u32(const uint8_t *buf);
uint64_t dislmdb_read_u64(const uint8_t *buf);

/**
 * @brief Encrypt-then-MAC (AES-128-CBC + HMAC-SHA256) using a 32-byte cluster key.
 * Output layout: IV(16) || ciphertext || HMAC(32)
 */
int dislmdb_aead_seal(const uint8_t key[32],
                      const uint8_t *plain, size_t plain_len,
                      uint8_t **out, size_t *out_len);

int dislmdb_aead_open(const uint8_t key[32],
                      const uint8_t *sealed, size_t sealed_len,
                      uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_CRYPTO_H */
