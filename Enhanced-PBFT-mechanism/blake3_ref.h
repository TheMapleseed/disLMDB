/**
 * @file blake3_ref.h
 * @brief In-tree BLAKE3 reference (Section 5.1), ported from Enhanced-PBFT-mechanism
 *        (BLAKE3-team reference_impl, CC0).
 */

#ifndef EPDFT_BLAKE3_REF_H
#define EPDFT_BLAKE3_REF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3_OUT_LEN 32
#define BLAKE3_KEY_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024

typedef struct blake3_hasher {
    uint32_t key_words[8];
    uint32_t cv_stack[54][8];
    uint8_t cv_stack_len;
    uint32_t flags;
    /* chunk state */
    uint32_t chunk_cv[8];
    uint64_t chunk_counter;
    uint8_t block[BLAKE3_BLOCK_LEN];
    uint8_t block_len;
    uint8_t blocks_compressed;
} blake3_hasher;

void blake3_hasher_init(blake3_hasher *self);
void blake3_hasher_update(blake3_hasher *self, const uint8_t *input, size_t input_len);
void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);

/** One-shot 32-byte BLAKE3 hash. */
void blake3_hash_32(const uint8_t *input, size_t input_len, uint8_t out[BLAKE3_OUT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_BLAKE3_REF_H */
