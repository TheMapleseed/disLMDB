/**
 * @file blake3_ref.c
 * @brief BLAKE3 reference implementation (CC0), ported from Enhanced-PBFT Rust.
 * Source lineage: https://github.com/BLAKE3-team/BLAKE3 reference_impl
 */

#include "blake3_ref.h"

#include <string.h>
/* strlen used by blake3_derive_key */

enum {
    CHUNK_START = 1u << 0,
    CHUNK_END = 1u << 1,
    PARENT = 1u << 2,
    ROOT = 1u << 3,
    KEYED_HASH = 1u << 4,
    DERIVE_KEY_CONTEXT = 1u << 5,
    DERIVE_KEY_MATERIAL = 1u << 6
};

static const uint32_t IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const size_t MSG_PERMUTATION[16] = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
};

static uint32_t rotr32(uint32_t w, unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static void g(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
              uint32_t mx, uint32_t my)
{
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

static void round_fn(uint32_t state[16], const uint32_t m[16])
{
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

static void permute(uint32_t m[16])
{
    uint32_t permuted[16];
    for (size_t i = 0; i < 16; i++) {
        permuted[i] = m[MSG_PERMUTATION[i]];
    }
    memcpy(m, permuted, sizeof(permuted));
}

static void compress(const uint32_t chaining_value[8],
                     const uint32_t block_words[16],
                     uint64_t counter,
                     uint32_t block_len,
                     uint32_t flags,
                     uint32_t out[16])
{
    uint32_t state[16] = {
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32), block_len, flags
    };
    uint32_t block[16];
    memcpy(block, block_words, sizeof(block));

    for (int i = 0; i < 7; i++) {
        round_fn(state, block);
        if (i != 6) {
            permute(block);
        }
    }

    for (int i = 0; i < 8; i++) {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    memcpy(out, state, sizeof(state));
}

static void words_from_le_bytes(const uint8_t *bytes, uint32_t *words, size_t nwords)
{
    for (size_t i = 0; i < nwords; i++) {
        words[i] = (uint32_t)bytes[4 * i]
                 | ((uint32_t)bytes[4 * i + 1] << 8)
                 | ((uint32_t)bytes[4 * i + 2] << 16)
                 | ((uint32_t)bytes[4 * i + 3] << 24);
    }
}

static void first_8_words(const uint32_t compression_output[16], uint32_t out[8])
{
    memcpy(out, compression_output, 8 * sizeof(uint32_t));
}

typedef struct {
    uint32_t input_chaining_value[8];
    uint32_t block_words[16];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;
} blake3_output;

static void output_chaining_value(const blake3_output *o, uint32_t out[8])
{
    uint32_t compressed[16];
    compress(o->input_chaining_value, o->block_words, o->counter, o->block_len, o->flags, compressed);
    first_8_words(compressed, out);
}

static void root_output_bytes(const blake3_output *o, uint8_t *out_slice, size_t out_len)
{
    uint64_t output_block_counter = 0;
    size_t offset = 0;
    while (offset < out_len) {
        uint32_t words[16];
        compress(o->input_chaining_value, o->block_words, output_block_counter,
                 o->block_len, o->flags | ROOT, words);
        size_t chunk = out_len - offset;
        if (chunk > 2 * BLAKE3_OUT_LEN) {
            chunk = 2 * BLAKE3_OUT_LEN;
        }
        for (size_t i = 0; i < chunk; i++) {
            size_t word_i = i / 4;
            size_t byte_i = i % 4;
            out_slice[offset + i] = (uint8_t)((words[word_i] >> (8 * byte_i)) & 0xffu);
        }
        offset += chunk;
        output_block_counter++;
    }
}

static size_t chunk_len(const blake3_hasher *h)
{
    return (size_t)BLAKE3_BLOCK_LEN * (size_t)h->blocks_compressed + (size_t)h->block_len;
}

static uint32_t start_flag(const blake3_hasher *h)
{
    return h->blocks_compressed == 0 ? CHUNK_START : 0;
}

static void chunk_update(blake3_hasher *h, const uint8_t *input, size_t input_len)
{
    while (input_len > 0) {
        if (h->block_len == BLAKE3_BLOCK_LEN) {
            uint32_t block_words[16];
            uint32_t compressed[16];
            words_from_le_bytes(h->block, block_words, 16);
            compress(h->chunk_cv, block_words, h->chunk_counter, BLAKE3_BLOCK_LEN,
                     h->flags | start_flag(h), compressed);
            first_8_words(compressed, h->chunk_cv);
            h->blocks_compressed++;
            memset(h->block, 0, sizeof(h->block));
            h->block_len = 0;
        }
        size_t want = (size_t)BLAKE3_BLOCK_LEN - (size_t)h->block_len;
        size_t take = want < input_len ? want : input_len;
        memcpy(h->block + h->block_len, input, take);
        h->block_len = (uint8_t)(h->block_len + take);
        input += take;
        input_len -= take;
    }
}

static void chunk_output(const blake3_hasher *h, blake3_output *out)
{
    words_from_le_bytes(h->block, out->block_words, 16);
    memcpy(out->input_chaining_value, h->chunk_cv, sizeof(out->input_chaining_value));
    out->counter = h->chunk_counter;
    out->block_len = h->block_len;
    out->flags = h->flags | start_flag(h) | CHUNK_END;
}

static void parent_output(const uint32_t left[8], const uint32_t right[8],
                          const uint32_t key_words[8], uint32_t flags,
                          blake3_output *out)
{
    memcpy(out->input_chaining_value, key_words, sizeof(out->input_chaining_value));
    memcpy(out->block_words, left, 8 * sizeof(uint32_t));
    memcpy(out->block_words + 8, right, 8 * sizeof(uint32_t));
    out->counter = 0;
    out->block_len = BLAKE3_BLOCK_LEN;
    out->flags = PARENT | flags;
}

static void parent_cv(const uint32_t left[8], const uint32_t right[8],
                      const uint32_t key_words[8], uint32_t flags, uint32_t out[8])
{
    blake3_output o;
    parent_output(left, right, key_words, flags, &o);
    output_chaining_value(&o, out);
}

static void push_stack(blake3_hasher *h, const uint32_t cv[8])
{
    memcpy(h->cv_stack[h->cv_stack_len], cv, 8 * sizeof(uint32_t));
    h->cv_stack_len++;
}

static void pop_stack(blake3_hasher *h, uint32_t out[8])
{
    h->cv_stack_len--;
    memcpy(out, h->cv_stack[h->cv_stack_len], 8 * sizeof(uint32_t));
}

static void add_chunk_chaining_value(blake3_hasher *h, uint32_t new_cv[8], uint64_t total_chunks)
{
    while ((total_chunks & 1u) == 0) {
        uint32_t left[8];
        pop_stack(h, left);
        parent_cv(left, new_cv, h->key_words, h->flags, new_cv);
        total_chunks >>= 1;
    }
    push_stack(h, new_cv);
}

void blake3_hasher_init(blake3_hasher *self)
{
    memset(self, 0, sizeof(*self));
    memcpy(self->key_words, IV, sizeof(IV));
    memcpy(self->chunk_cv, IV, sizeof(IV));
    self->flags = 0;
}

void blake3_hasher_init_cv_xor(blake3_hasher *self, const uint32_t tvb3_iv[8])
{
    memset(self, 0, sizeof(*self));
    for (int i = 0; i < 8; i++) {
        uint32_t w = IV[i] ^ (tvb3_iv ? tvb3_iv[i] : 0u);
        self->key_words[i] = w;
        self->chunk_cv[i] = w;
    }
    self->flags = 0;
}

void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN])
{
    memset(self, 0, sizeof(*self));
    words_from_le_bytes(key, self->key_words, 8);
    memcpy(self->chunk_cv, self->key_words, sizeof(self->chunk_cv));
    self->flags = KEYED_HASH;
}

void blake3_hasher_init_keyed_cv_xor(blake3_hasher *self,
                                     const uint8_t key[BLAKE3_KEY_LEN],
                                     const uint32_t tvb3_iv[8])
{
    memset(self, 0, sizeof(*self));
    words_from_le_bytes(key, self->key_words, 8);
    for (int i = 0; i < 8; i++) {
        self->key_words[i] ^= tvb3_iv ? tvb3_iv[i] : 0u;
        self->chunk_cv[i] = self->key_words[i];
    }
    self->flags = KEYED_HASH;
}

void blake3_derive_key(const char *context,
                       const uint8_t *key_material, size_t key_material_len,
                       uint8_t out_key[BLAKE3_KEY_LEN])
{
    blake3_hasher ctx_h;
    memset(&ctx_h, 0, sizeof(ctx_h));
    memcpy(ctx_h.key_words, IV, sizeof(IV));
    memcpy(ctx_h.chunk_cv, IV, sizeof(IV));
    ctx_h.flags = DERIVE_KEY_CONTEXT;
    if (context) {
        blake3_hasher_update(&ctx_h, (const uint8_t *)context, strlen(context));
    }
    uint8_t context_key[BLAKE3_KEY_LEN];
    blake3_hasher_finalize(&ctx_h, context_key, BLAKE3_KEY_LEN);

    blake3_hasher mat_h;
    memset(&mat_h, 0, sizeof(mat_h));
    words_from_le_bytes(context_key, mat_h.key_words, 8);
    memcpy(mat_h.chunk_cv, mat_h.key_words, sizeof(mat_h.chunk_cv));
    mat_h.flags = DERIVE_KEY_MATERIAL;
    if (key_material && key_material_len > 0) {
        blake3_hasher_update(&mat_h, key_material, key_material_len);
    }
    blake3_hasher_finalize(&mat_h, out_key, BLAKE3_KEY_LEN);
}

void blake3_hasher_update(blake3_hasher *self, const uint8_t *input, size_t input_len)
{
    while (input_len > 0) {
        if (chunk_len(self) == BLAKE3_CHUNK_LEN) {
            blake3_output o;
            uint32_t chunk_cv[8];
            chunk_output(self, &o);
            output_chaining_value(&o, chunk_cv);
            uint64_t total_chunks = self->chunk_counter + 1;
            add_chunk_chaining_value(self, chunk_cv, total_chunks);
            memcpy(self->chunk_cv, self->key_words, sizeof(self->chunk_cv));
            self->chunk_counter = total_chunks;
            memset(self->block, 0, sizeof(self->block));
            self->block_len = 0;
            self->blocks_compressed = 0;
        }
        size_t want = BLAKE3_CHUNK_LEN - chunk_len(self);
        size_t take = want < input_len ? want : input_len;
        chunk_update(self, input, take);
        input += take;
        input_len -= take;
    }
}

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len)
{
    blake3_output output;
    chunk_output(self, &output);
    size_t parent_nodes_remaining = self->cv_stack_len;
    while (parent_nodes_remaining > 0) {
        parent_nodes_remaining--;
        uint32_t right_cv[8];
        output_chaining_value(&output, right_cv);
        parent_output(self->cv_stack[parent_nodes_remaining], right_cv,
                      self->key_words, self->flags, &output);
    }
    root_output_bytes(&output, out, out_len);
}
