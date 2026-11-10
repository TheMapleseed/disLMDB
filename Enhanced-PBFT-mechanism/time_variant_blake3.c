/**
 * @file time_variant_blake3.c
 * @brief Port of Enhanced-PBFT Rust time_variant_blake3.rs
 */

#include "time_variant_blake3.h"
#include "blake3_ref.h"

#include <string.h>

TimeVariantBlake3Config tvb3_config_default(void)
{
    return (TimeVariantBlake3Config){.nu_cpu_hz = 3000000000ull};
}

static uint64_t rotl64(uint64_t x, unsigned n)
{
    return (x << n) | (x >> (64 - n));
}

uint64_t tvb3_t_i(ConsensusTemporal temporal, uint8_t i)
{
    if (i < 1 || i > 8) {
        return 0;
    }
    uint64_t j = (uint64_t)(i - 1);
    uint64_t x = temporal.view ^ rotl64(temporal.sequence, 17);
    x ^= j << (8 + ((uint32_t)j % 48));
    x = x * 0x9E3779B97F4A7C15ull;
    x ^= temporal.sequence * (0xC2B2AE3D27D4EB4Full + j);
    return x;
}

static uint64_t tau(uint64_t t_i, uint64_t nu_cpu_hz, uint8_t i)
{
    return t_i ^ (nu_cpu_hz * (uint64_t)i);
}

static uint32_t fold_u64_to_f32(uint64_t x)
{
    return (uint32_t)x ^ (uint32_t)(x >> 32);
}

static uint32_t sigma_t(ConsensusTemporal temporal, uint64_t nu_cpu_hz)
{
    uint64_t acc = 0;
    for (uint8_t i = 1; i <= 8; i++) {
        acc ^= tau(tvb3_t_i(temporal, i), nu_cpu_hz, i);
    }
    return fold_u64_to_f32(acc);
}

static int is_prime_u32(uint32_t n)
{
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if ((n % 2) == 0 || (n % 3) == 0) return 0;
    uint32_t d = 5;
    while ((uint64_t)d * (uint64_t)d <= (uint64_t)n) {
        if ((n % d) == 0 || (n % (d + 2)) == 0) {
            return 0;
        }
        d += 6;
    }
    return 1;
}

static uint32_t delta_p(uint32_t x)
{
    const uint32_t MAX_STEPS = 1u << 20;
    uint32_t steps = 0;
    uint32_t y = x + 1;
    for (;;) {
        if (is_prime_u32(y)) {
            return y - x;
        }
        steps++;
        if (steps >= MAX_STEPS) {
            return 1;
        }
        y++;
    }
}

static uint32_t r_rot_bits(uint32_t x)
{
    if (x == 0) {
        return 0;
    }
    uint32_t floor_log2 = 31u - (uint32_t)__builtin_clz(x);
    return floor_log2 % 32u;
}

static uint32_t mathcal_e(uint32_t x, uint32_t eta)
{
    uint32_t r = r_rot_bits(x);
    uint32_t rot = (r == 0) ? x : ((x >> r) | (x << (32u - r)));
    return x ^ rot ^ eta;
}

static void entropy_pool_64(ConsensusTemporal temporal, uint8_t pool[64])
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    static const char label[] = "TimeVariantBlake3|eta-pool|v1";
    blake3_hasher_update(&h, (const uint8_t *)label, sizeof(label) - 1);
    uint8_t le[16];
    for (int i = 0; i < 8; i++) {
        le[i] = (uint8_t)((temporal.view >> (8 * i)) & 0xffu);
        le[8 + i] = (uint8_t)((temporal.sequence >> (8 * i)) & 0xffu);
    }
    blake3_hasher_update(&h, le, 16);
    blake3_hasher_finalize(&h, pool, 64);
}

static uint32_t eta_i(const uint8_t pool[64], uint8_t i)
{
    size_t o = (size_t)(i - 1) * 4;
    uint32_t lo = (uint32_t)pool[o]
                | ((uint32_t)pool[o + 1] << 8)
                | ((uint32_t)pool[o + 2] << 16)
                | ((uint32_t)pool[o + 3] << 24);
    uint32_t hi = (uint32_t)pool[32 + o]
                | ((uint32_t)pool[32 + o + 1] << 8)
                | ((uint32_t)pool[32 + o + 2] << 16)
                | ((uint32_t)pool[32 + o + 3] << 24);
    return lo ^ hi;
}

static uint32_t h_mi(ConsensusTemporal temporal, uint8_t i)
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    static const char label[] = "TimeVariantBlake3|H|m_i|v1";
    blake3_hasher_update(&h, (const uint8_t *)label, sizeof(label) - 1);
    uint8_t le[17];
    for (int k = 0; k < 8; k++) {
        le[k] = (uint8_t)((temporal.view >> (8 * k)) & 0xffu);
        le[8 + k] = (uint8_t)((temporal.sequence >> (8 * k)) & 0xffu);
    }
    le[16] = i;
    blake3_hasher_update(&h, le, 17);
    uint8_t b[32];
    blake3_hasher_finalize(&h, b, 32);
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

void tvb3_iv_words(ConsensusTemporal temporal,
                   const TimeVariantBlake3Config *cfg,
                   uint32_t out_iv[8])
{
    TimeVariantBlake3Config local = cfg ? *cfg : tvb3_config_default();
    uint32_t sigma = sigma_t(temporal, local.nu_cpu_hz);
    uint8_t pool[64];
    entropy_pool_64(temporal, pool);
    for (uint8_t i = 1; i <= 8; i++) {
        uint32_t x = sigma + (uint32_t)i * 32u;
        uint32_t d = delta_p(x);
        uint32_t e = mathcal_e(d, eta_i(pool, i));
        out_iv[i - 1] = e ^ h_mi(temporal, i);
    }
}

void tvb3_hash_payload(ConsensusTemporal temporal,
                       const TimeVariantBlake3Config *cfg,
                       const uint8_t *payload,
                       size_t payload_len,
                       uint8_t out[32])
{
    /* TeX §4: G'(h,m,t) = G(h ⊕ IV(t), m, t) */
    uint32_t words[8];
    tvb3_iv_words(temporal, cfg, words);
    blake3_hasher h;
    blake3_hasher_init_cv_xor(&h, words);
    if (payload && payload_len > 0) {
        blake3_hasher_update(&h, payload, payload_len);
    }
    blake3_hasher_finalize(&h, out, 32);
}

void tvb3_hash_payload_prefixed(ConsensusTemporal temporal,
                                const TimeVariantBlake3Config *cfg,
                                const uint8_t *payload,
                                size_t payload_len,
                                uint8_t out[32])
{
    uint32_t words[8];
    tvb3_iv_words(temporal, cfg, words);
    uint8_t prefix[32];
    for (int k = 0; k < 8; k++) {
        prefix[k * 4 + 0] = (uint8_t)(words[k] & 0xffu);
        prefix[k * 4 + 1] = (uint8_t)((words[k] >> 8) & 0xffu);
        prefix[k * 4 + 2] = (uint8_t)((words[k] >> 16) & 0xffu);
        prefix[k * 4 + 3] = (uint8_t)((words[k] >> 24) & 0xffu);
    }
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, prefix, 32);
    if (payload && payload_len > 0) {
        blake3_hasher_update(&h, payload, payload_len);
    }
    blake3_hasher_finalize(&h, out, 32);
}

void tvb3_mac(ConsensusTemporal temporal,
              const TimeVariantBlake3Config *cfg,
              const uint8_t key[32],
              const uint8_t *msg,
              size_t msg_len,
              uint8_t out[32])
{
    uint32_t words[8];
    tvb3_iv_words(temporal, cfg, words);
    blake3_hasher h;
    blake3_hasher_init_keyed_cv_xor(&h, key, words);
    if (msg && msg_len > 0) {
        blake3_hasher_update(&h, msg, msg_len);
    }
    blake3_hasher_finalize(&h, out, 32);
}

bool tvb3_mac_verify(ConsensusTemporal temporal,
                     const TimeVariantBlake3Config *cfg,
                     const uint8_t key[32],
                     const uint8_t *msg,
                     size_t msg_len,
                     const uint8_t expect[32])
{
    uint8_t got[32];
    tvb3_mac(temporal, cfg, key, msg, msg_len, got);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (uint8_t)(got[i] ^ expect[i]);
    }
    return diff == 0;
}
