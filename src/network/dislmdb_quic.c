/**
 * @file dislmdb_quic.c
 * @brief QUIC long-header, VN, CRYPTO, Initial+Handshake AEAD + HP
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#include "dislmdb_quic.h"

#include <string.h>
#include <stdlib.h>

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include "dislmdb_crypto.h"
#include "dislmdb_internal.h"

/* RFC 9001 §5.2 — initial salt for QUICv1 (also used for DISLMDB_QUIC_VERSION). */
static const uint8_t QUIC_INITIAL_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

bool dislmdb_quic_stack_ready(void)
{
    return true;
}

const char *dislmdb_quic_status(void)
{
    return "QUIC ready (HS+1-RTT DQGM; X.509 CertificateVerify)";
}

void dislmdb_quic_cid_from_u64(uint64_t cid, uint8_t out[8])
{
    if (!out) {
        return;
    }
    dislmdb_write_u64(out, cid);
}

uint64_t dislmdb_quic_cid_to_u64(const uint8_t *cid, size_t len)
{
    uint8_t tmp[8];
    memset(tmp, 0, sizeof(tmp));
    if (cid && len > 0) {
        size_t n = len < sizeof(tmp) ? len : sizeof(tmp);
        if (len > sizeof(tmp)) {
            memcpy(tmp, cid + (len - sizeof(tmp)), sizeof(tmp));
        } else {
            memcpy(tmp + (sizeof(tmp) - n), cid, n);
        }
    }
    return dislmdb_read_u64(tmp);
}

dislmdb_quic_dgram_kind dislmdb_quic_classify(const uint8_t *data, size_t len)
{
    if (!data || len < 1) {
        return DISLMDB_QUIC_DGRAM_UNKNOWN;
    }
    if (len >= 4 && dislmdb_read_u32(data) == DISLMDB_DQGM_MAGIC) {
        return DISLMDB_QUIC_DGRAM_DQGM;
    }
    if ((data[0] & 0x80u) != 0) {
        if (len >= 5 &&
            dislmdb_read_u32(data + 1) == DISLMDB_QUIC_VERSION_NEGOTIATION) {
            return DISLMDB_QUIC_DGRAM_VERSION_NEG;
        }
        return DISLMDB_QUIC_DGRAM_QUIC_LONG;
    }
    if ((data[0] & 0x40u) != 0) {
        return DISLMDB_QUIC_DGRAM_QUIC_SHORT;
    }
    return DISLMDB_QUIC_DGRAM_UNKNOWN;
}

int dislmdb_quic_varint_encode(uint64_t v, uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    if (!out || !out_len) {
        return -1;
    }
    if (v <= 0x3full) {
        if (out_cap < 1) {
            return -1;
        }
        out[0] = (uint8_t)v;
        *out_len = 1;
        return 0;
    }
    if (v <= 0x3fffull) {
        if (out_cap < 2) {
            return -1;
        }
        out[0] = (uint8_t)(0x40u | ((v >> 8) & 0x3fu));
        out[1] = (uint8_t)(v & 0xffu);
        *out_len = 2;
        return 0;
    }
    if (v <= 0x3fffffffull) {
        if (out_cap < 4) {
            return -1;
        }
        out[0] = (uint8_t)(0x80u | ((v >> 24) & 0x3fu));
        out[1] = (uint8_t)((v >> 16) & 0xffu);
        out[2] = (uint8_t)((v >> 8) & 0xffu);
        out[3] = (uint8_t)(v & 0xffu);
        *out_len = 4;
        return 0;
    }
    if (out_cap < 8) {
        return -1;
    }
    out[0] = (uint8_t)(0xc0u | ((v >> 56) & 0x3fu));
    out[1] = (uint8_t)((v >> 48) & 0xffu);
    out[2] = (uint8_t)((v >> 40) & 0xffu);
    out[3] = (uint8_t)((v >> 32) & 0xffu);
    out[4] = (uint8_t)((v >> 24) & 0xffu);
    out[5] = (uint8_t)((v >> 16) & 0xffu);
    out[6] = (uint8_t)((v >> 8) & 0xffu);
    out[7] = (uint8_t)(v & 0xffu);
    *out_len = 8;
    return 0;
}

int dislmdb_quic_varint_decode(const uint8_t *data, size_t len, uint64_t *out,
                               size_t *consumed)
{
    if (!data || !out || !consumed || len < 1) {
        return -1;
    }
    unsigned prefix = data[0] >> 6;
    size_t need = 1u << prefix;
    if (len < need) {
        return -1;
    }
    uint64_t v = (uint64_t)(data[0] & 0x3fu);
    for (size_t i = 1; i < need; i++) {
        v = (v << 8) | data[i];
    }
    *out = v;
    *consumed = need;
    return 0;
}

int dislmdb_quic_parse_long_header(const uint8_t *data, size_t len,
                                   dislmdb_quic_long_header *out)
{
    if (!data || !out || len < 7) {
        return -1;
    }
    if ((data[0] & 0x80u) == 0) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->first_byte = data[0];
    out->type = (dislmdb_quic_long_type)((data[0] >> 4) & 0x03u);
    out->version = dislmdb_read_u32(data + 1);

    size_t o = 5;
    if (o >= len) {
        return -1;
    }
    out->dcid_len = data[o++];
    if (out->dcid_len > DISLMDB_QUIC_MAX_CID_LEN || o + out->dcid_len > len) {
        return -1;
    }
    if (out->dcid_len > 0) {
        memcpy(out->dcid, data + o, out->dcid_len);
    }
    o += out->dcid_len;

    if (o >= len) {
        return -1;
    }
    out->scid_len = data[o++];
    if (out->scid_len > DISLMDB_QUIC_MAX_CID_LEN || o + out->scid_len > len) {
        return -1;
    }
    if (out->scid_len > 0) {
        memcpy(out->scid, data + o, out->scid_len);
    }
    o += out->scid_len;
    out->header_len = o;
    return 0;
}

int dislmdb_quic_encode_version_negotiation(const dislmdb_quic_long_header *probe,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len)
{
    if (!probe || !out || !out_len) {
        return -1;
    }
    size_t need = 1 + 4 + 1 + probe->scid_len + 1 + probe->dcid_len + 4;
    if (need > out_cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = 0x80u;
    dislmdb_write_u32(out + o, DISLMDB_QUIC_VERSION_NEGOTIATION);
    o += 4;
    out[o++] = (uint8_t)probe->scid_len;
    if (probe->scid_len > 0) {
        memcpy(out + o, probe->scid, probe->scid_len);
        o += probe->scid_len;
    }
    out[o++] = (uint8_t)probe->dcid_len;
    if (probe->dcid_len > 0) {
        memcpy(out + o, probe->dcid, probe->dcid_len);
        o += probe->dcid_len;
    }
    dislmdb_write_u32(out + o, DISLMDB_QUIC_VERSION);
    o += 4;
    *out_len = o;
    return 0;
}

int dislmdb_quic_encode_crypto_frame(uint64_t offset, const uint8_t *data,
                                     size_t data_len, uint8_t *out,
                                     size_t out_cap, size_t *out_len)
{
    if (!out || !out_len || (data_len > 0 && !data)) {
        return -1;
    }
    uint8_t offb[8], lenb[8];
    size_t offn = 0, lenn = 0;
    if (dislmdb_quic_varint_encode(offset, offb, sizeof(offb), &offn) != 0 ||
        dislmdb_quic_varint_encode(data_len, lenb, sizeof(lenb), &lenn) != 0) {
        return -1;
    }
    size_t need = 1 + offn + lenn + data_len;
    if (need > out_cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = DISLMDB_QUIC_FRAME_CRYPTO;
    memcpy(out + o, offb, offn);
    o += offn;
    memcpy(out + o, lenb, lenn);
    o += lenn;
    if (data_len > 0) {
        memcpy(out + o, data, data_len);
        o += data_len;
    }
    *out_len = o;
    return 0;
}

int dislmdb_quic_decode_crypto_frame(const uint8_t *data, size_t len,
                                     uint64_t *offset, const uint8_t **payload,
                                     size_t *payload_len, size_t *consumed)
{
    if (!data || !offset || !payload || !payload_len || !consumed || len < 2) {
        return -1;
    }
    if (data[0] != DISLMDB_QUIC_FRAME_CRYPTO) {
        return -1;
    }
    size_t o = 1;
    uint64_t off = 0, plen = 0;
    size_t c1 = 0, c2 = 0;
    if (dislmdb_quic_varint_decode(data + o, len - o, &off, &c1) != 0) {
        return -1;
    }
    o += c1;
    if (dislmdb_quic_varint_decode(data + o, len - o, &plen, &c2) != 0) {
        return -1;
    }
    o += c2;
    if (o + plen > len) {
        return -1;
    }
    *offset = off;
    *payload = data + o;
    *payload_len = (size_t)plen;
    *consumed = o + (size_t)plen;
    return 0;
}

static int hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                        size_t ikm_len, uint8_t prk[32])
{
    static const uint8_t zeros[32] = {0};
    const uint8_t *s = salt;
    size_t sl = salt_len;
    if (!s || sl == 0) {
        s = zeros;
        sl = 32;
    }
    return dislmdb_crypto_hmac_sha256(s, sl, ikm, ikm_len, prk);
}

static int hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len)
{
    if (!prk || !out || out_len == 0 || out_len > 255 * 32) {
        return -1;
    }
    uint8_t t[32];
    size_t tlen = 0;
    size_t generated = 0;
    uint8_t counter = 1;
    while (generated < out_len) {
        uint8_t msg[32 + 256 + 1];
        size_t mlen = 0;
        if (tlen > 0) {
            memcpy(msg, t, tlen);
            mlen = tlen;
        }
        if (info && info_len > 0) {
            if (mlen + info_len > sizeof(msg) - 1) {
                return -1;
            }
            memcpy(msg + mlen, info, info_len);
            mlen += info_len;
        }
        msg[mlen++] = counter++;
        if (dislmdb_crypto_hmac_sha256(prk, 32, msg, mlen, t) != 0) {
            return -1;
        }
        tlen = 32;
        size_t copy = out_len - generated;
        if (copy > 32) {
            copy = 32;
        }
        memcpy(out + generated, t, copy);
        generated += copy;
    }
    return 0;
}

static int hkdf_expand_label(const uint8_t secret[32], const char *label,
                             const uint8_t *context, size_t context_len,
                             uint8_t *out, size_t out_len)
{
    /* HkdfLabel = uint16 length || uint8 label_len || "tls13 " + label ||
     *             uint8 context_len || context */
    char full_label[64];
    size_t label_len = strlen(label);
    if (label_len > 32 || context_len > 255 || out_len > 65535) {
        return -1;
    }
    memcpy(full_label, "tls13 ", 6);
    memcpy(full_label + 6, label, label_len);
    size_t flen = 6 + label_len;

    uint8_t hkdf_label[2 + 1 + 64 + 1 + 255];
    size_t o = 0;
    hkdf_label[o++] = (uint8_t)((out_len >> 8) & 0xffu);
    hkdf_label[o++] = (uint8_t)(out_len & 0xffu);
    hkdf_label[o++] = (uint8_t)flen;
    memcpy(hkdf_label + o, full_label, flen);
    o += flen;
    hkdf_label[o++] = (uint8_t)context_len;
    if (context_len > 0 && context) {
        memcpy(hkdf_label + o, context, context_len);
        o += context_len;
    }
    return hkdf_expand(secret, hkdf_label, o, out, out_len);
}

static int derive_directional(const uint8_t secret[32],
                              dislmdb_quic_initial_keys *out)
{
    if (!secret || !out) {
        return -1;
    }
    if (hkdf_expand_label(secret, "quic key", NULL, 0, out->key,
                          DISLMDB_QUIC_INITIAL_KEY_LEN) != 0 ||
        hkdf_expand_label(secret, "quic iv", NULL, 0, out->iv,
                          DISLMDB_QUIC_INITIAL_IV_LEN) != 0 ||
        hkdf_expand_label(secret, "quic hp", NULL, 0, out->hp,
                          DISLMDB_QUIC_INITIAL_KEY_LEN) != 0) {
        return -1;
    }
    return 0;
}

int dislmdb_quic_traffic_keys_from_secret(const uint8_t secret[32],
                                          dislmdb_quic_traffic_keys *out)
{
    return derive_directional(secret, out);
}

int dislmdb_quic_derive_initial_keys(const uint8_t *dcid, size_t dcid_len,
                                     dislmdb_quic_initial_keys *client_out,
                                     dislmdb_quic_initial_keys *server_out)
{
    if (!dcid || dcid_len == 0 || dcid_len > DISLMDB_QUIC_MAX_CID_LEN ||
        !client_out || !server_out) {
        return -1;
    }
    uint8_t initial_secret[32];
    if (hkdf_extract(QUIC_INITIAL_SALT, sizeof(QUIC_INITIAL_SALT), dcid, dcid_len,
                     initial_secret) != 0) {
        return -1;
    }
    uint8_t client_secret[32], server_secret[32];
    if (hkdf_expand_label(initial_secret, "client in", NULL, 0, client_secret,
                          32) != 0 ||
        hkdf_expand_label(initial_secret, "server in", NULL, 0, server_secret,
                          32) != 0) {
        return -1;
    }
    if (derive_directional(client_secret, client_out) != 0 ||
        derive_directional(server_secret, server_out) != 0) {
        return -1;
    }
    return 0;
}

/* Exposed for TLS key schedule (same HKDF-Expand-Label as Initial). */
int dislmdb_quic_hkdf_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t prk[32])
{
    return hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
}

int dislmdb_quic_hkdf_expand_label(const uint8_t secret[32], const char *label,
                                   const uint8_t *context, size_t context_len,
                                   uint8_t *out, size_t out_len)
{
    return hkdf_expand_label(secret, label, context, context_len, out, out_len);
}

static void quic_nonce(const uint8_t iv[DISLMDB_QUIC_INITIAL_IV_LEN], uint64_t pn,
                       uint8_t nonce[DISLMDB_QUIC_INITIAL_IV_LEN])
{
    memset(nonce, 0, DISLMDB_QUIC_INITIAL_IV_LEN);
    /* PN left-padded into the last 8 bytes, then XOR with IV. */
    for (int i = 0; i < 8; i++) {
        nonce[DISLMDB_QUIC_INITIAL_IV_LEN - 1 - i] = (uint8_t)((pn >> (8 * i)) & 0xffu);
    }
    for (size_t i = 0; i < DISLMDB_QUIC_INITIAL_IV_LEN; i++) {
        nonce[i] ^= iv[i];
    }
}

int dislmdb_quic_aead_seal(const dislmdb_quic_initial_keys *keys, uint64_t pn,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!keys || !out || !out_len || (plain_len > 0 && !plain) ||
        (aad_len > 0 && !aad)) {
        return -1;
    }
    if (out_cap < plain_len + DISLMDB_QUIC_AEAD_TAG_LEN) {
        return -1;
    }
    uint8_t nonce[DISLMDB_QUIC_INITIAL_IV_LEN];
    quic_nonce(keys->iv, pn, nonce);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, keys->key, 128);
    if (rc != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }
    uint8_t tag[DISLMDB_QUIC_AEAD_TAG_LEN];
    static const uint8_t empty_plain[1] = {0};
    rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len, nonce,
                                   DISLMDB_QUIC_INITIAL_IV_LEN, aad, aad_len,
                                   plain ? plain : empty_plain, out,
                                   DISLMDB_QUIC_AEAD_TAG_LEN, tag);
    mbedtls_gcm_free(&gcm);
    if (rc != 0) {
        return -1;
    }
    memcpy(out + plain_len, tag, DISLMDB_QUIC_AEAD_TAG_LEN);
    *out_len = plain_len + DISLMDB_QUIC_AEAD_TAG_LEN;
    return 0;
}

int dislmdb_quic_aead_open(const dislmdb_quic_initial_keys *keys, uint64_t pn,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *cipher, size_t cipher_len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!keys || !cipher || !out || !out_len ||
        cipher_len < DISLMDB_QUIC_AEAD_TAG_LEN || (aad_len > 0 && !aad)) {
        return -1;
    }
    size_t plain_len = cipher_len - DISLMDB_QUIC_AEAD_TAG_LEN;
    if (out_cap < plain_len) {
        return -1;
    }
    uint8_t nonce[DISLMDB_QUIC_INITIAL_IV_LEN];
    quic_nonce(keys->iv, pn, nonce);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, keys->key, 128);
    if (rc != 0) {
        mbedtls_gcm_free(&gcm);
        return -1;
    }
    rc = mbedtls_gcm_auth_decrypt(&gcm, plain_len, nonce, DISLMDB_QUIC_INITIAL_IV_LEN,
                                  aad, aad_len, cipher + plain_len,
                                  DISLMDB_QUIC_AEAD_TAG_LEN, cipher, out);
    mbedtls_gcm_free(&gcm);
    if (rc != 0) {
        return -1;
    }
    *out_len = plain_len;
    return 0;
}

int dislmdb_quic_hp_mask(const uint8_t hp[DISLMDB_QUIC_INITIAL_KEY_LEN],
                         const uint8_t sample[16], uint8_t mask[5])
{
    if (!hp || !sample || !mask) {
        return -1;
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int rc = mbedtls_aes_setkey_enc(&aes, hp, 128);
    if (rc != 0) {
        mbedtls_aes_free(&aes);
        return -1;
    }
    uint8_t block[16];
    rc = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, sample, block);
    mbedtls_aes_free(&aes);
    if (rc != 0) {
        return -1;
    }
    memcpy(mask, block, 5);
    return 0;
}

int dislmdb_quic_encode_initial_header(uint32_t version,
                                       const uint8_t *dcid, size_t dcid_len,
                                       const uint8_t *scid, size_t scid_len,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    if (!out || !out_len || dcid_len > DISLMDB_QUIC_MAX_CID_LEN ||
        scid_len > DISLMDB_QUIC_MAX_CID_LEN) {
        return -1;
    }
    if ((dcid_len > 0 && !dcid) || (scid_len > 0 && !scid)) {
        return -1;
    }
    size_t need = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2 + 1;
    if (need > out_cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = (uint8_t)(0xC0u | ((unsigned)DISLMDB_QUIC_LONG_INITIAL << 4));
    dislmdb_write_u32(out + o, version);
    o += 4;
    out[o++] = (uint8_t)dcid_len;
    if (dcid_len > 0) {
        memcpy(out + o, dcid, dcid_len);
        o += dcid_len;
    }
    out[o++] = (uint8_t)scid_len;
    if (scid_len > 0) {
        memcpy(out + o, scid, scid_len);
        o += scid_len;
    }
    out[o++] = 0;
    out[o++] = 0x40;
    out[o++] = 0x01;
    out[o++] = 0;
    *out_len = o;
    return 0;
}

int dislmdb_quic_conn_init(dislmdb_quic_conn *conn, bool is_server,
                           const uint8_t *dcid, size_t dcid_len,
                           const uint8_t *scid, size_t scid_len)
{
    if (!conn || !dcid || dcid_len == 0 || dcid_len > DISLMDB_QUIC_MAX_CID_LEN ||
        scid_len > DISLMDB_QUIC_MAX_CID_LEN || (scid_len > 0 && !scid)) {
        return -1;
    }
    memset(conn, 0, sizeof(*conn));
    conn->is_server = is_server;
    conn->state = DISLMDB_QUIC_HS_INITIAL;
    conn->dcid_len = dcid_len;
    memcpy(conn->dcid, dcid, dcid_len);
    conn->scid_len = scid_len;
    if (scid_len > 0) {
        memcpy(conn->scid, scid, scid_len);
    }
    if (dislmdb_quic_derive_initial_keys(dcid, dcid_len, &conn->client_in,
                                         &conn->server_in) != 0) {
        return -1;
    }
    conn->next_pn_out = 0;
    return 0;
}

void dislmdb_quic_conn_reset(dislmdb_quic_conn *conn)
{
    if (!conn) {
        return;
    }
    memset(conn, 0, sizeof(*conn));
    conn->state = DISLMDB_QUIC_HS_CLOSED;
}

int dislmdb_quic_build_initial_packet(const dislmdb_quic_conn *conn,
                                      bool from_client, uint64_t pn,
                                      const uint8_t *crypto, size_t crypto_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!conn || !out || !out_len || (crypto_len > 0 && !crypto) || pn > 0xffu) {
        return -1;
    }
    const dislmdb_quic_initial_keys *keys =
        from_client ? &conn->client_in : &conn->server_in;

    uint8_t frame[8192];
    size_t frame_len = 0;
    if (dislmdb_quic_encode_crypto_frame(0, crypto, crypto_len, frame,
                                         sizeof(frame), &frame_len) != 0) {
        return -1;
    }

    /* Header skeleton: pn_len=1 encoded in low 2 bits of first byte (=0). */
    size_t hdr_cap = 1 + 4 + 1 + conn->dcid_len + 1 + conn->scid_len + 1 + 8 + 1;
    uint8_t *hdr = malloc(hdr_cap);
    if (!hdr) {
        return -1;
    }
    size_t o = 0;
    hdr[o++] = (uint8_t)(0xC0u | ((unsigned)DISLMDB_QUIC_LONG_INITIAL << 4) | 0x00u);
    dislmdb_write_u32(hdr + o, DISLMDB_QUIC_VERSION);
    o += 4;
    hdr[o++] = (uint8_t)conn->dcid_len;
    memcpy(hdr + o, conn->dcid, conn->dcid_len);
    o += conn->dcid_len;
    hdr[o++] = (uint8_t)conn->scid_len;
    if (conn->scid_len > 0) {
        memcpy(hdr + o, conn->scid, conn->scid_len);
        o += conn->scid_len;
    }
    hdr[o++] = 0; /* token length */

    size_t length_field = 1 /* pn */ + frame_len + DISLMDB_QUIC_AEAD_TAG_LEN;
    uint8_t lenb[8];
    size_t lenn = 0;
    if (dislmdb_quic_varint_encode(length_field, lenb, sizeof(lenb), &lenn) != 0) {
        free(hdr);
        return -1;
    }
    if (o + lenn + 1 > hdr_cap) {
        free(hdr);
        return -1;
    }
    memcpy(hdr + o, lenb, lenn);
    o += lenn;
    size_t pn_offset = o;
    hdr[o++] = (uint8_t)(pn & 0xffu);
    size_t hdr_len = o;

    uint8_t *sealed = malloc(frame_len + DISLMDB_QUIC_AEAD_TAG_LEN);
    if (!sealed) {
        free(hdr);
        return -1;
    }
    size_t sealed_len = 0;
    if (dislmdb_quic_aead_seal(keys, pn, hdr, hdr_len, frame, frame_len, sealed,
                               frame_len + DISLMDB_QUIC_AEAD_TAG_LEN,
                               &sealed_len) != 0) {
        free(sealed);
        free(hdr);
        return -1;
    }

    size_t total = hdr_len + sealed_len;
    if (total > out_cap) {
        free(sealed);
        free(hdr);
        return -1;
    }
    memcpy(out, hdr, hdr_len);
    memcpy(out + hdr_len, sealed, sealed_len);
    free(sealed);
    free(hdr);

    /* Header protection: sample starts 4 bytes after pn start in ciphertext. */
    if (sealed_len < 20) {
        return -1;
    }
    const uint8_t *sample = out + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        return -1;
    }
    out[0] ^= (uint8_t)(mask[0] & 0x0fu); /* long header: protect low 4 bits */
    out[pn_offset] ^= mask[1];

    *out_len = total;
    return 0;
}

int dislmdb_quic_open_initial_packet(const dislmdb_quic_conn *conn,
                                     bool from_client, const uint8_t *pkt,
                                     size_t pkt_len, uint64_t *pn_out,
                                     uint8_t *crypto_out, size_t crypto_cap,
                                     size_t *crypto_len)
{
    if (!conn || !pkt || !pn_out || !crypto_out || !crypto_len || pkt_len < 20) {
        return -1;
    }
    const dislmdb_quic_initial_keys *keys =
        from_client ? &conn->client_in : &conn->server_in;

    dislmdb_quic_long_header lh;
    if (dislmdb_quic_parse_long_header(pkt, pkt_len, &lh) != 0 ||
        lh.type != DISLMDB_QUIC_LONG_INITIAL) {
        return -1;
    }
    size_t o = lh.header_len;
    /* token length */
    uint64_t token_len = 0;
    size_t tc = 0;
    if (dislmdb_quic_varint_decode(pkt + o, pkt_len - o, &token_len, &tc) != 0) {
        return -1;
    }
    o += tc + (size_t)token_len;
    uint64_t length_field = 0;
    size_t lc = 0;
    if (dislmdb_quic_varint_decode(pkt + o, pkt_len - o, &length_field, &lc) != 0) {
        return -1;
    }
    o += lc;
    size_t pn_offset = o;
    if (pn_offset + 1 + DISLMDB_QUIC_AEAD_TAG_LEN > pkt_len) {
        return -1;
    }

    /* Copy so we can remove HP in place for AAD reconstruction. */
    uint8_t *work = malloc(pkt_len);
    if (!work) {
        return -1;
    }
    memcpy(work, pkt, pkt_len);

    if (pkt_len < pn_offset + 4 + 16) {
        free(work);
        return -1;
    }
    const uint8_t *sample = work + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        free(work);
        return -1;
    }
    work[0] ^= (uint8_t)(mask[0] & 0x0fu);
    size_t pn_len = (size_t)((work[0] & 0x03u) + 1u);
    if (pn_len != 1 || pn_offset + pn_len > pkt_len) {
        free(work);
        return -1;
    }
    work[pn_offset] ^= mask[1];
    uint64_t pn = work[pn_offset];

    size_t hdr_len = pn_offset + pn_len;
    /* length_field = pn_len + ciphertext(payload||tag). */
    if (length_field < pn_len ||
        hdr_len + ((size_t)length_field - pn_len) > pkt_len) {
        free(work);
        return -1;
    }
    size_t ct_len = (size_t)length_field - pn_len;
    if (ct_len < DISLMDB_QUIC_AEAD_TAG_LEN) {
        free(work);
        return -1;
    }

    uint8_t *plain = malloc(ct_len);
    if (!plain) {
        free(work);
        return -1;
    }
    size_t plain_len = 0;
    if (dislmdb_quic_aead_open(keys, pn, work, hdr_len, work + hdr_len, ct_len,
                               plain, ct_len, &plain_len) != 0) {
        free(plain);
        free(work);
        return -1;
    }
    free(work);

    uint64_t coff = 0;
    const uint8_t *cpay = NULL;
    size_t clen = 0, consumed = 0;
    if (dislmdb_quic_decode_crypto_frame(plain, plain_len, &coff, &cpay, &clen,
                                         &consumed) != 0) {
        free(plain);
        return -1;
    }
    if (coff != 0 || clen > crypto_cap) {
        free(plain);
        return -1;
    }
    if (clen > 0) {
        memcpy(crypto_out, cpay, clen);
    }
    *crypto_len = clen;
    *pn_out = pn;
    free(plain);
    return 0;
}

int dislmdb_quic_build_handshake_packet(const dislmdb_quic_conn *conn,
                                        bool from_client, uint64_t pn,
                                        const uint8_t *crypto, size_t crypto_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (!conn || !conn->has_handshake_keys || !out || !out_len ||
        (crypto_len > 0 && !crypto) || pn > 0xffu) {
        return -1;
    }
    const dislmdb_quic_traffic_keys *keys =
        from_client ? &conn->client_hs : &conn->server_hs;

    size_t frame_cap = crypto_len + 64;
    if (frame_cap < 256) {
        frame_cap = 256;
    }
    uint8_t *frame = malloc(frame_cap);
    if (!frame) {
        return -1;
    }
    size_t frame_len = 0;
    if (dislmdb_quic_encode_crypto_frame(0, crypto, crypto_len, frame, frame_cap,
                                         &frame_len) != 0) {
        free(frame);
        return -1;
    }

    /* Handshake long header: no token field (RFC 9000 §17.2.4). */
    size_t hdr_cap = 1 + 4 + 1 + conn->dcid_len + 1 + conn->scid_len + 8 + 1;
    uint8_t *hdr = malloc(hdr_cap);
    if (!hdr) {
        free(frame);
        return -1;
    }
    size_t o = 0;
    hdr[o++] =
        (uint8_t)(0xC0u | ((unsigned)DISLMDB_QUIC_LONG_HANDSHAKE << 4) | 0x00u);
    dislmdb_write_u32(hdr + o, DISLMDB_QUIC_VERSION);
    o += 4;
    hdr[o++] = (uint8_t)conn->dcid_len;
    memcpy(hdr + o, conn->dcid, conn->dcid_len);
    o += conn->dcid_len;
    hdr[o++] = (uint8_t)conn->scid_len;
    if (conn->scid_len > 0) {
        memcpy(hdr + o, conn->scid, conn->scid_len);
        o += conn->scid_len;
    }

    size_t length_field = 1 /* pn */ + frame_len + DISLMDB_QUIC_AEAD_TAG_LEN;
    uint8_t lenb[8];
    size_t lenn = 0;
    if (dislmdb_quic_varint_encode(length_field, lenb, sizeof(lenb), &lenn) != 0) {
        free(frame);
        free(hdr);
        return -1;
    }
    if (o + lenn + 1 > hdr_cap) {
        free(frame);
        free(hdr);
        return -1;
    }
    memcpy(hdr + o, lenb, lenn);
    o += lenn;
    size_t pn_offset = o;
    hdr[o++] = (uint8_t)(pn & 0xffu);
    size_t hdr_len = o;

    uint8_t *sealed = malloc(frame_len + DISLMDB_QUIC_AEAD_TAG_LEN);
    if (!sealed) {
        free(frame);
        free(hdr);
        return -1;
    }
    size_t sealed_len = 0;
    if (dislmdb_quic_aead_seal(keys, pn, hdr, hdr_len, frame, frame_len, sealed,
                               frame_len + DISLMDB_QUIC_AEAD_TAG_LEN,
                               &sealed_len) != 0) {
        free(sealed);
        free(frame);
        free(hdr);
        return -1;
    }
    free(frame);

    size_t total = hdr_len + sealed_len;
    if (total > out_cap || sealed_len < 20) {
        free(sealed);
        free(hdr);
        return -1;
    }
    memcpy(out, hdr, hdr_len);
    memcpy(out + hdr_len, sealed, sealed_len);
    free(sealed);
    free(hdr);

    const uint8_t *sample = out + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        return -1;
    }
    out[0] ^= (uint8_t)(mask[0] & 0x0fu);
    out[pn_offset] ^= mask[1];

    *out_len = total;
    return 0;
}

int dislmdb_quic_open_handshake_packet(const dislmdb_quic_conn *conn,
                                       bool from_client, const uint8_t *pkt,
                                       size_t pkt_len, uint64_t *pn_out,
                                       uint8_t *crypto_out, size_t crypto_cap,
                                       size_t *crypto_len)
{
    if (!conn || !conn->has_handshake_keys || !pkt || !pn_out || !crypto_out ||
        !crypto_len || pkt_len < 20) {
        return -1;
    }
    const dislmdb_quic_traffic_keys *keys =
        from_client ? &conn->client_hs : &conn->server_hs;

    dislmdb_quic_long_header lh;
    if (dislmdb_quic_parse_long_header(pkt, pkt_len, &lh) != 0 ||
        lh.type != DISLMDB_QUIC_LONG_HANDSHAKE) {
        return -1;
    }
    size_t o = lh.header_len;
    uint64_t length_field = 0;
    size_t lc = 0;
    if (dislmdb_quic_varint_decode(pkt + o, pkt_len - o, &length_field, &lc) != 0) {
        return -1;
    }
    o += lc;
    size_t pn_offset = o;
    if (pn_offset + 1 + DISLMDB_QUIC_AEAD_TAG_LEN > pkt_len) {
        return -1;
    }

    uint8_t *work = malloc(pkt_len);
    if (!work) {
        return -1;
    }
    memcpy(work, pkt, pkt_len);

    if (pkt_len < pn_offset + 4 + 16) {
        free(work);
        return -1;
    }
    const uint8_t *sample = work + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        free(work);
        return -1;
    }
    work[0] ^= (uint8_t)(mask[0] & 0x0fu);
    size_t pn_len = (size_t)((work[0] & 0x03u) + 1u);
    if (pn_len != 1 || pn_offset + pn_len > pkt_len) {
        free(work);
        return -1;
    }
    work[pn_offset] ^= mask[1];
    uint64_t pn = work[pn_offset];

    size_t hdr_len = pn_offset + pn_len;
    if (length_field < pn_len ||
        hdr_len + ((size_t)length_field - pn_len) > pkt_len) {
        free(work);
        return -1;
    }
    size_t ct_len = (size_t)length_field - pn_len;
    if (ct_len < DISLMDB_QUIC_AEAD_TAG_LEN) {
        free(work);
        return -1;
    }

    uint8_t *plain = malloc(ct_len);
    if (!plain) {
        free(work);
        return -1;
    }
    size_t plain_len = 0;
    if (dislmdb_quic_aead_open(keys, pn, work, hdr_len, work + hdr_len, ct_len,
                               plain, ct_len, &plain_len) != 0) {
        free(plain);
        free(work);
        return -1;
    }
    free(work);

    uint64_t coff = 0;
    const uint8_t *cpay = NULL;
    size_t clen = 0, consumed = 0;
    if (dislmdb_quic_decode_crypto_frame(plain, plain_len, &coff, &cpay, &clen,
                                         &consumed) != 0) {
        free(plain);
        return -1;
    }
    if (coff != 0 || clen > crypto_cap) {
        free(plain);
        return -1;
    }
    if (clen > 0) {
        memcpy(crypto_out, cpay, clen);
    }
    *crypto_len = clen;
    *pn_out = pn;
    free(plain);
    return 0;
}

int dislmdb_quic_build_one_rtt_packet(const dislmdb_quic_conn *conn,
                                      bool from_client, uint64_t pn,
                                      const uint8_t *crypto, size_t crypto_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!conn || !conn->has_app_keys || !out || !out_len ||
        (crypto_len > 0 && !crypto) || pn > 0xffu || conn->dcid_len == 0) {
        return -1;
    }
    const dislmdb_quic_traffic_keys *keys =
        from_client ? &conn->client_app : &conn->server_app;

    uint8_t frame[2048];
    size_t frame_len = 0;
    if (dislmdb_quic_encode_crypto_frame(0, crypto, crypto_len, frame,
                                         sizeof(frame), &frame_len) != 0) {
        return -1;
    }

    /* Short header: DCID = peer (conn->dcid). */
    size_t hdr_len = 1 + conn->dcid_len + 1;
    if (hdr_len + frame_len + DISLMDB_QUIC_AEAD_TAG_LEN > out_cap) {
        return -1;
    }
    size_t o = 0;
    out[o++] = 0x40; /* short, fixed bit, pn_len=1 */
    memcpy(out + o, conn->dcid, conn->dcid_len);
    o += conn->dcid_len;
    size_t pn_offset = o;
    out[o++] = (uint8_t)(pn & 0xffu);

    uint8_t sealed[2048 + DISLMDB_QUIC_AEAD_TAG_LEN];
    size_t sealed_len = 0;
    if (dislmdb_quic_aead_seal(keys, pn, out, hdr_len, frame, frame_len, sealed,
                               sizeof(sealed), &sealed_len) != 0) {
        return -1;
    }
    if (hdr_len + sealed_len > out_cap || sealed_len < 20) {
        return -1;
    }
    memcpy(out + hdr_len, sealed, sealed_len);

    const uint8_t *sample = out + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        return -1;
    }
    out[0] ^= (uint8_t)(mask[0] & 0x1fu); /* short: protect low 5 bits */
    out[pn_offset] ^= mask[1];

    *out_len = hdr_len + sealed_len;
    return 0;
}

int dislmdb_quic_open_one_rtt_packet(const dislmdb_quic_conn *conn,
                                     bool from_client, const uint8_t *pkt,
                                     size_t pkt_len, uint64_t *pn_out,
                                     uint8_t *crypto_out, size_t crypto_cap,
                                     size_t *crypto_len)
{
    /* Inbound short-header DCID is our SCID. */
    if (!conn || !conn->has_app_keys || !pkt || !pn_out || !crypto_out ||
        !crypto_len || conn->scid_len == 0 ||
        pkt_len < 1 + conn->scid_len + 1 + DISLMDB_QUIC_AEAD_TAG_LEN) {
        return -1;
    }
    if ((pkt[0] & 0x80u) != 0) {
        return -1; /* long header */
    }
    if (memcmp(pkt + 1, conn->scid, conn->scid_len) != 0) {
        return -1;
    }
    const dislmdb_quic_traffic_keys *keys =
        from_client ? &conn->client_app : &conn->server_app;

    uint8_t *work = malloc(pkt_len);
    if (!work) {
        return -1;
    }
    memcpy(work, pkt, pkt_len);

    size_t pn_offset = 1 + conn->scid_len;
    if (pkt_len < pn_offset + 4 + 16) {
        free(work);
        return -1;
    }
    const uint8_t *sample = work + pn_offset + 4;
    uint8_t mask[5];
    if (dislmdb_quic_hp_mask(keys->hp, sample, mask) != 0) {
        free(work);
        return -1;
    }
    work[0] ^= (uint8_t)(mask[0] & 0x1fu);
    size_t pn_len = (size_t)((work[0] & 0x03u) + 1u);
    if (pn_len != 1 || pn_offset + pn_len > pkt_len) {
        free(work);
        return -1;
    }
    work[pn_offset] ^= mask[1];
    uint64_t pn = work[pn_offset];
    size_t hdr_len = pn_offset + pn_len;
    size_t ct_len = pkt_len - hdr_len;
    if (ct_len < DISLMDB_QUIC_AEAD_TAG_LEN) {
        free(work);
        return -1;
    }

    uint8_t plain[2048];
    size_t plain_len = 0;
    if (dislmdb_quic_aead_open(keys, pn, work, hdr_len, work + hdr_len, ct_len,
                               plain, sizeof(plain), &plain_len) != 0) {
        free(work);
        return -1;
    }
    free(work);

    uint64_t coff = 0;
    const uint8_t *cpay = NULL;
    size_t clen = 0, consumed = 0;
    if (dislmdb_quic_decode_crypto_frame(plain, plain_len, &coff, &cpay, &clen,
                                         &consumed) != 0) {
        return -1;
    }
    if (coff != 0 || clen > crypto_cap) {
        return -1;
    }
    if (clen > 0) {
        memcpy(crypto_out, cpay, clen);
    }
    *crypto_len = clen;
    *pn_out = pn;
    return 0;
}
