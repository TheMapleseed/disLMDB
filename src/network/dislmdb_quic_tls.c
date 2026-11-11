/**
 * @file dislmdb_quic_tls.c
 * @brief TLS 1.3 CH..Finished + X.509 CertificateVerify + HS/1-RTT keys
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#include "dislmdb_quic.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

#include "dislmdb_crypto.h"

struct dislmdb_quic_tls_identity {
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_key;
    mbedtls_x509_crt ca_cert;
    bool has_ca;
    uint8_t *leaf_der;
    size_t leaf_der_len;
};

/* From dislmdb_quic.c */
int dislmdb_quic_hkdf_extract(const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t prk[32]);
int dislmdb_quic_hkdf_expand_label(const uint8_t secret[32], const char *label,
                                   const uint8_t *context, size_t context_len,
                                   uint8_t *out, size_t out_len);

static int extract_cert_leaf(const uint8_t *cert_msg, size_t cert_len,
                             const uint8_t **leaf, size_t *leaf_len);

static void write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void write_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 16) & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)(v & 0xffu);
}

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

int dislmdb_quic_tls_encode_message(uint8_t type, const uint8_t *body,
                                    size_t body_len, uint8_t *out,
                                    size_t out_cap, size_t *out_len)
{
    if (!out || !out_len || body_len > 0xffffffu || (body_len > 0 && !body)) {
        return -1;
    }
    if (out_cap < 4 + body_len) {
        return -1;
    }
    out[0] = type;
    write_u24(out + 1, (uint32_t)body_len);
    if (body_len > 0) {
        memcpy(out + 4, body, body_len);
    }
    *out_len = 4 + body_len;
    return 0;
}

int dislmdb_quic_tls_parse_message(const uint8_t *data, size_t len,
                                   dislmdb_quic_tls_message *out)
{
    if (!data || !out || len < 4) {
        return -1;
    }
    uint32_t blen = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    if (4 + blen > len) {
        return -1;
    }
    out->type = data[0];
    out->body = data + 4;
    out->body_len = blen;
    out->total_len = 4 + blen;
    return 0;
}

static int append_ext(uint8_t *buf, size_t cap, size_t *o, uint16_t type,
                      const uint8_t *data, size_t data_len)
{
    if (*o + 4 + data_len > cap) {
        return -1;
    }
    write_u16(buf + *o, type);
    *o += 2;
    write_u16(buf + *o, (uint16_t)data_len);
    *o += 2;
    if (data_len > 0) {
        memcpy(buf + *o, data, data_len);
        *o += data_len;
    }
    return 0;
}

int dislmdb_quic_tls_encode_client_hello(const uint8_t random32[32],
                                         const uint8_t x25519_pub[32],
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len)
{
    if (!random32 || !x25519_pub || !out || !out_len) {
        return -1;
    }
    uint8_t body[512];
    size_t o = 0;
    write_u16(body + o, 0x0303); /* legacy_version */
    o += 2;
    memcpy(body + o, random32, 32);
    o += 32;
    body[o++] = 0; /* session_id empty */
    write_u16(body + o, 2); /* cipher_suites len */
    o += 2;
    write_u16(body + o, (uint16_t)DISLMDB_QUIC_TLS_CIPHER_AES_128_GCM_SHA256);
    o += 2;
    body[o++] = 1;
    body[o++] = 0; /* null compression */

    uint8_t exts[256];
    size_t eo = 0;
    /* supported_versions */
    uint8_t vers[3] = {0x02, 0x03, 0x04};
    if (append_ext(exts, sizeof(exts), &eo, 0x002b, vers, sizeof(vers)) != 0) {
        return -1;
    }
    /* supported_groups */
    uint8_t groups[4];
    write_u16(groups, 2);
    write_u16(groups + 2, (uint16_t)DISLMDB_QUIC_TLS_GROUP_X25519);
    if (append_ext(exts, sizeof(exts), &eo, 0x000a, groups, 4) != 0) {
        return -1;
    }
    /* key_share: client_shares */
    uint8_t ks[2 + 2 + 2 + 32];
    write_u16(ks, 2 + 2 + 32); /* client_shares length */
    write_u16(ks + 2, (uint16_t)DISLMDB_QUIC_TLS_GROUP_X25519);
    write_u16(ks + 4, 32);
    memcpy(ks + 6, x25519_pub, 32);
    if (append_ext(exts, sizeof(exts), &eo, 0x0033, ks, sizeof(ks)) != 0) {
        return -1;
    }

    if (o + 2 + eo > sizeof(body)) {
        return -1;
    }
    write_u16(body + o, (uint16_t)eo);
    o += 2;
    memcpy(body + o, exts, eo);
    o += eo;
    return dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_CLIENT_HELLO, body, o,
                                           out, out_cap, out_len);
}

int dislmdb_quic_tls_encode_server_hello(const uint8_t random32[32],
                                         const uint8_t x25519_pub[32],
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len)
{
    if (!random32 || !x25519_pub || !out || !out_len) {
        return -1;
    }
    uint8_t body[512];
    size_t o = 0;
    write_u16(body + o, 0x0303);
    o += 2;
    memcpy(body + o, random32, 32);
    o += 32;
    body[o++] = 0; /* session_id echo empty */
    write_u16(body + o, (uint16_t)DISLMDB_QUIC_TLS_CIPHER_AES_128_GCM_SHA256);
    o += 2;
    body[o++] = 0; /* compression */

    uint8_t exts[128];
    size_t eo = 0;
    uint8_t vers[2] = {0x03, 0x04};
    if (append_ext(exts, sizeof(exts), &eo, 0x002b, vers, sizeof(vers)) != 0) {
        return -1;
    }
    uint8_t ks[2 + 2 + 32];
    write_u16(ks, (uint16_t)DISLMDB_QUIC_TLS_GROUP_X25519);
    write_u16(ks + 2, 32);
    memcpy(ks + 4, x25519_pub, 32);
    if (append_ext(exts, sizeof(exts), &eo, 0x0033, ks, sizeof(ks)) != 0) {
        return -1;
    }
    if (o + 2 + eo > sizeof(body)) {
        return -1;
    }
    write_u16(body + o, (uint16_t)eo);
    o += 2;
    memcpy(body + o, exts, eo);
    o += eo;
    return dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_SERVER_HELLO, body, o,
                                           out, out_cap, out_len);
}

int dislmdb_quic_tls_extract_x25519_share(const uint8_t *hs_msg, size_t hs_len,
                                          uint8_t pub_out[32])
{
    if (!hs_msg || !pub_out || hs_len < 4) {
        return -1;
    }
    dislmdb_quic_tls_message msg;
    if (dislmdb_quic_tls_parse_message(hs_msg, hs_len, &msg) != 0) {
        return -1;
    }
    const uint8_t *p = msg.body;
    size_t len = msg.body_len;
    if (len < 2 + 32 + 1 + 2 + 1) {
        return -1;
    }
    /* Skip legacy_version + random */
    p += 2 + 32;
    len -= 2 + 32;
    if (len < 1) {
        return -1;
    }
    uint8_t sid_len = p[0];
    p += 1 + sid_len;
    len -= 1 + (size_t)sid_len;
    if (msg.type == DISLMDB_QUIC_TLS_CLIENT_HELLO) {
        if (len < 2) {
            return -1;
        }
        uint16_t cs_len = read_u16(p);
        p += 2 + cs_len;
        len -= 2 + cs_len;
        if (len < 1) {
            return -1;
        }
        uint8_t cm_len = p[0];
        p += 1 + cm_len;
        len -= 1 + (size_t)cm_len;
    } else if (msg.type == DISLMDB_QUIC_TLS_SERVER_HELLO) {
        if (len < 3) {
            return -1;
        }
        p += 2; /* cipher */
        len -= 2;
        p += 1; /* compression */
        len -= 1;
    } else {
        return -1;
    }
    if (len < 2) {
        return -1;
    }
    uint16_t ext_len = read_u16(p);
    p += 2;
    len -= 2;
    if (ext_len > len) {
        return -1;
    }
    size_t end = ext_len;
    size_t o = 0;
    while (o + 4 <= end) {
        uint16_t et = read_u16(p + o);
        uint16_t el = read_u16(p + o + 2);
        o += 4;
        if (o + el > end) {
            return -1;
        }
        if (et == 0x0033) {
            const uint8_t *ks = p + o;
            size_t ksl = el;
            if (msg.type == DISLMDB_QUIC_TLS_CLIENT_HELLO) {
                if (ksl < 2) {
                    return -1;
                }
                uint16_t shares = read_u16(ks);
                if (shares + 2 > ksl) {
                    return -1;
                }
                size_t so = 2;
                while (so + 4 <= 2 + shares) {
                    uint16_t grp = read_u16(ks + so);
                    uint16_t kl = read_u16(ks + so + 2);
                    so += 4;
                    if (so + kl > 2 + shares) {
                        return -1;
                    }
                    if (grp == DISLMDB_QUIC_TLS_GROUP_X25519 && kl == 32) {
                        memcpy(pub_out, ks + so, 32);
                        return 0;
                    }
                    so += kl;
                }
            } else {
                if (ksl < 4 + 32) {
                    return -1;
                }
                uint16_t grp = read_u16(ks);
                uint16_t kl = read_u16(ks + 2);
                if (grp == DISLMDB_QUIC_TLS_GROUP_X25519 && kl == 32 &&
                    4 + kl <= ksl) {
                    memcpy(pub_out, ks + 4, 32);
                    return 0;
                }
            }
        }
        o += el;
    }
    return -1;
}

static int x25519_rng(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return dislmdb_crypto_random_bytes(out, len) == 0 ? 0 : -1;
}

int dislmdb_quic_x25519_keypair(uint8_t priv_out[32], uint8_t pub_out[32])
{
    if (!priv_out || !pub_out) {
        return -1;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) {
        rc = mbedtls_ecdh_gen_public(&grp, &d, &Q, x25519_rng, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary_le(&d, priv_out, 32);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), pub_out, 32);
    }
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32],
                               uint8_t shared_out[32])
{
    if (!priv || !peer_pub || !shared_out) {
        return -1;
    }
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Qp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Qp);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary_le(&d, priv, 32);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary_le(&Qp.MBEDTLS_PRIVATE(X), peer_pub, 32);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1);
    }
    if (rc == 0) {
        rc = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, x25519_rng, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary_le(&z, shared_out, 32);
    }
    mbedtls_ecp_point_free(&Qp);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? 0 : -1;
}

static int derive_secret(const uint8_t secret[32], const char *label,
                         const uint8_t *transcript_hash, size_t hash_len,
                         uint8_t out[32])
{
    return dislmdb_quic_hkdf_expand_label(secret, label, transcript_hash, hash_len,
                                          out, 32);
}

int dislmdb_quic_tls_advance_keys(dislmdb_quic_conn *conn,
                                  const uint8_t shared_secret[32],
                                  const uint8_t *client_hello, size_t ch_len,
                                  const uint8_t *server_hello, size_t sh_len,
                                  bool derive_app)
{
    if (!conn || !shared_secret || !client_hello || !server_hello || ch_len == 0 ||
        sh_len == 0) {
        return -1;
    }

    uint8_t early_secret[32];
    static const uint8_t zeros[32] = {0};
    if (dislmdb_quic_hkdf_extract(zeros, 32, zeros, 32, early_secret) != 0) {
        return -1;
    }
    /* Derive-Secret(Early, "derived", "") — context is Hash("") */
    uint8_t empty_hash[32];
    if (dislmdb_crypto_sha256("", 0, empty_hash) != 0) {
        return -1;
    }
    uint8_t derived[32];
    if (dislmdb_quic_hkdf_expand_label(early_secret, "derived", empty_hash, 32,
                                       derived, 32) != 0) {
        return -1;
    }

    uint8_t handshake_secret[32];
    if (dislmdb_quic_hkdf_extract(derived, 32, shared_secret, 32,
                                  handshake_secret) != 0) {
        return -1;
    }

    uint8_t *transcript = malloc(ch_len + sh_len);
    if (!transcript) {
        return -1;
    }
    memcpy(transcript, client_hello, ch_len);
    memcpy(transcript + ch_len, server_hello, sh_len);
    uint8_t th_hs[32];
    if (dislmdb_crypto_sha256(transcript, ch_len + sh_len, th_hs) != 0) {
        free(transcript);
        return -1;
    }

    uint8_t client_hs_sec[32], server_hs_sec[32];
    if (derive_secret(handshake_secret, "c hs traffic", th_hs, 32, client_hs_sec) !=
            0 ||
        derive_secret(handshake_secret, "s hs traffic", th_hs, 32, server_hs_sec) !=
            0) {
        free(transcript);
        return -1;
    }
    if (dislmdb_quic_traffic_keys_from_secret(client_hs_sec, &conn->client_hs) != 0 ||
        dislmdb_quic_traffic_keys_from_secret(server_hs_sec, &conn->server_hs) != 0) {
        free(transcript);
        return -1;
    }
    memcpy(conn->client_hs_secret, client_hs_sec, 32);
    memcpy(conn->server_hs_secret, server_hs_sec, 32);
    memcpy(conn->handshake_secret, handshake_secret, 32);
    conn->has_handshake_keys = true;
    conn->state = DISLMDB_QUIC_HS_HANDSHAKE;

    if (derive_app) {
        /* Legacy path: synthetic Finished — prefer install_app_keys. */
        uint8_t fin[4 + DISLMDB_QUIC_TLS_FINISHED_LEN];
        fin[0] = DISLMDB_QUIC_TLS_FINISHED;
        write_u24(fin + 1, DISLMDB_QUIC_TLS_FINISHED_LEN);
        memset(fin + 4, 0, DISLMDB_QUIC_TLS_FINISHED_LEN);
        int rc = dislmdb_quic_tls_install_app_keys(conn, client_hello, ch_len,
                                                   server_hello, sh_len, fin,
                                                   sizeof(fin));
        free(transcript);
        return rc;
    }

    free(transcript);
    return 0;
}

int dislmdb_quic_tls_encode_encrypted_extensions(uint8_t *out, size_t out_cap,
                                                 size_t *out_len)
{
    uint8_t body[2] = {0, 0}; /* empty extensions */
    return dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_ENCRYPTED_EXTENSIONS,
                                           body, sizeof(body), out, out_cap,
                                           out_len);
}

int dislmdb_quic_tls_encode_certificate(const uint8_t *cert_der, size_t cert_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (!out || !out_len || (cert_len > 0 && !cert_der)) {
        return -1;
    }
    /* context_len(1)=0 || cert_list_len(3) || [cert_len(3)||cert||exts(2)=0]* */
    size_t body_need = (cert_len == 0) ? 4u : (1u + 3u + 3u + cert_len + 2u);
    if (cert_len > 0xffffffu || body_need > 0xffffffu) {
        return -1;
    }
    uint8_t *body = malloc(body_need);
    if (!body) {
        return -1;
    }
    size_t o = 0;
    body[o++] = 0; /* certificate_request_context empty */
    if (cert_len == 0) {
        write_u24(body + o, 0);
        o += 3;
    } else {
        write_u24(body + o, (uint32_t)(3 + cert_len + 2));
        o += 3;
        write_u24(body + o, (uint32_t)cert_len);
        o += 3;
        memcpy(body + o, cert_der, cert_len);
        o += cert_len;
        write_u16(body + o, 0); /* empty extensions per entry */
        o += 2;
    }
    int rc = dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_CERTIFICATE, body, o,
                                             out, out_cap, out_len);
    free(body);
    return rc;
}

static int identity_cache_leaf_der(dislmdb_quic_tls_identity *id)
{
    if (!id || !id->own_cert.raw.p || id->own_cert.raw.len == 0) {
        return -1;
    }
    free(id->leaf_der);
    id->leaf_der = malloc(id->own_cert.raw.len);
    if (!id->leaf_der) {
        id->leaf_der_len = 0;
        return -1;
    }
    memcpy(id->leaf_der, id->own_cert.raw.p, id->own_cert.raw.len);
    id->leaf_der_len = id->own_cert.raw.len;
    return 0;
}

static dislmdb_quic_tls_identity *identity_alloc(void)
{
    dislmdb_quic_tls_identity *id = calloc(1, sizeof(*id));
    if (!id) {
        return NULL;
    }
    mbedtls_x509_crt_init(&id->own_cert);
    mbedtls_pk_init(&id->own_key);
    mbedtls_x509_crt_init(&id->ca_cert);
    return id;
}

void dislmdb_quic_tls_identity_destroy(dislmdb_quic_tls_identity *id)
{
    if (!id) {
        return;
    }
    mbedtls_x509_crt_free(&id->own_cert);
    mbedtls_pk_free(&id->own_key);
    mbedtls_x509_crt_free(&id->ca_cert);
    free(id->leaf_der);
    free(id);
}

dislmdb_quic_tls_identity *dislmdb_quic_tls_identity_load(const char *cert_path,
                                                          const char *key_path,
                                                          const char *ca_path)
{
    if (!cert_path || !key_path || cert_path[0] == '\0' || key_path[0] == '\0') {
        return NULL;
    }
    dislmdb_quic_tls_identity *id = identity_alloc();
    if (!id) {
        return NULL;
    }
    if (mbedtls_x509_crt_parse_file(&id->own_cert, cert_path) != 0 ||
        mbedtls_pk_parse_keyfile(&id->own_key, key_path, NULL, x25519_rng, NULL) !=
            0) {
        dislmdb_quic_tls_identity_destroy(id);
        return NULL;
    }
    if (ca_path && ca_path[0] != '\0') {
        if (mbedtls_x509_crt_parse_file(&id->ca_cert, ca_path) != 0) {
            dislmdb_quic_tls_identity_destroy(id);
            return NULL;
        }
        id->has_ca = true;
    } else {
        /* Trust the leaf itself. */
        if (mbedtls_x509_crt_parse_der(&id->ca_cert, id->own_cert.raw.p,
                                       id->own_cert.raw.len) != 0) {
            dislmdb_quic_tls_identity_destroy(id);
            return NULL;
        }
        id->has_ca = true;
    }
    if (identity_cache_leaf_der(id) != 0) {
        dislmdb_quic_tls_identity_destroy(id);
        return NULL;
    }
    return id;
}

dislmdb_quic_tls_identity *dislmdb_quic_tls_identity_self_signed(const char *cn)
{
    dislmdb_quic_tls_identity *id = identity_alloc();
    if (!id) {
        return NULL;
    }
    const mbedtls_pk_info_t *info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (!info || mbedtls_pk_setup(&id->own_key, info) != 0 ||
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(id->own_key),
                            x25519_rng, NULL) != 0) {
        dislmdb_quic_tls_identity_destroy(id);
        return NULL;
    }

    mbedtls_x509write_cert wrt;
    mbedtls_x509write_crt_init(&wrt);
    mbedtls_x509write_crt_set_md_alg(&wrt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&wrt, &id->own_key);
    mbedtls_x509write_crt_set_issuer_key(&wrt, &id->own_key);
    char subject[128];
    snprintf(subject, sizeof(subject), "CN=%s",
             (cn && cn[0]) ? cn : "dislmdb-quic");
    uint8_t serial[8];
    (void)dislmdb_crypto_random_bytes(serial, sizeof(serial));
    serial[0] |= 0x01;
    int rc = mbedtls_x509write_crt_set_serial_raw(&wrt, serial, sizeof(serial));
    if (rc == 0) {
        rc = mbedtls_x509write_crt_set_subject_name(&wrt, subject);
    }
    if (rc == 0) {
        rc = mbedtls_x509write_crt_set_issuer_name(&wrt, subject);
    }
    if (rc == 0) {
        rc = mbedtls_x509write_crt_set_validity(&wrt, "20240101000000",
                                                "20341231235959");
    }
    if (rc == 0) {
        rc = mbedtls_x509write_crt_set_basic_constraints(&wrt, 0, -1);
    }
    uint8_t der_buf[2048];
    int der_len = -1;
    if (rc == 0) {
        der_len = mbedtls_x509write_crt_der(&wrt, der_buf, sizeof(der_buf),
                                            x25519_rng, NULL);
    }
    mbedtls_x509write_crt_free(&wrt);
    if (der_len <= 0) {
        dislmdb_quic_tls_identity_destroy(id);
        return NULL;
    }
    const uint8_t *der = der_buf + (sizeof(der_buf) - (size_t)der_len);
    if (mbedtls_x509_crt_parse_der(&id->own_cert, der, (size_t)der_len) != 0 ||
        mbedtls_x509_crt_parse_der(&id->ca_cert, der, (size_t)der_len) != 0 ||
        identity_cache_leaf_der(id) != 0) {
        dislmdb_quic_tls_identity_destroy(id);
        return NULL;
    }
    id->has_ca = true;
    return id;
}

int dislmdb_quic_tls_identity_leaf_der(const dislmdb_quic_tls_identity *id,
                                       const uint8_t **der_out, size_t *der_len)
{
    if (!id || !der_out || !der_len || !id->leaf_der || id->leaf_der_len == 0) {
        return -1;
    }
    *der_out = id->leaf_der;
    *der_len = id->leaf_der_len;
    return 0;
}

int dislmdb_quic_tls_identity_sign(const dislmdb_quic_tls_identity *id,
                                   const uint8_t *content, size_t content_len,
                                   uint16_t *scheme_out, uint8_t *sig_out,
                                   size_t sig_cap, size_t *sig_len)
{
    if (!id || !content || !scheme_out || !sig_out || !sig_len || content_len == 0) {
        return -1;
    }
    uint8_t hash[32];
    if (dislmdb_crypto_sha256(content, content_len, hash) != 0) {
        return -1;
    }
    mbedtls_pk_type_t kt = mbedtls_pk_get_type(&id->own_key);
    if (kt == MBEDTLS_PK_ECKEY || kt == MBEDTLS_PK_ECDSA ||
        kt == MBEDTLS_PK_ECKEY_DH) {
        *scheme_out = DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256;
    } else if (kt == MBEDTLS_PK_RSA || kt == MBEDTLS_PK_RSASSA_PSS) {
        *scheme_out = DISLMDB_QUIC_TLS_SIG_RSA_PKCS1_SHA256;
    } else {
        return -1;
    }
    int rc = mbedtls_pk_sign((mbedtls_pk_context *)&id->own_key, MBEDTLS_MD_SHA256,
                             hash, 32, sig_out, sig_cap, sig_len, x25519_rng,
                             NULL);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_tls_verify_peer_certificate(
    const uint8_t *cert_msg, size_t cert_len, const uint8_t *cv_msg,
    size_t cv_len, const uint8_t *content, size_t content_len,
    const dislmdb_quic_tls_identity *trust)
{
    if (!cert_msg || !cv_msg || !content || content_len == 0) {
        return -1;
    }
    const uint8_t *leaf_der = NULL;
    size_t leaf_len = 0;
    if (extract_cert_leaf(cert_msg, cert_len, &leaf_der, &leaf_len) != 0) {
        return -1;
    }
    mbedtls_x509_crt leaf;
    mbedtls_x509_crt_init(&leaf);
    int rc = mbedtls_x509_crt_parse_der(&leaf, leaf_der, leaf_len);
    if (rc != 0) {
        mbedtls_x509_crt_free(&leaf);
        return -1;
    }
    if (trust && trust->has_ca) {
        uint32_t flags = 0;
        rc = mbedtls_x509_crt_verify(&leaf, (mbedtls_x509_crt *)&trust->ca_cert,
                                     NULL, NULL, &flags, NULL, NULL);
        if (rc != 0) {
            mbedtls_x509_crt_free(&leaf);
            return -1;
        }
    }
    /* trust == NULL: TOFU — still require a parseable leaf + valid CV. */

    dislmdb_quic_tls_message msg;
    if (dislmdb_quic_tls_parse_message(cv_msg, cv_len, &msg) != 0 ||
        msg.type != DISLMDB_QUIC_TLS_CERTIFICATE_VERIFY || msg.body_len < 4) {
        mbedtls_x509_crt_free(&leaf);
        return -1;
    }
    uint16_t scheme = read_u16(msg.body);
    uint16_t sig_len = read_u16(msg.body + 2);
    if (4u + (size_t)sig_len != msg.body_len) {
        mbedtls_x509_crt_free(&leaf);
        return -1;
    }
    if (scheme != DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256 &&
        scheme != DISLMDB_QUIC_TLS_SIG_RSA_PKCS1_SHA256) {
        mbedtls_x509_crt_free(&leaf);
        return -1;
    }
    uint8_t hash[32];
    if (dislmdb_crypto_sha256(content, content_len, hash) != 0) {
        mbedtls_x509_crt_free(&leaf);
        return -1;
    }
    rc = mbedtls_pk_verify(&leaf.pk, MBEDTLS_MD_SHA256, hash, 32, msg.body + 4,
                           sig_len);
    mbedtls_x509_crt_free(&leaf);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_ecdsa_p256_keypair(uint8_t priv_out[32], uint8_t pub_out[65])
{
    if (!priv_out || !pub_out) {
        return -1;
    }
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int rc = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, x25519_rng, NULL);
    if (rc == 0) {
        rc = mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(d), priv_out, 32);
    }
    if (rc == 0) {
        size_t olen = 0;
        rc = mbedtls_ecp_point_write_binary(&ctx.MBEDTLS_PRIVATE(grp),
                                            &ctx.MBEDTLS_PRIVATE(Q),
                                            MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                            pub_out, 65);
        if (rc == 0 && olen != 65) {
            rc = -1;
        }
    }
    mbedtls_ecdsa_free(&ctx);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_tls_cert_verify_content(bool server_side,
                                         const uint8_t *transcript,
                                         size_t transcript_len, uint8_t *out,
                                         size_t out_cap, size_t *out_len)
{
    if (!out || !out_len || (transcript_len > 0 && !transcript)) {
        return -1;
    }
    static const char server_ctx[] = "TLS 1.3, server CertificateVerify";
    static const char client_ctx[] = "TLS 1.3, client CertificateVerify";
    const char *ctx = server_side ? server_ctx : client_ctx;
    size_t ctx_len = strlen(ctx);
    size_t need = 64 + ctx_len + 1 + 32;
    if (need > out_cap) {
        return -1;
    }
    uint8_t th[32];
    if (dislmdb_crypto_sha256(transcript ? transcript : (const uint8_t *)"",
                              transcript_len, th) != 0) {
        return -1;
    }
    memset(out, 0x20, 64);
    memcpy(out + 64, ctx, ctx_len);
    out[64 + ctx_len] = 0;
    memcpy(out + 64 + ctx_len + 1, th, 32);
    *out_len = need;
    return 0;
}

int dislmdb_quic_tls_sign_cert_verify(const uint8_t priv[32],
                                      const uint8_t *content, size_t content_len,
                                      uint8_t *sig_out, size_t sig_cap,
                                      size_t *sig_len)
{
    if (!priv || !content || !sig_out || !sig_len || content_len == 0) {
        return -1;
    }
    uint8_t hash[32];
    if (dislmdb_crypto_sha256(content, content_len, hash) != 0) {
        return -1;
    }
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int rc = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp),
                                    MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d), priv, 32);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(&ctx.MBEDTLS_PRIVATE(grp), &ctx.MBEDTLS_PRIVATE(Q),
                             &ctx.MBEDTLS_PRIVATE(d),
                             &ctx.MBEDTLS_PRIVATE(grp).G, x25519_rng, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32,
                                           sig_out, sig_cap, sig_len, x25519_rng,
                                           NULL);
    }
    mbedtls_ecdsa_free(&ctx);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_tls_encode_certificate_verify(uint16_t scheme,
                                               const uint8_t *sig, size_t sig_len,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len)
{
    if (!sig || !out || !out_len || sig_len == 0 || sig_len > 0xffffu) {
        return -1;
    }
    uint8_t *body = malloc(2 + 2 + sig_len);
    if (!body) {
        return -1;
    }
    write_u16(body, scheme);
    write_u16(body + 2, (uint16_t)sig_len);
    memcpy(body + 4, sig, sig_len);
    int rc = dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_CERTIFICATE_VERIFY,
                                             body, 4 + sig_len, out, out_cap,
                                             out_len);
    free(body);
    return rc;
}

int dislmdb_quic_tls_verify_certificate_verify(const uint8_t *cv_msg, size_t cv_len,
                                               const uint8_t pub65[65],
                                               const uint8_t *content,
                                               size_t content_len)
{
    if (!cv_msg || !pub65 || !content || content_len == 0) {
        return -1;
    }
    dislmdb_quic_tls_message msg;
    if (dislmdb_quic_tls_parse_message(cv_msg, cv_len, &msg) != 0) {
        return -1;
    }
    if (msg.type != DISLMDB_QUIC_TLS_CERTIFICATE_VERIFY || msg.body_len < 4) {
        return -1;
    }
    uint16_t scheme = read_u16(msg.body);
    uint16_t sig_len = read_u16(msg.body + 2);
    if (scheme != DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256 ||
        4u + (size_t)sig_len != msg.body_len) {
        return -1;
    }
    const uint8_t *sig = msg.body + 4;
    uint8_t hash[32];
    if (dislmdb_crypto_sha256(content, content_len, hash) != 0) {
        return -1;
    }
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int rc = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp),
                                    MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_ecp_point_read_binary(&ctx.MBEDTLS_PRIVATE(grp),
                                           &ctx.MBEDTLS_PRIVATE(Q), pub65, 65);
    }
    if (rc == 0) {
        rc = mbedtls_ecdsa_read_signature(&ctx, hash, 32, sig, sig_len);
    }
    mbedtls_ecdsa_free(&ctx);
    return rc == 0 ? 0 : -1;
}

int dislmdb_quic_tls_compute_finished(const uint8_t base_secret[32],
                                      const uint8_t *transcript,
                                      size_t transcript_len,
                                      uint8_t verify_out[32])
{
    if (!base_secret || !verify_out || (transcript_len > 0 && !transcript)) {
        return -1;
    }
    uint8_t finished_key[32];
    if (dislmdb_quic_hkdf_expand_label(base_secret, "finished", NULL, 0,
                                       finished_key, 32) != 0) {
        return -1;
    }
    uint8_t th[32];
    if (dislmdb_crypto_sha256(transcript ? transcript : (const uint8_t *)"",
                              transcript_len, th) != 0) {
        return -1;
    }
    return dislmdb_crypto_hmac_sha256(finished_key, 32, th, 32, verify_out) == 0
               ? 0
               : -1;
}

int dislmdb_quic_tls_encode_finished(const uint8_t verify_data[32], uint8_t *out,
                                     size_t out_cap, size_t *out_len)
{
    if (!verify_data) {
        return -1;
    }
    return dislmdb_quic_tls_encode_message(DISLMDB_QUIC_TLS_FINISHED, verify_data,
                                           DISLMDB_QUIC_TLS_FINISHED_LEN, out,
                                           out_cap, out_len);
}

int dislmdb_quic_tls_verify_finished(const uint8_t *finished_msg, size_t fin_len,
                                     const uint8_t expect[32])
{
    if (!finished_msg || !expect) {
        return -1;
    }
    dislmdb_quic_tls_message msg;
    if (dislmdb_quic_tls_parse_message(finished_msg, fin_len, &msg) != 0) {
        return -1;
    }
    if (msg.type != DISLMDB_QUIC_TLS_FINISHED ||
        msg.body_len != DISLMDB_QUIC_TLS_FINISHED_LEN) {
        return -1;
    }
    return dislmdb_crypto_secure_eq(msg.body, expect, DISLMDB_QUIC_TLS_FINISHED_LEN)
               ? 0
               : -1;
}

int dislmdb_quic_server_handle_initial(const uint8_t *pkt, size_t pkt_len,
                                       uint8_t *out_initial, size_t initial_cap,
                                       size_t *out_initial_len,
                                       uint8_t *out_handshake, size_t hs_cap,
                                       size_t *out_handshake_len,
                                       dislmdb_quic_conn *out_conn,
                                       const dislmdb_quic_tls_identity *id)
{
    if (!pkt || !out_initial || !out_initial_len || !out_handshake ||
        !out_handshake_len || pkt_len < 20) {
        return -1;
    }
    dislmdb_quic_tls_identity *ephemeral = NULL;
    if (!id) {
        ephemeral = dislmdb_quic_tls_identity_self_signed("dislmdb-quic");
        if (!ephemeral) {
            return -1;
        }
        id = ephemeral;
    }
    uint8_t *cert = NULL;
    uint8_t *cv_msg = NULL;
    uint8_t *tr_cv = NULL;
    uint8_t *tr_fin = NULL;
    uint8_t *post = NULL;
    dislmdb_quic_conn conn;
    memset(&conn, 0, sizeof(conn));

    dislmdb_quic_long_header lh;
    if (dislmdb_quic_parse_long_header(pkt, pkt_len, &lh) != 0 ||
        lh.type != DISLMDB_QUIC_LONG_INITIAL ||
        lh.version != DISLMDB_QUIC_VERSION) {
        goto fail;
    }

    uint8_t server_cid[8];
    if (dislmdb_crypto_random_bytes(server_cid, sizeof(server_cid)) != 0) {
        goto fail;
    }

    if (dislmdb_quic_conn_init(&conn, true, lh.dcid, lh.dcid_len, server_cid,
                               sizeof(server_cid)) != 0) {
        goto fail;
    }

    uint64_t pn = 0;
    uint8_t ch[2048];
    size_t ch_len = 0;
    if (dislmdb_quic_open_initial_packet(&conn, true, pkt, pkt_len, &pn, ch,
                                         sizeof(ch), &ch_len) != 0 ||
        ch_len == 0) {
        goto fail;
    }

    uint8_t client_pub[32];
    if (dislmdb_quic_tls_extract_x25519_share(ch, ch_len, client_pub) != 0) {
        goto fail;
    }

    uint8_t spriv[32], spub[32];
    if (dislmdb_quic_x25519_keypair(spriv, spub) != 0) {
        goto fail;
    }
    uint8_t shared[32];
    if (dislmdb_quic_x25519_shared(spriv, client_pub, shared) != 0) {
        goto fail;
    }

    uint8_t srand[32];
    if (dislmdb_crypto_random_bytes(srand, sizeof(srand)) != 0) {
        goto fail;
    }
    uint8_t sh[512];
    size_t sh_len = 0;
    if (dislmdb_quic_tls_encode_server_hello(srand, spub, sh, sizeof(sh),
                                             &sh_len) != 0) {
        goto fail;
    }
    if (dislmdb_quic_tls_advance_keys(&conn, shared, ch, ch_len, sh, sh_len,
                                      false) != 0) {
        goto fail;
    }

    const uint8_t *leaf_der = NULL;
    size_t leaf_der_len = 0;
    if (dislmdb_quic_tls_identity_leaf_der(id, &leaf_der, &leaf_der_len) != 0) {
        goto fail;
    }

    uint8_t ee[64], fin_msg[64];
    size_t ee_len = 0, cert_len = 0, cv_len = 0, fin_len = 0;
    size_t cert_cap = 8 + leaf_der_len + 64;
    cert = malloc(cert_cap);
    cv_msg = malloc(512);
    if (!cert || !cv_msg) {
        goto fail;
    }
    if (dislmdb_quic_tls_encode_encrypted_extensions(ee, sizeof(ee), &ee_len) !=
            0 ||
        dislmdb_quic_tls_encode_certificate(leaf_der, leaf_der_len, cert, cert_cap,
                                            &cert_len) != 0) {
        goto fail;
    }

    size_t pre_cv = ch_len + sh_len + ee_len + cert_len;
    tr_cv = malloc(pre_cv);
    if (!tr_cv) {
        goto fail;
    }
    memcpy(tr_cv, ch, ch_len);
    memcpy(tr_cv + ch_len, sh, sh_len);
    memcpy(tr_cv + ch_len + sh_len, ee, ee_len);
    memcpy(tr_cv + ch_len + sh_len + ee_len, cert, cert_len);

    uint8_t cv_content[160];
    size_t cv_content_len = 0;
    uint8_t sig[512];
    size_t sig_len = 0;
    uint16_t scheme = 0;
    if (dislmdb_quic_tls_cert_verify_content(true, tr_cv, pre_cv, cv_content,
                                             sizeof(cv_content),
                                             &cv_content_len) != 0 ||
        dislmdb_quic_tls_identity_sign(id, cv_content, cv_content_len, &scheme,
                                       sig, sizeof(sig), &sig_len) != 0 ||
        dislmdb_quic_tls_encode_certificate_verify(scheme, sig, sig_len, cv_msg,
                                                   512, &cv_len) != 0) {
        goto fail;
    }

    size_t pre_fin = pre_cv + cv_len;
    tr_fin = malloc(pre_fin);
    if (!tr_fin) {
        goto fail;
    }
    memcpy(tr_fin, tr_cv, pre_cv);
    memcpy(tr_fin + pre_cv, cv_msg, cv_len);
    free(tr_cv);
    tr_cv = NULL;

    uint8_t verify[32];
    if (dislmdb_quic_tls_compute_finished(conn.server_hs_secret, tr_fin, pre_fin,
                                          verify) != 0 ||
        dislmdb_quic_tls_encode_finished(verify, fin_msg, sizeof(fin_msg),
                                         &fin_len) != 0) {
        goto fail;
    }
    free(tr_fin);
    tr_fin = NULL;

    size_t post_len = ee_len + cert_len + cv_len + fin_len;
    post = malloc(post_len);
    if (!post) {
        goto fail;
    }
    size_t po = 0;
    memcpy(post + po, ee, ee_len);
    po += ee_len;
    memcpy(post + po, cert, cert_len);
    po += cert_len;
    memcpy(post + po, cv_msg, cv_len);
    po += cv_len;
    memcpy(post + po, fin_msg, fin_len);

    if (lh.scid_len > 0) {
        memcpy(conn.dcid, lh.scid, lh.scid_len);
        conn.dcid_len = lh.scid_len;
    } else {
        conn.dcid_len = 0;
    }

    if (dislmdb_quic_build_initial_packet(&conn, false, 0, sh, sh_len, out_initial,
                                          initial_cap, out_initial_len) != 0 ||
        dislmdb_quic_build_handshake_packet(&conn, false, 0, post, post_len,
                                            out_handshake, hs_cap,
                                            out_handshake_len) != 0) {
        goto fail;
    }

    if (dislmdb_quic_tls_install_app_keys(&conn, ch, ch_len, sh, sh_len, post,
                                          post_len) != 0) {
        goto fail;
    }

    memcpy(conn.scid, server_cid, sizeof(server_cid));
    conn.scid_len = sizeof(server_cid);

    if (out_conn) {
        *out_conn = conn;
    } else {
        dislmdb_quic_conn_reset(&conn);
    }
    free(cert);
    free(cv_msg);
    free(post);
    dislmdb_quic_tls_identity_destroy(ephemeral);
    return 0;

fail:
    free(cert);
    free(cv_msg);
    free(tr_cv);
    free(tr_fin);
    free(post);
    dislmdb_quic_conn_reset(&conn);
    dislmdb_quic_tls_identity_destroy(ephemeral);
    return -1;
}

/** Extract first certificate leaf bytes from a TLS 1.3 Certificate message. */
static int extract_cert_leaf(const uint8_t *cert_msg, size_t cert_len,
                             const uint8_t **leaf, size_t *leaf_len)
{
    dislmdb_quic_tls_message msg;
    if (dislmdb_quic_tls_parse_message(cert_msg, cert_len, &msg) != 0 ||
        msg.type != DISLMDB_QUIC_TLS_CERTIFICATE || msg.body_len < 4) {
        return -1;
    }
    size_t o = 0;
    uint8_t ctx_len = msg.body[o++];
    if (o + ctx_len + 3 > msg.body_len) {
        return -1;
    }
    o += ctx_len;
    uint32_t list_len = ((uint32_t)msg.body[o] << 16) |
                        ((uint32_t)msg.body[o + 1] << 8) | msg.body[o + 2];
    o += 3;
    if (o + list_len > msg.body_len || list_len < 3) {
        return -1;
    }
    uint32_t clen = ((uint32_t)msg.body[o] << 16) |
                    ((uint32_t)msg.body[o + 1] << 8) | msg.body[o + 2];
    o += 3;
    if (clen == 0 || o + clen + 2 > msg.body_len) {
        return -1;
    }
    *leaf = msg.body + o;
    *leaf_len = clen;
    return 0;
}

int dislmdb_quic_client_start(dislmdb_quic_conn *conn, uint8_t dcid_out[8],
                              uint8_t scid_out[8], uint8_t x25519_priv_out[32],
                              uint8_t *client_hello_out, size_t ch_cap,
                              size_t *client_hello_len, uint8_t *out_initial,
                              size_t initial_cap, size_t *out_initial_len)
{
    if (!conn || !dcid_out || !scid_out || !x25519_priv_out || !out_initial ||
        !out_initial_len) {
        return -1;
    }
    if (dislmdb_crypto_random_bytes(dcid_out, 8) != 0 ||
        dislmdb_crypto_random_bytes(scid_out, 8) != 0) {
        return -1;
    }
    uint8_t xpub[32];
    if (dislmdb_quic_x25519_keypair(x25519_priv_out, xpub) != 0) {
        return -1;
    }
    uint8_t crand[32];
    if (dislmdb_crypto_random_bytes(crand, sizeof(crand)) != 0) {
        return -1;
    }
    uint8_t ch_local[512];
    uint8_t *ch = client_hello_out ? client_hello_out : ch_local;
    size_t ch_cap_use = client_hello_out ? ch_cap : sizeof(ch_local);
    size_t ch_len = 0;
    if (dislmdb_quic_tls_encode_client_hello(crand, xpub, ch, ch_cap_use,
                                             &ch_len) != 0) {
        return -1;
    }
    if (client_hello_len) {
        *client_hello_len = ch_len;
    }
    if (dislmdb_quic_conn_init(conn, false, dcid_out, 8, scid_out, 8) != 0) {
        return -1;
    }
    return dislmdb_quic_build_initial_packet(conn, true, 0, ch, ch_len,
                                             out_initial, initial_cap,
                                             out_initial_len);
}

int dislmdb_quic_client_complete_handshake(
    dislmdb_quic_conn *conn, const uint8_t *client_hello, size_t ch_len,
    const uint8_t client_x25519_priv[32], const uint8_t *server_initial,
    size_t server_initial_len, const uint8_t *server_handshake,
    size_t server_handshake_len, const dislmdb_quic_tls_identity *trust,
    uint8_t *out_client_fin, size_t fin_cap, size_t *out_client_fin_len)
{
    if (!conn || !client_hello || !client_x25519_priv || !server_initial ||
        !server_handshake || ch_len == 0 || server_initial_len == 0 ||
        server_handshake_len == 0) {
        return -1;
    }
    if (out_client_fin_len) {
        *out_client_fin_len = 0;
    }

    uint64_t pn = 0;
    uint8_t sh[512];
    size_t sh_len = 0;
    if (dislmdb_quic_open_initial_packet(conn, false, server_initial,
                                         server_initial_len, &pn, sh, sizeof(sh),
                                         &sh_len) != 0 ||
        sh_len == 0) {
        return -1;
    }

    uint8_t server_x_pub[32];
    if (dislmdb_quic_tls_extract_x25519_share(sh, sh_len, server_x_pub) != 0) {
        return -1;
    }
    uint8_t shared[32];
    if (dislmdb_quic_x25519_shared(client_x25519_priv, server_x_pub, shared) !=
        0) {
        return -1;
    }
    if (dislmdb_quic_tls_advance_keys(conn, shared, client_hello, ch_len, sh,
                                      sh_len, false) != 0) {
        return -1;
    }

    /* Adopt server SCID as our DCID for subsequent Handshake/1-RTT. */
    dislmdb_quic_long_header sh_lh;
    if (dislmdb_quic_parse_long_header(server_initial, server_initial_len,
                                       &sh_lh) == 0 &&
        sh_lh.scid_len > 0) {
        memcpy(conn->dcid, sh_lh.scid, sh_lh.scid_len);
        conn->dcid_len = sh_lh.scid_len;
    }

    uint64_t hpn = 0;
    uint8_t crypto[8192];
    size_t crypto_len = 0;
    if (dislmdb_quic_open_handshake_packet(conn, false, server_handshake,
                                           server_handshake_len, &hpn, crypto,
                                           sizeof(crypto), &crypto_len) != 0 ||
        crypto_len == 0) {
        return -1;
    }

    /* Walk EE || Certificate || CertificateVerify || Finished */
    size_t o = 0;
    dislmdb_quic_tls_message ee, cert, cv, sfin;
    if (dislmdb_quic_tls_parse_message(crypto + o, crypto_len - o, &ee) != 0 ||
        ee.type != DISLMDB_QUIC_TLS_ENCRYPTED_EXTENSIONS) {
        return -1;
    }
    o += ee.total_len;
    if (dislmdb_quic_tls_parse_message(crypto + o, crypto_len - o, &cert) != 0 ||
        cert.type != DISLMDB_QUIC_TLS_CERTIFICATE) {
        return -1;
    }
    const uint8_t *cert_msg = crypto + o;
    size_t cert_msg_len = cert.total_len;
    o += cert.total_len;
    if (dislmdb_quic_tls_parse_message(crypto + o, crypto_len - o, &cv) != 0 ||
        cv.type != DISLMDB_QUIC_TLS_CERTIFICATE_VERIFY) {
        return -1;
    }
    const uint8_t *cv_msg = crypto + o;
    size_t cv_msg_len = cv.total_len;
    o += cv.total_len;
    if (dislmdb_quic_tls_parse_message(crypto + o, crypto_len - o, &sfin) != 0 ||
        sfin.type != DISLMDB_QUIC_TLS_FINISHED) {
        return -1;
    }
    const uint8_t *sfin_msg = crypto + o;
    size_t sfin_msg_len = sfin.total_len;
    o += sfin.total_len;
    if (o != crypto_len) {
        return -1;
    }

    size_t pre_cv = ch_len + sh_len + ee.total_len + cert_msg_len;
    uint8_t *tr_cv = malloc(pre_cv);
    if (!tr_cv) {
        return -1;
    }
    memcpy(tr_cv, client_hello, ch_len);
    memcpy(tr_cv + ch_len, sh, sh_len);
    memcpy(tr_cv + ch_len + sh_len, crypto, ee.total_len + cert_msg_len);

    uint8_t cv_content[160];
    size_t cv_content_len = 0;
    if (dislmdb_quic_tls_cert_verify_content(true, tr_cv, pre_cv, cv_content,
                                             sizeof(cv_content),
                                             &cv_content_len) != 0 ||
        dislmdb_quic_tls_verify_peer_certificate(cert_msg, cert_msg_len, cv_msg,
                                                 cv_msg_len, cv_content,
                                                 cv_content_len, trust) != 0) {
        free(tr_cv);
        return -1;
    }

    size_t pre_sfin = pre_cv + cv_msg_len;
    uint8_t *tr_sfin = malloc(pre_sfin);
    if (!tr_sfin) {
        free(tr_cv);
        return -1;
    }
    memcpy(tr_sfin, tr_cv, pre_cv);
    memcpy(tr_sfin + pre_cv, cv_msg, cv_msg_len);
    free(tr_cv);

    uint8_t expect_sfin[32];
    if (dislmdb_quic_tls_compute_finished(conn->server_hs_secret, tr_sfin,
                                          pre_sfin, expect_sfin) != 0 ||
        dislmdb_quic_tls_verify_finished(sfin_msg, sfin_msg_len, expect_sfin) !=
            0) {
        free(tr_sfin);
        return -1;
    }

    /* Client Finished over CH||SH||EE||Cert||CV||server Finished */
    size_t pre_cfin = pre_sfin + sfin_msg_len;
    uint8_t *tr_cfin = malloc(pre_cfin);
    if (!tr_cfin) {
        free(tr_sfin);
        return -1;
    }
    memcpy(tr_cfin, tr_sfin, pre_sfin);
    memcpy(tr_cfin + pre_sfin, sfin_msg, sfin_msg_len);
    free(tr_sfin);

    uint8_t cverify[32];
    uint8_t cfin_msg[64];
    size_t cfin_len = 0;
    if (dislmdb_quic_tls_compute_finished(conn->client_hs_secret, tr_cfin,
                                          pre_cfin, cverify) != 0 ||
        dislmdb_quic_tls_encode_finished(cverify, cfin_msg, sizeof(cfin_msg),
                                         &cfin_len) != 0) {
        free(tr_cfin);
        return -1;
    }

    /* App keys from transcript through server Finished (not client Fin). */
    size_t post_sh_len = ee.total_len + cert_msg_len + cv_msg_len + sfin_msg_len;
    if (dislmdb_quic_tls_install_app_keys(conn, client_hello, ch_len, sh, sh_len,
                                          crypto, post_sh_len) != 0) {
        free(tr_cfin);
        return -1;
    }
    free(tr_cfin);

    if (out_client_fin && out_client_fin_len) {
        if (dislmdb_quic_build_handshake_packet(conn, true, 0, cfin_msg, cfin_len,
                                                out_client_fin, fin_cap,
                                                out_client_fin_len) != 0) {
            return -1;
        }
    }
    return 0;
}

int dislmdb_quic_tls_install_app_keys(dislmdb_quic_conn *conn,
                                      const uint8_t *client_hello, size_t ch_len,
                                      const uint8_t *server_hello, size_t sh_len,
                                      const uint8_t *post_sh, size_t post_sh_len)
{
    if (!conn || !conn->has_handshake_keys || !client_hello || !server_hello ||
        ch_len == 0 || sh_len == 0 || (post_sh_len > 0 && !post_sh)) {
        return -1;
    }
    static const uint8_t zeros[32] = {0};
    uint8_t empty_hash[32];
    if (dislmdb_crypto_sha256("", 0, empty_hash) != 0) {
        return -1;
    }
    uint8_t derived2[32];
    if (dislmdb_quic_hkdf_expand_label(conn->handshake_secret, "derived", empty_hash,
                                       32, derived2, 32) != 0) {
        return -1;
    }
    uint8_t master[32];
    if (dislmdb_quic_hkdf_extract(derived2, 32, zeros, 32, master) != 0) {
        return -1;
    }
    size_t total = ch_len + sh_len + post_sh_len;
    uint8_t *tr = malloc(total);
    if (!tr) {
        return -1;
    }
    memcpy(tr, client_hello, ch_len);
    memcpy(tr + ch_len, server_hello, sh_len);
    if (post_sh_len > 0) {
        memcpy(tr + ch_len + sh_len, post_sh, post_sh_len);
    }
    uint8_t th_app[32];
    if (dislmdb_crypto_sha256(tr, total, th_app) != 0) {
        free(tr);
        return -1;
    }
    free(tr);
    uint8_t client_app_sec[32], server_app_sec[32];
    if (derive_secret(master, "c ap traffic", th_app, 32, client_app_sec) != 0 ||
        derive_secret(master, "s ap traffic", th_app, 32, server_app_sec) != 0) {
        return -1;
    }
    if (dislmdb_quic_traffic_keys_from_secret(client_app_sec, &conn->client_app) !=
            0 ||
        dislmdb_quic_traffic_keys_from_secret(server_app_sec, &conn->server_app) !=
            0) {
        return -1;
    }
    conn->has_app_keys = true;
    conn->state = DISLMDB_QUIC_HS_APP;
    return 0;
}
