/**
 * @file dislmdb_quic.h
 * @brief QUIC / WebTransport substrate for DisLMDB (RFC 9000/9001/8446 pieces)
 *
 * Shipped: long-header/VN, CRYPTO frames, Initial+Handshake AEAD/HP, TLS 1.3
 * CH/SH/EE/Certificate/CertificateVerify/Finished, X25519, ECDSA P-256,
 * Handshake + 1-RTT key schedule.
 * Shipped on the net thread: client dial, server Initial reply, 1-RTT DQGM
 * RX/TX. CertificateVerify uses X.509 (loaded PEM or ephemeral self-signed).
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#ifndef DISLMDB_QUIC_H
#define DISLMDB_QUIC_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** DisLMDB local QUIC version (not an IETF draft codepoint). */
#define DISLMDB_QUIC_VERSION 0x00000001u
/** RFC 9000 Version Negotiation packet version field. */
#define DISLMDB_QUIC_VERSION_NEGOTIATION 0u
/** Max connection ID length we accept/emit (RFC allows 0..20). */
#define DISLMDB_QUIC_MAX_CID_LEN 20
/** CRYPTO frame type (RFC 9000 §19.6). */
#define DISLMDB_QUIC_FRAME_CRYPTO 0x06u
/** AES-128-GCM tag length for Initial AEAD. */
#define DISLMDB_QUIC_AEAD_TAG_LEN 16
/** Initial traffic key / HP key length. */
#define DISLMDB_QUIC_INITIAL_KEY_LEN 16
/** Initial IV length. */
#define DISLMDB_QUIC_INITIAL_IV_LEN 12

/** Long-header packet types (RFC 9000 §17.2). */
typedef enum dislmdb_quic_long_type {
    DISLMDB_QUIC_LONG_INITIAL = 0,
    DISLMDB_QUIC_LONG_ZERO_RTT = 1,
    DISLMDB_QUIC_LONG_HANDSHAKE = 2,
    DISLMDB_QUIC_LONG_RETRY = 3
} dislmdb_quic_long_type;

/** Classification of an inbound UDP datagram relative to QUIC/DQGM. */
typedef enum dislmdb_quic_dgram_kind {
    DISLMDB_QUIC_DGRAM_UNKNOWN = 0,
    DISLMDB_QUIC_DGRAM_DQGM,
    DISLMDB_QUIC_DGRAM_QUIC_LONG,
    DISLMDB_QUIC_DGRAM_QUIC_SHORT,
    DISLMDB_QUIC_DGRAM_VERSION_NEG
} dislmdb_quic_dgram_kind;

/** Handshake / 1-RTT readiness (stack gate). */
typedef enum dislmdb_quic_hs_state {
    DISLMDB_QUIC_HS_IDLE = 0,
    DISLMDB_QUIC_HS_INITIAL,
    DISLMDB_QUIC_HS_HANDSHAKE,
    DISLMDB_QUIC_HS_APP,
    DISLMDB_QUIC_HS_CLOSED
} dislmdb_quic_hs_state;

/** TLS 1.3 handshake message types (RFC 8446). */
#define DISLMDB_QUIC_TLS_CLIENT_HELLO 1
#define DISLMDB_QUIC_TLS_SERVER_HELLO 2
#define DISLMDB_QUIC_TLS_ENCRYPTED_EXTENSIONS 8
#define DISLMDB_QUIC_TLS_CERTIFICATE 11
#define DISLMDB_QUIC_TLS_CERTIFICATE_VERIFY 15
#define DISLMDB_QUIC_TLS_FINISHED 20
/** TLS_AES_128_GCM_SHA256 */
#define DISLMDB_QUIC_TLS_CIPHER_AES_128_GCM_SHA256 0x1301u
/** NamedGroup x25519 */
#define DISLMDB_QUIC_TLS_GROUP_X25519 0x001du
#define DISLMDB_QUIC_TLS_RANDOM_LEN 32
#define DISLMDB_QUIC_TLS_X25519_LEN 32
#define DISLMDB_QUIC_TLS_FINISHED_LEN 32
/** SignatureScheme ecdsa_secp256r1_sha256 (RFC 8446). */
#define DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256 0x0403u
/** SignatureScheme rsa_pkcs1_sha256 (RFC 8446) — mTLS PEM reuse. */
#define DISLMDB_QUIC_TLS_SIG_RSA_PKCS1_SHA256 0x0401u
/** Uncompressed P-256 public key: 0x04 || X || Y. */
#define DISLMDB_QUIC_TLS_ECDSA_P256_PUB_LEN 65
/** Raw P-256 private scalar length. */
#define DISLMDB_QUIC_TLS_ECDSA_P256_PRIV_LEN 32

/** Opaque X.509 identity (leaf + key + optional CA trust). */
typedef struct dislmdb_quic_tls_identity dislmdb_quic_tls_identity;

/** Parsed long-header fields (through SCID; type-specific follows). */
typedef struct dislmdb_quic_long_header {
    uint8_t first_byte;
    dislmdb_quic_long_type type;
    uint32_t version;
    uint8_t dcid[DISLMDB_QUIC_MAX_CID_LEN];
    size_t dcid_len;
    uint8_t scid[DISLMDB_QUIC_MAX_CID_LEN];
    size_t scid_len;
    size_t header_len; /**< Bytes consumed through SCID */
} dislmdb_quic_long_header;

/** Directional traffic keys (Initial / Handshake / 1-RTT). */
typedef struct dislmdb_quic_initial_keys {
    uint8_t key[DISLMDB_QUIC_INITIAL_KEY_LEN];
    uint8_t iv[DISLMDB_QUIC_INITIAL_IV_LEN];
    uint8_t hp[DISLMDB_QUIC_INITIAL_KEY_LEN];
} dislmdb_quic_initial_keys;

typedef dislmdb_quic_initial_keys dislmdb_quic_traffic_keys;

/** Parsed TLS handshake message header + body pointer. */
typedef struct dislmdb_quic_tls_message {
    uint8_t type;
    const uint8_t *body;
    size_t body_len;
    size_t total_len; /**< 4 + body_len */
} dislmdb_quic_tls_message;

/** Minimal connection object for Initial → Handshake → App keying. */
typedef struct dislmdb_quic_conn {
    dislmdb_quic_hs_state state;
    bool is_server;
    uint8_t dcid[DISLMDB_QUIC_MAX_CID_LEN];
    size_t dcid_len;
    uint8_t scid[DISLMDB_QUIC_MAX_CID_LEN];
    size_t scid_len;
    dislmdb_quic_traffic_keys client_in;
    dislmdb_quic_traffic_keys server_in;
    dislmdb_quic_traffic_keys client_hs;
    dislmdb_quic_traffic_keys server_hs;
    dislmdb_quic_traffic_keys client_app;
    dislmdb_quic_traffic_keys server_app;
    uint8_t client_hs_secret[32]; /**< Base secret for Finished / traffic keys */
    uint8_t server_hs_secret[32];
    uint8_t handshake_secret[32]; /**< For Master Secret derivation */
    bool has_handshake_keys;
    bool has_app_keys;
    uint64_t next_pn_out;
    uint64_t crypto_read_offset;
    uint64_t crypto_write_offset;
} dislmdb_quic_conn;

bool dislmdb_quic_stack_ready(void);
const char *dislmdb_quic_status(void);

dislmdb_quic_dgram_kind dislmdb_quic_classify(const uint8_t *data, size_t len);

int dislmdb_quic_parse_long_header(const uint8_t *data, size_t len,
                                   dislmdb_quic_long_header *out);

int dislmdb_quic_encode_version_negotiation(const dislmdb_quic_long_header *probe,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len);

void dislmdb_quic_cid_from_u64(uint64_t cid, uint8_t out[8]);
uint64_t dislmdb_quic_cid_to_u64(const uint8_t *cid, size_t len);

/** RFC 9000 variable-length integer encode/decode. */
int dislmdb_quic_varint_encode(uint64_t v, uint8_t *out, size_t out_cap,
                               size_t *out_len);
int dislmdb_quic_varint_decode(const uint8_t *data, size_t len, uint64_t *out,
                               size_t *consumed);

/** CRYPTO frame (type 0x06) encode/decode. */
int dislmdb_quic_encode_crypto_frame(uint64_t offset, const uint8_t *data,
                                     size_t data_len, uint8_t *out,
                                     size_t out_cap, size_t *out_len);
int dislmdb_quic_decode_crypto_frame(const uint8_t *data, size_t len,
                                     uint64_t *offset, const uint8_t **payload,
                                     size_t *payload_len, size_t *consumed);

/**
 * @brief Derive client+server Initial keys from the destination CID (RFC 9001).
 * Uses the QUICv1 initial salt; applies to @ref DISLMDB_QUIC_VERSION as well.
 */
int dislmdb_quic_derive_initial_keys(const uint8_t *dcid, size_t dcid_len,
                                     dislmdb_quic_initial_keys *client_out,
                                     dislmdb_quic_initial_keys *server_out);

/** AEAD_AES_128_GCM seal/open with QUIC nonce = IV XOR packet number. */
int dislmdb_quic_aead_seal(const dislmdb_quic_initial_keys *keys, uint64_t pn,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plain, size_t plain_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);
int dislmdb_quic_aead_open(const dislmdb_quic_initial_keys *keys, uint64_t pn,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *cipher, size_t cipher_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * @brief Apply/remove Initial header protection (AES-ECB mask).
 * @param sample 16 bytes from ciphertext (pn offset dependent)
 */
int dislmdb_quic_hp_mask(const uint8_t hp[DISLMDB_QUIC_INITIAL_KEY_LEN],
                         const uint8_t sample[16], uint8_t mask[5]);

int dislmdb_quic_encode_initial_header(uint32_t version,
                                       const uint8_t *dcid, size_t dcid_len,
                                       const uint8_t *scid, size_t scid_len,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len);

/**
 * @brief Build a protected Initial packet carrying one CRYPTO frame.
 * Packet number length is 1 byte; payload is CRYPTO + AEAD tag.
 */
int dislmdb_quic_build_initial_packet(const dislmdb_quic_conn *conn,
                                      bool from_client, uint64_t pn,
                                      const uint8_t *crypto, size_t crypto_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len);

/**
 * @brief Open a protected Initial packet; returns CRYPTO payload if present.
 * @param crypto_out Caller buffer for reassembled CRYPTO data at frame offset 0
 */
int dislmdb_quic_open_initial_packet(const dislmdb_quic_conn *conn,
                                     bool from_client, const uint8_t *pkt,
                                     size_t pkt_len, uint64_t *pn_out,
                                     uint8_t *crypto_out, size_t crypto_cap,
                                     size_t *crypto_len);

int dislmdb_quic_conn_init(dislmdb_quic_conn *conn, bool is_server,
                           const uint8_t *dcid, size_t dcid_len,
                           const uint8_t *scid, size_t scid_len);
void dislmdb_quic_conn_reset(dislmdb_quic_conn *conn);

/** Derive QUIC traffic keys from a TLS traffic secret (quic key/iv/hp). */
int dislmdb_quic_traffic_keys_from_secret(const uint8_t secret[32],
                                          dislmdb_quic_traffic_keys *out);

/** TLS 1.3 handshake header encode/parse (type + uint24 length + body). */
int dislmdb_quic_tls_encode_message(uint8_t type, const uint8_t *body,
                                    size_t body_len, uint8_t *out,
                                    size_t out_cap, size_t *out_len);
int dislmdb_quic_tls_parse_message(const uint8_t *data, size_t len,
                                   dislmdb_quic_tls_message *out);

/**
 * @brief Minimal TLS 1.3 ClientHello with x25519 key_share + TLS_AES_128_GCM.
 * @param random32  Client random (32 bytes)
 * @param x25519_pub Client ephemeral public key (32 bytes)
 */
int dislmdb_quic_tls_encode_client_hello(const uint8_t random32[32],
                                         const uint8_t x25519_pub[32],
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len);

/**
 * @brief Minimal TLS 1.3 ServerHello selecting AES-128-GCM + x25519.
 */
int dislmdb_quic_tls_encode_server_hello(const uint8_t random32[32],
                                         const uint8_t x25519_pub[32],
                                         uint8_t *out, size_t out_cap,
                                         size_t *out_len);

/** Extract first x25519 key_share public from a ClientHello/ServerHello body. */
int dislmdb_quic_tls_extract_x25519_share(const uint8_t *hs_msg, size_t hs_len,
                                          uint8_t pub_out[32]);

/** X25519 keypair + shared secret (mbedTLS). */
int dislmdb_quic_x25519_keypair(uint8_t priv_out[32], uint8_t pub_out[32]);
int dislmdb_quic_x25519_shared(const uint8_t priv[32], const uint8_t peer_pub[32],
                               uint8_t shared_out[32]);

/**
 * @brief TLS 1.3 + QUIC key schedule after ClientHello/ServerHello.
 *
 * Fills Handshake traffic keys from ECDHE @p shared_secret and transcript
 * Hash(CH||SH). Stores HS secrets for Finished. When @p derive_app is true and
 * @p post_sh is NULL, uses a synthetic Finished (legacy). Prefer
 * @ref dislmdb_quic_tls_install_app_keys with a real post-SH transcript.
 */
int dislmdb_quic_tls_advance_keys(dislmdb_quic_conn *conn,
                                  const uint8_t shared_secret[32],
                                  const uint8_t *client_hello, size_t ch_len,
                                  const uint8_t *server_hello, size_t sh_len,
                                  bool derive_app);

/** Empty EncryptedExtensions message. */
int dislmdb_quic_tls_encode_encrypted_extensions(uint8_t *out, size_t out_cap,
                                                 size_t *out_len);

/**
 * @brief Certificate message (TLS 1.3).
 * @param cert_der Optional leaf DER (NULL/0 ⇒ empty certificate_list).
 */
int dislmdb_quic_tls_encode_certificate(const uint8_t *cert_der, size_t cert_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len);

/**
 * @brief Load PEM leaf + key (+ optional CA) for QUIC CertificateVerify.
 * @param ca_path NULL/empty ⇒ trust the leaf itself (self-signed / TOFU tests)
 */
dislmdb_quic_tls_identity *dislmdb_quic_tls_identity_load(const char *cert_path,
                                                          const char *key_path,
                                                          const char *ca_path);

/** Ephemeral ECDSA-P256 self-signed identity (CN default "dislmdb-quic"). */
dislmdb_quic_tls_identity *dislmdb_quic_tls_identity_self_signed(const char *cn);

void dislmdb_quic_tls_identity_destroy(dislmdb_quic_tls_identity *id);

/** Leaf DER bytes (for Certificate message); valid until destroy. */
int dislmdb_quic_tls_identity_leaf_der(const dislmdb_quic_tls_identity *id,
                                       const uint8_t **der_out, size_t *der_len);

/** Sign CertificateVerify content; sets @p scheme_out to the TLS SignatureScheme. */
int dislmdb_quic_tls_identity_sign(const dislmdb_quic_tls_identity *id,
                                   const uint8_t *content, size_t content_len,
                                   uint16_t *scheme_out, uint8_t *sig_out,
                                   size_t sig_cap, size_t *sig_len);

/**
 * @brief Parse Certificate + CertificateVerify: X.509 + CV signature.
 * @param trust CA trust anchor; NULL ⇒ TOFU (verify CV against leaf only)
 */
int dislmdb_quic_tls_verify_peer_certificate(
    const uint8_t *cert_msg, size_t cert_len, const uint8_t *cv_msg,
    size_t cv_len, const uint8_t *content, size_t content_len,
    const dislmdb_quic_tls_identity *trust);

/** ECDSA P-256 keypair (mbedTLS); pub is uncompressed 65 bytes. */
int dislmdb_quic_ecdsa_p256_keypair(uint8_t priv_out[32], uint8_t pub_out[65]);

/**
 * @brief Build RFC 8446 §4.4.3 CertificateVerify signed content.
 * 64×0x20 || context || 0x00 || SHA256(transcript).
 * @param server_side true ⇒ "TLS 1.3, server CertificateVerify"
 */
int dislmdb_quic_tls_cert_verify_content(bool server_side,
                                         const uint8_t *transcript,
                                         size_t transcript_len, uint8_t *out,
                                         size_t out_cap, size_t *out_len);

/**
 * @brief Sign CertificateVerify content with ECDSA-P256-SHA256 (DER sig).
 * @param sig_out DER-encoded ECDSA signature
 */
int dislmdb_quic_tls_sign_cert_verify(const uint8_t priv[32],
                                      const uint8_t *content, size_t content_len,
                                      uint8_t *sig_out, size_t sig_cap,
                                      size_t *sig_len);

/**
 * @brief Encode CertificateVerify (scheme + signature).
 * Default scheme: @ref DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256.
 */
int dislmdb_quic_tls_encode_certificate_verify(uint16_t scheme,
                                               const uint8_t *sig, size_t sig_len,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

/**
 * @brief Verify a CertificateVerify message against ECDSA-P256 public key.
 * @param pub65 Uncompressed P-256 public key (65 bytes)
 * @param content Output of @ref dislmdb_quic_tls_cert_verify_content
 */
int dislmdb_quic_tls_verify_certificate_verify(const uint8_t *cv_msg, size_t cv_len,
                                               const uint8_t pub65[65],
                                               const uint8_t *content,
                                               size_t content_len);

/**
 * @brief Compute TLS 1.3 Finished verify_data for the given base HS secret.
 * @param base_secret client_hs_secret or server_hs_secret
 * @param transcript  Handshake context hashed for Finished (CH..prior messages)
 */
int dislmdb_quic_tls_compute_finished(const uint8_t base_secret[32],
                                      const uint8_t *transcript,
                                      size_t transcript_len,
                                      uint8_t verify_out[32]);

/** Encode a Finished handshake message wrapping @p verify_data. */
int dislmdb_quic_tls_encode_finished(const uint8_t verify_data[32], uint8_t *out,
                                     size_t out_cap, size_t *out_len);

/** Constant-time verify of a Finished message against expected verify_data. */
int dislmdb_quic_tls_verify_finished(const uint8_t *finished_msg, size_t fin_len,
                                     const uint8_t expect[32]);

/**
 * @brief Derive 1-RTT keys from Master Secret using Hash(CH||SH||post_sh).
 * Requires prior @ref dislmdb_quic_tls_advance_keys (Handshake secrets).
 */
int dislmdb_quic_tls_install_app_keys(dislmdb_quic_conn *conn,
                                      const uint8_t *client_hello, size_t ch_len,
                                      const uint8_t *server_hello, size_t sh_len,
                                      const uint8_t *post_sh, size_t post_sh_len);

/**
 * @brief Build/open a Handshake long-header packet (CRYPTO + HS AEAD + HP).
 * Requires @ref dislmdb_quic_conn.has_handshake_keys.
 */
int dislmdb_quic_build_handshake_packet(const dislmdb_quic_conn *conn,
                                        bool from_client, uint64_t pn,
                                        const uint8_t *crypto, size_t crypto_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len);
int dislmdb_quic_open_handshake_packet(const dislmdb_quic_conn *conn,
                                       bool from_client, const uint8_t *pkt,
                                       size_t pkt_len, uint64_t *pn_out,
                                       uint8_t *crypto_out, size_t crypto_cap,
                                       size_t *crypto_len);

/**
 * @brief Server substrate: answer a client Initial (ClientHello CRYPTO).
 *
 * Opens the Initial, runs X25519 + TLS key schedule, emits:
 * - @p out_initial: ServerHello in a protected Initial packet
 * - @p out_handshake: EE||Certificate||CertificateVerify||Finished in a
 *   Handshake packet
 *
 * @param id X.509 identity for Certificate + CV (NULL ⇒ ephemeral self-signed).
 * When @p out_conn is non-NULL, leaves it with Handshake+1-RTT keys (server
 * SCID in @c scid, peer CID in @c dcid) instead of resetting.
 */
int dislmdb_quic_server_handle_initial(const uint8_t *pkt, size_t pkt_len,
                                       uint8_t *out_initial, size_t initial_cap,
                                       size_t *out_initial_len,
                                       uint8_t *out_handshake, size_t hs_cap,
                                       size_t *out_handshake_len,
                                       dislmdb_quic_conn *out_conn,
                                       const dislmdb_quic_tls_identity *id);

/**
 * @brief Client: init conn + X25519 + ClientHello Initial packet.
 * @param dcid_out / scid_out Filled with random CIDs (8 bytes each)
 * @param x25519_priv_out Client ephemeral private key (keep for complete)
 * @param client_hello_out Optional buffer for raw CH (for complete)
 */
int dislmdb_quic_client_start(dislmdb_quic_conn *conn, uint8_t dcid_out[8],
                              uint8_t scid_out[8], uint8_t x25519_priv_out[32],
                              uint8_t *client_hello_out, size_t ch_cap,
                              size_t *client_hello_len, uint8_t *out_initial,
                              size_t initial_cap, size_t *out_initial_len);

/**
 * @brief Client: consume server Initial(SH) + Handshake(EE..Fin), verify CV+Fin,
 *        install 1-RTT keys, optionally emit client Finished Handshake packet.
 *
 * @param trust CA trust for peer Certificate; NULL ⇒ TOFU (CV vs leaf only)
 * @param out_client_fin Optional; client Finished Handshake packet (may be NULL)
 */
int dislmdb_quic_client_complete_handshake(
    dislmdb_quic_conn *conn, const uint8_t *client_hello, size_t ch_len,
    const uint8_t client_x25519_priv[32], const uint8_t *server_initial,
    size_t server_initial_len, const uint8_t *server_handshake,
    size_t server_handshake_len, const dislmdb_quic_tls_identity *trust,
    uint8_t *out_client_fin, size_t fin_cap, size_t *out_client_fin_len);

/**
 * @brief 1-RTT short-header packet (CRYPTO frame) with app traffic keys.
 * Header: 0x40 | pn_len, DCID (conn->dcid), 1-byte PN, protected payload.
 */
int dislmdb_quic_build_one_rtt_packet(const dislmdb_quic_conn *conn,
                                      bool from_client, uint64_t pn,
                                      const uint8_t *crypto, size_t crypto_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len);
int dislmdb_quic_open_one_rtt_packet(const dislmdb_quic_conn *conn,
                                     bool from_client, const uint8_t *pkt,
                                     size_t pkt_len, uint64_t *pn_out,
                                     uint8_t *crypto_out, size_t crypto_cap,
                                     size_t *crypto_len);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_QUIC_H */
