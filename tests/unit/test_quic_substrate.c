/**
 * @file test_quic_substrate.c
 * @brief Unit: QUIC VN/CRYPTO/Initial+HS AEAD + TLS CH..Finished
 */
#include "../harness/test_harness.h"
#include "dislmdb_quic.h"
#include "dislmdb_iouring.h"
#include "dislmdb_crypto.h"
#include "dislmdb_internal.h"

#include <stdlib.h>
#include <string.h>

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/quic_substrate");

    EXPECT_TRUE(&ctx, "stack_ready", dislmdb_quic_stack_ready());
    EXPECT_TRUE(&ctx, "status_nonempty",
                dislmdb_quic_status() != NULL && dislmdb_quic_status()[0] != '\0');

    uint8_t cid[8];
    dislmdb_quic_cid_from_u64(0x1122334455667788ull, cid);
    EXPECT_TRUE(&ctx, "cid_roundtrip",
                dislmdb_quic_cid_to_u64(cid, 8) == 0x1122334455667788ull);

    /* Varints */
    uint8_t vb[8];
    size_t vn = 0;
    EXPECT_EQ_INT(&ctx, "vi_enc_63", dislmdb_quic_varint_encode(63, vb, 8, &vn), 0);
    EXPECT_EQ_INT(&ctx, "vi_enc_63_len", (int)vn, 1);
    uint64_t vd = 0;
    size_t vc = 0;
    EXPECT_EQ_INT(&ctx, "vi_dec_63", dislmdb_quic_varint_decode(vb, vn, &vd, &vc), 0);
    EXPECT_TRUE(&ctx, "vi_63_val", vd == 63 && vc == 1);
    EXPECT_EQ_INT(&ctx, "vi_enc_64", dislmdb_quic_varint_encode(64, vb, 8, &vn), 0);
    EXPECT_EQ_INT(&ctx, "vi_enc_64_len", (int)vn, 2);

    /* CRYPTO frame */
    const uint8_t hello[] = "ClientHello-stub";
    uint8_t frame[128];
    size_t flen = 0;
    EXPECT_EQ_INT(&ctx, "crypto_enc",
                  dislmdb_quic_encode_crypto_frame(0, hello, sizeof(hello) - 1, frame,
                                                   sizeof(frame), &flen),
                  0);
    uint64_t coff = 1;
    const uint8_t *cpay = NULL;
    size_t clen = 0, ccons = 0;
    EXPECT_EQ_INT(&ctx, "crypto_dec",
                  dislmdb_quic_decode_crypto_frame(frame, flen, &coff, &cpay, &clen,
                                                   &ccons),
                  0);
    EXPECT_TRUE(&ctx, "crypto_off0", coff == 0);
    EXPECT_TRUE(&ctx, "crypto_len", clen == sizeof(hello) - 1);
    EXPECT_TRUE(&ctx, "crypto_body",
                cpay && memcmp(cpay, hello, clen) == 0);

    uint8_t dqgm[16];
    memset(dqgm, 0, sizeof(dqgm));
    dislmdb_write_u32(dqgm, DISLMDB_DQGM_MAGIC);
    EXPECT_EQ_INT(&ctx, "class_dqgm",
                  (int)dislmdb_quic_classify(dqgm, sizeof(dqgm)),
                  (int)DISLMDB_QUIC_DGRAM_DQGM);

    uint8_t scid[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    uint8_t dcid[8];
    dislmdb_quic_cid_from_u64(0x0102030405060708ull, dcid);

    uint8_t initial[128];
    size_t ilen = 0;
    EXPECT_EQ_INT(&ctx, "enc_initial",
                  dislmdb_quic_encode_initial_header(0x00000001u, dcid, 8, scid, 4,
                                                     initial, sizeof(initial), &ilen),
                  0);
    EXPECT_EQ_INT(&ctx, "class_long",
                  (int)dislmdb_quic_classify(initial, ilen),
                  (int)DISLMDB_QUIC_DGRAM_QUIC_LONG);

    dislmdb_quic_long_header hdr;
    EXPECT_EQ_INT(&ctx, "parse_long",
                  dislmdb_quic_parse_long_header(initial, ilen, &hdr), 0);
    EXPECT_EQ_INT(&ctx, "parse_ver", (int)hdr.version, 1);
    EXPECT_EQ_INT(&ctx, "parse_type", (int)hdr.type, (int)DISLMDB_QUIC_LONG_INITIAL);

    /* VN */
    uint8_t foreign[128];
    size_t fl = 0;
    EXPECT_EQ_INT(&ctx, "enc_foreign",
                  dislmdb_quic_encode_initial_header(0x0a0a0a0au, dcid, 8, scid, 4,
                                                     foreign, sizeof(foreign), &fl),
                  0);
    EXPECT_EQ_INT(&ctx, "parse_foreign",
                  dislmdb_quic_parse_long_header(foreign, fl, &hdr), 0);
    uint8_t vnb[256];
    size_t vn_len = 0;
    EXPECT_EQ_INT(&ctx, "enc_vn",
                  dislmdb_quic_encode_version_negotiation(&hdr, vnb, sizeof(vnb),
                                                          &vn_len),
                  0);
    EXPECT_EQ_INT(&ctx, "class_vn",
                  (int)dislmdb_quic_classify(vnb, vn_len),
                  (int)DISLMDB_QUIC_DGRAM_VERSION_NEG);

    /* Initial key derivation + AEAD round-trip */
    dislmdb_quic_initial_keys client_k, server_k;
    EXPECT_EQ_INT(&ctx, "derive",
                  dislmdb_quic_derive_initial_keys(dcid, 8, &client_k, &server_k), 0);
    EXPECT_TRUE(&ctx, "keys_differ",
                memcmp(client_k.key, server_k.key, 16) != 0);

    const uint8_t aad[] = "aad-test";
    const uint8_t plain[] = "initial-payload";
    uint8_t sealed[64];
    size_t slen = 0;
    EXPECT_EQ_INT(&ctx, "aead_seal",
                  dislmdb_quic_aead_seal(&client_k, 7, aad, sizeof(aad) - 1, plain,
                                         sizeof(plain) - 1, sealed, sizeof(sealed),
                                         &slen),
                  0);
    EXPECT_TRUE(&ctx, "aead_tag", slen == sizeof(plain) - 1 + DISLMDB_QUIC_AEAD_TAG_LEN);
    uint8_t opened[64];
    size_t olen = 0;
    EXPECT_EQ_INT(&ctx, "aead_open",
                  dislmdb_quic_aead_open(&client_k, 7, aad, sizeof(aad) - 1, sealed,
                                         slen, opened, sizeof(opened), &olen),
                  0);
    EXPECT_TRUE(&ctx, "aead_roundtrip",
                olen == sizeof(plain) - 1 && memcmp(opened, plain, olen) == 0);
    EXPECT_TRUE(&ctx, "aead_bad_pn",
                dislmdb_quic_aead_open(&client_k, 8, aad, sizeof(aad) - 1, sealed,
                                       slen, opened, sizeof(opened), &olen) != 0);

    /* HP mask deterministic for fixed sample */
    uint8_t sample[16];
    memset(sample, 0x5a, sizeof(sample));
    uint8_t mask[5], mask2[5];
    EXPECT_EQ_INT(&ctx, "hp1", dislmdb_quic_hp_mask(client_k.hp, sample, mask), 0);
    EXPECT_EQ_INT(&ctx, "hp2", dislmdb_quic_hp_mask(client_k.hp, sample, mask2), 0);
    EXPECT_TRUE(&ctx, "hp_stable", memcmp(mask, mask2, 5) == 0);

    /* Full Initial packet build/open */
    dislmdb_quic_conn cconn, sconn;
    EXPECT_EQ_INT(&ctx, "client_init",
                  dislmdb_quic_conn_init(&cconn, false, dcid, 8, scid, 4), 0);
    EXPECT_EQ_INT(&ctx, "server_init",
                  dislmdb_quic_conn_init(&sconn, true, dcid, 8, scid, 4), 0);
    EXPECT_EQ_INT(&ctx, "hs_initial", (int)cconn.state, (int)DISLMDB_QUIC_HS_INITIAL);

    uint8_t pkt[512];
    size_t pkt_len = 0;
    EXPECT_EQ_INT(&ctx, "build_pkt",
                  dislmdb_quic_build_initial_packet(&cconn, true, 0, hello,
                                                    sizeof(hello) - 1, pkt,
                                                    sizeof(pkt), &pkt_len),
                  0);
    EXPECT_TRUE(&ctx, "pkt_len", pkt_len > 30);
    EXPECT_EQ_INT(&ctx, "pkt_class",
                  (int)dislmdb_quic_classify(pkt, pkt_len),
                  (int)DISLMDB_QUIC_DGRAM_QUIC_LONG);

    uint64_t pn = 99;
    uint8_t got[128];
    size_t got_len = 0;
    EXPECT_EQ_INT(&ctx, "open_pkt",
                  dislmdb_quic_open_initial_packet(&sconn, true, pkt, pkt_len, &pn,
                                                   got, sizeof(got), &got_len),
                  0);
    EXPECT_TRUE(&ctx, "open_pn", pn == 0);
    EXPECT_TRUE(&ctx, "open_crypto",
                got_len == sizeof(hello) - 1 && memcmp(got, hello, got_len) == 0);

    dislmdb_quic_conn_reset(&cconn);
    dislmdb_quic_conn_reset(&sconn);
    EXPECT_EQ_INT(&ctx, "closed", (int)cconn.state, (int)DISLMDB_QUIC_HS_CLOSED);

    /* TLS 1.3 ClientHello / ServerHello + X25519 + key schedule */
    uint8_t cpriv[32], cpub[32], spriv[32], spub[32];
    EXPECT_EQ_INT(&ctx, "x25519_c", dislmdb_quic_x25519_keypair(cpriv, cpub), 0);
    EXPECT_EQ_INT(&ctx, "x25519_s", dislmdb_quic_x25519_keypair(spriv, spub), 0);
    uint8_t shared_c[32], shared_s[32];
    EXPECT_EQ_INT(&ctx, "x25519_sc",
                  dislmdb_quic_x25519_shared(cpriv, spub, shared_c), 0);
    EXPECT_EQ_INT(&ctx, "x25519_ss",
                  dislmdb_quic_x25519_shared(spriv, cpub, shared_s), 0);
    EXPECT_TRUE(&ctx, "x25519_agree", memcmp(shared_c, shared_s, 32) == 0);

    uint8_t crand[32], srand[32];
    memset(crand, 0x11, sizeof(crand));
    memset(srand, 0x22, sizeof(srand));
    uint8_t ch[512], sh[512];
    size_t ch_len = 0, sh_len = 0;
    EXPECT_EQ_INT(&ctx, "enc_ch",
                  dislmdb_quic_tls_encode_client_hello(crand, cpub, ch, sizeof(ch),
                                                       &ch_len),
                  0);
    EXPECT_EQ_INT(&ctx, "enc_sh",
                  dislmdb_quic_tls_encode_server_hello(srand, spub, sh, sizeof(sh),
                                                       &sh_len),
                  0);
    dislmdb_quic_tls_message tm;
    EXPECT_EQ_INT(&ctx, "parse_ch",
                  dislmdb_quic_tls_parse_message(ch, ch_len, &tm), 0);
    EXPECT_EQ_INT(&ctx, "ch_type", (int)tm.type, DISLMDB_QUIC_TLS_CLIENT_HELLO);
    uint8_t got_pub[32];
    EXPECT_EQ_INT(&ctx, "ext_ch_share",
                  dislmdb_quic_tls_extract_x25519_share(ch, ch_len, got_pub), 0);
    EXPECT_TRUE(&ctx, "ch_share", memcmp(got_pub, cpub, 32) == 0);
    EXPECT_EQ_INT(&ctx, "ext_sh_share",
                  dislmdb_quic_tls_extract_x25519_share(sh, sh_len, got_pub), 0);
    EXPECT_TRUE(&ctx, "sh_share", memcmp(got_pub, spub, 32) == 0);

    EXPECT_EQ_INT(&ctx, "client_reinit",
                  dislmdb_quic_conn_init(&cconn, false, dcid, 8, scid, 4), 0);
    EXPECT_EQ_INT(&ctx, "advance_hs",
                  dislmdb_quic_tls_advance_keys(&cconn, shared_c, ch, ch_len, sh,
                                                sh_len, false),
                  0);
    EXPECT_TRUE(&ctx, "has_hs", cconn.has_handshake_keys);
    EXPECT_EQ_INT(&ctx, "st_hs", (int)cconn.state, (int)DISLMDB_QUIC_HS_HANDSHAKE);
    EXPECT_TRUE(&ctx, "hs_keys_differ",
                memcmp(cconn.client_hs.key, cconn.server_hs.key, 16) != 0);

    EXPECT_EQ_INT(&ctx, "advance_app",
                  dislmdb_quic_tls_advance_keys(&cconn, shared_c, ch, ch_len, sh,
                                                sh_len, true),
                  0);
    EXPECT_TRUE(&ctx, "has_app", cconn.has_app_keys);
    EXPECT_EQ_INT(&ctx, "st_app", (int)cconn.state, (int)DISLMDB_QUIC_HS_APP);
    EXPECT_TRUE(&ctx, "app_ne_hs",
                memcmp(cconn.client_app.key, cconn.client_hs.key, 16) != 0);

    /* Handshake AEAD round-trip with HS keys */
    const uint8_t hs_plain[] = "hs-aead";
    uint8_t hs_sealed[64];
    size_t hs_slen = 0;
    EXPECT_EQ_INT(&ctx, "hs_seal",
                  dislmdb_quic_aead_seal(&cconn.client_hs, 1, NULL, 0, hs_plain,
                                         sizeof(hs_plain) - 1, hs_sealed,
                                         sizeof(hs_sealed), &hs_slen),
                  0);
    uint8_t hs_open[64];
    size_t hs_olen = 0;
    EXPECT_EQ_INT(&ctx, "hs_open",
                  dislmdb_quic_aead_open(&cconn.client_hs, 1, NULL, 0, hs_sealed,
                                         hs_slen, hs_open, sizeof(hs_open),
                                         &hs_olen),
                  0);
    EXPECT_TRUE(&ctx, "hs_rt",
                hs_olen == sizeof(hs_plain) - 1 &&
                    memcmp(hs_open, hs_plain, hs_olen) == 0);

    /* EE + Certificate + CertificateVerify + Finished + Handshake packet */
    uint8_t ee[64], cert[128], cv_msg[256], fin_msg[64];
    size_t ee_len = 0, cert_len = 0, cv_len = 0, fin_len = 0;
    EXPECT_EQ_INT(&ctx, "enc_ee",
                  dislmdb_quic_tls_encode_encrypted_extensions(ee, sizeof(ee),
                                                               &ee_len),
                  0);
    const uint8_t leaf[] = {0x30, 0x03, 0x01, 0x01, 0x00}; /* tiny DER stub */
    EXPECT_EQ_INT(&ctx, "enc_cert",
                  dislmdb_quic_tls_encode_certificate(leaf, sizeof(leaf), cert,
                                                      sizeof(cert), &cert_len),
                  0);
    dislmdb_quic_tls_message cm;
    EXPECT_EQ_INT(&ctx, "parse_cert",
                  dislmdb_quic_tls_parse_message(cert, cert_len, &cm), 0);
    EXPECT_EQ_INT(&ctx, "cert_type", (int)cm.type, DISLMDB_QUIC_TLS_CERTIFICATE);

    uint8_t epriv[32], epub[65];
    EXPECT_EQ_INT(&ctx, "ecdsa_kp",
                  dislmdb_quic_ecdsa_p256_keypair(epriv, epub), 0);
    EXPECT_EQ_INT(&ctx, "ecdsa_pub_fmt", (int)epub[0], 0x04);

    size_t pre_cv = ch_len + sh_len + ee_len + cert_len;
    uint8_t *tr_cv = (uint8_t *)malloc(pre_cv);
    EXPECT_TRUE(&ctx, "tr_cv_alloc", tr_cv != NULL);
    if (tr_cv) {
        memcpy(tr_cv, ch, ch_len);
        memcpy(tr_cv + ch_len, sh, sh_len);
        memcpy(tr_cv + ch_len + sh_len, ee, ee_len);
        memcpy(tr_cv + ch_len + sh_len + ee_len, cert, cert_len);
    }
    uint8_t cv_content[160];
    size_t cv_content_len = 0;
    EXPECT_EQ_INT(&ctx, "cv_content",
                  dislmdb_quic_tls_cert_verify_content(true, tr_cv, pre_cv,
                                                       cv_content,
                                                       sizeof(cv_content),
                                                       &cv_content_len),
                  0);
    uint8_t sig[128];
    size_t sig_len = 0;
    EXPECT_EQ_INT(&ctx, "cv_sign",
                  dislmdb_quic_tls_sign_cert_verify(epriv, cv_content,
                                                    cv_content_len, sig,
                                                    sizeof(sig), &sig_len),
                  0);
    EXPECT_EQ_INT(&ctx, "enc_cv",
                  dislmdb_quic_tls_encode_certificate_verify(
                      DISLMDB_QUIC_TLS_SIG_ECDSA_P256_SHA256, sig, sig_len, cv_msg,
                      sizeof(cv_msg), &cv_len),
                  0);
    EXPECT_EQ_INT(&ctx, "verify_cv",
                  dislmdb_quic_tls_verify_certificate_verify(
                      cv_msg, cv_len, epub, cv_content, cv_content_len),
                  0);
    uint8_t bad_pub[65];
    memcpy(bad_pub, epub, 65);
    bad_pub[1] ^= 0x01;
    EXPECT_TRUE(&ctx, "verify_cv_bad",
                dislmdb_quic_tls_verify_certificate_verify(
                    cv_msg, cv_len, bad_pub, cv_content, cv_content_len) != 0);

    size_t pre_fin = pre_cv + cv_len;
    uint8_t *tr_fin = (uint8_t *)malloc(pre_fin);
    EXPECT_TRUE(&ctx, "tr_fin_alloc", tr_fin != NULL);
    if (tr_fin && tr_cv) {
        memcpy(tr_fin, tr_cv, pre_cv);
        memcpy(tr_fin + pre_cv, cv_msg, cv_len);
    }
    uint8_t verify[32];
    EXPECT_EQ_INT(&ctx, "fin_compute",
                  dislmdb_quic_tls_compute_finished(cconn.server_hs_secret, tr_fin,
                                                    pre_fin, verify),
                  0);
    EXPECT_EQ_INT(&ctx, "enc_fin",
                  dislmdb_quic_tls_encode_finished(verify, fin_msg, sizeof(fin_msg),
                                                   &fin_len),
                  0);
    EXPECT_EQ_INT(&ctx, "verify_fin",
                  dislmdb_quic_tls_verify_finished(fin_msg, fin_len, verify), 0);
    uint8_t bad_verify[32];
    memcpy(bad_verify, verify, 32);
    bad_verify[0] ^= 0x01;
    EXPECT_TRUE(&ctx, "verify_fin_bad",
                dislmdb_quic_tls_verify_finished(fin_msg, fin_len, bad_verify) != 0);

    size_t post_sh = ee_len + cert_len + cv_len + fin_len;
    uint8_t *post = (uint8_t *)malloc(post_sh);
    EXPECT_TRUE(&ctx, "post_alloc", post != NULL);
    if (post) {
        size_t po = 0;
        memcpy(post + po, ee, ee_len);
        po += ee_len;
        memcpy(post + po, cert, cert_len);
        po += cert_len;
        memcpy(post + po, cv_msg, cv_len);
        po += cv_len;
        memcpy(post + po, fin_msg, fin_len);
    }
    EXPECT_EQ_INT(&ctx, "install_app",
                  dislmdb_quic_tls_install_app_keys(&cconn, ch, ch_len, sh, sh_len,
                                                    post, post_sh),
                  0);
    EXPECT_TRUE(&ctx, "has_app2", cconn.has_app_keys);

    uint8_t hspkt[512];
    size_t hspkt_len = 0;
    EXPECT_EQ_INT(&ctx, "build_hs_pkt",
                  dislmdb_quic_build_handshake_packet(&cconn, false, 1, fin_msg,
                                                      fin_len, hspkt, sizeof(hspkt),
                                                      &hspkt_len),
                  0);
    EXPECT_TRUE(&ctx, "hs_pkt_len", hspkt_len > 20);
    dislmdb_quic_long_header hslh;
    EXPECT_EQ_INT(&ctx, "hs_hdr",
                  dislmdb_quic_parse_long_header(hspkt, hspkt_len, &hslh), 0);
    EXPECT_EQ_INT(&ctx, "hs_type", (int)hslh.type, (int)DISLMDB_QUIC_LONG_HANDSHAKE);

    uint64_t hspn = 99;
    uint8_t hs_got[128];
    size_t hs_got_len = 0;
    EXPECT_EQ_INT(&ctx, "open_hs_pkt",
                  dislmdb_quic_open_handshake_packet(&cconn, false, hspkt, hspkt_len,
                                                     &hspn, hs_got, sizeof(hs_got),
                                                     &hs_got_len),
                  0);
    EXPECT_TRUE(&ctx, "hs_pn", hspn == 1);
    EXPECT_TRUE(&ctx, "hs_crypto",
                hs_got_len == fin_len && memcmp(hs_got, fin_msg, fin_len) == 0);

    free(tr_cv);
    free(tr_fin);
    free(post);
    dislmdb_quic_conn_reset(&cconn);

    /* Server Initial driver: X.509 identity + client_start → 1-RTT */
    {
        dislmdb_quic_tls_identity *sid =
            dislmdb_quic_tls_identity_self_signed("quic-unit");
        EXPECT_TRUE(&ctx, "drv_id", sid != NULL);
        dislmdb_quic_conn c2;
        uint8_t dcid2[8], scid2[8], cpriv2[32], ch2[512];
        size_t ch2_len = 0;
        uint8_t ipkt[512];
        size_t ipkt_len = 0;
        EXPECT_EQ_INT(&ctx, "drv_start",
                      dislmdb_quic_client_start(&c2, dcid2, scid2, cpriv2, ch2,
                                                sizeof(ch2), &ch2_len, ipkt,
                                                sizeof(ipkt), &ipkt_len),
                      0);
        EXPECT_TRUE(&ctx, "drv_ch_len", ch2_len > 4);
        EXPECT_TRUE(&ctx, "drv_ipkt", ipkt_len > 20);
        uint8_t sini[512], shs[4096];
        size_t sini_len = 0, shs_len = 0;
        dislmdb_quic_conn s2;
        memset(&s2, 0, sizeof(s2));
        EXPECT_EQ_INT(&ctx, "drv_server",
                      dislmdb_quic_server_handle_initial(ipkt, ipkt_len, sini,
                                                         sizeof(sini), &sini_len,
                                                         shs, sizeof(shs),
                                                         &shs_len, &s2, sid),
                      0);
        EXPECT_TRUE(&ctx, "drv_s_app", s2.has_app_keys);
        EXPECT_TRUE(&ctx, "drv_ini_len", sini_len > 20);
        EXPECT_TRUE(&ctx, "drv_hs_len", shs_len > 20);

        uint8_t cfin[512];
        size_t cfin_len = 0;
        EXPECT_EQ_INT(&ctx, "drv_complete",
                      dislmdb_quic_client_complete_handshake(
                          &c2, ch2, ch2_len, cpriv2, sini, sini_len, shs, shs_len,
                          sid, cfin, sizeof(cfin), &cfin_len),
                      0);
        EXPECT_TRUE(&ctx, "drv_app", c2.has_app_keys);
        EXPECT_TRUE(&ctx, "drv_cfin", cfin_len > 20);
        EXPECT_EQ_INT(&ctx, "drv_st_app", (int)c2.state, (int)DISLMDB_QUIC_HS_APP);

        const uint8_t app_msg[] = "1rtt-hello";
        uint8_t app_pkt[256];
        size_t app_pkt_len = 0;
        EXPECT_EQ_INT(&ctx, "drv_1rtt_build",
                      dislmdb_quic_build_one_rtt_packet(&c2, true, 0, app_msg,
                                                        sizeof(app_msg) - 1, app_pkt,
                                                        sizeof(app_pkt),
                                                        &app_pkt_len),
                      0);
        EXPECT_EQ_INT(&ctx, "drv_1rtt_class",
                      (int)dislmdb_quic_classify(app_pkt, app_pkt_len),
                      (int)DISLMDB_QUIC_DGRAM_QUIC_SHORT);
        uint64_t app_pn = 99;
        uint8_t app_got[64];
        size_t app_got_len = 0;
        EXPECT_EQ_INT(&ctx, "drv_1rtt_open",
                      dislmdb_quic_open_one_rtt_packet(&s2, true, app_pkt,
                                                       app_pkt_len, &app_pn, app_got,
                                                       sizeof(app_got),
                                                       &app_got_len),
                      0);
        EXPECT_TRUE(&ctx, "drv_1rtt_pn", app_pn == 0);
        EXPECT_TRUE(&ctx, "drv_1rtt_body",
                    app_got_len == sizeof(app_msg) - 1 &&
                        memcmp(app_got, app_msg, app_got_len) == 0);
        dislmdb_quic_conn_reset(&c2);
        dislmdb_quic_conn_reset(&s2);
        dislmdb_quic_tls_identity_destroy(sid);
    }

    /* PEM load (RSA) — same shape as mTLS IT certs */
    {
        (void)system("mkdir -p ./it_quic_certs && openssl req -x509 -newkey rsa:2048 "
                     "-nodes -keyout ./it_quic_certs/key.pem "
                     "-out ./it_quic_certs/cert.pem -days 1 "
                     "-subj '/CN=quic-pem' >/dev/null 2>&1");
        dislmdb_quic_tls_identity *pem = dislmdb_quic_tls_identity_load(
            "./it_quic_certs/cert.pem", "./it_quic_certs/key.pem",
            "./it_quic_certs/cert.pem");
        EXPECT_TRUE(&ctx, "pem_load", pem != NULL);
        if (pem) {
            const uint8_t *der = NULL;
            size_t der_len = 0;
            EXPECT_EQ_INT(&ctx, "pem_leaf",
                          dislmdb_quic_tls_identity_leaf_der(pem, &der, &der_len),
                          0);
            EXPECT_TRUE(&ctx, "pem_der_len", der_len > 64);
            uint8_t content[32];
            memset(content, 0xab, sizeof(content));
            uint8_t sig[512];
            size_t sig_len = 0;
            uint16_t scheme = 0;
            EXPECT_EQ_INT(&ctx, "pem_sign",
                          dislmdb_quic_tls_identity_sign(pem, content, sizeof(content),
                                                         &scheme, sig, sizeof(sig),
                                                         &sig_len),
                          0);
            EXPECT_EQ_INT(&ctx, "pem_scheme", (int)scheme,
                          (int)DISLMDB_QUIC_TLS_SIG_RSA_PKCS1_SHA256);

            /* CA mismatch: peer leaf signed by other CA must fail strict verify */
            dislmdb_quic_tls_identity *other =
                dislmdb_quic_tls_identity_self_signed("other-ca");
            EXPECT_TRUE(&ctx, "other_id", other != NULL);
            if (other) {
                const uint8_t *oder = NULL;
                size_t oder_len = 0;
                EXPECT_EQ_INT(&ctx, "other_leaf",
                              dislmdb_quic_tls_identity_leaf_der(other, &oder,
                                                                 &oder_len),
                              0);
                uint8_t cert_msg[2048];
                size_t cert_msg_len = 0;
                EXPECT_EQ_INT(&ctx, "other_cert_enc",
                              dislmdb_quic_tls_encode_certificate(
                                  oder, oder_len, cert_msg, sizeof(cert_msg),
                                  &cert_msg_len),
                              0);
                uint8_t cv_content[160];
                size_t cv_content_len = 0;
                uint8_t tr[32];
                memset(tr, 0x11, sizeof(tr));
                EXPECT_EQ_INT(&ctx, "cv_content",
                              dislmdb_quic_tls_cert_verify_content(
                                  true, tr, sizeof(tr), cv_content,
                                  sizeof(cv_content), &cv_content_len),
                              0);
                uint8_t osig[512];
                size_t osig_len = 0;
                uint16_t oscheme = 0;
                EXPECT_EQ_INT(&ctx, "other_sign",
                              dislmdb_quic_tls_identity_sign(
                                  other, cv_content, cv_content_len, &oscheme,
                                  osig, sizeof(osig), &osig_len),
                              0);
                uint8_t cv_msg[640];
                size_t cv_msg_len = 0;
                EXPECT_EQ_INT(&ctx, "cv_enc",
                              dislmdb_quic_tls_encode_certificate_verify(
                                  oscheme, osig, osig_len, cv_msg,
                                  sizeof(cv_msg), &cv_msg_len),
                              0);
                /* Strict CA (pem) rejects unrelated self-signed leaf */
                EXPECT_TRUE(&ctx, "ca_reject",
                            dislmdb_quic_tls_verify_peer_certificate(
                                cert_msg, cert_msg_len, cv_msg, cv_msg_len,
                                cv_content, cv_content_len, pem) != 0);
                /* TOFU (NULL trust) accepts CV against leaf */
                EXPECT_EQ_INT(&ctx, "tofu_ok",
                              dislmdb_quic_tls_verify_peer_certificate(
                                  cert_msg, cert_msg_len, cv_msg, cv_msg_len,
                                  cv_content, cv_content_len, NULL),
                              0);
                dislmdb_quic_tls_identity_destroy(other);
            }
            dislmdb_quic_tls_identity_destroy(pem);
        }
    }

    uint8_t short_hdr[1] = {0x40};
    EXPECT_EQ_INT(&ctx, "class_short",
                  (int)dislmdb_quic_classify(short_hdr, 1),
                  (int)DISLMDB_QUIC_DGRAM_QUIC_SHORT);

    EXPECT_TRUE(&ctx, "iouring_status",
                dislmdb_iouring_status() != NULL &&
                    dislmdb_iouring_status()[0] != '\0');
#if !defined(__linux__)
    EXPECT_TRUE(&ctx, "iouring_off", !dislmdb_iouring_available());
#endif

    return test_end(&ctx);
}
