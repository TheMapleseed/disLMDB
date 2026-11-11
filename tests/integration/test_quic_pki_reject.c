/**
 * @file test_quic_pki_reject.c
 * @brief Live QUIC: mismatched CA trust must not replicate (strict PKI)
 */
#include "../harness/test_harness.h"
#include "dislmdb_quic.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30770
#define PORT_B 30771

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/quic_pki_reject");

    EXPECT_TRUE(&ctx, "quic_stack", dislmdb_quic_stack_ready());

    it_rm_rf("./it_qpki_a");
    it_rm_rf("./it_qpki_b");
    it_rm_rf("./it_qpki_ca_a");
    it_rm_rf("./it_qpki_ca_b");
    it_mkdir("./it_qpki_a");
    it_mkdir("./it_qpki_b");
    EXPECT_EQ_INT(&ctx, "certs_a", it_gen_certs("./it_qpki_ca_a"), 0);
    EXPECT_EQ_INT(&ctx, "certs_b", it_gen_certs("./it_qpki_ca_b"), 0);

    uint8_t key[32];
    memset(key, 0x71, 32);

    DISLMDB_node_addr peers_a, peers_b;
    it_peer(&peers_a, "qpki-b", PORT_B);
    it_peer(&peers_b, "qpki-a", PORT_A);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_qpki_a";
    oa.name = "qpki-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = &peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_QUIC;
    oa.cert_dir = "./it_qpki_ca_a"; /* strict CA = own leaf */
    oa.timeout_ms = 8000;
    oa.election_min_ms = 300;
    oa.election_max_ms = 600;

    it_raft_opts ob = oa;
    ob.path = "./it_qpki_b";
    ob.name = "qpki-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = &peers_b;
    ob.cert_dir = "./it_qpki_ca_b"; /* different CA → reject */

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 40);

    int put_rc = it_put_kv(a, "pki-secret", "nope");
    EXPECT_TRUE(&ctx, "put_or_timeout",
                put_rc == 0 || put_rc == DISLMDB_ERR_CONSENSUS_TIMEOUT ||
                    put_rc == DISLMDB_ERR_CONSENSUS_FAILED ||
                    put_rc == DISLMDB_ERR_NO_LEADER);
    EXPECT_EQ_INT(&ctx, "b_must_miss",
                  it_wait_val(b, "pki-secret", "nope", 2000), -1);

    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_qpki_a");
    it_rm_rf("./it_qpki_b");
    it_rm_rf("./it_qpki_ca_a");
    it_rm_rf("./it_qpki_ca_b");
    return test_end(&ctx);
}
