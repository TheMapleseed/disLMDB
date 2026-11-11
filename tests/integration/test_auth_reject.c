/**
 * @file test_auth_reject.c
 * @brief Negative crypto: mismatched cluster keys must not replicate
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30740
#define PORT_B 30741

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/auth_reject");

    it_rm_rf("./it_ar_a");
    it_rm_rf("./it_ar_b");
    it_mkdir("./it_ar_a");
    it_mkdir("./it_ar_b");

    uint8_t key_a[32], key_b[32];
    memset(key_a, 0x11, 32);
    memset(key_b, 0x22, 32);

    DISLMDB_node_addr peers_a, peers_b;
    it_peer(&peers_a, "ar-b", PORT_B);
    it_peer(&peers_b, "ar-a", PORT_A);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_ar_a";
    oa.name = "ar-a";
    oa.port = PORT_A;
    oa.cluster_key = key_a;
    oa.peers = &peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_ar_b";
    ob.name = "ar-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.cluster_key = key_b;
    ob.peers = &peers_b;

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 20);

    /* A can still open locally; cross-peer auth must fail closed. */
    int put_rc = it_put_kv(a, "secret", "nope");
    /*
     * Solo-ish fallback: with no authenticated peer vote, Raft may time out
     * or refuse. Either way B must not observe the value.
     */
    EXPECT_TRUE(&ctx, "put_or_timeout",
                put_rc == 0 || put_rc == DISLMDB_ERR_CONSENSUS_TIMEOUT ||
                    put_rc == DISLMDB_ERR_CONSENSUS_FAILED ||
                    put_rc == DISLMDB_ERR_NO_LEADER);
    EXPECT_EQ_INT(&ctx, "b_must_miss", it_wait_val(b, "secret", "nope", 1500), -1);

    DISLMDB_network_stats st;
    memset(&st, 0, sizeof(st));
    if (dislmdb_network_get_stats(a, &st) == 0) {
        EXPECT_TRUE(&ctx, "auth_errors_or_quiet",
                    st.total_errors > 0 || st.total_messages_received == 0 ||
                        put_rc != 0);
    }

    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_ar_a");
    it_rm_rf("./it_ar_b");
    return test_end(&ctx);
}
