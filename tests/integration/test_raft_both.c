/**
 * @file test_raft_both.c
 * @brief Raft over TRANSPORT_BOTH (UDP signal / TCP data) with AEAD
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30620
#define PORT_B 30621

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_both");

    it_rm_rf("./it_rb_a");
    it_rm_rf("./it_rb_b");
    it_mkdir("./it_rb_a");
    it_mkdir("./it_rb_b");

    uint8_t key[32];
    memset(key, 0x46, 32);

    DISLMDB_node_addr peers_a[1], peers_b[1];
    it_peer(&peers_a[0], "raft-b", PORT_B);
    it_peer(&peers_b[0], "raft-a", PORT_A);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_rb_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_BOTH;

    it_raft_opts ob = oa;
    ob.path = "./it_rb_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 30);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 2, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    EXPECT_EQ_INT(&ctx, "put_both", it_put_kv(writer, "bothk", "bothv"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "bothk", "bothv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "bothk", "bothv", 10000), 0);

    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rb_a");
    it_rm_rf("./it_rb_b");
    return test_end(&ctx);
}
