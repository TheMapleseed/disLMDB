/**
 * @file test_raft_fault.c
 * @brief Raft 3-node LMDB soak: kill one replica, majority still commits
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30640
#define PORT_B 30641
#define PORT_C 30642

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_fault");

    it_rm_rf("./it_rf_a");
    it_rm_rf("./it_rf_b");
    it_rm_rf("./it_rf_c");
    it_mkdir("./it_rf_a");
    it_mkdir("./it_rf_b");
    it_mkdir("./it_rf_c");

    uint8_t key[32];
    memset(key, 0x48, 32);

    DISLMDB_node_addr peers_a[2], peers_b[2], peers_c[2];
    it_peer(&peers_a[0], "raft-b", PORT_B);
    it_peer(&peers_a[1], "raft-c", PORT_C);
    it_peer(&peers_b[0], "raft-a", PORT_A);
    it_peer(&peers_b[1], "raft-c", PORT_C);
    it_peer(&peers_c[0], "raft-a", PORT_A);
    it_peer(&peers_c[1], "raft-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_rf_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_TCP;

    it_raft_opts ob = oa;
    ob.path = "./it_rf_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rf_c";
    oc.name = "raft-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);
    EXPECT_EQ_INT(&ctx, "open_c", it_open_raft(&c, &oc), 0);

    DISLMDB_env *envs[3] = {a, b, c};
    it_mesh_warmup(envs, 3, 20);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 3, leader, sizeof(leader), 12000), 0);

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_all_up", it_put_kv(writer, "k1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_b_k1", it_wait_val(b, "k1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c_k1", it_wait_val(c, "k1", "v1", 10000), 0);

    /* Kill a follower when possible; if leader is C, kill C and re-elect on A/B. */
    DISLMDB_env *killed = c;
    if (strcmp(leader, "raft-c") == 0) {
        killed = c;
    } else if (strcmp(leader, "raft-b") == 0) {
        killed = a;
        if (killed == writer) {
            killed = c;
        }
    } else {
        killed = c;
    }
    if (killed == a) {
        dislmdb_env_close(a);
        a = NULL;
        envs[0] = NULL;
    } else if (killed == b) {
        dislmdb_env_close(b);
        b = NULL;
        envs[1] = NULL;
    } else {
        dislmdb_env_close(c);
        c = NULL;
        envs[2] = NULL;
    }

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "reelect", it_wait_leader(envs, 3, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader2", leader[0] != '\0');

    writer = NULL;
    if (a && strcmp(leader, "raft-a") == 0) {
        writer = a;
    } else if (b && strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (c && strcmp(leader, "raft-c") == 0) {
        writer = c;
    } else if (a) {
        writer = a;
    } else if (b) {
        writer = b;
    } else {
        writer = c;
    }
    EXPECT_TRUE(&ctx, "writer_alive", writer != NULL);
    EXPECT_EQ_INT(&ctx, "put_after_kill", it_put_kv(writer, "k2", "v2"), 0);
    if (a) {
        EXPECT_EQ_INT(&ctx, "see_a_k2", it_wait_val(a, "k2", "v2", 10000), 0);
    }
    if (b) {
        EXPECT_EQ_INT(&ctx, "see_b_k2", it_wait_val(b, "k2", "v2", 10000), 0);
    }
    if (c) {
        EXPECT_EQ_INT(&ctx, "see_c_k2", it_wait_val(c, "k2", "v2", 10000), 0);
    }

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rf_a");
    it_rm_rf("./it_rf_b");
    it_rm_rf("./it_rf_c");
    return test_end(&ctx);
}
