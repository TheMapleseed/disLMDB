/**
 * @file test_raft_stage.c
 * @brief Staged bootstrap: A+B elect first; C joins later via HELLO/mesh then replicates
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PORT_A 30650
#define PORT_B 30651
#define PORT_C 30652

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_stage");

    it_rm_rf("./it_rs_a");
    it_rm_rf("./it_rs_b");
    it_rm_rf("./it_rs_c");
    it_mkdir("./it_rs_a");
    it_mkdir("./it_rs_b");
    it_mkdir("./it_rs_c");

    uint8_t key[32];
    memset(key, 0x49, 32);

    /* A/B know about C even while C is offline (staged join). */
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
    oa.path = "./it_rs_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_rs_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rs_c";
    oc.name = "raft-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    /* Mesh settle before second node — staged engage */
    usleep(200 * 1000);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *early[2] = {a, b};
    it_mesh_warmup(early, 2, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect_ab", it_wait_leader(early, 2, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_ab", leader[0] != '\0');

    DISLMDB_env *writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    EXPECT_EQ_INT(&ctx, "put_before_c", it_put_kv(writer, "stagek", "early"), 0);
    EXPECT_EQ_INT(&ctx, "see_a_early", it_wait_val(a, "stagek", "early", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b_early", it_wait_val(b, "stagek", "early", 10000), 0);

    /* Delayed third node joins after cluster already engaged */
    usleep(300 * 1000);
    EXPECT_EQ_INT(&ctx, "open_c_late", it_open_raft(&c, &oc), 0);

    DISLMDB_env *all[3] = {a, b, c};
    it_mesh_warmup(all, 3, 40);

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "elect_abc", it_wait_leader(all, 3, leader, sizeof(leader), 12000), 0);

    writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_after_c", it_put_kv(writer, "stagek2", "late"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "stagek2", "late", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "stagek2", "late", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", it_wait_val(c, "stagek2", "late", 10000), 0);

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rs_a");
    it_rm_rf("./it_rs_b");
    it_rm_rf("./it_rs_c");
    return test_end(&ctx);
}
