/**
 * @file test_raft_membership.c
 * @brief Raft joint-consensus: 2-node elect, reconfigure adds 3rd, then replicate
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PORT_A 30710
#define PORT_B 30711
#define PORT_C 30712

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_membership");

    it_rm_rf("./it_rmem_a");
    it_rm_rf("./it_rmem_b");
    it_rm_rf("./it_rmem_c");
    it_mkdir("./it_rmem_a");
    it_mkdir("./it_rmem_b");
    it_mkdir("./it_rmem_c");

    uint8_t key[32];
    memset(key, 0x4d, 32);

    DISLMDB_node_addr peers_a[1], peers_b[1], peers_c[2];
    it_peer(&peers_a[0], "raft-b", PORT_B);
    it_peer(&peers_b[0], "raft-a", PORT_A);
    it_peer(&peers_c[0], "raft-a", PORT_A);
    it_peer(&peers_c[1], "raft-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_rmem_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_rmem_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rmem_c";
    oc.name = "raft-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;
    oc.npeers = 2;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    usleep(200 * 1000);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *early[2] = {a, b};
    it_mesh_warmup(early, 2, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect_ab", it_wait_leader(early, 2, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_ab", leader[0] != '\0');

    DISLMDB_env *writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    EXPECT_EQ_INT(&ctx, "put_before", it_put_kv(writer, "mk1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_a_early", it_wait_val(a, "mk1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b_early", it_wait_val(b, "mk1", "v1", 10000), 0);

    /* Bring C online, then joint-consensus reconfigure on the leader. */
    EXPECT_EQ_INT(&ctx, "open_c", it_open_raft(&c, &oc), 0);
    usleep(400 * 1000);
    DISLMDB_env *warm3[3] = {a, b, c};
    it_mesh_warmup(warm3, 3, 20);

    DISLMDB_node_addr full[3];
    it_peer(&full[0], "raft-a", PORT_A);
    it_peer(&full[1], "raft-b", PORT_B);
    it_peer(&full[2], "raft-c", PORT_C);

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "leader_before_cfg",
                  it_wait_leader(early, 2, leader, sizeof(leader), 8000), 0);
    writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    EXPECT_EQ_INT(&ctx, "reconfigure", dislmdb_reconfigure_replicas(writer, full, 3), 0);

    it_mesh_warmup(warm3, 3, 30);

    DISLMDB_env *all[3] = {a, b, c};
    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "elect_abc", it_wait_leader(all, 3, leader, sizeof(leader), 12000), 0);
    writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_after", it_put_kv(writer, "mk2", "v2"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "mk2", "v2", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "mk2", "v2", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", it_wait_val(c, "mk2", "v2", 10000), 0);

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rmem_a");
    it_rm_rf("./it_rmem_b");
    it_rm_rf("./it_rmem_c");
    return test_end(&ctx);
}
