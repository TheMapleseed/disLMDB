/**
 * @file test_raft_leave.c
 * @brief Raft graceful leave: 3-node elect, remove peer, remaining replicate
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"
#include "dislmdb_consensus.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PORT_A 30740
#define PORT_B 30741
#define PORT_C 30742

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_leave");

    it_rm_rf("./it_rl_a");
    it_rm_rf("./it_rl_b");
    it_rm_rf("./it_rl_c");
    it_mkdir("./it_rl_a");
    it_mkdir("./it_rl_b");
    it_mkdir("./it_rl_c");

    uint8_t key[32];
    memset(key, 0x4c, 32);

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
    oa.path = "./it_rl_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_rl_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rl_c";
    oc.name = "raft-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);
    EXPECT_EQ_INT(&ctx, "open_c", it_open_raft(&c, &oc), 0);

    DISLMDB_env *all[3] = {a, b, c};
    it_mesh_warmup(all, 3, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(all, 3, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_before", it_put_kv(writer, "lk1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "lk1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "lk1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", it_wait_val(c, "lk1", "v1", 10000), 0);

    /* Leader removes a follower (never self). */
    const char *victim_id = "raft-c";
    DISLMDB_env *victim_env = c;
    if (strcmp(leader, "raft-c") == 0) {
        victim_id = "raft-b";
        victim_env = b;
    }
    EXPECT_EQ_INT(&ctx, "remove_peer", dislmdb_remove_node(writer, victim_id), 0);
    usleep(300 * 1000);
    dislmdb_env_close(victim_env);
    if (victim_env == b) {
        b = NULL;
    } else {
        c = NULL;
    }

    DISLMDB_env *remain[2];
    remain[0] = a;
    remain[1] = (b != NULL) ? b : c;
    EXPECT_TRUE(&ctx, "remain1", remain[1] != NULL);

    it_mesh_warmup(remain, 2, 20);

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "elect_remain",
                  it_wait_leader(remain, 2, leader, sizeof(leader), 12000), 0);
    writer = remain[0];
    if (b && strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (c && strcmp(leader, "raft-c") == 0) {
        writer = c;
    } else if (strcmp(leader, "raft-a") == 0) {
        writer = a;
    }
    EXPECT_EQ_INT(&ctx, "put_after_leave", it_put_kv(writer, "lk2", "v2"), 0);
    EXPECT_EQ_INT(&ctx, "see0_after", it_wait_val(remain[0], "lk2", "v2", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see1_after", it_wait_val(remain[1], "lk2", "v2", 10000), 0);

    EXPECT_EQ_INT(&ctx, "force_election", dislmdb_consensus_trigger_view_change(writer), 0);
    usleep(200 * 1000);
    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "reelect", it_wait_leader(remain, 2, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_after_stepdown", leader[0] != '\0');

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rl_a");
    it_rm_rf("./it_rl_b");
    it_rm_rf("./it_rl_c");
    return test_end(&ctx);
}
