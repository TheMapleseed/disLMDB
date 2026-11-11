/**
 * @file test_raft_tcp.c
 * @brief Raft election + replication over TCP with AEAD; bytecode + checkpoint
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30610
#define PORT_B 30611
#define PORT_C 30612

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_tcp");

    it_rm_rf("./it_rt_a");
    it_rm_rf("./it_rt_b");
    it_rm_rf("./it_rt_c");
    it_mkdir("./it_rt_a");
    it_mkdir("./it_rt_b");
    it_mkdir("./it_rt_c");

    uint8_t key[32];
    memset(key, 0x45, 32);

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
    oa.path = "./it_rt_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_TCP;

    it_raft_opts ob = oa;
    ob.path = "./it_rt_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rt_c";
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
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }

    EXPECT_EQ_INT(&ctx, "put_raft_tcp", it_put_kv(writer, "raftk", "tcpv"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "raftk", "tcpv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "raftk", "tcpv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", it_wait_val(c, "raftk", "tcpv", 10000), 0);

    const uint8_t bc[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01};
    EXPECT_EQ_INT(&ctx, "store_bc",
                  dislmdb_store_bytecode(writer, bc, sizeof(bc), "raft-bc-1", 0), 0);
    uint8_t out[16];
    size_t out_sz = sizeof(out);
    unsigned opts = 0;
    int got = -1;
    for (int w = 0; w < 100 && got != 0; w++) {
        out_sz = sizeof(out);
        got = dislmdb_get_bytecode(a, "raft-bc-1", out, &out_sz, &opts);
        if (got != 0) {
            usleep(50 * 1000);
        }
    }
    EXPECT_EQ_INT(&ctx, "get_bc", got, 0);
    EXPECT_EQ_INT(&ctx, "bc_len", (int)out_sz, (int)sizeof(bc));
    EXPECT_EQ_INT(&ctx, "checkpoint", dislmdb_checkpoint(writer), 0);

    DISLMDB_shard_desc shards[2];
    memset(shards, 0, sizeof(shards));
    strncpy(shards[0].shard_id, "shardA", sizeof(shards[0].shard_id) - 1);
    strncpy(shards[0].key_prefix, "shardA/", sizeof(shards[0].key_prefix) - 1);
    strncpy(shards[0].owner_node_id, "raft-a", sizeof(shards[0].owner_node_id) - 1);
    strncpy(shards[1].shard_id, "shardB", sizeof(shards[1].shard_id) - 1);
    strncpy(shards[1].key_prefix, "shardB/", sizeof(shards[1].key_prefix) - 1);
    strncpy(shards[1].owner_node_id, "raft-b", sizeof(shards[1].owner_node_id) - 1);
    EXPECT_EQ_INT(&ctx, "shard_set", dislmdb_shard_map_set(writer, shards, 2), 0);
    char owner[64] = {0};
    int shard_ok = -1;
    for (int w = 0; w < 100 && shard_ok != 0; w++) {
        memset(owner, 0, sizeof(owner));
        shard_ok = dislmdb_shard_lookup(c, "shardA/item", strlen("shardA/item"), owner);
        if (shard_ok != 0 || strcmp(owner, "raft-a") != 0) {
            shard_ok = -1;
            usleep(50 * 1000);
        }
    }
    EXPECT_EQ_INT(&ctx, "shard_see_c", shard_ok, 0);
    EXPECT_STREQ(&ctx, "shard_owner_c", owner, "raft-a");

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rt_a");
    it_rm_rf("./it_rt_b");
    it_rm_rf("./it_rt_c");
    return test_end(&ctx);
}
