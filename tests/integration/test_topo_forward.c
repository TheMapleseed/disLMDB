/**
 * @file test_topo_forward.c
 * @brief Shard owner write forward (non-owner → owner via FORWARD RPC)
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30940
#define PORT_B 30941

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/topo_forward");

    it_rm_rf("./it_tf_a");
    it_rm_rf("./it_tf_b");
    it_mkdir("./it_tf_a");
    it_mkdir("./it_tf_b");

    uint8_t key[32];
    memset(key, 0x41, 32);

    DISLMDB_node_addr peers_a[1], peers_b[1];
    it_peer(&peers_a[0], "tf-b", PORT_B);
    it_peer(&peers_b[0], "tf-a", PORT_A);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_tf_a";
    oa.name = "tf-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_UDP;
    oa.set_topology_mode = true;
    oa.topology_mode = DISLMDB_TOPO_SHARD;

    it_raft_opts ob = oa;
    ob.path = "./it_tf_b";
    ob.name = "tf-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 40);

    DISLMDB_shard_desc shards[1];
    memset(shards, 0, sizeof(shards));
    strncpy(shards[0].shard_id, "s1", sizeof(shards[0].shard_id) - 1);
    strncpy(shards[0].key_prefix, "owned/", sizeof(shards[0].key_prefix) - 1);
    strncpy(shards[0].owner_node_id, "tf-a", sizeof(shards[0].owner_node_id) - 1);
    EXPECT_EQ_INT(&ctx, "map_a", dislmdb_shard_map_set(a, shards, 1), 0);
    /* B learns map via consensus apply; wait briefly then install locally if needed. */
    for (int w = 0; w < 40; w++) {
        char owner[64] = {0};
        if (dislmdb_shard_lookup(b, "owned/k", 7, owner) == 0 &&
            strcmp(owner, "tf-a") == 0) {
            break;
        }
        usleep(50 * 1000);
    }
    if (dislmdb_topo_key_writable(b, "owned/k", 7) == DISLMDB_SUCCESS) {
        /* Map may not have replicated — install on B for gate + resolve. */
        EXPECT_EQ_INT(&ctx, "map_b", dislmdb_shard_map_set(b, shards, 1), 0);
    }

    EXPECT_EQ_INT(&ctx, "b_rejected",
                  dislmdb_topo_key_writable(b, "owned/k", 7),
                  DISLMDB_ERR_OPERATION_REJECTED);
    EXPECT_EQ_INT(&ctx, "a_ok",
                  dislmdb_topo_key_writable(a, "owned/k", 7), DISLMDB_SUCCESS);

    char lid[64] = {0};
    EXPECT_EQ_INT(&ctx, "have_leader", it_wait_leader(envs, 2, lid, sizeof(lid), 5000), 0);
    it_mesh_warmup(envs, 2, 20);

    EXPECT_EQ_INT(&ctx, "fwd_put",
                  dislmdb_topo_forward_put(b, "kv", "owned/k", 7, "via-fwd", 7, 10000),
                  0);
    EXPECT_EQ_INT(&ctx, "a_sees", it_wait_val(a, "owned/k", "via-fwd", 5000), 0);

    EXPECT_EQ_INT(&ctx, "fwd_del",
                  dislmdb_topo_forward_del(b, "kv", "owned/k", 7, 10000), 0);

    dislmdb_env_close(b);
    dislmdb_env_close(a);
    it_rm_rf("./it_tf_a");
    it_rm_rf("./it_tf_b");
    return test_end(&ctx);
}
