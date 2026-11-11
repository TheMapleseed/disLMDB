/**
 * @file test_raft_learner.c
 * @brief Hub voter + non-voting learner: AE replication without learner votes
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_H 30880
#define PORT_L 30881

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_learner");

    it_rm_rf("./it_rl_hub");
    it_rm_rf("./it_rl_leaf");
    it_mkdir("./it_rl_hub");
    it_mkdir("./it_rl_leaf");

    uint8_t key[32];
    memset(key, 0x6C, sizeof(key));

    /* Hub alone first so solo election is not blocked by a default-voter peer. */
    it_raft_opts oh = it_raft_opts_default();
    oh.path = "./it_rl_hub";
    oh.name = "hub";
    oh.port = PORT_H;
    oh.cluster_key = key;
    oh.transport = DISLMDB_TRANSPORT_TCP;
    oh.region = "east";
    oh.set_enable_voting = true;
    oh.enable_voting = true;
    oh.election_min_ms = 120;
    oh.election_max_ms = 240;
    oh.heartbeat_ms = 60;
    oh.timeout_ms = 5000;

    DISLMDB_env *hub = NULL;
    EXPECT_EQ_INT(&ctx, "open_hub", it_open_raft(&hub, &oh), 0);

    DISLMDB_env *envs1[1] = {hub};
    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect_solo",
                  it_wait_leader(envs1, 1, leader, sizeof(leader), 5000), 0);
    EXPECT_STREQ(&ctx, "hub_leader", leader, "hub");
    EXPECT_TRUE(&ctx, "hub_voting", dislmdb_voting_enabled(hub));

    DISLMDB_node_addr leaf_addr;
    it_peer_region(&leaf_addr, "leaf", PORT_L, "east");
    int arc = dislmdb_add_node(hub, &leaf_addr);
    EXPECT_TRUE(&ctx, "add_leaf",
                arc == DISLMDB_SUCCESS || arc == DISLMDB_ERR_CONNECTION ||
                    arc == DISLMDB_ERR_NODE_UNREACHABLE);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_H);

    DISLMDB_node_addr hub_peer;
    it_peer_region(&hub_peer, "hub", PORT_H, "east");

    it_raft_opts ol = it_raft_opts_default();
    ol.path = "./it_rl_leaf";
    ol.name = "leaf";
    ol.port = PORT_L;
    ol.cluster_key = key;
    ol.transport = DISLMDB_TRANSPORT_TCP;
    ol.seed = seed;
    ol.peers = &hub_peer;
    ol.npeers = 1;
    ol.region = "east";
    ol.set_enable_voting = true;
    ol.enable_voting = false;
    ol.election_min_ms = 120;
    ol.election_max_ms = 240;
    ol.heartbeat_ms = 60;
    ol.timeout_ms = 5000;

    DISLMDB_env *leaf = NULL;
    EXPECT_EQ_INT(&ctx, "open_leaf", it_open_raft(&leaf, &ol), 0);
    EXPECT_TRUE(&ctx, "leaf_voting_off", !dislmdb_voting_enabled(leaf));

    DISLMDB_env *envs[2] = {hub, leaf};
    it_mesh_warmup(envs, 2, 40);

    /* Learner must not become leader */
    char leaf_leader[64] = {0};
    (void)dislmdb_get_leader(leaf, leaf_leader, sizeof(leaf_leader));
    EXPECT_TRUE(&ctx, "leaf_not_self_leader",
                leaf_leader[0] == '\0' || strcmp(leaf_leader, "leaf") != 0);

    EXPECT_EQ_INT(&ctx, "put_hub", it_put_kv(hub, "learn-k", "learn-v"), 0);
    EXPECT_EQ_INT(&ctx, "see_hub", it_wait_val(hub, "learn-k", "learn-v", 3000), 0);
    EXPECT_EQ_INT(&ctx, "see_leaf", it_wait_val(leaf, "learn-k", "learn-v", 12000),
                  0);

    DISLMDB_metrics mh, ml;
    memset(&mh, 0, sizeof(mh));
    memset(&ml, 0, sizeof(ml));
    EXPECT_EQ_INT(&ctx, "m_hub", dislmdb_get_metrics(hub, &mh), 0);
    EXPECT_EQ_INT(&ctx, "m_leaf", dislmdb_get_metrics(leaf, &ml), 0);
    EXPECT_TRUE(&ctx, "hub_vote_metric", mh.voting_enabled);
    EXPECT_TRUE(&ctx, "leaf_vote_metric", !ml.voting_enabled);
    EXPECT_TRUE(&ctx, "hub_is_leader", mh.is_leader);

    if (leaf) {
        dislmdb_env_close(leaf);
    }
    if (hub) {
        dislmdb_env_close(hub);
    }
    it_rm_rf("./it_rl_hub");
    it_rm_rf("./it_rl_leaf");
    return test_end(&ctx);
}
