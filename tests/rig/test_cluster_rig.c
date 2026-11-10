/**
 * @file test_cluster_rig.c
 * @brief Sandbox-safe multi-node scenarios (stand-ins for integration tests)
 *
 * Mirrors: multinode replicate, UDP substrate, Raft election, f=1 after kill.
 */
#include "../harness/test_harness.h"
#include "cluster_rig.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t index_of_id(RigCluster *c, const char *id)
{
    for (uint32_t i = 0; i < rig_node_count(c); i++) {
        if (strcmp(rig_node_id(c, i), id) == 0) {
            return i;
        }
    }
    return UINT32_MAX;
}

static void scenario_multinode(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 3;
    cfg.transport = RIG_TRANSPORT_BUS;
    cfg.id_prefix = "mn";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "mn_create", c != NULL);
    if (!c) {
        return;
    }

    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "mn_elect", rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_EQ_INT(ctx, "mn_put", rig_put(c, "alpha", "omega", 3000), 0);

    for (uint32_t i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "mn_see_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "alpha", "omega", 3000), 0);
    }

    /* Follower-originated write: still goes through leader propose */
    EXPECT_EQ_INT(ctx, "mn_put2", rig_put(c, "beta", "gamma", 3000), 0);
    for (uint32_t i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "mn_see2_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "beta", "gamma", 3000), 0);
    }
    rig_cluster_destroy(c);
}

static void scenario_udp_substrate(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 2;
    cfg.transport = RIG_TRANSPORT_DGRAM;
    cfg.id_prefix = "udp";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "udp_create", c != NULL);
    if (!c) {
        return;
    }
    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "udp_elect", rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_EQ_INT(ctx, "udp_put", rig_put(c, "wt", "datagram", 3000), 0);
    EXPECT_EQ_INT(ctx, "udp_see_0", rig_wait_get(c, 0, "wt", "datagram", 3000), 0);
    EXPECT_EQ_INT(ctx, "udp_see_1", rig_wait_get(c, 1, "wt", "datagram", 3000), 0);
    rig_cluster_destroy(c);
}

static void scenario_mixed_transport(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 3;
    cfg.transport = RIG_TRANSPORT_MIXED;
    cfg.id_prefix = "mix";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "mix_create", c != NULL);
    if (!c) {
        return;
    }
    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "mix_elect",
                  rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_TRUE(ctx, "mix_signal_lane",
                rig_signal_msgs(c) > 0); /* RequestVote traffic */
    EXPECT_EQ_INT(ctx, "mix_put", rig_put(c, "both", "adapt", 3000), 0);
    EXPECT_TRUE(ctx, "mix_data_lane", rig_data_msgs(c) > 0);
    for (uint32_t i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "mix_see_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "both", "adapt", 3000), 0);
    }
    rig_cluster_destroy(c);
}

static void scenario_raft_election(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 3;
    cfg.id_prefix = "raft";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "raft_create", c != NULL);
    if (!c) {
        return;
    }
    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "raft_elect",
                  rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_TRUE(ctx, "raft_leader_named", leader[0] != '\0');
    EXPECT_EQ_INT(ctx, "raft_put", rig_put(c, "raftk", "udpv", 3000), 0);
    for (uint32_t i = 0; i < 3; i++) {
        char name[32];
        snprintf(name, sizeof(name), "raft_see_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "raftk", "udpv", 3000), 0);
    }
    (void)index_of_id;
    rig_cluster_destroy(c);
}

static void scenario_fault_tolerance(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 4; /* majority = 3; kill 1 → still commit */
    cfg.id_prefix = "ft";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "ft_create", c != NULL);
    if (!c) {
        return;
    }

    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "ft_elect",
                  rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_EQ_INT(ctx, "ft_put_all_up", rig_put(c, "k1", "v1", 3000), 0);
    for (uint32_t i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "ft_see_k1_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "k1", "v1", 3000), 0);
    }

    uint32_t li = index_of_id(c, leader);
    uint32_t victim = (li == 0) ? 3u : 0u; /* prefer non-leader */
    if (victim == li) {
        victim = (li + 1) % 4;
    }
    rig_kill(c, victim);
    EXPECT_TRUE(ctx, "ft_killed", !rig_alive(c, victim));

    EXPECT_EQ_INT(ctx, "ft_put_after_kill",
                  rig_put(c, "k2", "v2", 5000), 0);
    for (uint32_t i = 0; i < 4; i++) {
        if (!rig_alive(c, i)) {
            continue;
        }
        char name[32];
        snprintf(name, sizeof(name), "ft_see_k2_%u", i);
        EXPECT_EQ_INT(ctx, name, rig_wait_get(c, i, "k2", "v2", 5000), 0);
    }
    rig_cluster_destroy(c);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "rig/cluster");

    scenario_multinode(&ctx);
    scenario_udp_substrate(&ctx);
    scenario_mixed_transport(&ctx);
    scenario_raft_election(&ctx);
    scenario_fault_tolerance(&ctx);

    return test_end(&ctx);
}
