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
#include <unistd.h>

static uint32_t index_of_id(RigCluster *c, const char *id)
{
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (!rig_in_use(c, i)) {
            continue;
        }
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

/** Mild packet loss still allows quorum commit. */
static void scenario_adversity_drop(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 3;
    cfg.id_prefix = "drop";
    cfg.drop_pct = 15;
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "drop_create", c != NULL);
    if (!c) {
        return;
    }
    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "drop_elect",
                  rig_wait_leader(c, leader, sizeof(leader), 8000), 0);
    EXPECT_EQ_INT(ctx, "drop_put", rig_put(c, "lossy", "ok", 8000), 0);
    EXPECT_EQ_INT(ctx, "drop_see_all",
                  rig_wait_get_all_alive(c, "lossy", "ok", 8000), 0);
    EXPECT_TRUE(ctx, "drop_saw_drops", rig_dropped_msgs(c) > 0);
    rig_cluster_destroy(c);
}

/**
 * Spontaneous spawn/despawn + kill/revive churn — connect/disconnect soak.
 * Keeps a live majority; verifies puts still replicate to survivors.
 */
static void scenario_chaos_churn(test_ctx_t *ctx)
{
    RigConfig cfg = rig_config_default();
    cfg.node_count = 3;
    cfg.id_prefix = "churn";
    RigCluster *c = rig_cluster_create(&cfg);
    EXPECT_TRUE(ctx, "churn_create", c != NULL);
    if (!c) {
        return;
    }

    char leader[64] = {0};
    EXPECT_EQ_INT(ctx, "churn_elect0",
                  rig_wait_leader(c, leader, sizeof(leader), 5000), 0);
    EXPECT_EQ_INT(ctx, "churn_put0", rig_put(c, "base", "v0", 5000), 0);
    EXPECT_EQ_INT(ctx, "churn_see0",
                  rig_wait_get_all_alive(c, "base", "v0", 5000), 0);

    int spawned = rig_spawn(c, "churn-extra");
    EXPECT_TRUE(ctx, "churn_spawn", spawned >= 0);
    EXPECT_EQ_INT(ctx, "churn_active4", (int)rig_active_count(c), 4);

    /* Brief settle so the newcomer can hear AppendEntries */
    usleep(200 * 1000);
    EXPECT_EQ_INT(ctx, "churn_put1",
                  rig_put(c, "after_spawn", "v1", 8000), 0);
    EXPECT_EQ_INT(ctx, "churn_see1",
                  rig_wait_get_all_alive(c, "after_spawn", "v1", 8000), 0);

    uint32_t rounds_ok = 0;
    for (uint32_t round = 0; round < 24; round++) {
        uint32_t mode = round % 4u;
        if (mode == 0 && rig_active_count(c) < RIG_MAX_NODES - 1) {
            char id[64];
            snprintf(id, sizeof(id), "churn-dyn-%u", round);
            (void)rig_spawn(c, id);
        } else if (mode == 1) {
            /* Kill a non-leader if we still have ≥3 alive after */
            char lid[64] = {0};
            if (rig_wait_leader(c, lid, sizeof(lid), 2000) == 0) {
                uint32_t li = index_of_id(c, lid);
                for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
                    if (!rig_in_use(c, i) || !rig_alive(c, i) || i == li) {
                        continue;
                    }
                    uint32_t alive_n = 0;
                    for (uint32_t j = 0; j < RIG_MAX_NODES; j++) {
                        if (rig_alive(c, j)) {
                            alive_n++;
                        }
                    }
                    if (alive_n > 3) {
                        rig_kill(c, i);
                    }
                    break;
                }
            }
        } else if (mode == 2) {
            for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
                if (rig_in_use(c, i) && !rig_alive(c, i)) {
                    rig_revive(c, i);
                    break;
                }
            }
        } else if (mode == 3 && rig_active_count(c) > 3) {
            char lid[64] = {0};
            uint32_t li = UINT32_MAX;
            if (rig_wait_leader(c, lid, sizeof(lid), 2000) == 0) {
                li = index_of_id(c, lid);
            }
            for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
                if (rig_in_use(c, i) && i != li) {
                    if (rig_despawn(c, i) == 0) {
                        break;
                    }
                }
            }
        }

        usleep(50 * 1000);
        char key[32], val[32];
        snprintf(key, sizeof(key), "r%u", round);
        snprintf(val, sizeof(val), "v%u", round);
        if (rig_put(c, key, val, 6000) == 0 &&
            rig_wait_get_all_alive(c, key, val, 6000) == 0) {
            rounds_ok++;
        }
    }

    EXPECT_TRUE(ctx, "churn_majority_rounds", rounds_ok >= 16);
    EXPECT_TRUE(ctx, "churn_still_active", rig_active_count(c) >= 2);

    EXPECT_EQ_INT(ctx, "churn_final_put",
                  rig_put(c, "final", "ok", 8000), 0);
    EXPECT_EQ_INT(ctx, "churn_final_see",
                  rig_wait_get_all_alive(c, "final", "ok", 8000), 0);

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
    scenario_adversity_drop(&ctx);
    scenario_chaos_churn(&ctx);

    return test_end(&ctx);
}
