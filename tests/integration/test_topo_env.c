/**
 * @file test_topo_env.c
 * @brief Region/locality/topology/voting from env + persist round-trip
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/topo_env");

    it_rm_rf("./it_topo");
    it_mkdir("./it_topo");

    setenv("DISLMDB_REGION", "us-east", 1);
    setenv("DISLMDB_LOCALITY", "az-1", 1);
    setenv("DISLMDB_TOPOLOGY_MODE", "shard", 1);
    setenv("DISLMDB_VOTING", "off", 1);
    setenv("DISLMDB_RTT_BUDGET_MS", "120", 1);
    setenv("DISLMDB_MAX_PEERS", "0", 1);

    uint8_t key[32];
    memset(key, 0x61, 32);

    it_raft_opts o = it_raft_opts_default();
    o.path = "./it_topo";
    o.name = "topo-a";
    o.port = 30750;
    o.cluster_key = key;
    o.transport = DISLMDB_TRANSPORT_UDP;
    o.npeers = 0;

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "open", it_open_raft(&env, &o), 0);
    if (!env) {
        unsetenv("DISLMDB_REGION");
        unsetenv("DISLMDB_LOCALITY");
        unsetenv("DISLMDB_TOPOLOGY_MODE");
        unsetenv("DISLMDB_VOTING");
        unsetenv("DISLMDB_RTT_BUDGET_MS");
        unsetenv("DISLMDB_MAX_PEERS");
        return test_end(&ctx);
    }

    char region[64] = {0}, locality[64] = {0};
    DISLMDB_TOPOLOGY_MODE mode = DISLMDB_TOPO_MIRROR;
    EXPECT_EQ_INT(&ctx, "get_region", dislmdb_get_region(env, region, sizeof(region)), 0);
    EXPECT_STREQ(&ctx, "region", region, "us-east");
    EXPECT_EQ_INT(&ctx, "get_locality",
                  dislmdb_get_locality(env, locality, sizeof(locality)), 0);
    EXPECT_STREQ(&ctx, "locality", locality, "az-1");
    EXPECT_EQ_INT(&ctx, "get_mode", dislmdb_get_topology_mode(env, &mode), 0);
    EXPECT_EQ_INT(&ctx, "mode_shard", (int)mode, (int)DISLMDB_TOPO_SHARD);
    EXPECT_TRUE(&ctx, "voting_off", !dislmdb_voting_enabled(env));

    EXPECT_EQ_INT(&ctx, "checkpoint", dislmdb_checkpoint(env), 0);
    dislmdb_env_close(env);
    env = NULL;

    /* Clear env so restore comes from meta DBI */
    unsetenv("DISLMDB_REGION");
    unsetenv("DISLMDB_LOCALITY");
    unsetenv("DISLMDB_TOPOLOGY_MODE");
    unsetenv("DISLMDB_VOTING");
    unsetenv("DISLMDB_RTT_BUDGET_MS");
    unsetenv("DISLMDB_MAX_PEERS");

    o.name = "topo-a2";
    EXPECT_EQ_INT(&ctx, "reopen", it_open_raft(&env, &o), 0);
    if (env) {
        memset(region, 0, sizeof(region));
        memset(locality, 0, sizeof(locality));
        mode = DISLMDB_TOPO_MIRROR;
        EXPECT_EQ_INT(&ctx, "reload_region_rc",
                      dislmdb_get_region(env, region, sizeof(region)), 0);
        EXPECT_STREQ(&ctx, "reload_region", region, "us-east");
        EXPECT_EQ_INT(&ctx, "reload_locality_rc",
                      dislmdb_get_locality(env, locality, sizeof(locality)), 0);
        EXPECT_STREQ(&ctx, "reload_locality", locality, "az-1");
        EXPECT_EQ_INT(&ctx, "reload_mode_rc",
                      dislmdb_get_topology_mode(env, &mode), 0);
        EXPECT_EQ_INT(&ctx, "reload_mode", (int)mode, (int)DISLMDB_TOPO_SHARD);
        /* Voting comes from config/env default on reopen without DISLMDB_VOTING */
        EXPECT_TRUE(&ctx, "voting_default_on", dislmdb_voting_enabled(env));
        dislmdb_env_close(env);
    }

    it_rm_rf("./it_topo");
    return test_end(&ctx);
}
