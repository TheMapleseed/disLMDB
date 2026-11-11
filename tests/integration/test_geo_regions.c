/**
 * @file test_geo_regions.c
 * @brief Multi-region soak: east hub + west learner (mirror) replicate;
 *        REGION_PRIORITY write gate on non-primary region.
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_E 30850
#define PORT_W 30851

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/geo_regions");

    it_rm_rf("./it_geo_e");
    it_rm_rf("./it_geo_w");
    it_mkdir("./it_geo_e");
    it_mkdir("./it_geo_w");

    uint8_t cluster[32], region_k[32], cross[32];
    memset(cluster, 0x47, 32);
    memset(region_k, 0x52, 32);
    memset(cross, 0x43, 32);

    DISLMDB_node_addr peer_e, peer_w;
    it_peer_region(&peer_e, "geo-w", PORT_W, "west");
    it_peer_region(&peer_w, "geo-e", PORT_E, "east");

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_E);

    /* East hub: voting on; west leaf: voting off; mirror + matching cross key */
    it_raft_opts oe = it_raft_opts_default();
    oe.path = "./it_geo_e";
    oe.name = "geo-e";
    oe.port = PORT_E;
    oe.cluster_key = cluster;
    oe.peers = &peer_e;
    oe.npeers = 1;
    oe.transport = DISLMDB_TRANSPORT_UDP;
    oe.region = "east";
    oe.locality = "az-1";
    oe.region_key = region_k;
    oe.cross_region_key = cross;
    oe.set_topology_mode = true;
    oe.topology_mode = DISLMDB_TOPO_MIRROR;
    oe.set_enable_voting = true;
    oe.enable_voting = true;
    oe.election_min_ms = 150;
    oe.election_max_ms = 300;
    oe.heartbeat_ms = 60;
    oe.timeout_ms = 8000;

    it_raft_opts ow = oe;
    ow.path = "./it_geo_w";
    ow.name = "geo-w";
    ow.port = PORT_W;
    ow.seed = seed;
    ow.peers = &peer_w;
    ow.region = "west";
    ow.locality = "az-2";
    ow.set_enable_voting = true;
    ow.enable_voting = false;

    DISLMDB_env *east = NULL, *west = NULL;
    EXPECT_EQ_INT(&ctx, "open_east", it_open_raft(&east, &oe), 0);
    EXPECT_EQ_INT(&ctx, "open_west", it_open_raft(&west, &ow), 0);
    EXPECT_TRUE(&ctx, "east_votes", dislmdb_voting_enabled(east));
    EXPECT_TRUE(&ctx, "west_learner", !dislmdb_voting_enabled(west));

    DISLMDB_env *envs[2] = {east, west};
    it_mesh_warmup(envs, 2, 50);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect",
                  it_wait_leader(envs, 2, leader, sizeof(leader), 10000), 0);
    EXPECT_STREQ(&ctx, "east_leader", leader, "geo-e");

    EXPECT_EQ_INT(&ctx, "put_east", it_put_kv(east, "geo/k1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_east", it_wait_val(east, "geo/k1", "v1", 5000), 0);
    EXPECT_EQ_INT(&ctx, "see_west_learner",
                  it_wait_val(west, "geo/k1", "v1", 15000), 0);

    char region[64] = {0}, locality[64] = {0};
    EXPECT_EQ_INT(&ctx, "get_region_e",
                  dislmdb_get_region(east, region, sizeof(region)), 0);
    EXPECT_STREQ(&ctx, "region_east", region, "east");
    EXPECT_EQ_INT(&ctx, "get_locality_w",
                  dislmdb_get_locality(west, locality, sizeof(locality)), 0);
    EXPECT_STREQ(&ctx, "locality_west", locality, "az-2");

    if (west) {
        dislmdb_env_close(west);
        west = NULL;
    }
    if (east) {
        dislmdb_env_close(east);
        east = NULL;
    }
    it_rm_rf("./it_geo_e");
    it_rm_rf("./it_geo_w");

    /* REGION_PRIORITY: west edge cannot write when primary is east */
    it_mkdir("./it_geo_prio");
    DISLMDB_env *edge = NULL;
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = "./it_geo_prio";
    cfg.mapsize = 4 * 1024 * 1024;
    cfg.maxdbs = 8;
    strncpy(cfg.node_name, "edge-west", sizeof(cfg.node_name) - 1);
    cfg.network.local_port = 30852;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    cfg.topology_mode = DISLMDB_TOPO_MIRROR;
    cfg.mirror_conflict_policy = DISLMDB_MIRROR_REGION_PRIORITY;
    strncpy(cfg.region, "west", sizeof(cfg.region) - 1);
    strncpy(cfg.mirror_primary_region, "east",
            sizeof(cfg.mirror_primary_region) - 1);
    EXPECT_EQ_INT(&ctx, "prio_create", dislmdb_env_create(&edge), 0);
    EXPECT_EQ_INT(&ctx, "prio_open", dislmdb_env_open(edge, &cfg), 0);

    DISLMDB_txn *txn = NULL;
    EXPECT_EQ_INT(&ctx, "prio_begin", dislmdb_txn_begin(edge, NULL, 0, &txn), 0);
    MDB_dbi dbi;
    EXPECT_EQ_INT(&ctx, "prio_dbi", dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi),
                  0);
    MDB_val k = {.mv_size = 5, .mv_data = (void *)"prio/"};
    MDB_val v = {.mv_size = 1, .mv_data = (void *)"x"};
    EXPECT_EQ_INT(&ctx, "prio_put_rej", dislmdb_put(txn, dbi, &k, &v, 0),
                  DISLMDB_ERR_OPERATION_REJECTED);
    dislmdb_txn_abort(txn);
    dislmdb_env_close(edge);
    it_rm_rf("./it_geo_prio");

    return test_end(&ctx);
}
