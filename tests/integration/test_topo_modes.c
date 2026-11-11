/**
 * @file test_topo_modes.c
 * @brief Topology modes: mirror / shard / hybrid write gating + flag persist
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define DBPATH "./it_topo_modes_db"

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static void reset_db(void)
{
    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);
}

static int open_with_mode(DISLMDB_env **out, DISLMDB_TOPOLOGY_MODE mode,
                          const char *node_name, uint16_t port)
{
    DISLMDB_env *env = NULL;
    int rc = dislmdb_env_create(&env);
    if (rc != 0) {
        return rc;
    }
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 4 * 1024 * 1024;
    cfg.maxdbs = 8;
    strncpy(cfg.node_name, node_name, sizeof(cfg.node_name) - 1);
    cfg.network.local_port = port;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    cfg.consensus.persist_state = true;
    cfg.topology_mode = mode;
    strncpy(cfg.region, "us-east", sizeof(cfg.region) - 1);
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *out = env;
    return 0;
}

static int put_key(DISLMDB_env *env, const char *k, const char *v)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val key = {.mv_size = strlen(k), .mv_data = (void *)k};
    MDB_val val = {.mv_size = strlen(v), .mv_data = (void *)v};
    rc = dislmdb_put(txn, dbi, &key, &val, 0);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    return dislmdb_txn_commit(txn);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/topo_modes");

    /* --- mirror: any key writable --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        EXPECT_EQ_INT(&ctx, "mirror_open", open_with_mode(&env, DISLMDB_TOPO_MIRROR,
                                                          "topo-mirror", 30910), 0);
        EXPECT_EQ_INT(&ctx, "mirror_put", put_key(env, "any/key", "v"), 0);
        EXPECT_EQ_INT(&ctx, "mirror_writable",
                      dislmdb_topo_key_writable(env, "x", 1), DISLMDB_SUCCESS);
        dislmdb_env_close(env);
    }

    /* --- mirror region_priority: non-primary region rejected --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        int rc = dislmdb_env_create(&env);
        EXPECT_EQ_INT(&ctx, "mrp_create", rc, 0);
        DISLMDB_env_config cfg;
        dislmdb_env_config_init(&cfg);
        cfg.path = DBPATH;
        cfg.mapsize = 4 * 1024 * 1024;
        cfg.maxdbs = 8;
        strncpy(cfg.node_name, "edge-west", sizeof(cfg.node_name) - 1);
        cfg.network.local_port = 30915;
        cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
        cfg.topology_mode = DISLMDB_TOPO_MIRROR;
        cfg.mirror_conflict_policy = DISLMDB_MIRROR_REGION_PRIORITY;
        strncpy(cfg.region, "us-west", sizeof(cfg.region) - 1);
        strncpy(cfg.mirror_primary_region, "us-east",
                sizeof(cfg.mirror_primary_region) - 1);
        EXPECT_EQ_INT(&ctx, "mrp_open", dislmdb_env_open(env, &cfg), 0);
        EXPECT_EQ_INT(&ctx, "mrp_rej", put_key(env, "prio/k", "v"),
                      DISLMDB_ERR_OPERATION_REJECTED);
        EXPECT_EQ_INT(&ctx, "mrp_writable",
                      dislmdb_topo_key_writable(env, "prio/k", 6),
                      DISLMDB_ERR_OPERATION_REJECTED);
        dislmdb_env_close(env);
    }

    /* --- mirror LAST_WRITE: non-primary region still writable --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        int rc = dislmdb_env_create(&env);
        EXPECT_EQ_INT(&ctx, "mlw_create", rc, 0);
        DISLMDB_env_config cfg;
        dislmdb_env_config_init(&cfg);
        cfg.path = DBPATH;
        cfg.mapsize = 4 * 1024 * 1024;
        cfg.maxdbs = 8;
        strncpy(cfg.node_name, "edge-west-lw", sizeof(cfg.node_name) - 1);
        cfg.network.local_port = 30916;
        cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
        cfg.topology_mode = DISLMDB_TOPO_MIRROR;
        cfg.mirror_conflict_policy = DISLMDB_MIRROR_LAST_WRITE;
        strncpy(cfg.region, "us-west", sizeof(cfg.region) - 1);
        strncpy(cfg.mirror_primary_region, "us-east",
                sizeof(cfg.mirror_primary_region) - 1);
        EXPECT_EQ_INT(&ctx, "mlw_open", dislmdb_env_open(env, &cfg), 0);
        EXPECT_EQ_INT(&ctx, "mlw_ok", put_key(env, "lw/k", "v"), 0);
        EXPECT_EQ_INT(&ctx, "mlw_writable",
                      dislmdb_topo_key_writable(env, "lw/k", 4), DISLMDB_SUCCESS);
        dislmdb_env_close(env);
    }

    /* --- shard: only owner may write matching keys --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        EXPECT_EQ_INT(&ctx, "shard_open", open_with_mode(&env, DISLMDB_TOPO_SHARD,
                                                         "owner-a", 30911), 0);
        DISLMDB_shard_desc shards[2];
        memset(shards, 0, sizeof(shards));
        strncpy(shards[0].shard_id, "sa", sizeof(shards[0].shard_id) - 1);
        strncpy(shards[0].key_prefix, "a/", sizeof(shards[0].key_prefix) - 1);
        strncpy(shards[0].owner_node_id, "owner-a", sizeof(shards[0].owner_node_id) - 1);
        strncpy(shards[1].shard_id, "sb", sizeof(shards[1].shard_id) - 1);
        strncpy(shards[1].key_prefix, "b/", sizeof(shards[1].key_prefix) - 1);
        strncpy(shards[1].owner_node_id, "owner-b", sizeof(shards[1].owner_node_id) - 1);
        EXPECT_EQ_INT(&ctx, "shard_set", dislmdb_shard_map_set(env, shards, 2), 0);

        EXPECT_EQ_INT(&ctx, "shard_own_ok", put_key(env, "a/item", "1"), 0);
        EXPECT_EQ_INT(&ctx, "shard_other_rej", put_key(env, "b/item", "2"),
                      DISLMDB_ERR_OPERATION_REJECTED);
        EXPECT_EQ_INT(&ctx, "shard_miss", put_key(env, "c/item", "3"),
                      DISLMDB_ERR_NODE_NOT_FOUND);
        EXPECT_EQ_INT(&ctx, "shard_writable_a",
                      dislmdb_topo_key_writable(env, "a/x", 3), DISLMDB_SUCCESS);
        EXPECT_EQ_INT(&ctx, "shard_writable_b",
                      dislmdb_topo_key_writable(env, "b/x", 3),
                      DISLMDB_ERR_OPERATION_REJECTED);
        dislmdb_env_close(env);
    }

    /* --- hybrid: mirrored prefix free; cold sharded --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        EXPECT_EQ_INT(&ctx, "hybrid_open", open_with_mode(&env, DISLMDB_TOPO_HYBRID,
                                                          "hub-1", 30912), 0);
        DISLMDB_shard_desc shards[2];
        memset(shards, 0, sizeof(shards));
        strncpy(shards[0].shard_id, "hot", sizeof(shards[0].shard_id) - 1);
        strncpy(shards[0].key_prefix, "hot/", sizeof(shards[0].key_prefix) - 1);
        strncpy(shards[0].owner_node_id, "hub-1", sizeof(shards[0].owner_node_id) - 1);
        shards[0].flags = DISLMDB_SHARD_FLAG_MIRRORED;
        strncpy(shards[1].shard_id, "cold", sizeof(shards[1].shard_id) - 1);
        strncpy(shards[1].key_prefix, "cold/", sizeof(shards[1].key_prefix) - 1);
        strncpy(shards[1].owner_node_id, "other", sizeof(shards[1].owner_node_id) - 1);
        EXPECT_EQ_INT(&ctx, "hybrid_set", dislmdb_shard_map_set(env, shards, 2), 0);

        EXPECT_EQ_INT(&ctx, "hybrid_hot_ok", put_key(env, "hot/k", "1"), 0);
        EXPECT_EQ_INT(&ctx, "hybrid_cold_rej", put_key(env, "cold/k", "2"),
                      DISLMDB_ERR_OPERATION_REJECTED);

        /* Persist flags across reopen */
        dislmdb_env_close(env);
        EXPECT_EQ_INT(&ctx, "hybrid_reopen", open_with_mode(&env, DISLMDB_TOPO_HYBRID,
                                                            "hub-1", 30912), 0);
        DISLMDB_shard_desc got[4];
        size_t n = 0;
        EXPECT_EQ_INT(&ctx, "hybrid_get", dislmdb_shard_map_get(env, got, 4, &n), 0);
        EXPECT_EQ_INT(&ctx, "hybrid_count", (int)n, 2);
        int saw_mirrored = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(got[i].shard_id, "hot") == 0 &&
                (got[i].flags & DISLMDB_SHARD_FLAG_MIRRORED)) {
                saw_mirrored = 1;
            }
        }
        EXPECT_EQ_INT(&ctx, "hybrid_flag_persist", saw_mirrored, 1);
        EXPECT_EQ_INT(&ctx, "hybrid_hot_after",
                      dislmdb_topo_key_writable(env, "hot/z", 5), DISLMDB_SUCCESS);
        char owner[64] = {0};
        EXPECT_EQ_INT(&ctx, "resolve_hot",
                      dislmdb_topo_resolve_owner(env, "hot/z", 5, owner), 0);
        EXPECT_STREQ(&ctx, "resolve_hot_owner", owner, "hub-1");
        EXPECT_EQ_INT(&ctx, "resolve_cold",
                      dislmdb_topo_resolve_owner(env, "cold/z", 6, owner), 0);
        EXPECT_STREQ(&ctx, "resolve_cold_owner", owner, "other");
        dislmdb_env_close(env);
    }

    /* --- forward API: local owner must use dislmdb_put, not forward --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        EXPECT_EQ_INT(&ctx, "fwd_open", open_with_mode(&env, DISLMDB_TOPO_SHARD,
                                                       "owner-a", 30914), 0);
        DISLMDB_shard_desc shards[1];
        memset(shards, 0, sizeof(shards));
        strncpy(shards[0].shard_id, "a", sizeof(shards[0].shard_id) - 1);
        strncpy(shards[0].key_prefix, "a/", sizeof(shards[0].key_prefix) - 1);
        strncpy(shards[0].owner_node_id, "owner-a", sizeof(shards[0].owner_node_id) - 1);
        EXPECT_EQ_INT(&ctx, "fwd_map", dislmdb_shard_map_set(env, shards, 1), 0);
        EXPECT_EQ_INT(&ctx, "fwd_local_owner",
                      dislmdb_topo_forward_put(env, "kv", "a/x", 3, "v", 1, 500),
                      DISLMDB_ERR_INVALID_PARAMETER);
        dislmdb_env_close(env);
    }

    /* --- topo map publish (solo persist path) --- */
    {
        reset_db();
        DISLMDB_env *env = NULL;
        EXPECT_EQ_INT(&ctx, "pub_open", open_with_mode(&env, DISLMDB_TOPO_MIRROR,
                                                       "pub-node", 30913), 0);
        DISLMDB_node_addr peer;
        memset(&peer, 0, sizeof(peer));
        strncpy(peer.node_id, "peer-x", sizeof(peer.node_id) - 1);
        strncpy(peer.hostname, "127.0.0.1", sizeof(peer.hostname) - 1);
        peer.port = 30999;
        strncpy(peer.region, "eu-west", sizeof(peer.region) - 1);
        EXPECT_EQ_INT(&ctx, "pub_add", dislmdb_add_node(env, &peer), 0);
        EXPECT_EQ_INT(&ctx, "pub_topo", dislmdb_topo_map_publish(env), 0);
        dislmdb_env_close(env);

        EXPECT_EQ_INT(&ctx, "pub_reopen", open_with_mode(&env, DISLMDB_TOPO_MIRROR,
                                                         "pub-node", 30913), 0);
        DISLMDB_NODE_STATE st = DISLMDB_NODE_STATE_UNKNOWN;
        EXPECT_EQ_INT(&ctx, "pub_find",
                      dislmdb_get_node_state(env, "peer-x", &st), 0);
        dislmdb_env_close(env);
    }

    rm_rf(DBPATH);
    return test_end(&ctx);
}
