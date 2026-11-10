/**
 * @file test_shard_map.c
 * @brief Native shard map: set/get/lookup + persist across reopen
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define DBPATH "./it_shard_map_db"

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static int open_solo(DISLMDB_env **out)
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
    strncpy(cfg.node_name, "shard-solo", sizeof(cfg.node_name) - 1);
    cfg.network.local_port = 30880;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    cfg.consensus.persist_state = true;
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *out = env;
    return 0;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/shard_map");

    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "open", open_solo(&env), 0);

    DISLMDB_shard_desc shards[2];
    memset(shards, 0, sizeof(shards));
    strncpy(shards[0].shard_id, "shardA", sizeof(shards[0].shard_id) - 1);
    strncpy(shards[0].key_prefix, "shardA/", sizeof(shards[0].key_prefix) - 1);
    strncpy(shards[0].owner_node_id, "node-a", sizeof(shards[0].owner_node_id) - 1);
    strncpy(shards[1].shard_id, "shardB", sizeof(shards[1].shard_id) - 1);
    strncpy(shards[1].key_prefix, "shardB/", sizeof(shards[1].key_prefix) - 1);
    strncpy(shards[1].owner_node_id, "node-b", sizeof(shards[1].owner_node_id) - 1);

    EXPECT_EQ_INT(&ctx, "set", dislmdb_shard_map_set(env, shards, 2), 0);

    size_t count = 0;
    DISLMDB_shard_desc got[4];
    memset(got, 0, sizeof(got));
    EXPECT_EQ_INT(&ctx, "get", dislmdb_shard_map_get(env, got, 4, &count), 0);
    EXPECT_EQ_INT(&ctx, "count", (int)count, 2);

    char owner[64] = {0};
    EXPECT_EQ_INT(&ctx, "lookup_a",
                  dislmdb_shard_lookup(env, "shardA/item1", strlen("shardA/item1"), owner), 0);
    EXPECT_STREQ(&ctx, "owner_a", owner, "node-a");

    char sid[DISLMDB_SHARD_ID_LEN] = {0};
    EXPECT_EQ_INT(&ctx, "lookup_b_id",
                  dislmdb_shard_lookup_id(env, "shardB/x", strlen("shardB/x"), sid), 0);
    EXPECT_STREQ(&ctx, "id_b", sid, "shardB");

    EXPECT_EQ_INT(&ctx, "miss",
                  dislmdb_shard_lookup(env, "other/x", strlen("other/x"), owner),
                  DISLMDB_ERR_NODE_NOT_FOUND);

    /* Longer prefix wins */
    DISLMDB_shard_desc nested[3];
    memset(nested, 0, sizeof(nested));
    nested[0] = shards[0];
    nested[1] = shards[1];
    strncpy(nested[2].shard_id, "shardA-hot", sizeof(nested[2].shard_id) - 1);
    strncpy(nested[2].key_prefix, "shardA/hot/", sizeof(nested[2].key_prefix) - 1);
    strncpy(nested[2].owner_node_id, "node-hot", sizeof(nested[2].owner_node_id) - 1);
    EXPECT_EQ_INT(&ctx, "set_nested", dislmdb_shard_map_set(env, nested, 3), 0);
    memset(owner, 0, sizeof(owner));
    EXPECT_EQ_INT(&ctx, "lookup_nested",
                  dislmdb_shard_lookup(env, "shardA/hot/k", strlen("shardA/hot/k"), owner), 0);
    EXPECT_STREQ(&ctx, "owner_hot", owner, "node-hot");

    dislmdb_env_close(env);
    env = NULL;
    EXPECT_EQ_INT(&ctx, "reopen", open_solo(&env), 0);
    count = 0;
    EXPECT_EQ_INT(&ctx, "get_persisted", dislmdb_shard_map_get(env, got, 4, &count), 0);
    EXPECT_EQ_INT(&ctx, "persisted_count", (int)count, 3);
    memset(owner, 0, sizeof(owner));
    EXPECT_EQ_INT(&ctx, "persisted_lookup",
                  dislmdb_shard_lookup(env, "shardA/hot/k", strlen("shardA/hot/k"), owner), 0);
    EXPECT_STREQ(&ctx, "persisted_owner", owner, "node-hot");

    if (env) {
        dislmdb_env_close(env);
    }
    rm_rf(DBPATH);
    return test_end(&ctx);
}
