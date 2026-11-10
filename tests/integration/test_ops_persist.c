/**
 * @file test_ops_persist.c
 * @brief Integration: put/del oplog, cluster key, checkpoint, persist reload
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_ops_persist_db"

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static int open_env(DISLMDB_env **env, bool persist)
{
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 16 * 1024 * 1024;
    cfg.maxdbs = 16;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.enable_liveness = true;
    cfg.consensus.persist_state = persist;
    cfg.consensus.persist_cluster_key = persist;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = true;
    int rc = dislmdb_env_create(env);
    if (rc) return rc;
    return dislmdb_env_open(*env, &cfg);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/ops_persist");
    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "open", open_env(&env, true), 0);

    uint8_t fixed_key[32];
    for (int i = 0; i < 32; i++) fixed_key[i] = (uint8_t)(i + 1);
    EXPECT_EQ_INT(&ctx, "set_cluster_key", dislmdb_set_cluster_key(env, fixed_key), 0);

    DISLMDB_txn *txn = NULL;
    EXPECT_EQ_INT(&ctx, "begin", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    MDB_dbi dbi;
    EXPECT_EQ_INT(&ctx, "dbi_open", dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi), 0);

    MDB_val k = {.mv_size = 3, .mv_data = (void *)"foo"};
    MDB_val v = {.mv_size = 3, .mv_data = (void *)"bar"};
    EXPECT_EQ_INT(&ctx, "put", dislmdb_put(txn, dbi, &k, &v, 0), 0);
    EXPECT_EQ_INT(&ctx, "commit", dislmdb_txn_commit(txn), 0);

    EXPECT_EQ_INT(&ctx, "checkpoint", dislmdb_checkpoint(env), 0);

    DISLMDB_metrics m;
    EXPECT_EQ_INT(&ctx, "metrics", dislmdb_get_metrics(env, &m), 0);
    EXPECT_TRUE(&ctx, "metrics_commits", m.total_commits >= 1);
    EXPECT_TRUE(&ctx, "metrics_ops", m.total_operations >= 1);
    EXPECT_TRUE(&ctx, "metrics_ckpt", m.checkpoints >= 1);

    /* read back */
    EXPECT_EQ_INT(&ctx, "begin_ro", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_ro", dislmdb_dbi_open(txn, "kv", 0, &dbi), 0);
    MDB_txn *mt = dislmdb_get_lmdb_txn(txn);
    MDB_val got;
    EXPECT_EQ_INT(&ctx, "get", mdb_get(mt, dbi, &k, &got), 0);
    EXPECT_TRUE(&ctx, "value", got.mv_size == 3 && memcmp(got.mv_data, "bar", 3) == 0);
    dislmdb_txn_abort(txn);

    /* delete */
    EXPECT_EQ_INT(&ctx, "begin_del", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_del", dislmdb_dbi_open(txn, "kv", 0, &dbi), 0);
    EXPECT_EQ_INT(&ctx, "del", dislmdb_del(txn, dbi, &k, NULL), 0);
    EXPECT_EQ_INT(&ctx, "commit_del", dislmdb_txn_commit(txn), 0);

    dislmdb_env_close(env);
    env = NULL;

    /* reload persist + cluster key */
    EXPECT_EQ_INT(&ctx, "reopen", open_env(&env, true), 0);
    uint8_t loaded[32];
    EXPECT_EQ_INT(&ctx, "get_cluster_key", dislmdb_get_cluster_key(env, loaded), 0);
    EXPECT_MEMEQ(&ctx, "cluster_key_persisted", loaded, fixed_key, 32);

    EXPECT_EQ_INT(&ctx, "begin_miss", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_miss", dislmdb_dbi_open(txn, "kv", 0, &dbi), 0);
    mt = dislmdb_get_lmdb_txn(txn);
    int grc = mdb_get(mt, dbi, &k, &got);
    EXPECT_EQ_INT(&ctx, "deleted", grc, MDB_NOTFOUND);
    dislmdb_txn_abort(txn);

    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
