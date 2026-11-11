/**
 * @file test_index_versioned.c
 * @brief Phase K: dislmdb_index_* + put/get_versioned LWW helpers
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_index_ver_db"

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/index_versioned");
    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 16;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    cfg.consensus.persist_state = true;
    cfg.topology_mode = DISLMDB_TOPO_MIRROR;
    cfg.mirror_conflict_policy = DISLMDB_MIRROR_CLIENT_TIMESTAMP;
    cfg.network.local_port = 30960;
    strncpy(cfg.node_name, "idx-solo", sizeof(cfg.node_name) - 1);

    EXPECT_EQ_INT(&ctx, "create", dislmdb_env_create(&env), 0);
    EXPECT_EQ_INT(&ctx, "open", dislmdb_env_open(env, &cfg), 0);

    DISLMDB_txn *txn = NULL;
    EXPECT_EQ_INT(&ctx, "begin", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    MDB_dbi primary, index;
    EXPECT_EQ_INT(&ctx, "dbi_p", dislmdb_dbi_open(txn, "entities", MDB_CREATE, &primary),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_i", dislmdb_dbi_open(txn, "idx_name", MDB_CREATE, &index),
                  0);

    uint8_t uuid[16];
    memset(uuid, 0x42, sizeof(uuid));
    MDB_val pk = {.mv_size = sizeof(uuid), .mv_data = uuid};
    MDB_val pv = {.mv_size = 5, .mv_data = (void *)"alice"};
    MDB_val sk = {.mv_size = 5, .mv_data = (void *)"alice"};

    EXPECT_EQ_INT(&ctx, "index_put",
                  dislmdb_index_put(txn, primary, index, &pk, &pv, &sk, 0), 0);
    EXPECT_EQ_INT(&ctx, "commit1", dislmdb_txn_commit(txn), 0);
    txn = NULL;

    /* Lookup via index → primary */
    EXPECT_EQ_INT(&ctx, "begin_ro", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_i_ro", dislmdb_dbi_open(txn, "idx_name", 0, &index), 0);
    EXPECT_EQ_INT(&ctx, "dbi_p_ro", dislmdb_dbi_open(txn, "entities", 0, &primary),
                  0);
    MDB_val got;
    EXPECT_EQ_INT(&ctx, "idx_get",
                  mdb_get(dislmdb_get_lmdb_txn(txn), index, &sk, &got), 0);
    EXPECT_TRUE(&ctx, "idx_points",
                got.mv_size == sizeof(uuid) && memcmp(got.mv_data, uuid, 16) == 0);
    EXPECT_EQ_INT(&ctx, "pri_get",
                  mdb_get(dislmdb_get_lmdb_txn(txn), primary, &pk, &got), 0);
    EXPECT_TRUE(&ctx, "pri_val",
                got.mv_size == 5 && memcmp(got.mv_data, "alice", 5) == 0);
    dislmdb_txn_abort(txn);
    txn = NULL;

    /* Versioned LWW */
    EXPECT_EQ_INT(&ctx, "begin_v", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_v", dislmdb_dbi_open(txn, "kv", MDB_CREATE, &primary),
                  0);
    MDB_val vk = {.mv_size = 3, .mv_data = (void *)"doc"};
    MDB_val vv = {.mv_size = 4, .mv_data = (void *)"v100"};
    EXPECT_EQ_INT(&ctx, "put_v100",
                  dislmdb_put_versioned(txn, primary, &vk, &vv, 0, 100), 0);
    EXPECT_EQ_INT(&ctx, "commit_v", dislmdb_txn_commit(txn), 0);
    txn = NULL;

    EXPECT_EQ_INT(&ctx, "begin_v2", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_v2", dislmdb_dbi_open(txn, "kv", 0, &primary), 0);
    MDB_val stale = {.mv_size = 4, .mv_data = (void *)"old!"};
    EXPECT_EQ_INT(&ctx, "stale_rej",
                  dislmdb_put_versioned(txn, primary, &vk, &stale, 0, 50),
                  DISLMDB_ERR_OPERATION_REJECTED);
    MDB_val newer = {.mv_size = 4, .mv_data = (void *)"v200"};
    EXPECT_EQ_INT(&ctx, "put_v200",
                  dislmdb_put_versioned(txn, primary, &vk, &newer, 0, 200), 0);
    EXPECT_EQ_INT(&ctx, "commit_v2", dislmdb_txn_commit(txn), 0);
    txn = NULL;

    EXPECT_EQ_INT(&ctx, "begin_get", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_get", dislmdb_dbi_open(txn, "kv", 0, &primary), 0);
    uint64_t ver = 0;
    char buf[32];
    size_t cap = sizeof(buf);
    EXPECT_EQ_INT(&ctx, "get_ver",
                  dislmdb_get_versioned(txn, primary, &vk, &ver, buf, &cap), 0);
    EXPECT_TRUE(&ctx, "ver_200", ver == 200);
    EXPECT_EQ_INT(&ctx, "payload_len", (int)cap, 4);
    EXPECT_MEMEQ(&ctx, "payload", buf, "v200", 4);
    dislmdb_txn_abort(txn);

    /* Index delete */
    EXPECT_EQ_INT(&ctx, "begin_del", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    EXPECT_EQ_INT(&ctx, "dbi_pd",
                  dislmdb_dbi_open(txn, "entities", 0, &primary), 0);
    EXPECT_EQ_INT(&ctx, "dbi_id", dislmdb_dbi_open(txn, "idx_name", 0, &index), 0);
    EXPECT_EQ_INT(&ctx, "index_del",
                  dislmdb_index_del(txn, primary, index, &pk, &sk), 0);
    EXPECT_EQ_INT(&ctx, "commit_del", dislmdb_txn_commit(txn), 0);

    EXPECT_EQ_INT(&ctx, "begin_miss", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_pm",
                  dislmdb_dbi_open(txn, "entities", 0, &primary), 0);
    EXPECT_EQ_INT(&ctx, "miss_pri",
                  mdb_get(dislmdb_get_lmdb_txn(txn), primary, &pk, &got),
                  MDB_NOTFOUND);
    dislmdb_txn_abort(txn);

    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
