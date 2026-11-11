/**
 * @file test_raft_wal.c
 * @brief Raft WAL: durable term/log across reopen; checkpoint snapshot
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define DBPATH "./it_raft_wal_db"
#define PORT 30920

static int open_solo_raft(DISLMDB_env **out, const char *name, uint16_t port,
                          bool sync_every_zero)
{
    uint8_t key[32];
    memset(key, 0x77, sizeof(key));
    it_raft_opts o = it_raft_opts_default();
    o.path = DBPATH;
    o.name = name;
    o.port = port;
    o.cluster_key = key;
    o.transport = DISLMDB_TRANSPORT_UDP;
    o.timeout_ms = 3000;
    o.election_min_ms = 150;
    o.election_max_ms = 300;
    if (sync_every_zero) {
        o.set_raft_wal_sync_every = true;
        o.raft_wal_sync_every = 0; /* checkpoint/close only */
    }
    return it_open_raft(out, &o);
}

static int put_named(DISLMDB_env *env, const char *db, const char *k, const char *v)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, db, MDB_CREATE, &dbi);
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

static int get_named(DISLMDB_env *env, const char *db, const char *k,
                     const char *expect)
{
    DISLMDB_txn *txn = NULL;
    if (dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn) != 0) {
        return -1;
    }
    MDB_dbi dbi;
    if (dislmdb_dbi_open(txn, db, 0, &dbi) != 0) {
        dislmdb_txn_abort(txn);
        return -1;
    }
    MDB_val key = {.mv_size = strlen(k), .mv_data = (void *)k};
    MDB_val val;
    int rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &key, &val);
    int ok = (rc == 0 && val.mv_size == strlen(expect) &&
              memcmp(val.mv_data, expect, val.mv_size) == 0)
                 ? 0
                 : -1;
    dislmdb_txn_abort(txn);
    return ok;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_wal");

    it_rm_rf(DBPATH);
    it_mkdir(DBPATH);

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "open1", open_solo_raft(&env, "wal-solo", PORT, false), 0);

    char leader[64] = {0};
    DISLMDB_env *envs[1] = {env};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 1, leader, sizeof(leader), 3000), 0);
    EXPECT_EQ_INT(&ctx, "put1", it_put_kv(env, "durable", "yes"), 0);
    EXPECT_EQ_INT(&ctx, "see1", it_wait_val(env, "durable", "yes", 1000), 0);
    EXPECT_EQ_INT(&ctx, "put_named", put_named(env, "appdata", "nk", "nv"), 0);

    DISLMDB_metrics m1;
    memset(&m1, 0, sizeof(m1));
    EXPECT_EQ_INT(&ctx, "metrics1", dislmdb_get_metrics(env, &m1), 0);
    EXPECT_TRUE(&ctx, "term_live", m1.raft_term > 0);
    EXPECT_TRUE(&ctx, "commit_live", m1.raft_commit_index > 0);
    uint64_t term_before = m1.raft_term;
    uint64_t commit_before = m1.raft_commit_index;

    EXPECT_EQ_INT(&ctx, "ckpt", dislmdb_checkpoint(env), 0);
    dislmdb_env_close(env);
    env = NULL;

    EXPECT_EQ_INT(&ctx, "open2", open_solo_raft(&env, "wal-solo", PORT, false), 0);
    EXPECT_EQ_INT(&ctx, "see2", it_wait_val(env, "durable", "yes", 1000), 0);
    EXPECT_EQ_INT(&ctx, "see_named", get_named(env, "appdata", "nk", "nv"), 0);

    DISLMDB_metrics m2;
    memset(&m2, 0, sizeof(m2));
    EXPECT_EQ_INT(&ctx, "metrics2", dislmdb_get_metrics(env, &m2), 0);
    EXPECT_TRUE(&ctx, "term_restored", m2.raft_term >= term_before);
    EXPECT_TRUE(&ctx, "commit_restored", m2.raft_commit_index >= commit_before);

    EXPECT_EQ_INT(&ctx, "put2", it_put_kv(env, "after", "reopen"), 0);
    EXPECT_EQ_INT(&ctx, "see3", it_wait_val(env, "after", "reopen", 1000), 0);
    EXPECT_EQ_INT(&ctx, "ckpt2", dislmdb_checkpoint(env), 0);

    dislmdb_env_close(env);
    it_rm_rf(DBPATH);

    /* raft_wal_sync_every=0: durable after explicit checkpoint */
    it_mkdir(DBPATH);
    EXPECT_EQ_INT(&ctx, "open_sync0",
                  open_solo_raft(&env, "wal-sync0", (uint16_t)(PORT + 1), true), 0);
    DISLMDB_env *e0[1] = {env};
    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "elect_sync0",
                  it_wait_leader(e0, 1, leader, sizeof(leader), 3000), 0);
    EXPECT_EQ_INT(&ctx, "put_sync0", it_put_kv(env, "lazy", "wal"), 0);
    EXPECT_EQ_INT(&ctx, "see_sync0", it_wait_val(env, "lazy", "wal", 1000), 0);
    EXPECT_EQ_INT(&ctx, "ckpt_sync0", dislmdb_checkpoint(env), 0);
    dislmdb_env_close(env);
    env = NULL;
    EXPECT_EQ_INT(&ctx, "reopen_sync0",
                  open_solo_raft(&env, "wal-sync0", (uint16_t)(PORT + 1), true), 0);
    EXPECT_EQ_INT(&ctx, "see_sync0_re", it_wait_val(env, "lazy", "wal", 1000), 0);
    dislmdb_env_close(env);
    it_rm_rf(DBPATH);
    return test_end(&ctx);
}
