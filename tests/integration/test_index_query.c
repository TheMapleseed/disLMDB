/**
 * @file test_index_query.c
 * @brief Phase L: dislmdb_index_get + dislmdb_index_scan
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_index_query_db"

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

typedef struct {
    int count;
    char last_skey[64];
    char last_pval[64];
} scan_acc;

static int scan_cb(const MDB_val *skey, const MDB_val *pkey,
                   const MDB_val *pval, void *user)
{
    (void)pkey;
    scan_acc *a = user;
    a->count++;
    size_t n = skey->mv_size < sizeof(a->last_skey) - 1 ? skey->mv_size
                                                        : sizeof(a->last_skey) - 1;
    memcpy(a->last_skey, skey->mv_data, n);
    a->last_skey[n] = '\0';
    n = pval->mv_size < sizeof(a->last_pval) - 1 ? pval->mv_size
                                                 : sizeof(a->last_pval) - 1;
    memcpy(a->last_pval, pval->mv_data, n);
    a->last_pval[n] = '\0';
    return 0;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/index_query");
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
    cfg.network.local_port = 30970;
    strncpy(cfg.node_name, "idxq", sizeof(cfg.node_name) - 1);

    EXPECT_EQ_INT(&ctx, "create", dislmdb_env_create(&env), 0);
    EXPECT_EQ_INT(&ctx, "open", dislmdb_env_open(env, &cfg), 0);

    DISLMDB_txn *txn = NULL;
    EXPECT_EQ_INT(&ctx, "begin", dislmdb_txn_begin(env, NULL, 0, &txn), 0);
    MDB_dbi primary, index;
    EXPECT_EQ_INT(&ctx, "dbi_p", dislmdb_dbi_open(txn, "entities", MDB_CREATE, &primary),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_i", dislmdb_dbi_open(txn, "idx_name", MDB_CREATE, &index),
                  0);

    MDB_val pk1 = {.mv_size = 2, .mv_data = (void *)"u1"};
    MDB_val pv1 = {.mv_size = 5, .mv_data = (void *)"alice"};
    MDB_val sk1 = {.mv_size = 5, .mv_data = (void *)"alice"};
    MDB_val pk2 = {.mv_size = 2, .mv_data = (void *)"u2"};
    MDB_val pv2 = {.mv_size = 3, .mv_data = (void *)"bob"};
    MDB_val sk2 = {.mv_size = 3, .mv_data = (void *)"bob"};
    MDB_val pk3 = {.mv_size = 2, .mv_data = (void *)"u3"};
    MDB_val pv3 = {.mv_size = 3, .mv_data = (void *)"amy"};
    MDB_val sk3 = {.mv_size = 5, .mv_data = (void *)"amy/x"};

    EXPECT_EQ_INT(&ctx, "put1",
                  dislmdb_index_put(txn, primary, index, &pk1, &pv1, &sk1, 0), 0);
    EXPECT_EQ_INT(&ctx, "put2",
                  dislmdb_index_put(txn, primary, index, &pk2, &pv2, &sk2, 0), 0);
    EXPECT_EQ_INT(&ctx, "put3",
                  dislmdb_index_put(txn, primary, index, &pk3, &pv3, &sk3, 0), 0);
    EXPECT_EQ_INT(&ctx, "commit", dislmdb_txn_commit(txn), 0);
    txn = NULL;

    EXPECT_EQ_INT(&ctx, "begin_ro", dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_p2", dislmdb_dbi_open(txn, "entities", 0, &primary),
                  0);
    EXPECT_EQ_INT(&ctx, "dbi_i2", dislmdb_dbi_open(txn, "idx_name", 0, &index), 0);

    MDB_val got_pk, got_pv;
    EXPECT_EQ_INT(&ctx, "idx_get",
                  dislmdb_index_get(txn, primary, index, &sk1, &got_pk, &got_pv),
                  0);
    EXPECT_TRUE(&ctx, "pkey",
                got_pk.mv_size == 2 && memcmp(got_pk.mv_data, "u1", 2) == 0);
    EXPECT_TRUE(&ctx, "pval",
                got_pv.mv_size == 5 && memcmp(got_pv.mv_data, "alice", 5) == 0);

    scan_acc acc;
    memset(&acc, 0, sizeof(acc));
    MDB_val pfx = {.mv_size = 1, .mv_data = (void *)"a"};
    EXPECT_EQ_INT(&ctx, "scan_a",
                  dislmdb_index_scan(txn, primary, index, NULL, &pfx, 0, scan_cb,
                                     &acc),
                  0);
    EXPECT_EQ_INT(&ctx, "scan_a_n", acc.count, 2); /* alice + amy/x */

    memset(&acc, 0, sizeof(acc));
    EXPECT_EQ_INT(&ctx, "scan_all",
                  dislmdb_index_scan(txn, primary, index, NULL, NULL, 0, scan_cb,
                                     &acc),
                  0);
    EXPECT_EQ_INT(&ctx, "scan_all_n", acc.count, 3);

    memset(&acc, 0, sizeof(acc));
    EXPECT_EQ_INT(&ctx, "scan_lim",
                  dislmdb_index_scan(txn, primary, index, NULL, NULL, 1, scan_cb,
                                     &acc),
                  0);
    EXPECT_EQ_INT(&ctx, "scan_lim_n", acc.count, 1);

    dislmdb_txn_abort(txn);
    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
