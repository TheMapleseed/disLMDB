/**
 * @file test_op_status.c
 * @brief Integration: dislmdb_consensus_get_operation_status via SOLO propose
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_consensus.h"
#include "dislmdb_crypto.h"
#include "dislmdb_errors.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_op_status_db"

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/op_status");
    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    cfg.network.local_port = 0;

    EXPECT_EQ_INT(&ctx, "create", dislmdb_env_create(&env), 0);
    EXPECT_EQ_INT(&ctx, "open", dislmdb_env_open(env, &cfg), 0);

    DISLMDB_op_id missing;
    memset(missing.bytes, 0xab, DISLMDB_OP_ID_SIZE);
    DISLMDB_consensus_result st;
    EXPECT_EQ_INT(&ctx, "status_miss_rc",
                  dislmdb_consensus_get_operation_status(env, &missing, &st), 0);
    EXPECT_EQ_INT(&ctx, "status_miss", (int)st.status, (int)DISLMDB_CONSENSUS_UNKNOWN);

    DISLMDB_operation op;
    memset(&op, 0, sizeof(op));
    EXPECT_EQ_INT(&ctx, "gen_id", dislmdb_consensus_generate_op_id(env, &op.id), 0);
    op.type = DISLMDB_OP_TYPE_NOP;
    op.timestamp = 1;
    strncpy(op.node_id, "solo", sizeof(op.node_id) - 1);

    DISLMDB_consensus_result prop;
    EXPECT_EQ_INT(&ctx, "propose",
                  dislmdb_consensus_propose(env, &op, 1000, &prop), 0);
    EXPECT_EQ_INT(&ctx, "prop_committed", (int)prop.status,
                  (int)DISLMDB_CONSENSUS_COMMITTED);

    memset(&st, 0, sizeof(st));
    EXPECT_EQ_INT(&ctx, "status_hit_rc",
                  dislmdb_consensus_get_operation_status(env, &op.id, &st), 0);
    EXPECT_EQ_INT(&ctx, "status_hit", (int)st.status, (int)DISLMDB_CONSENSUS_COMMITTED);
    EXPECT_EQ_INT(&ctx, "status_seq", (int)st.commit_sequence, (int)prop.commit_sequence);

    DISLMDB_op_id last;
    EXPECT_EQ_INT(&ctx, "last_op_rc",
                  dislmdb_consensus_get_last_op_id(env, &last), 0);
    EXPECT_TRUE(&ctx, "last_op_match",
                memcmp(last.bytes, op.id.bytes, DISLMDB_OP_ID_SIZE) == 0);

    /* Rejected digest still recorded */
    DISLMDB_operation bad;
    memset(&bad, 0, sizeof(bad));
    EXPECT_EQ_INT(&ctx, "gen_bad", dislmdb_consensus_generate_op_id(env, &bad.id), 0);
    bad.type = DISLMDB_OP_TYPE_PUT;
    uint8_t payload[4] = {1, 2, 3, 4};
    bad.data = payload;
    bad.data_size = sizeof(payload);
    memset(bad.digest, 0, sizeof(bad.digest)); /* wrong digest */
    DISLMDB_consensus_result rej;
    EXPECT_EQ_INT(&ctx, "propose_bad",
                  dislmdb_consensus_propose(env, &bad, 1000, &rej),
                  DISLMDB_ERR_DIGEST_MISMATCH);
    memset(&st, 0, sizeof(st));
    EXPECT_EQ_INT(&ctx, "status_rej_rc",
                  dislmdb_consensus_get_operation_status(env, &bad.id, &st), 0);
    EXPECT_EQ_INT(&ctx, "status_rej", (int)st.status, (int)DISLMDB_CONSENSUS_REJECTED);

    EXPECT_EQ_INT(&ctx, "last_after_rej",
                  dislmdb_consensus_get_last_op_id(env, &last), 0);
    EXPECT_TRUE(&ctx, "last_is_rej",
                memcmp(last.bytes, bad.id.bytes, DISLMDB_OP_ID_SIZE) == 0);

    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
