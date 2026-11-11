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

static int open_solo_raft(DISLMDB_env **out, const char *name, uint16_t port)
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
    return it_open_raft(out, &o);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_wal");

    it_rm_rf(DBPATH);
    it_mkdir(DBPATH);

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "open1", open_solo_raft(&env, "wal-solo", PORT), 0);

    char leader[64] = {0};
    DISLMDB_env *envs[1] = {env};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 1, leader, sizeof(leader), 3000), 0);
    EXPECT_EQ_INT(&ctx, "put1", it_put_kv(env, "durable", "yes"), 0);
    EXPECT_EQ_INT(&ctx, "see1", it_wait_val(env, "durable", "yes", 1000), 0);

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

    EXPECT_EQ_INT(&ctx, "open2", open_solo_raft(&env, "wal-solo", PORT), 0);
    EXPECT_EQ_INT(&ctx, "see2", it_wait_val(env, "durable", "yes", 1000), 0);

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
    return test_end(&ctx);
}
