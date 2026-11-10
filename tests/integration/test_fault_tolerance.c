/**
 * @file test_fault_tolerance.c
 * @brief PBFT f=1 soak: 4 replicas, kill one, quorum still commits
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define BASE 30500
#define N0 "ft-a"
#define N1 "ft-b"
#define N2 "ft-c"
#define N3 "ft-d"

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static void fill_peers(DISLMDB_node_addr out[3], const char *ids[3],
                       const uint16_t ports[3])
{
    for (int i = 0; i < 3; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        strncpy(out[i].node_id, ids[i], 63);
        strncpy(out[i].hostname, "127.0.0.1", sizeof(out[i].hostname) - 1);
        out[i].port = ports[i];
    }
}

static int open_ft(DISLMDB_env **out, const char *path, const char *name,
                   uint16_t port, const char *seed, const uint8_t key[32],
                   const DISLMDB_node_addr *peers, size_t npeers)
{
    DISLMDB_env *env = NULL;
    int rc = dislmdb_env_create(&env);
    if (rc != 0) {
        return rc;
    }
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = path;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    strncpy(cfg.node_name, name, sizeof(cfg.node_name) - 1);
    cfg.network.local_port = port;
    cfg.network.has_cluster_key = true;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = true; /* encrypted f=1 soak */
    memcpy(cfg.network.cluster_key, key, 32);
    if (peers && npeers) {
        cfg.network.nodes = (DISLMDB_node_addr *)peers;
        cfg.network.node_count = npeers;
    }
    if (seed) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], seed, sizeof(cfg.network.seed_nodes[0]) - 1);
    }
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 1; /* 2f+1 = 3 of 4 */
    cfg.consensus.timeout_ms = 8000;
    cfg.consensus.heartbeat_interval_ms = 200;
    cfg.consensus.enable_liveness = false;
    cfg.consensus.persist_state = true;
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *out = env;
    return 0;
}

static int put_kv(DISLMDB_env *env, const char *k, const char *v)
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

static int wait_val(DISLMDB_env *env, const char *k, const char *expect, int ms)
{
    int w = 0;
    while (w < ms) {
        DISLMDB_txn *txn = NULL;
        if (dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn) == 0) {
            MDB_dbi dbi;
            if (dislmdb_dbi_open(txn, "kv", 0, &dbi) == 0) {
                MDB_val key = {.mv_size = strlen(k), .mv_data = (void *)k};
                MDB_val val;
                if (mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &key, &val) == 0 &&
                    val.mv_size == strlen(expect) &&
                    memcmp(val.mv_data, expect, val.mv_size) == 0) {
                    dislmdb_txn_abort(txn);
                    return 0;
                }
            }
            dislmdb_txn_abort(txn);
        }
        /* Nudge state transfer if this replica missed the original broadcast */
        if ((w % 200) == 0) {
            (void)dislmdb_force_sync(env);
        }
        usleep(50 * 1000);
        w += 50;
    }
    return -1;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/fault_tolerance");

    const char *paths[4] = {"./it_ft_a", "./it_ft_b", "./it_ft_c", "./it_ft_d"};
    const char *names[4] = {N0, N1, N2, N3};
    uint16_t ports[4] = {BASE, BASE + 1, BASE + 2, BASE + 3};
    for (int i = 0; i < 4; i++) {
        rm_rf(paths[i]);
        mkdir(paths[i], 0700);
    }

    uint8_t key[32];
    memset(key, 0xF1, 32);

    DISLMDB_node_addr peers[4][3];
    const char *ids0[3] = {N1, N2, N3};
    uint16_t p0[3] = {ports[1], ports[2], ports[3]};
    fill_peers(peers[0], ids0, p0);
    const char *ids1[3] = {N0, N2, N3};
    uint16_t p1[3] = {ports[0], ports[2], ports[3]};
    fill_peers(peers[1], ids1, p1);
    const char *ids2[3] = {N0, N1, N3};
    uint16_t p2[3] = {ports[0], ports[1], ports[3]};
    fill_peers(peers[2], ids2, p2);
    const char *ids3[3] = {N0, N1, N2};
    uint16_t p3[3] = {ports[0], ports[1], ports[2]};
    fill_peers(peers[3], ids3, p3);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)ports[0]);

    DISLMDB_env *n[4] = {0};
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_ft(&n[0], paths[0], names[0], ports[0], NULL, key, peers[0], 3), 0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_ft(&n[1], paths[1], names[1], ports[1], seed, key, peers[1], 3), 0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_ft(&n[2], paths[2], names[2], ports[2], seed, key, peers[2], 3), 0);
    EXPECT_EQ_INT(&ctx, "open_d",
                  open_ft(&n[3], paths[3], names[3], ports[3], seed, key, peers[3], 3), 0);

    for (int i = 0; i < 50; i++) {
        for (int j = 0; j < 4; j++) {
            (void)dislmdb_force_sync(n[j]);
        }
        usleep(50 * 1000);
    }

    /* Baseline with all four up */
    EXPECT_EQ_INT(&ctx, "put_all_up", put_kv(n[0], "k1", "v1"), 0);
    for (int j = 0; j < 4; j++) {
        (void)dislmdb_force_sync(n[j]);
    }
    EXPECT_EQ_INT(&ctx, "see_b_k1", wait_val(n[1], "k1", "v1", 12000), 0);
    EXPECT_EQ_INT(&ctx, "see_c_k1", wait_val(n[2], "k1", "v1", 12000), 0);
    EXPECT_EQ_INT(&ctx, "see_d_k1", wait_val(n[3], "k1", "v1", 12000), 0);

    /* Kill a non-primary follower (ft-d); sorted primary is ft-a */
    dislmdb_env_close(n[3]);
    n[3] = NULL;
    /*
     * Give net threads time to hit SO_SNDTIMEO on the dead peer, close the
     * slot, and continue quorum traffic among the remaining three.
     */
    for (int i = 0; i < 40; i++) {
        (void)dislmdb_force_sync(n[0]);
        (void)dislmdb_force_sync(n[1]);
        (void)dislmdb_force_sync(n[2]);
        usleep(100 * 1000);
    }

    EXPECT_EQ_INT(&ctx, "put_after_kill", put_kv(n[0], "k2", "v2"), 0);
    EXPECT_EQ_INT(&ctx, "see_a_k2", wait_val(n[0], "k2", "v2", 3000), 0);
    EXPECT_EQ_INT(&ctx, "see_b_k2", wait_val(n[1], "k2", "v2", 12000), 0);
    EXPECT_EQ_INT(&ctx, "see_c_k2", wait_val(n[2], "k2", "v2", 12000), 0);

    for (int i = 0; i < 4; i++) {
        if (n[i]) {
            dislmdb_env_close(n[i]);
        }
        rm_rf(paths[i]);
    }
    return test_end(&ctx);
}
