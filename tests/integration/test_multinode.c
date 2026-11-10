/**
 * @file test_multinode.c
 * @brief Real 3-node ACID replication: HELLO membership + consensus put/commit
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define BASE_PORT 29100
#define N0 "node-a"
#define N1 "node-b"
#define N2 "node-c"

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static int open_node(DISLMDB_env **out, const char *path, const char *name,
                     uint16_t port, const char *seed_addr, const uint8_t key[32],
                     const DISLMDB_node_addr *peers, size_t peer_count)
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
    cfg.network.enable_payload_encryption = false;
    memcpy(cfg.network.cluster_key, key, 32);
    if (peers && peer_count > 0) {
        cfg.network.nodes = (DISLMDB_node_addr *)peers;
        cfg.network.node_count = peer_count;
    }
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.timeout_ms = 5000;
    cfg.consensus.heartbeat_interval_ms = 400;
    cfg.consensus.enable_liveness = false;
    cfg.consensus.persist_state = true;
    if (seed_addr) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], seed_addr, sizeof(cfg.network.seed_nodes[0]) - 1);
    }
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *out = env;
    return 0;
}

static int read_value(DISLMDB_env *env, const char *key, char *out, size_t out_sz)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, "kv", 0, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
    MDB_val v;
    rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &k, &v);
    if (rc == 0 && out && out_sz > 0) {
        size_t n = v.mv_size < out_sz - 1 ? v.mv_size : out_sz - 1;
        memcpy(out, v.mv_data, n);
        out[n] = '\0';
    }
    dislmdb_txn_abort(txn);
    return rc;
}

static int wait_key(DISLMDB_env *env, const char *key, const char *expect, int ms)
{
    char buf[128];
    int waited = 0;
    while (waited < ms) {
        (void)dislmdb_force_sync(env);
        if (read_value(env, key, buf, sizeof(buf)) == 0 && strcmp(buf, expect) == 0) {
            return 0;
        }
        usleep(50 * 1000);
        waited += 50;
    }
    return -1;
}

static int put_kv(DISLMDB_env *env, const char *key, const char *val)
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
    MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
    MDB_val v = {.mv_size = strlen(val), .mv_data = (void *)val};
    rc = dislmdb_put(txn, dbi, &k, &v, 0);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    return dislmdb_txn_commit(txn);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/multinode");

    const char *p0 = "./it_mn_a";
    const char *p1 = "./it_mn_b";
    const char *p2 = "./it_mn_c";
    rm_rf(p0); rm_rf(p1); rm_rf(p2);
    mkdir(p0, 0700); mkdir(p1, 0700); mkdir(p2, 0700);

    uint8_t key[32];
    memset(key, 0xA5, sizeof(key));

    /* Canonical membership known at open (sorted primary = node-a) */
    DISLMDB_node_addr peers_a[2] = {0};
    strncpy(peers_a[0].node_id, N1, 63);
    strncpy(peers_a[0].hostname, "127.0.0.1", sizeof(peers_a[0].hostname) - 1);
    peers_a[0].port = BASE_PORT + 1;
    strncpy(peers_a[1].node_id, N2, 63);
    strncpy(peers_a[1].hostname, "127.0.0.1", sizeof(peers_a[1].hostname) - 1);
    peers_a[1].port = BASE_PORT + 2;

    DISLMDB_node_addr peers_b[2] = {0};
    strncpy(peers_b[0].node_id, N0, 63);
    strncpy(peers_b[0].hostname, "127.0.0.1", sizeof(peers_b[0].hostname) - 1);
    peers_b[0].port = BASE_PORT;
    strncpy(peers_b[1].node_id, N2, 63);
    strncpy(peers_b[1].hostname, "127.0.0.1", sizeof(peers_b[1].hostname) - 1);
    peers_b[1].port = BASE_PORT + 2;

    DISLMDB_node_addr peers_c[2] = {0};
    strncpy(peers_c[0].node_id, N0, 63);
    strncpy(peers_c[0].hostname, "127.0.0.1", sizeof(peers_c[0].hostname) - 1);
    peers_c[0].port = BASE_PORT;
    strncpy(peers_c[1].node_id, N1, 63);
    strncpy(peers_c[1].hostname, "127.0.0.1", sizeof(peers_c[1].hostname) - 1);
    peers_c[1].port = BASE_PORT + 1;

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)BASE_PORT);

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_node(&a, p0, N0, BASE_PORT, NULL, key, peers_a, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_node(&b, p1, N1, BASE_PORT + 1, seed, key, peers_b, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_node(&c, p2, N2, BASE_PORT + 2, seed, key, peers_c, 2), 0);

    for (int i = 0; i < 20; i++) {
        (void)dislmdb_force_sync(a);
        (void)dislmdb_force_sync(b);
        (void)dislmdb_force_sync(c);
        usleep(50 * 1000);
    }

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "leader_ok", dislmdb_get_leader(a, leader, sizeof(leader)), 0);
    EXPECT_STREQ(&ctx, "leader_is_a", leader, N0);

    /* Write on primary — consensus apply must persist locally */
    EXPECT_EQ_INT(&ctx, "put_primary", put_kv(a, "alpha", "omega"), 0);
    EXPECT_EQ_INT(&ctx, "visible_a", wait_key(a, "alpha", "omega", 3000), 0);
    EXPECT_EQ_INT(&ctx, "visible_b", wait_key(b, "alpha", "omega", 8000), 0);
    EXPECT_EQ_INT(&ctx, "visible_c", wait_key(c, "alpha", "omega", 8000), 0);

    /* Write on follower — forwarded to primary, then replicated */
    EXPECT_EQ_INT(&ctx, "put_follower", put_kv(b, "beta", "gamma"), 0);
    EXPECT_EQ_INT(&ctx, "fwd_a", wait_key(a, "beta", "gamma", 8000), 0);
    EXPECT_EQ_INT(&ctx, "fwd_b", wait_key(b, "beta", "gamma", 8000), 0);
    EXPECT_EQ_INT(&ctx, "fwd_c", wait_key(c, "beta", "gamma", 8000), 0);

    if (c) dislmdb_env_close(c);
    if (b) dislmdb_env_close(b);
    if (a) dislmdb_env_close(a);
    rm_rf(p0); rm_rf(p1); rm_rf(p2);
    return test_end(&ctx);
}
