/**
 * @file test_raft_fault.c
 * @brief Raft 3-node LMDB soak: kill one replica, majority still commits
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT_A 30640
#define PORT_B 30641
#define PORT_C 30642

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static int open_raft(DISLMDB_env **out, const char *path, const char *name,
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
    cfg.network.transport = DISLMDB_TRANSPORT_TCP;
    cfg.network.has_cluster_key = true;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = true;
    memcpy(cfg.network.cluster_key, key, 32);
    if (peers && npeers) {
        cfg.network.nodes = (DISLMDB_node_addr *)peers;
        cfg.network.node_count = npeers;
    }
    if (seed) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], seed, sizeof(cfg.network.seed_nodes[0]) - 1);
    }
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_RAFT;
    cfg.consensus.timeout_ms = 8000;
    cfg.consensus.heartbeat_interval_ms = 80;
    cfg.consensus.election_timeout_min_ms = 250;
    cfg.consensus.election_timeout_max_ms = 500;
    cfg.consensus.enable_liveness = true;
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
        usleep(50 * 1000);
        w += 50;
    }
    return -1;
}

static int wait_leader(DISLMDB_env *envs[], int n, char *out, size_t out_sz, int ms)
{
    int w = 0;
    while (w < ms) {
        for (int i = 0; i < n; i++) {
            if (!envs[i]) {
                continue;
            }
            char leader[64] = {0};
            if (dislmdb_get_leader(envs[i], leader, sizeof(leader)) == 0 &&
                leader[0] != '\0') {
                strncpy(out, leader, out_sz - 1);
                out[out_sz - 1] = '\0';
                return 0;
            }
        }
        usleep(50 * 1000);
        w += 50;
    }
    return -1;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_fault");

    rm_rf("./it_rf_a");
    rm_rf("./it_rf_b");
    rm_rf("./it_rf_c");
    mkdir("./it_rf_a", 0700);
    mkdir("./it_rf_b", 0700);
    mkdir("./it_rf_c", 0700);

    uint8_t key[32];
    memset(key, 0x48, 32);

    DISLMDB_node_addr peers_a[2] = {0};
    strncpy(peers_a[0].node_id, "raft-b", 63);
    strncpy(peers_a[0].hostname, "127.0.0.1", sizeof(peers_a[0].hostname) - 1);
    peers_a[0].port = PORT_B;
    strncpy(peers_a[1].node_id, "raft-c", 63);
    strncpy(peers_a[1].hostname, "127.0.0.1", sizeof(peers_a[1].hostname) - 1);
    peers_a[1].port = PORT_C;

    DISLMDB_node_addr peers_b[2] = {0};
    strncpy(peers_b[0].node_id, "raft-a", 63);
    strncpy(peers_b[0].hostname, "127.0.0.1", sizeof(peers_b[0].hostname) - 1);
    peers_b[0].port = PORT_A;
    strncpy(peers_b[1].node_id, "raft-c", 63);
    strncpy(peers_b[1].hostname, "127.0.0.1", sizeof(peers_b[1].hostname) - 1);
    peers_b[1].port = PORT_C;

    DISLMDB_node_addr peers_c[2] = {0};
    strncpy(peers_c[0].node_id, "raft-a", 63);
    strncpy(peers_c[0].hostname, "127.0.0.1", sizeof(peers_c[0].hostname) - 1);
    peers_c[0].port = PORT_A;
    strncpy(peers_c[1].node_id, "raft-b", 63);
    strncpy(peers_c[1].hostname, "127.0.0.1", sizeof(peers_c[1].hostname) - 1);
    peers_c[1].port = PORT_B;

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_raft(&a, "./it_rf_a", "raft-a", PORT_A, NULL, key, peers_a, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_raft(&b, "./it_rf_b", "raft-b", PORT_B, seed, key, peers_b, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_raft(&c, "./it_rf_c", "raft-c", PORT_C, seed, key, peers_c, 2), 0);

    for (int i = 0; i < 20; i++) {
        (void)dislmdb_force_sync(a);
        (void)dislmdb_force_sync(b);
        (void)dislmdb_force_sync(c);
        usleep(50 * 1000);
    }

    DISLMDB_env *envs[3] = {a, b, c};
    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", wait_leader(envs, 3, leader, sizeof(leader), 12000), 0);

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_all_up", put_kv(writer, "k1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_b_k1", wait_val(b, "k1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c_k1", wait_val(c, "k1", "v1", 10000), 0);

    /* Kill a follower when possible; if leader is C, kill C and re-elect on A/B. */
    DISLMDB_env *killed = c;
    if (strcmp(leader, "raft-c") == 0) {
        killed = c;
    } else if (strcmp(leader, "raft-b") == 0) {
        killed = a; /* kill non-leader a */
        if (killed == writer) {
            killed = c;
        }
    } else {
        killed = c;
    }
    if (killed == a) {
        dislmdb_env_close(a);
        a = NULL;
        envs[0] = NULL;
    } else if (killed == b) {
        dislmdb_env_close(b);
        b = NULL;
        envs[1] = NULL;
    } else {
        dislmdb_env_close(c);
        c = NULL;
        envs[2] = NULL;
    }

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "reelect", wait_leader(envs, 3, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader2", leader[0] != '\0');

    writer = NULL;
    if (a && strcmp(leader, "raft-a") == 0) {
        writer = a;
    } else if (b && strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (c && strcmp(leader, "raft-c") == 0) {
        writer = c;
    } else if (a) {
        writer = a;
    } else if (b) {
        writer = b;
    } else {
        writer = c;
    }
    EXPECT_TRUE(&ctx, "writer_alive", writer != NULL);
    EXPECT_EQ_INT(&ctx, "put_after_kill", put_kv(writer, "k2", "v2"), 0);
    if (a) {
        EXPECT_EQ_INT(&ctx, "see_a_k2", wait_val(a, "k2", "v2", 10000), 0);
    }
    if (b) {
        EXPECT_EQ_INT(&ctx, "see_b_k2", wait_val(b, "k2", "v2", 10000), 0);
    }
    if (c) {
        EXPECT_EQ_INT(&ctx, "see_c_k2", wait_val(c, "k2", "v2", 10000), 0);
    }

    if (c) dislmdb_env_close(c);
    if (b) dislmdb_env_close(b);
    if (a) dislmdb_env_close(a);
    rm_rf("./it_rf_a");
    rm_rf("./it_rf_b");
    rm_rf("./it_rf_c");
    return test_end(&ctx);
}
