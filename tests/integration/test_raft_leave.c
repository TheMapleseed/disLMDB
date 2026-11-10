/**
 * @file test_raft_leave.c
 * @brief Raft graceful leave: 3-node elect, remove peer, remaining replicate
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include "dislmdb_consensus.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT_A 30740
#define PORT_B 30741
#define PORT_C 30742

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
    cfg.network.transport = DISLMDB_TRANSPORT_UDP;
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
    test_begin(&ctx, "integration/raft_leave");

    rm_rf("./it_rl_a");
    rm_rf("./it_rl_b");
    rm_rf("./it_rl_c");
    mkdir("./it_rl_a", 0700);
    mkdir("./it_rl_b", 0700);
    mkdir("./it_rl_c", 0700);

    uint8_t key[32];
    memset(key, 0x4c, 32);

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
                  open_raft(&a, "./it_rl_a", "raft-a", PORT_A, NULL, key, peers_a, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_raft(&b, "./it_rl_b", "raft-b", PORT_B, seed, key, peers_b, 2), 0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_raft(&c, "./it_rl_c", "raft-c", PORT_C, seed, key, peers_c, 2), 0);

    for (int i = 0; i < 40; i++) {
        (void)dislmdb_force_sync(a);
        (void)dislmdb_force_sync(b);
        (void)dislmdb_force_sync(c);
        usleep(50 * 1000);
    }

    DISLMDB_env *all[3] = {a, b, c};
    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", wait_leader(all, 3, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put_before", put_kv(writer, "lk1", "v1"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", wait_val(a, "lk1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", wait_val(b, "lk1", "v1", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", wait_val(c, "lk1", "v1", 10000), 0);

    /* Leader removes a follower (never self). */
    const char *victim_id = "raft-c";
    DISLMDB_env *victim_env = c;
    if (strcmp(leader, "raft-c") == 0) {
        victim_id = "raft-b";
        victim_env = b;
    }
    EXPECT_EQ_INT(&ctx, "remove_peer", dislmdb_remove_node(writer, victim_id), 0);
    usleep(300 * 1000);
    dislmdb_env_close(victim_env);
    if (victim_env == b) {
        b = NULL;
    } else {
        c = NULL;
    }

    DISLMDB_env *remain[2];
    remain[0] = a;
    remain[1] = (b != NULL) ? b : c;
    EXPECT_TRUE(&ctx, "remain1", remain[1] != NULL);

    for (int i = 0; i < 20; i++) {
        (void)dislmdb_force_sync(remain[0]);
        (void)dislmdb_force_sync(remain[1]);
        usleep(50 * 1000);
    }

    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "elect_remain", wait_leader(remain, 2, leader, sizeof(leader), 12000), 0);
    writer = remain[0];
    if (b && strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (c && strcmp(leader, "raft-c") == 0) {
        writer = c;
    } else if (strcmp(leader, "raft-a") == 0) {
        writer = a;
    }
    EXPECT_EQ_INT(&ctx, "put_after_leave", put_kv(writer, "lk2", "v2"), 0);
    EXPECT_EQ_INT(&ctx, "see0_after", wait_val(remain[0], "lk2", "v2", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see1_after", wait_val(remain[1], "lk2", "v2", 10000), 0);

    EXPECT_EQ_INT(&ctx, "force_election", dislmdb_consensus_trigger_view_change(writer), 0);
    usleep(200 * 1000);
    memset(leader, 0, sizeof(leader));
    EXPECT_EQ_INT(&ctx, "reelect", wait_leader(remain, 2, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_after_stepdown", leader[0] != '\0');

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    rm_rf("./it_rl_a");
    rm_rf("./it_rl_b");
    rm_rf("./it_rl_c");
    return test_end(&ctx);
}
