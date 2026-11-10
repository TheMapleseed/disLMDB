/**
 * @file test_udp.c
 * @brief Integration: cluster traffic over UDP datagrams (WebTransport substrate)
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT_A 29210
#define PORT_B 29211

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static int open_udp_node(DISLMDB_env **out, const char *path, const char *name,
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
    cfg.network.enable_payload_encryption = false;
    cfg.network.enable_mtls = false;
    memcpy(cfg.network.cluster_key, key, 32);
    if (peers && npeers) {
        cfg.network.nodes = (DISLMDB_node_addr *)peers;
        cfg.network.node_count = npeers;
    }
    if (seed) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], seed, sizeof(cfg.network.seed_nodes[0]) - 1);
    }
    /* PBFT f=0 validates datagram framing/replication; Raft unit-tested separately */
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.timeout_ms = 5000;
    cfg.consensus.heartbeat_interval_ms = 80;
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
        usleep(50 * 1000);
        w += 50;
    }
    return -1;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/udp");

    rm_rf("./it_udp_a");
    rm_rf("./it_udp_b");
    mkdir("./it_udp_a", 0700);
    mkdir("./it_udp_b", 0700);

    uint8_t key[32];
    memset(key, 0x3C, 32);

    DISLMDB_node_addr peers_a = {0};
    strncpy(peers_a.node_id, "udp-b", 63);
    strncpy(peers_a.hostname, "127.0.0.1", sizeof(peers_a.hostname) - 1);
    peers_a.port = PORT_B;

    DISLMDB_node_addr peers_b = {0};
    strncpy(peers_b.node_id, "udp-a", 63);
    strncpy(peers_b.hostname, "127.0.0.1", sizeof(peers_b.hostname) - 1);
    peers_b.port = PORT_A;

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_udp_node(&a, "./it_udp_a", "udp-a", PORT_A, NULL, key, &peers_a, 1), 0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_udp_node(&b, "./it_udp_b", "udp-b", PORT_B, seed, key, &peers_b, 1), 0);

    for (int i = 0; i < 30; i++) {
        (void)dislmdb_force_sync(a);
        (void)dislmdb_force_sync(b);
        usleep(50 * 1000);
    }

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "leader_ok", dislmdb_get_leader(a, leader, sizeof(leader)), 0);
    EXPECT_STREQ(&ctx, "leader_a", leader, "udp-a"); /* sorted ids: udp-a < udp-b */

    EXPECT_EQ_INT(&ctx, "put_udp", put_kv(a, "wt", "datagram"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", wait_val(a, "wt", "datagram", 3000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", wait_val(b, "wt", "datagram", 10000), 0);

    if (b) dislmdb_env_close(b);
    if (a) dislmdb_env_close(a);
    rm_rf("./it_udp_a");
    rm_rf("./it_udp_b");
    return test_end(&ctx);
}
