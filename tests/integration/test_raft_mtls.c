/**
 * @file test_raft_mtls.c
 * @brief Raft over BOTH: UDP election signalling + TCP data with mTLS 1.3 + AEAD
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT_A 30630
#define PORT_B 30631

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static int gen_certs(const char *dir)
{
    char cmd[512];
    mkdir(dir, 0700);
    snprintf(cmd, sizeof(cmd),
             "openssl req -x509 -newkey rsa:2048 -nodes "
             "-keyout '%s/key.pem' -out '%s/cert.pem' -days 1 "
             "-subj '/CN=dislmdb-raft-mtls' >/dev/null 2>&1",
             dir, dir);
    return system(cmd);
}

static int open_raft_mtls(DISLMDB_env **out, const char *path, const char *name,
                          uint16_t port, const char *seed, const uint8_t key[32],
                          const DISLMDB_node_addr *peers, size_t npeers,
                          const char *cert_dir)
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
    /* BOTH: RequestVote/AppendEntries heartbeats on UDP; commits on mTLS TCP */
    cfg.network.transport = DISLMDB_TRANSPORT_BOTH;
    cfg.network.has_cluster_key = true;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = true;
    cfg.network.enable_mtls = true;
    snprintf(cfg.network.tls_cert_path, sizeof(cfg.network.tls_cert_path),
             "%s/cert.pem", cert_dir);
    snprintf(cfg.network.tls_key_path, sizeof(cfg.network.tls_key_path),
             "%s/key.pem", cert_dir);
    snprintf(cfg.network.tls_ca_path, sizeof(cfg.network.tls_ca_path),
             "%s/cert.pem", cert_dir);
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
        (void)dislmdb_force_sync(env);
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
    test_begin(&ctx, "integration/raft_mtls");

    rm_rf("./it_rm_certs");
    rm_rf("./it_rm_a");
    rm_rf("./it_rm_b");
    mkdir("./it_rm_a", 0700);
    mkdir("./it_rm_b", 0700);
    EXPECT_EQ_INT(&ctx, "gen_certs", gen_certs("./it_rm_certs"), 0);

    uint8_t key[32];
    memset(key, 0x47, 32);

    DISLMDB_node_addr peers_a[1] = {0};
    strncpy(peers_a[0].node_id, "raft-b", 63);
    strncpy(peers_a[0].hostname, "127.0.0.1", sizeof(peers_a[0].hostname) - 1);
    peers_a[0].port = PORT_B;

    DISLMDB_node_addr peers_b[1] = {0};
    strncpy(peers_b[0].node_id, "raft-a", 63);
    strncpy(peers_b[0].hostname, "127.0.0.1", sizeof(peers_b[0].hostname) - 1);
    peers_b[0].port = PORT_A;

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_raft_mtls(&a, "./it_rm_a", "raft-a", PORT_A, NULL, key, peers_a, 1,
                                 "./it_rm_certs"),
                  0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_raft_mtls(&b, "./it_rm_b", "raft-b", PORT_B, seed, key, peers_b, 1,
                                 "./it_rm_certs"),
                  0);

    for (int i = 0; i < 60; i++) {
        (void)dislmdb_force_sync(a);
        (void)dislmdb_force_sync(b);
        usleep(50 * 1000);
    }

    DISLMDB_env *envs[2] = {a, b};
    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", wait_leader(envs, 2, leader, sizeof(leader), 20000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    EXPECT_EQ_INT(&ctx, "put_mtls", put_kv(writer, "mtk", "mtv"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", wait_val(a, "mtk", "mtv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", wait_val(b, "mtk", "mtv", 10000), 0);

    if (b) dislmdb_env_close(b);
    if (a) dislmdb_env_close(a);
    rm_rf("./it_rm_a");
    rm_rf("./it_rm_b");
    rm_rf("./it_rm_certs");
    return test_end(&ctx);
}
