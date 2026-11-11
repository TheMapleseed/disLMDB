/**
 * @file it_cluster.h
 * @brief Shared helpers for DisLMDB integration cluster tests
 *
 * One place for put/wait/open/certs so transport-matrix and chaos ITs stay
 * consistent (timeouts, ports, cleanup) without copy-paste drift.
 */
#ifndef DISLMDB_IT_CLUSTER_H
#define DISLMDB_IT_CLUSTER_H

#include "dislmdb.h"
#include "dislmdb_errors.h"
#include "dislmdb_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void it_rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static inline int it_mkdir(const char *p)
{
    return mkdir(p, 0700);
}

static inline int it_gen_certs(const char *dir)
{
    char cmd[512];
    it_mkdir(dir);
    snprintf(cmd, sizeof(cmd),
             "openssl req -x509 -newkey rsa:2048 -nodes "
             "-keyout '%s/key.pem' -out '%s/cert.pem' -days 1 "
             "-subj '/CN=dislmdb-it' >/dev/null 2>&1",
             dir, dir);
    return system(cmd);
}

static inline int it_put_kv(DISLMDB_env *env, const char *k, const char *v)
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

static inline int it_wait_val(DISLMDB_env *env, const char *k, const char *expect,
                              int ms)
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

static inline int it_wait_leader(DISLMDB_env *envs[], int n, char *out,
                                 size_t out_sz, int ms)
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

typedef struct it_raft_opts {
    const char *path;
    const char *name;
    uint16_t port;
    const char *seed; /* "host:port" or NULL */
    const uint8_t *cluster_key; /* 32 bytes */
    const DISLMDB_node_addr *peers;
    size_t npeers;
    DISLMDB_TRANSPORT transport;
    bool enable_mtls;
    const char *cert_dir; /* required when enable_mtls */
    uint32_t timeout_ms;
    uint32_t heartbeat_ms;
    uint32_t election_min_ms;
    uint32_t election_max_ms;
    /* Optional topology / plane keys (NULL / 0 = unset) */
    const char *region;
    const char *locality;
    DISLMDB_TOPOLOGY_MODE topology_mode;
    bool set_topology_mode;
    const uint8_t *region_key; /* 32 bytes */
    const uint8_t *cross_region_key; /* 32 bytes */
    uint32_t rtt_budget_ms;
    /* Optional consensus / net knobs (defaults keep prior IT behavior) */
    bool set_enable_voting;
    bool enable_voting;
    uint32_t max_peers; /* 0 = unlimited / unset */
    uint32_t handshake_workers; /* 0 = library default */
    uint32_t raft_wal_sync_every; /* UINT32_MAX = unset; else 0/N */
    bool set_raft_wal_sync_every;
} it_raft_opts;

static inline it_raft_opts it_raft_opts_default(void)
{
    it_raft_opts o;
    memset(&o, 0, sizeof(o));
    o.transport = DISLMDB_TRANSPORT_BOTH;
    o.enable_mtls = false;
    o.timeout_ms = 8000;
    o.heartbeat_ms = 80;
    o.election_min_ms = 250;
    o.election_max_ms = 500;
    o.topology_mode = DISLMDB_TOPO_MIRROR;
    return o;
}

static inline int it_open_raft(DISLMDB_env **out, const it_raft_opts *opts)
{
    if (!out || !opts || !opts->path || !opts->name || !opts->cluster_key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (opts->enable_mtls && (!opts->cert_dir || opts->cert_dir[0] == '\0')) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_env *env = NULL;
    int rc = dislmdb_env_create(&env);
    if (rc != 0) {
        return rc;
    }
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = opts->path;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    strncpy(cfg.node_name, opts->name, sizeof(cfg.node_name) - 1);
    cfg.network.local_port = opts->port;
    cfg.network.transport = opts->transport;
    cfg.network.has_cluster_key = true;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = true;
    cfg.network.enable_mtls = opts->enable_mtls;
    memcpy(cfg.network.cluster_key, opts->cluster_key, 32);
    if (opts->enable_mtls) {
        snprintf(cfg.network.tls_cert_path, sizeof(cfg.network.tls_cert_path),
                 "%s/cert.pem", opts->cert_dir);
        snprintf(cfg.network.tls_key_path, sizeof(cfg.network.tls_key_path),
                 "%s/key.pem", opts->cert_dir);
        snprintf(cfg.network.tls_ca_path, sizeof(cfg.network.tls_ca_path),
                 "%s/cert.pem", opts->cert_dir);
    }
    if (opts->peers && opts->npeers) {
        cfg.network.nodes = (DISLMDB_node_addr *)opts->peers;
        cfg.network.node_count = opts->npeers;
    }
    if (opts->seed) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], opts->seed,
                sizeof(cfg.network.seed_nodes[0]) - 1);
    }
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_RAFT;
    cfg.consensus.timeout_ms = opts->timeout_ms ? opts->timeout_ms : 8000;
    cfg.consensus.heartbeat_interval_ms =
        opts->heartbeat_ms ? opts->heartbeat_ms : 80;
    cfg.consensus.election_timeout_min_ms =
        opts->election_min_ms ? opts->election_min_ms : 250;
    cfg.consensus.election_timeout_max_ms =
        opts->election_max_ms ? opts->election_max_ms : 500;
    cfg.consensus.enable_liveness = true;
    cfg.consensus.persist_state = true;
    if (opts->region && opts->region[0] != '\0') {
        strncpy(cfg.region, opts->region, sizeof(cfg.region) - 1);
    }
    if (opts->locality && opts->locality[0] != '\0') {
        strncpy(cfg.locality, opts->locality, sizeof(cfg.locality) - 1);
    }
    if (opts->set_topology_mode) {
        cfg.topology_mode = opts->topology_mode;
    }
    if (opts->region_key) {
        memcpy(cfg.region_key, opts->region_key, 32);
        cfg.has_region_key = true;
    }
    if (opts->cross_region_key) {
        memcpy(cfg.cross_region_key, opts->cross_region_key, 32);
        cfg.has_cross_region_key = true;
    }
    if (opts->rtt_budget_ms) {
        cfg.rtt_budget_ms = opts->rtt_budget_ms;
    }
    if (opts->set_enable_voting) {
        cfg.consensus.enable_voting = opts->enable_voting;
    }
    if (opts->max_peers) {
        cfg.max_peers = opts->max_peers;
    }
    if (opts->handshake_workers) {
        cfg.network.handshake_workers = opts->handshake_workers;
    }
    if (opts->set_raft_wal_sync_every) {
        cfg.consensus.raft_wal_sync_every = opts->raft_wal_sync_every;
    }
    rc = dislmdb_env_open(env, &cfg);
    if (rc != 0) {
        dislmdb_env_close(env);
        return rc;
    }
    *out = env;
    return 0;
}

static inline void it_peer(DISLMDB_node_addr *out, const char *id, uint16_t port)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->node_id, id, sizeof(out->node_id) - 1);
    strncpy(out->hostname, "127.0.0.1", sizeof(out->hostname) - 1);
    out->port = port;
}

static inline void it_peer_region(DISLMDB_node_addr *out, const char *id,
                                  uint16_t port, const char *region)
{
    it_peer(out, id, port);
    if (region) {
        strncpy(out->region, region, sizeof(out->region) - 1);
    }
}

static inline void it_mesh_warmup(DISLMDB_env *envs[], int n, int rounds)
{
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < n; i++) {
            if (envs[i]) {
                (void)dislmdb_force_sync(envs[i]);
            }
        }
        usleep(50 * 1000);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_IT_CLUSTER_H */
