/**
 * @file test_system_surface.c
 * @brief System-wide API surface: soft peer cap, voting env, multi-DBI persist,
 *        status callback, force_sync, handshake_workers, mirror LAST_WRITE.
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include "dislmdb_network.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define DBPATH "./it_system_surface_db"
#define PORT 30940

static void rm_rf(const char *p)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    (void)system(cmd);
}

static int g_status_hits;

static void on_status(const char *node_id, DISLMDB_NODE_STATE old_state,
                      DISLMDB_NODE_STATE new_state, void *ud)
{
    (void)node_id;
    (void)old_state;
    (void)new_state;
    (void)ud;
    g_status_hits++;
}

static int put_named(DISLMDB_env *env, const char *db, const char *k, const char *v)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, db, MDB_CREATE, &dbi);
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

static int get_named(DISLMDB_env *env, const char *db, const char *k, char *out,
                     size_t out_sz)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, db, 0, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val key = {.mv_size = strlen(k), .mv_data = (void *)k};
    MDB_val val;
    rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &key, &val);
    if (rc == 0) {
        size_t n = val.mv_size < out_sz - 1 ? val.mv_size : out_sz - 1;
        memcpy(out, val.mv_data, n);
        out[n] = '\0';
    }
    dislmdb_txn_abort(txn);
    return rc;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/system_surface");

    /* --- max_peers soft cap --- */
    {
        rm_rf(DBPATH);
        mkdir(DBPATH, 0700);
        DISLMDB_env *env = NULL;
        DISLMDB_env_config cfg;
        dislmdb_env_config_init(&cfg);
        cfg.path = DBPATH;
        cfg.mapsize = 4 * 1024 * 1024;
        cfg.maxdbs = 8;
        cfg.max_peers = 1;
        cfg.network.local_port = PORT;
        cfg.network.handshake_workers = 3;
        cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
        cfg.consensus.persist_state = true;
        strncpy(cfg.node_name, "cap-solo", sizeof(cfg.node_name) - 1);
        strncpy(cfg.region, "lab", sizeof(cfg.region) - 1);
        strncpy(cfg.locality, "rack-1", sizeof(cfg.locality) - 1);

        EXPECT_EQ_INT(&ctx, "cap_create", dislmdb_env_create(&env), 0);
        EXPECT_EQ_INT(&ctx, "cap_open", dislmdb_env_open(env, &cfg), 0);

        EXPECT_TRUE(&ctx, "voting_default", dislmdb_voting_enabled(env));

        char region[64] = {0}, locality[64] = {0};
        DISLMDB_TOPOLOGY_MODE mode = (DISLMDB_TOPOLOGY_MODE)99;
        EXPECT_EQ_INT(&ctx, "get_region", dislmdb_get_region(env, region, sizeof(region)),
                      0);
        EXPECT_STREQ(&ctx, "region_lab", region, "lab");
        EXPECT_EQ_INT(&ctx, "get_locality",
                      dislmdb_get_locality(env, locality, sizeof(locality)), 0);
        EXPECT_STREQ(&ctx, "locality_rack", locality, "rack-1");
        EXPECT_EQ_INT(&ctx, "get_topo", dislmdb_get_topology_mode(env, &mode), 0);
        EXPECT_EQ_INT(&ctx, "topo_mirror", (int)mode, (int)DISLMDB_TOPO_MIRROR);

        g_status_hits = 0;
        EXPECT_EQ_INT(&ctx, "status_cb",
                      dislmdb_set_status_callback(env, on_status, NULL), 0);

        DISLMDB_node_addr p1 = {0}, p2 = {0};
        strncpy(p1.node_id, "peer-1", sizeof(p1.node_id) - 1);
        strncpy(p1.hostname, "127.0.0.1", sizeof(p1.hostname) - 1);
        p1.port = (uint16_t)(PORT + 1);
        strncpy(p2.node_id, "peer-2", sizeof(p2.node_id) - 1);
        strncpy(p2.hostname, "127.0.0.1", sizeof(p2.hostname) - 1);
        p2.port = (uint16_t)(PORT + 2);

        int a1 = dislmdb_add_node(env, &p1);
        EXPECT_TRUE(&ctx, "add_peer1",
                    a1 == DISLMDB_SUCCESS || a1 == DISLMDB_ERR_CONNECTION ||
                        a1 == DISLMDB_ERR_NODE_UNREACHABLE);
        EXPECT_EQ_INT(&ctx, "add_peer2_cap", dislmdb_add_node(env, &p2),
                      DISLMDB_ERR_MAX_NODES);

        DISLMDB_node_addr too_many[2] = {p1, p2};
        EXPECT_EQ_INT(&ctx, "reconfig_cap",
                      dislmdb_reconfigure_replicas(env, too_many, 2),
                      DISLMDB_ERR_MAX_NODES);

        EXPECT_EQ_INT(&ctx, "force_sync", dislmdb_force_sync(env), 0);
        EXPECT_EQ_INT(&ctx, "env_sync", dislmdb_env_sync(env, 1), 0);

        DISLMDB_metrics m;
        memset(&m, 0, sizeof(m));
        EXPECT_EQ_INT(&ctx, "metrics", dislmdb_get_metrics(env, &m), 0);
        EXPECT_TRUE(&ctx, "voting_metric", m.voting_enabled);
        char mbuf[4096];
        size_t mw = 0;
        EXPECT_EQ_INT(&ctx, "fmt_live",
                      dislmdb_format_metrics(&m, mbuf, sizeof(mbuf), &mw), 0);
        EXPECT_TRUE(&ctx, "fmt_live_len", mw > 80);
        EXPECT_TRUE(&ctx, "fmt_voting",
                    strstr(mbuf, "dislmdb_voting_enabled 1") != NULL);

        DISLMDB_network_stats ns;
        memset(&ns, 0, sizeof(ns));
        EXPECT_EQ_INT(&ctx, "net_stats", dislmdb_network_get_stats(env, &ns), 0);

        /* Multi named DBI + checkpoint + reopen */
        EXPECT_EQ_INT(&ctx, "put_app", put_named(env, "app", "a1", "va"), 0);
        EXPECT_EQ_INT(&ctx, "put_meta2", put_named(env, "meta2", "m1", "vm"), 0);
        EXPECT_EQ_INT(&ctx, "ckpt", dislmdb_checkpoint(env), 0);
        dislmdb_env_close(env);
        env = NULL;

        EXPECT_EQ_INT(&ctx, "recreate", dislmdb_env_create(&env), 0);
        EXPECT_EQ_INT(&ctx, "reopen", dislmdb_env_open(env, &cfg), 0);
        char got[64];
        EXPECT_EQ_INT(&ctx, "get_app", get_named(env, "app", "a1", got, sizeof(got)),
                      0);
        EXPECT_STREQ(&ctx, "app_val", got, "va");
        EXPECT_EQ_INT(&ctx, "get_meta2",
                      get_named(env, "meta2", "m1", got, sizeof(got)), 0);
        EXPECT_STREQ(&ctx, "meta2_val", got, "vm");
        dislmdb_env_close(env);
        rm_rf(DBPATH);
    }

    /* --- open rejects peer list past max_peers --- */
    {
        rm_rf(DBPATH);
        mkdir(DBPATH, 0700);
        DISLMDB_env *env = NULL;
        DISLMDB_env_config cfg;
        dislmdb_env_config_init(&cfg);
        cfg.path = DBPATH;
        cfg.mapsize = 4 * 1024 * 1024;
        cfg.maxdbs = 4;
        cfg.max_peers = 1;
        cfg.network.local_port = (uint16_t)(PORT + 10);
        cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
        DISLMDB_node_addr peers[2];
        memset(peers, 0, sizeof(peers));
        strncpy(peers[0].node_id, "x", sizeof(peers[0].node_id) - 1);
        strncpy(peers[0].hostname, "127.0.0.1", sizeof(peers[0].hostname) - 1);
        peers[0].port = 1;
        strncpy(peers[1].node_id, "y", sizeof(peers[1].node_id) - 1);
        strncpy(peers[1].hostname, "127.0.0.1", sizeof(peers[1].hostname) - 1);
        peers[1].port = 2;
        cfg.network.nodes = peers;
        cfg.network.node_count = 2;
        EXPECT_EQ_INT(&ctx, "over_create", dislmdb_env_create(&env), 0);
        EXPECT_EQ_INT(&ctx, "over_open", dislmdb_env_open(env, &cfg),
                      DISLMDB_ERR_MAX_NODES);
        dislmdb_env_close(env);
        rm_rf(DBPATH);
    }

    /* --- DISLMDB_VOTING=off + mirror LAST_WRITE --- */
    {
        rm_rf(DBPATH);
        mkdir(DBPATH, 0700);
        setenv("DISLMDB_VOTING", "off", 1);
        DISLMDB_env *env = NULL;
        DISLMDB_env_config cfg;
        dislmdb_env_config_init(&cfg);
        cfg.path = DBPATH;
        cfg.mapsize = 4 * 1024 * 1024;
        cfg.maxdbs = 4;
        cfg.network.local_port = (uint16_t)(PORT + 20);
        cfg.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
        cfg.topology_mode = DISLMDB_TOPO_MIRROR;
        cfg.mirror_conflict_policy = DISLMDB_MIRROR_LAST_WRITE;
        strncpy(cfg.region, "us-west", sizeof(cfg.region) - 1);
        strncpy(cfg.mirror_primary_region, "us-east",
                sizeof(cfg.mirror_primary_region) - 1);
        EXPECT_EQ_INT(&ctx, "vote_create", dislmdb_env_create(&env), 0);
        EXPECT_EQ_INT(&ctx, "vote_open", dislmdb_env_open(env, &cfg), 0);
        EXPECT_TRUE(&ctx, "voting_off", !dislmdb_voting_enabled(env));
        DISLMDB_metrics m;
        EXPECT_EQ_INT(&ctx, "vote_metrics", dislmdb_get_metrics(env, &m), 0);
        EXPECT_TRUE(&ctx, "vote_metric_off", !m.voting_enabled);
        /* LAST_WRITE ignores primary-region gate */
        EXPECT_EQ_INT(&ctx, "lw_writable",
                      dislmdb_topo_key_writable(env, "any", 3), DISLMDB_SUCCESS);
        EXPECT_EQ_INT(&ctx, "lw_put", put_named(env, "kv", "lw", "1"), 0);
        dislmdb_env_close(env);
        unsetenv("DISLMDB_VOTING");
        rm_rf(DBPATH);
    }

    (void)g_status_hits; /* may stay 0 if no peer state transitions */
    return test_end(&ctx);
}
