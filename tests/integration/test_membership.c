/**
 * @file test_membership.c
 * @brief Integration: node membership + reconfigure + state transfer API
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_membership_db"

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/membership");
    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.persist_state = true;
    cfg.network.local_port = 19876;

    EXPECT_EQ_INT(&ctx, "create", dislmdb_env_create(&env), 0);
    EXPECT_EQ_INT(&ctx, "open", dislmdb_env_open(env, &cfg), 0);

    DISLMDB_node_addr n1 = {0};
    strncpy(n1.hostname, "127.0.0.1", sizeof(n1.hostname) - 1);
    n1.port = 19877;
    strncpy(n1.node_id, "replica-b", sizeof(n1.node_id) - 1);

    int arc = dislmdb_add_node(env, &n1);
    EXPECT_TRUE(&ctx, "add_node", arc == DISLMDB_SUCCESS || arc == DISLMDB_ERR_CONNECTION
                || arc == DISLMDB_ERR_NODE_UNREACHABLE);

    DISLMDB_node_addr nodes[2] = {0};
    nodes[0] = n1;
    strncpy(nodes[1].hostname, "127.0.0.1", sizeof(nodes[1].hostname) - 1);
    nodes[1].port = 19878;
    strncpy(nodes[1].node_id, "replica-c", sizeof(nodes[1].node_id) - 1);

    int rrc = dislmdb_reconfigure_replicas(env, nodes, 2);
    EXPECT_TRUE(&ctx, "reconfigure", rrc == DISLMDB_SUCCESS || rrc == DISLMDB_ERR_CONNECTION
                || rrc == DISLMDB_ERR_NODE_UNREACHABLE || rrc == DISLMDB_ERR_NODE_EXISTS);

    int st = dislmdb_request_state_transfer(env);
    EXPECT_TRUE(&ctx, "state_transfer_api",
                st == DISLMDB_SUCCESS || st == DISLMDB_ERR_SYNC_FAILED
                || st == DISLMDB_ERR_INVALID_PARAMETER);

    DISLMDB_metrics m;
    EXPECT_EQ_INT(&ctx, "metrics", dislmdb_get_metrics(env, &m), 0);
    EXPECT_TRUE(&ctx, "replica_count", m.replica_count >= 1);

    /* errors */
    EXPECT_EQ_INT(&ctx, "bad_key_get", dislmdb_get_cluster_key(env, NULL),
                  DISLMDB_ERR_INVALID_PARAMETER);
    EXPECT_EQ_INT(&ctx, "null_metrics", dislmdb_get_metrics(env, NULL),
                  DISLMDB_ERR_INVALID_PARAMETER);

    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
