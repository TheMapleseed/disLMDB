/**
 * @file raft_adapter.c
 * @brief DisLMDB ↔ Raft bridge (propose oplog, apply on commit)
 */
#include "raft_adapter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dislmdb_errors.h"
#include "dislmdb_network.h"
#include "../../Enhanced-Raft-mechanism/raft.h"
#include "pbft_adapter.h" /* serialize + apply oplog helpers */

typedef struct {
    DISLMDB_env *env;
    RaftNode *node;
} raft_adapter_ctx;

static void raft_outbound(const RaftMessage *msg, void *user_data)
{
    DISLMDB_env *env = user_data;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (raft_message_serialize(msg, &wire, &wire_len) != 0) {
        return;
    }
    DISLMDB_network_message nm;
    if (dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_ELECTION, wire, (uint32_t)wire_len,
                                       msg->to[0] ? msg->to : NULL) == DISLMDB_SUCCESS) {
        strncpy(nm.header.sender_id, msg->from, sizeof(nm.header.sender_id) - 1);
        if (msg->to[0] != '\0') {
            (void)dislmdb_network_send(env, &nm, msg->to, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
        } else {
            (void)dislmdb_network_broadcast(env, &nm, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
        }
        dislmdb_network_free_message(&nm);
    }
    free(wire);
}

static void raft_apply(uint64_t index, const uint8_t *data, size_t len, void *user_data)
{
    (void)index;
    DISLMDB_env *env = user_data;
    if (!env || !data || len == 0) {
        return;
    }
    (void)dislmdb_pbft_apply_transaction(env, data, len);
    env->pbft_state.sequence = (uint32_t)raft_commit_index(
        ((raft_adapter_ctx *)env->consensus_context)->node);
}

int dislmdb_raft_init(DISLMDB_env *env)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    RaftConfig cfg = raft_config_default();
    strncpy(cfg.node_id, env->local_node_id, RAFT_NODE_ID_LEN - 1);
    cfg.election_timeout_min_ms = env->config.consensus.election_timeout_min_ms
                                      ? env->config.consensus.election_timeout_min_ms
                                      : 300;
    cfg.election_timeout_max_ms = env->config.consensus.election_timeout_max_ms
                                      ? env->config.consensus.election_timeout_max_ms
                                      : 600;
    cfg.heartbeat_ms = env->config.consensus.heartbeat_interval_ms
                           ? env->config.consensus.heartbeat_interval_ms
                           : 100;

    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count && cfg.peer_count < RAFT_MAX_PEERS; i++) {
        if (strncmp(env->nodes[i].node_id, env->local_node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        if (strncmp(env->nodes[i].node_id, "seed-", 5) == 0) {
            continue;
        }
        strncpy(cfg.peer_ids[cfg.peer_count], env->nodes[i].node_id, RAFT_NODE_ID_LEN - 1);
        cfg.peer_count++;
    }
    pthread_mutex_unlock(&env->nodes_mutex);

    raft_adapter_ctx *actx = calloc(1, sizeof(*actx));
    if (!actx) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    actx->env = env;
    actx->node = raft_create(&cfg, raft_outbound, raft_apply, env);
    if (!actx->node) {
        free(actx);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    env->consensus_context = actx;
    env->pbft_state.is_primary = false;
    env->pbft_state.node_count = cfg.peer_count + 1;
    env->pbft_state.f = 0;
    strncpy(env->pbft_state.primary_id, "", sizeof(env->pbft_state.primary_id) - 1);

    int rc = dislmdb_network_set_message_callback(env, dislmdb_raft_message_handler, env);
    if (rc != DISLMDB_SUCCESS) {
        raft_destroy(actx->node);
        free(actx);
        env->consensus_context = NULL;
        return rc;
    }
    raft_start(actx->node);
    env->consensus_running = true;
    dislmdb_log(env, DISLMDB_LOG_INFO, "RAFT",
                "Raft initialized peers=%u election=%u-%ums",
                cfg.peer_count, cfg.election_timeout_min_ms, cfg.election_timeout_max_ms);
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_shutdown(DISLMDB_env *env)
{
    if (!env || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    raft_stop(actx->node);
    raft_destroy(actx->node);
    free(actx);
    env->consensus_context = NULL;
    env->consensus_running = false;
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_propose_transaction(DISLMDB_txn *txn)
{
    if (!txn || !txn->env || !txn->env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!txn->is_write_txn) {
        return DISLMDB_SUCCESS;
    }
    DISLMDB_env *env = txn->env;
    raft_adapter_ctx *actx = env->consensus_context;
    RaftNode *node = actx->node;

    uint8_t *data = NULL;
    size_t size = 0;
    int rc = dislmdb_pbft_serialize_transaction(txn, &data, &size);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    /* Drop staging write txn before Raft apply (LMDB single-writer) */
    if (txn->mdb_txn) {
        mdb_txn_abort(txn->mdb_txn);
        txn->mdb_txn = NULL;
    }

    /* Wait briefly for leadership if election still settling */
    for (int i = 0; i < 50 && !raft_is_leader(node); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    RaftError err = raft_propose(node, data, size, env->config.consensus.timeout_ms);
    if (err == RAFT_ERR_NOT_LEADER) {
        /* Forward to known leader over SYNC_REQUEST (same as PBFT path) */
        char leader[RAFT_NODE_ID_LEN];
        raft_leader_id(node, leader);
        if (leader[0] == '\0') {
            free(data);
            return DISLMDB_ERR_NO_LEADER;
        }
        DISLMDB_network_message nm;
        rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_SYNC_REQUEST, data,
                                            (uint32_t)size, leader);
        if (rc != DISLMDB_SUCCESS) {
            free(data);
            return rc;
        }
        strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);
        rc = dislmdb_network_send(env, &nm, leader, env->config.consensus.timeout_ms);
        dislmdb_network_free_message(&nm);
        free(data);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
        uint64_t before = raft_last_applied(node);
        uint64_t start = (uint64_t)time(NULL) * 1000ull;
        while (raft_last_applied(node) <= before) {
            uint64_t now = (uint64_t)time(NULL) * 1000ull;
            if (now - start > env->config.consensus.timeout_ms) {
                return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            }
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
            nanosleep(&ts, NULL);
        }
        return DISLMDB_SUCCESS;
    }
    if (err != RAFT_OK) {
        free(data);
        switch (err) {
            case RAFT_ERR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case RAFT_ERR_MEMORY: return DISLMDB_ERR_MEMORY_ERROR;
            default: return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }

    /* Leader applied via raft_apply; keep payload free. */
    free(data);
    env->pbft_state.is_primary = raft_is_leader(node);
    env->pbft_state.sequence = (uint32_t)raft_commit_index(node);
    raft_leader_id(node, env->pbft_state.primary_id);
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_current_leader(DISLMDB_env *env, char *out, size_t out_len)
{
    if (!env || !out || out_len < 2 || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    char leader[RAFT_NODE_ID_LEN];
    raft_leader_id(actx->node, leader);
    if (leader[0] == '\0') {
        return DISLMDB_ERR_NO_LEADER;
    }
    strncpy(out, leader, out_len - 1);
    out[out_len - 1] = '\0';
    strncpy(env->pbft_state.primary_id, leader, sizeof(env->pbft_state.primary_id) - 1);
    env->pbft_state.is_primary = raft_is_leader(actx->node);
    return DISLMDB_SUCCESS;
}

void dislmdb_raft_message_handler(const DISLMDB_network_message *message, void *user_data)
{
    DISLMDB_env *env = user_data;
    if (!env || !message || !env->consensus_context) {
        return;
    }
    raft_adapter_ctx *actx = env->consensus_context;

    if (message->header.type == DISLMDB_MESSAGE_SYNC_REQUEST && message->payload) {
        if (raft_is_leader(actx->node)) {
            (void)raft_propose(actx->node, message->payload, message->header.payload_size,
                               env->config.consensus.timeout_ms);
        }
        return;
    }
    if (message->header.type != DISLMDB_MESSAGE_ELECTION || !message->payload) {
        return;
    }
    RaftMessage msg;
    if (raft_message_deserialize(message->payload, message->header.payload_size, &msg) != 0) {
        return;
    }
    (void)raft_handle_message(actx->node, &msg);
    raft_message_clear(&msg);
    env->pbft_state.is_primary = raft_is_leader(actx->node);
    raft_leader_id(actx->node, env->pbft_state.primary_id);
}
