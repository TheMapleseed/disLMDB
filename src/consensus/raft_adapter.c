/**
 * @file raft_adapter.c
 * @brief DisLMDB ↔ Raft bridge (propose oplog, apply on commit)
 *
 * Bootstrap is staged: create the Raft node and install the network callback
 * first so JOIN/HELLO can engage the mesh; elections start only after
 * dislmdb_raft_start() once peers are wired.
 */
#include "raft_adapter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_network.h"
#include "../../Enhanced-Raft-mechanism/raft.h"
#include "pbft_adapter.h" /* serialize + apply oplog helpers + HELLO */

typedef struct {
    DISLMDB_env *env;
    RaftNode *node;
    bool started;
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
    /*
     * All Raft frames use ELECTION (UDP under BOTH) until TCP upgrade under
     * mTLS is proven not to strand CONNECTING slots. Commit visibility is
     * ensured by advance_commit() → immediate empty AppendEntries.
     */
    if (dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_ELECTION, wire,
                                       (uint32_t)wire_len,
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

static void raft_sync_peers_from_env(raft_adapter_ctx *actx)
{
    DISLMDB_env *env = actx->env;
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        const char *id = env->nodes[i].node_id;
        if (strncmp(id, env->local_node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        if (strncmp(id, "seed-", 5) == 0) {
            continue;
        }
        (void)raft_add_peer(actx->node, id);
    }
    pthread_mutex_unlock(&env->nodes_mutex);
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

    /* Seed peers from the configured node table; HELLO may add more before start. */
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
    actx->started = false;
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
    /* Do not raft_start yet — cluster HELLO/mesh engages first. */
    env->consensus_running = false;
    dislmdb_log(env, DISLMDB_LOG_INFO, "RAFT",
                "Raft armed (not started) peers=%u election=%u-%ums",
                cfg.peer_count, cfg.election_timeout_min_ms, cfg.election_timeout_max_ms);
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_start(DISLMDB_env *env)
{
    if (!env || !env->consensus_context ||
        env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (actx->started) {
        return DISLMDB_SUCCESS;
    }

    /*
     * Prefer a live peer before the election ticker fires — critical for
     * TCP+mTLS where CONNECTING handshakes otherwise burn the first votes.
     * Solo / first-node opens time out cleanly and start anyway.
     */
    if (env->node_count > 1) {
        uint32_t wait_ms = env->config.network.enable_mtls ? 3000u : 750u;
        int wrc = dislmdb_network_wait_connected(env, 1, wait_ms);
        dislmdb_log(env, DISLMDB_LOG_INFO, "RAFT",
                    "pre-start mesh wait peers=%u rc=%d connected=%u",
                    env->node_count, wrc,
                    (unsigned)dislmdb_network_connected_peer_count(env));
        (void)dislmdb_pbft_send_hello(env, "");
    }

    raft_sync_peers_from_env(actx);
    raft_start(actx->node);
    actx->started = true;
    env->consensus_running = true;
    env->pbft_state.node_count = env->node_count ? env->node_count : 1;
    dislmdb_log(env, DISLMDB_LOG_INFO, "RAFT",
                "Raft started after cluster engage node_count=%u", env->pbft_state.node_count);
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

static void raft_record_commit(DISLMDB_env *env)
{
    DISLMDB_op_id oid;
    if (dislmdb_consensus_generate_op_id(env, &oid) != DISLMDB_SUCCESS) {
        return;
    }
    DISLMDB_consensus_result cres;
    memset(&cres, 0, sizeof(cres));
    cres.status = DISLMDB_CONSENSUS_COMMITTED;
    cres.error_code = DISLMDB_SUCCESS;
    cres.commit_view = env->pbft_state.view;
    cres.commit_sequence = env->pbft_state.sequence;
    cres.commit_time = dislmdb_get_time_ms();
    cres.node_count = env->node_count ? env->node_count : 1;
    cres.agree_count = cres.node_count;
    dislmdb_record_consensus_result(env, &oid, DISLMDB_OP_TYPE_PUT, &cres);
}

/** Propose opaque consensus payload (oplog / BCOD / SMAP); takes ownership of data. */
static int raft_propose_owned(DISLMDB_env *env, uint8_t *data, size_t size)
{
    raft_adapter_ctx *actx = env->consensus_context;
    RaftNode *node = actx->node;

    for (int i = 0; i < 50 && !raft_is_leader(node); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }

    RaftError err = raft_propose(node, data, size, env->config.consensus.timeout_ms);
    if (err == RAFT_ERR_NOT_LEADER) {
        char leader[RAFT_NODE_ID_LEN];
        raft_leader_id(node, leader);
        if (leader[0] == '\0') {
            free(data);
            return DISLMDB_ERR_NO_LEADER;
        }
        DISLMDB_network_message nm;
        int rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_SYNC_REQUEST, data,
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
        env->pbft_state.sequence = (uint32_t)raft_commit_index(node);
        raft_record_commit(env);
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

    free(data);
    env->pbft_state.is_primary = raft_is_leader(node);
    env->pbft_state.sequence = (uint32_t)raft_commit_index(node);
    raft_leader_id(node, env->pbft_state.primary_id);
    raft_record_commit(env);
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_force_election(DISLMDB_env *env)
{
    if (!env || !env->consensus_context ||
        env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (!actx->started) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    RaftError err = raft_step_down(actx->node);
    if (err != RAFT_OK) {
        return DISLMDB_ERR_CONSENSUS_FAILED;
    }
    env->view_changes++;
    env->pbft_state.is_primary = false;
    env->pbft_state.primary_id[0] = '\0';
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_propose_raw(DISLMDB_env *env, uint8_t *data, size_t size)
{
    if (!env || !env->consensus_context || !data) {
        free(data);
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        free(data);
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (!actx->started) {
        free(data);
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    return raft_propose_owned(env, data, size);
}

int dislmdb_raft_remove_peer(DISLMDB_env *env, const char *node_id)
{
    if (!env || !env->consensus_context || !node_id || node_id[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strncmp(node_id, env->local_node_id, RAFT_NODE_ID_LEN) == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    (void)raft_remove_peer(actx->node, node_id);

    if (!actx->started || !raft_is_leader(actx->node)) {
        return DISLMDB_SUCCESS;
    }
    if (raft_in_joint_consensus(actx->node)) {
        return DISLMDB_ERR_IN_PROGRESS;
    }

    char peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t pc = 0;
    memset(peers, 0, sizeof(peers));
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count && pc < RAFT_MAX_PEERS; i++) {
        const char *id = env->nodes[i].node_id;
        if (strncmp(id, env->local_node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        if (strncmp(id, node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        if (strncmp(id, "seed-", 5) == 0) {
            continue;
        }
        strncpy(peers[pc], id, RAFT_NODE_ID_LEN - 1);
        peers[pc][RAFT_NODE_ID_LEN - 1] = '\0';
        pc++;
    }
    pthread_mutex_unlock(&env->nodes_mutex);

    RaftError err = raft_propose_membership(actx->node, peers, pc,
                                            env->config.consensus.timeout_ms);
    if (err != RAFT_OK) {
        switch (err) {
            case RAFT_ERR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case RAFT_ERR_NOT_LEADER: return DISLMDB_SUCCESS; /* raced away */
            case RAFT_ERR_STATE: return DISLMDB_ERR_IN_PROGRESS;
            default: return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }
    env->pbft_state.node_count = pc + 1;
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

    if (!actx->started) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }

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

    return raft_propose_owned(env, data, size);
}

#define RAFT_BCOD_MAGIC 0x42434F44u /* BCOD — must match pbft_adapter */

int dislmdb_raft_store_bytecode(DISLMDB_env *env,
                                const uint8_t *bytecode,
                                size_t bytecode_size,
                                const char *bytecode_id,
                                unsigned int options)
{
    if (!env || !env->consensus_context || !bytecode || !bytecode_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (bytecode_size == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (!actx->started) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }

    size_t id_len = strnlen(bytecode_id, 129);
    if (id_len == 0 || id_len > 128) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t meta = 4 + 4 + 4 + id_len + 4 + 8;
    if (meta + bytecode_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    uint8_t *buffer = malloc(meta + bytecode_size);
    if (!buffer) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buffer + o, RAFT_BCOD_MAGIC); o += 4;
    dislmdb_write_u32(buffer + o, 1); o += 4;
    dislmdb_write_u32(buffer + o, (uint32_t)id_len); o += 4;
    memcpy(buffer + o, bytecode_id, id_len); o += id_len;
    dislmdb_write_u32(buffer + o, options); o += 4;
    dislmdb_write_u64(buffer + o, (uint64_t)time(NULL)); o += 8;
    memcpy(buffer + o, bytecode, bytecode_size);

    return raft_propose_owned(env, buffer, meta + bytecode_size);
}

int dislmdb_raft_checkpoint(DISLMDB_env *env)
{
    if (!env || !env->consensus_context ||
        env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (!actx->started) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    env->pbft_state.sequence = (uint32_t)raft_commit_index(actx->node);
    env->pbft_state.is_primary = raft_is_leader(actx->node);
    raft_leader_id(actx->node, env->pbft_state.primary_id);
    env->checkpoints++;
    return dislmdb_persist_save(env);
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
    if (!actx->started) {
        return DISLMDB_ERR_NO_LEADER;
    }
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

int dislmdb_raft_reconfigure(DISLMDB_env *env,
                             const DISLMDB_node_addr *nodes,
                             size_t node_count)
{
    if (!env || !env->consensus_context || !nodes || node_count == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism != DISLMDB_CONSENSUS_RAFT) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_adapter_ctx *actx = env->consensus_context;
    if (!actx->started) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (node_count > RAFT_MAX_PEERS + 1) {
        return DISLMDB_ERR_MAX_NODES;
    }

    char peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t pc = 0;
    memset(peers, 0, sizeof(peers));

    for (size_t i = 0; i < node_count; i++) {
        int arc = dislmdb_add_node(env, &nodes[i]);
        if (arc != DISLMDB_SUCCESS) {
            return arc;
        }
        if (strncmp(nodes[i].node_id, env->local_node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        if (pc >= RAFT_MAX_PEERS) {
            return DISLMDB_ERR_MAX_NODES;
        }
        strncpy(peers[pc], nodes[i].node_id, RAFT_NODE_ID_LEN - 1);
        peers[pc][RAFT_NODE_ID_LEN - 1] = '\0';
        pc++;
    }

    /* Wait briefly so new peers can complete TCP/mTLS before AppendEntries. */
    if (pc > 0) {
        uint32_t wait_ms = env->config.network.enable_mtls ? 2000u : 500u;
        (void)dislmdb_network_wait_connected(env, pc > 3 ? 3 : pc, wait_ms);
    }

    for (int i = 0; i < 50 && !raft_is_leader(actx->node); i++) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (!raft_is_leader(actx->node)) {
        return DISLMDB_ERR_NO_LEADER;
    }

    RaftError err = raft_propose_membership(actx->node, peers, pc,
                                            env->config.consensus.timeout_ms);
    if (err != RAFT_OK) {
        switch (err) {
            case RAFT_ERR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case RAFT_ERR_NOT_LEADER: return DISLMDB_ERR_NO_LEADER;
            case RAFT_ERR_MEMORY: return DISLMDB_ERR_MEMORY_ERROR;
            case RAFT_ERR_STATE: return DISLMDB_ERR_IN_PROGRESS;
            default: return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }
    env->pbft_state.node_count = pc + 1;
    raft_sync_peers_from_env(actx);
    return dislmdb_persist_save(env);
}

void dislmdb_raft_message_handler(const DISLMDB_network_message *message, void *user_data)
{
    DISLMDB_env *env = user_data;
    if (!env || !message || !env->consensus_context) {
        return;
    }
    raft_adapter_ctx *actx = env->consensus_context;

    /* Membership engages before / alongside Raft elections */
    if (message->header.type == DISLMDB_MESSAGE_JOIN) {
        dislmdb_pbft_handle_hello(env, message);
        raft_sync_peers_from_env(actx);
        return;
    }
    if (message->header.type == DISLMDB_MESSAGE_LEAVE) {
        dislmdb_pbft_handle_leave(env, message);
        /* Durably shrink voter set when we are leader; else local drop. */
        if (message->payload && message->header.payload_size >= 5) {
            const uint8_t *p = message->payload;
            if (dislmdb_read_u32(p) == DISLMDB_LEAV_MAGIC) {
                uint8_t id_len = p[4];
                if ((size_t)5 + id_len <= message->header.payload_size &&
                    id_len > 0 && id_len < 64) {
                    char peer_id[RAFT_NODE_ID_LEN];
                    memset(peer_id, 0, sizeof(peer_id));
                    memcpy(peer_id, p + 5, id_len);
                    (void)dislmdb_raft_remove_peer(env, peer_id);
                }
            }
        }
        return;
    }

    if (message->header.type == DISLMDB_MESSAGE_SYNC_REQUEST && message->payload) {
        if (actx->started && raft_is_leader(actx->node)) {
            (void)raft_propose(actx->node, message->payload, message->header.payload_size,
                               env->config.consensus.timeout_ms);
        }
        return;
    }
    if (message->header.type != DISLMDB_MESSAGE_ELECTION || !message->payload) {
        return;
    }
    /* Accept election traffic once armed; tick thread only after start. */
    RaftMessage msg;
    if (raft_message_deserialize(message->payload, message->header.payload_size, &msg) != 0) {
        return;
    }
    (void)raft_handle_message(actx->node, &msg);
    raft_message_clear(&msg);
    env->pbft_state.is_primary = raft_is_leader(actx->node);
    raft_leader_id(actx->node, env->pbft_state.primary_id);
}
