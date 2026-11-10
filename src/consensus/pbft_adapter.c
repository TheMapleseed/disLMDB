/**
 * @file pbft_adapter.c
 * @brief Bridge DisLMDB ↔ Enhanced PBFT (Rust-aligned C port)
 */

#include "pbft_adapter.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_network.h"

#define BYTECODE_DBI_NAME "__dislmdb_bytecode__"
#define TXN_MAGIC 0x4454584Eu
#define BCOD_MAGIC 0x42434F44u
#define HELO_MAGIC 0x48454C4Fu /* HELO */

static void *broadcast_thread(void *arg)
{
    DISLMDB_env *env = arg;
    ConsensusCore *core = env->consensus_context;
    int subscriber_id = env->pbft_subscriber_id;

    while (env->consensus_running) {
        uint8_t *data = NULL;
        size_t data_size = 0;
        struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};

        ConsensusError err = (ConsensusError)broadcast_channel_receive(
            core->commit_channel, subscriber_id, &data, &data_size, &timeout);

        if (err == CONSENSUS_OK) {
            int rc = dislmdb_pbft_apply_transaction(env, data, data_size);
            if (rc != DISLMDB_SUCCESS) {
                dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT",
                            "Failed to apply committed transaction: %s",
                            dislmdb_strerror(rc));
            }
            free(data);
        } else if (err != CONSENSUS_ERROR_TIMEOUT) {
            dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT",
                        "Error receiving broadcast: %d", (int)err);
        }
    }
    return NULL;
}

static void outbound_pbft(const PbftMessage *msg, void *user_data)
{
    DISLMDB_env *env = user_data;
    if (!env || !msg) {
        return;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (pbft_message_serialize(msg, &wire, &wire_len) != 0) {
        return;
    }
    DISLMDB_MESSAGE_TYPE dtype;
    switch (msg->type) {
        case MSG_PRE_PREPARE: dtype = DISLMDB_MESSAGE_PREPARE; break; /* closest public enum */
        case MSG_PREPARE: dtype = DISLMDB_MESSAGE_PREPARE; break;
        case MSG_COMMIT: dtype = DISLMDB_MESSAGE_COMMIT; break;
        case MSG_VIEW_CHANGE: dtype = DISLMDB_MESSAGE_ELECTION; break;
        default: dtype = DISLMDB_MESSAGE_CHECKPOINT; break;
    }
    DISLMDB_network_message nm;
    if (dislmdb_network_create_message(&nm, dtype, wire, (uint32_t)wire_len, NULL) == DISLMDB_SUCCESS) {
        strncpy(nm.header.sender_id, msg->from, sizeof(nm.header.sender_id) - 1);
        (void)dislmdb_network_broadcast(env, &nm, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
        dislmdb_network_free_message(&nm);
    }
    free(wire);
}

void dislmdb_convert_consensus_config(const DISLMDB_consensus_config *dislmdb_config,
                                      ConsensusConfig *pbft_config)
{
    if (!dislmdb_config || !pbft_config) {
        return;
    }
    *pbft_config = consensus_config_default();
    uint32_t f = dislmdb_config->fault_tolerance;
    pbft_config->fault_tolerance = f;
    pbft_config->min_nodes = 3u * f + 1u;
    if (pbft_config->min_nodes == 0) {
        pbft_config->min_nodes = 1;
    }
    pbft_config->timeouts.prepare_timeout.tv_sec = dislmdb_config->timeout_ms / 1000;
    pbft_config->timeouts.prepare_timeout.tv_nsec =
        (long)(dislmdb_config->timeout_ms % 1000) * 1000000L;
    pbft_config->timeouts.commit_timeout = pbft_config->timeouts.prepare_timeout;
    pbft_config->timeouts.view_change_timeout.tv_sec =
        dislmdb_config->election_timeout_max_ms / 1000;
    pbft_config->timeouts.view_change_timeout.tv_nsec =
        (long)(dislmdb_config->election_timeout_max_ms % 1000) * 1000000L;
    pbft_config->timeouts.wait_pre_prepare_ms = dislmdb_config->timeout_ms;
    pbft_config->timeouts.prepare_certificate_ms = dislmdb_config->timeout_ms;
    pbft_config->timeouts.commit_certificate_ms = dislmdb_config->timeout_ms;
    pbft_config->timeouts.view_change_resend_ms = dislmdb_config->election_timeout_max_ms;

    uint64_t batch = dislmdb_config->max_batch_size ? dislmdb_config->max_batch_size : 1;
    uint64_t msg = batch * (1024ull * 1024ull);
    if (msg > DISLMDB_MAX_MESSAGE_SIZE) {
        msg = DISLMDB_MAX_MESSAGE_SIZE;
    }
    pbft_config->max_message_size = (size_t)msg;
    /* TV-BLAKE3 keyed MACs verified when a cluster key is installed */
    pbft_config->verify_signatures = true;
    pbft_config->timeouts.enabled = dislmdb_config->enable_liveness;
}

static void on_network_message(const DISLMDB_network_message *message, void *user_data)
{
    dislmdb_pbft_message_handler(message, user_data);
}

int dislmdb_pbft_init(DISLMDB_env *env)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    NodeId *node_id = node_id_create(env->local_node_id);
    if (!node_id) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }

    ConsensusConfig config = consensus_config_default();
    dislmdb_convert_consensus_config(&env->config.consensus, &config);

    /* Replica set: local + known peers. Order is normalized (sorted) so every
     * node computes the same primary for a given view. */
    strncpy(config.replica_ids[0], env->local_node_id, EPDFT_NODE_ID_LEN - 1);
    config.replica_count = 1;
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count && config.replica_count < EPDFT_MAX_REPLICAS; i++) {
        if (strncmp(env->nodes[i].node_id, env->local_node_id, EPDFT_NODE_ID_LEN) == 0) {
            continue;
        }
        /* Skip unresolved seed placeholders — real IDs arrive via HELLO */
        if (strncmp(env->nodes[i].node_id, "seed-", 5) == 0) {
            continue;
        }
        strncpy(config.replica_ids[config.replica_count], env->nodes[i].node_id,
                EPDFT_NODE_ID_LEN - 1);
        config.replica_count++;
    }
    pthread_mutex_unlock(&env->nodes_mutex);

    if (config.replica_count < config.min_nodes) {
        /* Solo / under-provisioned: force f=0 until peers join via HELLO */
        config.fault_tolerance = 0;
        config.min_nodes = 1;
    }

    SecurityConfig sec_config = security_config_default();
    SecurityManager *security = security_manager_create(&sec_config);
    if (!security) {
        node_id_destroy(node_id);
        return DISLMDB_ERR_MEMORY_ERROR;
    }

    ConsensusCore *core = consensus_core_create(node_id, &config, security);
    if (!core) {
        security_manager_destroy(security);
        node_id_destroy(node_id);
        return DISLMDB_ERR_MEMORY_ERROR;
    }

    consensus_core_set_outbound(core, outbound_pbft, env);
    env->consensus_context = core;
    consensus_core_normalize_replicas(core);
    if (env->has_cluster_key) {
        security_manager_set_cluster_key(core->security, env->cluster_key);
    }

    int sub = broadcast_channel_subscribe(core->commit_channel);
    if (sub < 0) {
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        return DISLMDB_ERR_CONSENSUS_FAILED;
    }
    env->pbft_subscriber_id = sub;
    env->pbft_state.is_primary = consensus_core_is_primary(core);
    env->pbft_state.f = config.fault_tolerance;
    env->pbft_state.node_count = config.replica_count;
    env->pbft_state.view = consensus_core_view(core);
    env->pbft_state.sequence = (uint32_t)consensus_core_last_committed(core);
    strncpy(env->pbft_state.primary_id, env->local_node_id,
            sizeof(env->pbft_state.primary_id) - 1);

    int rc = dislmdb_network_set_message_callback(env, on_network_message, env);
    if (rc != DISLMDB_SUCCESS) {
        broadcast_channel_unsubscribe(core->commit_channel, sub);
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        return rc;
    }

    env->consensus_running = true;
    if (pthread_create(&env->consensus_thread, NULL, broadcast_thread, env) != 0) {
        broadcast_channel_unsubscribe(core->commit_channel, sub);
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        env->consensus_running = false;
        return DISLMDB_ERR_THREAD_ERROR;
    }

    if (env->config.consensus.enable_liveness) {
        consensus_core_start_liveness(core);
    }
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_load(env);
    }

    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT",
                "Enhanced PBFT (TV-BLAKE3) initialized f=%u n=%u liveness=%d",
                config.fault_tolerance, config.replica_count,
                (int)env->config.consensus.enable_liveness);
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_shutdown(DISLMDB_env *env)
{
    if (!env || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    ConsensusCore *core = env->consensus_context;
    env->consensus_running = false;
    pthread_join(env->consensus_thread, NULL);
    if (env->pbft_subscriber_id >= 0) {
        broadcast_channel_unsubscribe(core->commit_channel, env->pbft_subscriber_id);
        env->pbft_subscriber_id = -1;
    }
    consensus_core_destroy(core);
    env->consensus_context = NULL;
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_serialize_transaction(DISLMDB_txn *txn, uint8_t **data, size_t *size)
{
    if (!txn || !data || !size) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    /* Prefer full operation log when puts/dels were recorded via dislmdb_put/del */
    if (txn->pending_ops && txn->operation_count > 0) {
        return dislmdb_serialize_pending_ops(txn, data, size);
    }
    /* Fallback marker envelope for empty / legacy write txns */
    size_t total = 4 + 4 + 4 + 2 + 2 + 8 + 64 + DISLMDB_SHA256_DIGEST_LENGTH;
    uint8_t *buf = calloc(1, total);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, TXN_MAGIC); o += 4;
    dislmdb_write_u32(buf + o, 1); o += 4;
    dislmdb_write_u32(buf + o, txn->operation_count); o += 4;
    buf[o++] = txn->is_write_txn ? 1 : 0;
    buf[o++] = txn->is_distributed ? 1 : 0;
    buf[o++] = 0;
    buf[o++] = 0;
    dislmdb_write_u64(buf + o, txn->start_time); o += 8;
    memcpy(buf + o, txn->txn_id, 64); o += 64;
    uint8_t digest[32];
    dislmdb_crypto_sha256(txn->txn_id, strnlen(txn->txn_id, sizeof(txn->txn_id)), digest);
    memcpy(buf + o, digest, 32);
    o += 32;
    *data = buf;
    *size = o;
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_apply_transaction(DISLMDB_env *env, const uint8_t *data, size_t size)
{
    if (!env || !data) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    if (size >= 12 && dislmdb_read_u32(data) == DISLMDB_OPLOG_MAGIC) {
        int rc = dislmdb_apply_oplog_payload(env, data, size);
        if (rc == DISLMDB_SUCCESS) {
            env->consensus_commits++;
            (void)dislmdb_persist_save(env);
        }
        return rc;
    }

    if (size >= 12 && dislmdb_read_u32(data) == DISLMDB_SMAP_MAGIC) {
        int rc = dislmdb_shard_map_apply_payload(env, data, size);
        if (rc == DISLMDB_SUCCESS) {
            env->consensus_commits++;
        }
        return rc;
    }

    if (size >= 16 && dislmdb_read_u32(data) == BCOD_MAGIC) {
        size_t o = 0;
        (void)dislmdb_read_u32(data + o); o += 4;
        uint32_t version = dislmdb_read_u32(data + o); o += 4;
        if (version != 1) {
            return DISLMDB_ERR_VERSION_MISMATCH;
        }
        uint32_t id_len = dislmdb_read_u32(data + o); o += 4;
        if (id_len == 0 || id_len > 128 || o + id_len + 4 + 8 > size) {
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        char bytecode_id[129];
        memcpy(bytecode_id, data + o, id_len);
        bytecode_id[id_len] = '\0';
        o += id_len;
        uint32_t options = dislmdb_read_u32(data + o); o += 4;
        (void)dislmdb_read_u64(data + o); o += 8;
        const uint8_t *bytecode = data + o;
        size_t bytecode_size = size - o;

        MDB_txn *txn = NULL;
        int rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
        if (rc != 0) {
            return rc;
        }
        MDB_dbi dbi;
        rc = mdb_dbi_open(txn, BYTECODE_DBI_NAME, MDB_CREATE, &dbi);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
        size_t stored_size = 4 + bytecode_size;
        uint8_t *stored = malloc(stored_size);
        if (!stored) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        dislmdb_write_u32(stored, options);
        memcpy(stored + 4, bytecode, bytecode_size);
        MDB_val key = {.mv_size = id_len, .mv_data = bytecode_id};
        MDB_val val = {.mv_size = stored_size, .mv_data = stored};
        rc = mdb_put(txn, dbi, &key, &val, 0);
        free(stored);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
        rc = mdb_txn_commit(txn);
        if (rc != 0) {
            return rc;
        }
        env->consensus_commits++;
        return DISLMDB_SUCCESS;
    }

    if (size >= 8 && dislmdb_read_u32(data) == TXN_MAGIC) {
        return DISLMDB_SUCCESS;
    }
    return DISLMDB_ERR_MESSAGE_VALIDATION;
}

static int wait_committed_after(ConsensusCore *core, uint64_t before, uint32_t timeout_ms)
{
    uint64_t start = (uint64_t)time(NULL) * 1000ull;
    while (consensus_core_last_committed(core) <= before) {
        uint64_t now = (uint64_t)time(NULL) * 1000ull;
        if (now - start > timeout_ms) {
            return DISLMDB_ERR_CONSENSUS_TIMEOUT;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return DISLMDB_SUCCESS;
}

typedef struct {
    DISLMDB_env *env;
    uint8_t *data;
    size_t size;
} forwarded_propose_job;

static void *forwarded_propose_thread(void *arg)
{
    forwarded_propose_job *job = arg;
    if (job && job->env && job->env->consensus_context) {
        ConsensusError err = consensus_core_propose(job->env->consensus_context,
                                                   job->data, job->size);
        if (err != CONSENSUS_OK) {
            dislmdb_log(job->env, DISLMDB_LOG_WARNING, "PBFT",
                        "Forwarded write propose failed err=%d", (int)err);
        }
    }
    if (job) {
        free(job->data);
        free(job);
    }
    return NULL;
}

static int forward_oplog_to_primary(DISLMDB_env *env, const uint8_t *data, size_t size)
{
    ConsensusCore *core = env->consensus_context;
    char primary[EPDFT_NODE_ID_LEN];
    consensus_core_primary_id(core, primary);
    if (primary[0] == '\0' ||
        strncmp(primary, env->local_node_id, EPDFT_NODE_ID_LEN) == 0) {
        return DISLMDB_ERR_NO_LEADER;
    }
    uint64_t before = consensus_core_last_committed(core);
    DISLMDB_network_message nm;
    int rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_SYNC_REQUEST,
                                            data, (uint32_t)size, primary);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);
    rc = dislmdb_network_send(env, &nm, primary, env->config.consensus.timeout_ms);
    dislmdb_network_free_message(&nm);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    return wait_committed_after(core, before, env->config.consensus.timeout_ms);
}

int dislmdb_pbft_propose_transaction(DISLMDB_txn *txn)
{
    if (!txn || !txn->env || !txn->env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!txn->is_write_txn) {
        return DISLMDB_SUCCESS;
    }
    DISLMDB_env *env = txn->env;
    ConsensusCore *core = env->consensus_context;

    uint8_t *txn_data = NULL;
    size_t txn_size = 0;
    int rc = dislmdb_pbft_serialize_transaction(txn, &txn_data, &txn_size);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }

    ConsensusError err = consensus_core_propose(core, txn_data, txn_size);
    if (err == CONSENSUS_ERROR_NOT_LEADER) {
        /* Forward oplog to the current primary and wait for cluster commit */
        rc = forward_oplog_to_primary(env, txn_data, txn_size);
        if (rc != DISLMDB_SUCCESS) {
            free(txn_data);
            return rc;
        }
    } else if (err != CONSENSUS_OK) {
        free(txn_data);
        switch (err) {
            case CONSENSUS_ERROR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case CONSENSUS_ERROR_MEMORY_ERROR: return DISLMDB_ERR_MEMORY_ERROR;
            case CONSENSUS_ERROR_MESSAGE_TOO_LARGE: return DISLMDB_ERR_BUFFER_OVERFLOW;
            default: return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }

    /*
     * Cluster has a commit certificate. Drop the staging LMDB write txn first
     * (LMDB allows only one writer) then apply the oplog so durability matches
     * followers. Apply is idempotent if the commit-channel worker also runs.
     */
    if (txn->mdb_txn) {
        mdb_txn_abort(txn->mdb_txn);
        txn->mdb_txn = NULL;
    }
    if (txn_size >= 12 && dislmdb_read_u32(txn_data) == DISLMDB_OPLOG_MAGIC) {
        rc = dislmdb_pbft_apply_transaction(env, txn_data, txn_size);
        if (rc != DISLMDB_SUCCESS) {
            free(txn_data);
            return rc;
        }
    }
    free(txn_data);

    env->pbft_state.sequence = (uint32_t)consensus_core_last_committed(core);
    env->pbft_state.view = consensus_core_view(core);
    env->pbft_state.is_primary = consensus_core_is_primary(core);
    consensus_core_primary_id(core, env->pbft_state.primary_id);

    /* Track committed txn for get_operation_status */
    DISLMDB_op_id oid;
    if (dislmdb_consensus_generate_op_id(env, &oid) == DISLMDB_SUCCESS) {
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
    return DISLMDB_SUCCESS;
}

static void replace_seed_node_id(DISLMDB_env *env, const char *real_id,
                                 const char *hostname, uint16_t port)
{
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strncmp(env->nodes[i].node_id, "seed-", 5) != 0) {
            continue;
        }
        bool same_host = (hostname && hostname[0] != '\0' &&
                          strcmp(env->nodes[i].hostname, hostname) == 0);
        bool same_port = (port != 0 && env->nodes[i].port == port);
        if (same_host || same_port || env->nodes[i].port == port) {
            strncpy(env->nodes[i].node_id, real_id, sizeof(env->nodes[i].node_id) - 1);
            env->nodes[i].node_id[sizeof(env->nodes[i].node_id) - 1] = '\0';
            if (hostname && hostname[0] != '\0') {
                strncpy(env->nodes[i].hostname, hostname, sizeof(env->nodes[i].hostname) - 1);
            }
            if (port != 0) {
                env->nodes[i].port = port;
            }
            break;
        }
    }
    pthread_mutex_unlock(&env->nodes_mutex);
}

void dislmdb_pbft_handle_hello(DISLMDB_env *env, const DISLMDB_network_message *message)
{
    if (!env || !message || !message->payload || message->header.payload_size < 4 + 2 + 1) {
        return;
    }
    const uint8_t *p = message->payload;
    if (dislmdb_read_u32(p) != HELO_MAGIC) {
        return;
    }
    uint16_t peer_port = dislmdb_read_u16(p + 4);
    uint8_t id_len = p[6];
    if ((size_t)7 + id_len > message->header.payload_size || id_len == 0 || id_len >= 64) {
        return;
    }
    char peer_id[64];
    memset(peer_id, 0, sizeof(peer_id));
    memcpy(peer_id, p + 7, id_len);

    /* Ignore self-advertisements */
    if (strncmp(peer_id, env->local_node_id, 63) == 0) {
        return;
    }

    DISLMDB_node_addr addr;
    memset(&addr, 0, sizeof(addr));
    strncpy(addr.node_id, peer_id, sizeof(addr.node_id) - 1);
    strncpy(addr.hostname, "127.0.0.1", sizeof(addr.hostname) - 1);
    addr.port = peer_port;

    /* Prefer hostname already known on the wire connection */
    DISLMDB_connection_info ci;
    if (message->header.sender_id[0] != '\0' &&
        dislmdb_network_get_connection_info(env, message->header.sender_id, &ci) == DISLMDB_SUCCESS) {
        if (ci.hostname[0] != '\0') {
            strncpy(addr.hostname, ci.hostname, sizeof(addr.hostname) - 1);
        }
    } else if (dislmdb_network_get_connection_info(env, peer_id, &ci) == DISLMDB_SUCCESS) {
        if (ci.hostname[0] != '\0') {
            strncpy(addr.hostname, ci.hostname, sizeof(addr.hostname) - 1);
        }
    }

    bool already_known = false;
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strncmp(env->nodes[i].node_id, peer_id, 63) == 0) {
            already_known = true;
            break;
        }
    }
    pthread_mutex_unlock(&env->nodes_mutex);

    replace_seed_node_id(env, peer_id, addr.hostname, peer_port);
    (void)dislmdb_network_bind_peer_id(env, message->header.sender_id, peer_id, peer_port);
    (void)dislmdb_add_node_internal(env, &addr);

    /* consensus_context is ConsensusCore* only under PBFT */
    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        (void)consensus_core_add_replica(env->consensus_context, peer_id);
        consensus_core_recompute_faults(env->consensus_context,
                                       env->config.consensus.fault_tolerance);
    }
    dislmdb_log(env, DISLMDB_LOG_INFO, "HELLO",
                "Learned peer id=%s port=%u", peer_id, (unsigned)peer_port);

    /* One-shot reply so the peer can drop its seed-* label (avoid HELLO loops) */
    if (!already_known) {
        (void)dislmdb_pbft_send_hello(env, peer_id);
    }
}

int dislmdb_pbft_send_hello(DISLMDB_env *env, const char *target_node_id)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t id_len = strnlen(env->local_node_id, 63);
    uint8_t buf[4 + 2 + 1 + 64];
    size_t o = 0;
    dislmdb_write_u32(buf + o, HELO_MAGIC); o += 4;
    dislmdb_write_u16(buf + o, env->config.network.local_port
                                    ? env->config.network.local_port
                                    : DISLMDB_DEFAULT_PORT);
    o += 2;
    buf[o++] = (uint8_t)id_len;
    memcpy(buf + o, env->local_node_id, id_len);
    o += id_len;

    DISLMDB_network_message nm;
    const char *target = (target_node_id && target_node_id[0] != '\0') ? target_node_id : NULL;
    int rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_JOIN, buf, (uint32_t)o, target);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);

    if (!target) {
        rc = dislmdb_network_broadcast(env, &nm, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    } else {
        rc = dislmdb_network_send(env, &nm, target, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
        if (rc != DISLMDB_SUCCESS) {
            rc = dislmdb_network_broadcast(env, &nm, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
        }
    }
    dislmdb_network_free_message(&nm);
    return rc;
}

int dislmdb_pbft_send_leave(DISLMDB_env *env, const char *node_id)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    const char *id = (node_id && node_id[0] != '\0') ? node_id : env->local_node_id;
    size_t id_len = strnlen(id, 63);
    if (id_len == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uint8_t buf[4 + 1 + 64];
    size_t o = 0;
    dislmdb_write_u32(buf + o, DISLMDB_LEAV_MAGIC); o += 4;
    buf[o++] = (uint8_t)id_len;
    memcpy(buf + o, id, id_len); o += id_len;

    DISLMDB_network_message nm;
    int rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_LEAVE, buf, (uint32_t)o, NULL);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);
    rc = dislmdb_network_broadcast(env, &nm, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    dislmdb_network_free_message(&nm);
    return rc;
}

void dislmdb_pbft_handle_leave(DISLMDB_env *env, const DISLMDB_network_message *message)
{
    if (!env || !message || !message->payload || message->header.payload_size < 5) {
        return;
    }
    const uint8_t *p = message->payload;
    if (dislmdb_read_u32(p) != DISLMDB_LEAV_MAGIC) {
        return;
    }
    uint8_t id_len = p[4];
    if ((size_t)5 + id_len > message->header.payload_size || id_len == 0 || id_len >= 64) {
        return;
    }
    char peer_id[64];
    memset(peer_id, 0, sizeof(peer_id));
    memcpy(peer_id, p + 5, id_len);
    if (strncmp(peer_id, env->local_node_id, 63) == 0) {
        return;
    }

    dislmdb_log(env, DISLMDB_LOG_INFO, "LEAVE", "Peer leaving id=%s", peer_id);
    (void)dislmdb_update_node_state(env, peer_id, DISLMDB_NODE_STATE_LEAVING);
    (void)dislmdb_network_disconnect(env, peer_id);

    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        (void)consensus_core_remove_replica(env->consensus_context, peer_id);
        consensus_core_recompute_faults(env->consensus_context,
                                       env->config.consensus.fault_tolerance);
    }

    uint32_t index = 0;
    if (dislmdb_find_node(env, peer_id, &index) == DISLMDB_SUCCESS) {
        pthread_mutex_lock(&env->nodes_mutex);
        for (uint32_t i = index; i + 1 < env->node_count; i++) {
            env->nodes[i] = env->nodes[i + 1];
            env->node_states[i] = env->node_states[i + 1];
        }
        if (env->node_count > 0) {
            env->node_count--;
        }
        pthread_mutex_unlock(&env->nodes_mutex);
        (void)dislmdb_persist_save(env);
    }
}

void dislmdb_pbft_message_handler(const DISLMDB_network_message *message, void *user_data)
{
    DISLMDB_env *env = user_data;
    if (!env || !message) {
        return;
    }

    /* Membership HELLO / LEAVE */
    if (message->header.type == DISLMDB_MESSAGE_JOIN) {
        dislmdb_pbft_handle_hello(env, message);
        return;
    }
    if (message->header.type == DISLMDB_MESSAGE_LEAVE) {
        dislmdb_pbft_handle_leave(env, message);
        return;
    }

    /* Client write forwarded to primary — never block the network thread */
    if (message->header.type == DISLMDB_MESSAGE_SYNC_REQUEST &&
        env->consensus_context && message->payload) {
        ConsensusCore *core = env->consensus_context;
        if (consensus_core_is_primary(core)) {
            forwarded_propose_job *job = malloc(sizeof(*job));
            if (!job) {
                return;
            }
            job->env = env;
            job->size = message->header.payload_size;
            job->data = malloc(job->size ? job->size : 1);
            if (!job->data) {
                free(job);
                return;
            }
            memcpy(job->data, message->payload, job->size);
            pthread_t th;
            if (pthread_create(&th, NULL, forwarded_propose_thread, job) != 0) {
                free(job->data);
                free(job);
                return;
            }
            pthread_detach(th);
        }
        return;
    }

    if (!env->consensus_context || !message->payload) {
        return;
    }
    ConsensusCore *core = env->consensus_context;
    PbftMessage msg;
    if (pbft_message_deserialize(message->payload, message->header.payload_size, &msg) != 0) {
        return;
    }
    if (message->header.sender_id[0] != '\0') {
        if (msg.from[0] != '\0' &&
            strncmp(msg.from, message->header.sender_id, EPDFT_NODE_ID_LEN) != 0) {
            dislmdb_log(env, DISLMDB_LOG_WARNING, "PBFT",
                        "Dropping PBFT msg: wire from=%s != header sender=%s",
                        msg.from, message->header.sender_id);
            pbft_message_clear(&msg);
            return;
        }
        strncpy(msg.from, message->header.sender_id, sizeof(msg.from) - 1);
        msg.from[sizeof(msg.from) - 1] = '\0';
    }
    ConsensusError err = consensus_core_handle_pbft(core, &msg);
    if (err != CONSENSUS_OK) {
        dislmdb_log(env, DISLMDB_LOG_WARNING, "PBFT",
                    "Rejected inbound PBFT message from=%s err=%d",
                    message->header.sender_id, (int)err);
    }
    pbft_message_clear(&msg);
}

int dislmdb_pbft_store_bytecode(DISLMDB_env *env,
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

    ConsensusCore *core = env->consensus_context;
    size_t id_len = strnlen(bytecode_id, 129);
    if (id_len == 0 || id_len > 128) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    size_t meta = 4 + 4 + 4 + id_len + 4 + 8;
    if (meta + bytecode_size > core->config.max_message_size) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    uint8_t *buffer = malloc(meta + bytecode_size);
    if (!buffer) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buffer + o, BCOD_MAGIC); o += 4;
    dislmdb_write_u32(buffer + o, 1); o += 4;
    dislmdb_write_u32(buffer + o, (uint32_t)id_len); o += 4;
    memcpy(buffer + o, bytecode_id, id_len); o += id_len;
    dislmdb_write_u32(buffer + o, options); o += 4;
    dislmdb_write_u64(buffer + o, (uint64_t)time(NULL)); o += 8;
    memcpy(buffer + o, bytecode, bytecode_size);

    /* propose blocks until commit certificate; apply via commit broadcast.
     * Also apply locally so the caller observes durable storage immediately
     * (replay on the apply thread is idempotent). */
    ConsensusError err = consensus_core_propose(core, buffer, meta + bytecode_size);
    if (err != CONSENSUS_OK) {
        free(buffer);
        switch (err) {
            case CONSENSUS_ERROR_NOT_LEADER: return DISLMDB_ERR_NO_LEADER;
            case CONSENSUS_ERROR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case CONSENSUS_ERROR_MEMORY_ERROR: return DISLMDB_ERR_MEMORY_ERROR;
            default: return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }
    int arc = dislmdb_pbft_apply_transaction(env, buffer, meta + bytecode_size);
    free(buffer);
    return arc;
}
