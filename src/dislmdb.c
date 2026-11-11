/**
 * @file dislmdb.c
 * @brief Implementation of the Distributed LMDB core API
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_network.h"
#include "dislmdb_quic.h"
#include "consensus/pbft_adapter.h"
#include "consensus/raft_adapter.h"
#include "../Enhanced-PBFT-mechanism/epdft.h"

#define DISLMDB_VERSION_STRING "DisLMDB 0.1.0"
#define DISLMDB_DEFAULT_OPLOG_SIZE 1000
#define BYTECODE_DBI_NAME "__dislmdb_bytecode__"

extern const char *dislmdb_error_string(int err);

int dislmdb_bytecode_pack(unsigned int options,
                          const uint8_t *src,
                          size_t src_len,
                          uint8_t **out,
                          size_t *out_len)
{
    if (!src || src_len == 0 || !out || !out_len) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (options & DISLMDB_BYTECODE_COMPRESS) {
        return DISLMDB_ERR_NOT_IMPLEMENTED;
    }
    size_t hdr = 4;
    if (options & DISLMDB_BYTECODE_VERIFY) {
        hdr += DISLMDB_SHA256_DIGEST_LENGTH;
    }
    uint8_t *buf = malloc(hdr + src_len);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(buf, options);
    size_t o = 4;
    if (options & DISLMDB_BYTECODE_VERIFY) {
        if (dislmdb_crypto_sha256(src, src_len, buf + o) != 0) {
            free(buf);
            return DISLMDB_ERR_AUTH_FAILED;
        }
        o += DISLMDB_SHA256_DIGEST_LENGTH;
    }
    memcpy(buf + o, src, src_len);
    *out = buf;
    *out_len = hdr + src_len;
    return DISLMDB_SUCCESS;
}

int dislmdb_bytecode_unpack(const uint8_t *stored,
                            size_t stored_len,
                            unsigned int *options_out,
                            const uint8_t **data_out,
                            size_t *data_len_out)
{
    if (!stored || stored_len < 4 || !options_out || !data_out || !data_len_out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    unsigned int opts = dislmdb_read_u32(stored);
    size_t o = 4;
    if (opts & DISLMDB_BYTECODE_VERIFY) {
        if (stored_len < 4 + DISLMDB_SHA256_DIGEST_LENGTH) {
            return DISLMDB_ERR_DATA_CORRUPTION;
        }
        const uint8_t *expect = stored + o;
        o += DISLMDB_SHA256_DIGEST_LENGTH;
        const uint8_t *payload = stored + o;
        size_t plen = stored_len - o;
        uint8_t got[DISLMDB_SHA256_DIGEST_LENGTH];
        if (dislmdb_crypto_sha256(payload, plen, got) != 0) {
            return DISLMDB_ERR_AUTH_FAILED;
        }
        if (memcmp(expect, got, DISLMDB_SHA256_DIGEST_LENGTH) != 0) {
            return DISLMDB_ERR_DATA_CORRUPTION;
        }
        *options_out = opts;
        *data_out = payload;
        *data_len_out = plen;
        return DISLMDB_SUCCESS;
    }
    *options_out = opts;
    *data_out = stored + 4;
    *data_len_out = stored_len - 4;
    return DISLMDB_SUCCESS;
}

static const DISLMDB_env_config default_env_config = {
    .path = NULL,
    .lmdb_flags = 0,
    .mode = 0644,
    .mapsize = 10485760,
    .maxreaders = 126,
    .maxdbs = 0,
    .network = {
        .nodes = NULL,
        .node_count = 0,
        .local_port = 9876,
        .is_seed_node = false,
        .seed_nodes = {{0}},
        .seed_node_count = 0,
        .enable_message_auth = true,
        .cluster_key = {0},
        .has_cluster_key = false,
        .enable_payload_encryption = true,
        .enable_tls = false,
        .enable_mtls = false,
        .transport = DISLMDB_TRANSPORT_TCP,
        .tls_cert_path = {0},
        .tls_key_path = {0},
        .tls_ca_path = {0}
    },
    .consensus = {
        .mechanism = DISLMDB_CONSENSUS_PBFT,
        .timeout_ms = 5000,
        .heartbeat_interval_ms = 1000,
        .election_timeout_min_ms = 3000,
        .election_timeout_max_ms = 6000,
        .max_batch_size = 100,
        .checkpoint_interval = 1000,
        .fault_tolerance = 0,
        .enable_liveness = true,
        .persist_state = true,
        .raft_wal_sync_every = 1,
        .persist_cluster_key = false,
        .enable_voting = true
    },
    .read_only_node = false,
    .sync_interval_ms = 60000,
    .max_sync_batch_size = 1000,
    .node_name = "DisLMDB Node",
    .region = {0},
    .locality = {0},
    .topology_mode = DISLMDB_TOPO_MIRROR,
    .rtt_budget_ms = 0,
    .region_key = {0},
    .has_region_key = false,
    .cross_region_key = {0},
    .has_cross_region_key = false,
    .max_peers = 0, /* unlimited */
    .enable_auto_forward = true,
    .mirror_conflict_policy = DISLMDB_MIRROR_LAST_WRITE,
    .mirror_primary_region = {0}
};

const char *dislmdb_version(int *major, int *minor, int *patch)
{
    if (major) *major = DISLMDB_VERSION_MAJOR;
    if (minor) *minor = DISLMDB_VERSION_MINOR;
    if (patch) *patch = DISLMDB_VERSION_PATCH;
    return DISLMDB_VERSION_STRING;
}

const char *dislmdb_strerror(int err)
{
    if (err >= DISLMDB_ERR_BASE || err == DISLMDB_SUCCESS) {
        const char *s = dislmdb_error_string(err);
        if (s) {
            return s;
        }
    }
    return mdb_strerror(err);
}

int dislmdb_env_config_init(DISLMDB_env_config *config)
{
    if (!config) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    memcpy(config, &default_env_config, sizeof(DISLMDB_env_config));
    return DISLMDB_SUCCESS;
}

uint64_t dislmdb_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ull + (uint64_t)tv.tv_usec / 1000ull;
}

int dislmdb_generate_node_id(char *node_id)
{
    if (!node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, node_id);
    return DISLMDB_SUCCESS;
}

int dislmdb_sha256(const void *data, size_t size, uint8_t *digest)
{
    return dislmdb_crypto_sha256(data, size, digest);
}

void dislmdb_log(DISLMDB_env *env, DISLMDB_LOG_LEVEL level,
                 const char *module, const char *format, ...)
{
    if (!env || !module || !format) {
        return;
    }

    va_list args;
    char message[DISLMDB_MAX_LOG_LENGTH];
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    pthread_mutex_lock(&env->log_mutex);
    uint32_t index;
    if (env->log_count < DISLMDB_MAX_LOG_MESSAGES) {
        index = env->log_count++;
    } else {
        index = env->log_head;
        env->log_head = (env->log_head + 1) % DISLMDB_MAX_LOG_MESSAGES;
    }
    DISLMDB_log_message *log_msg = &env->log_messages[index];
    log_msg->level = level;
    log_msg->timestamp = dislmdb_get_time_ms();
    strncpy(log_msg->module, module, sizeof(log_msg->module) - 1);
    log_msg->module[sizeof(log_msg->module) - 1] = '\0';
    strncpy(log_msg->message, message, sizeof(log_msg->message) - 1);
    log_msg->message[sizeof(log_msg->message) - 1] = '\0';
    pthread_mutex_unlock(&env->log_mutex);

    if (level >= DISLMDB_LOG_ERROR) {
        fprintf(stderr, "[%s] %s: %s\n", module,
                level == DISLMDB_LOG_ERROR ? "ERROR" : "FATAL", message);
    }
}

void dislmdb_set_error(DISLMDB_env *env, int code, const char *format, ...)
{
    if (!env || !format) {
        return;
    }
    va_list args;
    va_start(args, format);
    vsnprintf(env->last_error, sizeof(env->last_error), format, args);
    va_end(args);
    env->last_error_code = code;
    dislmdb_log(env, DISLMDB_LOG_ERROR, "ERROR", "%s (code %d)",
                env->last_error, code);
}

static void destroy_mutexes(DISLMDB_env *e)
{
    pthread_mutex_destroy(&e->txn_mutex);
    pthread_mutex_destroy(&e->oplog_mutex);
    pthread_mutex_destroy(&e->nodes_mutex);
    pthread_mutex_destroy(&e->status_mutex);
    pthread_mutex_destroy(&e->log_mutex);
    pthread_mutex_destroy(&e->shard_mutex);
    pthread_mutex_destroy(&e->forward_mutex);
    pthread_cond_destroy(&e->forward_cv);
}

int dislmdb_env_create(DISLMDB_env **env)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    DISLMDB_env *e = calloc(1, sizeof(DISLMDB_env));
    if (!e) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    e->magic = DISLMDB_MAGIC;

    int rc = mdb_env_create(&e->mdb_env);
    if (rc != 0) {
        free(e);
        return rc;
    }

    if (pthread_mutex_init(&e->txn_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->oplog_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->nodes_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->status_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->log_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->shard_mutex, NULL) != 0 ||
        pthread_mutex_init(&e->forward_mutex, NULL) != 0 ||
        pthread_cond_init(&e->forward_cv, NULL) != 0) {
        mdb_env_close(e->mdb_env);
        free(e);
        return DISLMDB_ERR_THREAD_ERROR;
    }

    e->log_messages = calloc(DISLMDB_MAX_LOG_MESSAGES, sizeof(DISLMDB_log_message));
    if (!e->log_messages) {
        destroy_mutexes(e);
        mdb_env_close(e->mdb_env);
        free(e);
        return DISLMDB_ERR_MEMORY_ERROR;
    }

    e->oplog = calloc(DISLMDB_DEFAULT_OPLOG_SIZE, sizeof(DISLMDB_operation_log_entry));
    if (!e->oplog) {
        free(e->log_messages);
        destroy_mutexes(e);
        mdb_env_close(e->mdb_env);
        free(e);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    e->oplog_size = DISLMDB_DEFAULT_OPLOG_SIZE;

    dislmdb_generate_node_id(e->local_node_id);
    e->pbft_subscriber_id = -1;
    e->start_time = dislmdb_get_time_ms();
    dislmdb_log(e, DISLMDB_LOG_INFO, "ENV", "Created environment with node ID %s",
                e->local_node_id);

    *env = e;
    return DISLMDB_SUCCESS;
}

static void free_config_nodes(DISLMDB_env *env)
{
    free(env->config.network.nodes);
    env->config.network.nodes = NULL;
    env->config.network.node_count = 0;
}

static int deep_copy_config(DISLMDB_env *env, const DISLMDB_env_config *config)
{
    env->config = *config;
    env->config.network.nodes = NULL;
    env->config.network.node_count = 0;

    if (config->network.node_count > 0) {
        if (config->max_peers != 0 &&
            config->network.node_count > config->max_peers) {
            return DISLMDB_ERR_MAX_NODES;
        }
        if (!config->network.nodes) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        env->config.network.nodes = calloc(config->network.node_count,
                                           sizeof(DISLMDB_node_addr));
        if (!env->config.network.nodes) {
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(env->config.network.nodes, config->network.nodes,
               config->network.node_count * sizeof(DISLMDB_node_addr));
        env->config.network.node_count = config->network.node_count;
    }
    return DISLMDB_SUCCESS;
}

static void env_open_cleanup(DISLMDB_env *env, bool close_mdb, bool stop_net, bool stop_cons)
{
    if (stop_cons) {
        if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
            if (env->consensus_context) {
                dislmdb_pbft_shutdown(env);
            }
        } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
            if (env->consensus_context) {
                dislmdb_raft_shutdown(env);
            }
        } else if (env->consensus_context) {
            dislmdb_consensus_shutdown(env);
        }
    }
    if (stop_net && env->network_context) {
        dislmdb_network_shutdown(env);
    }
    free(env->nodes);
    env->nodes = NULL;
    free(env->node_states);
    env->node_states = NULL;
    env->node_count = 0;
    free_config_nodes(env);
    if (close_mdb && env->mdb_env) {
        mdb_env_close(env->mdb_env);
        env->mdb_env = NULL;
        env->lmdb_opened = false;
    }
}

static int env_parse_bool(const char *s, bool *out)
{
    if (!s || !out) {
        return -1;
    }
    if (strcmp(s, "0") == 0 || strcasecmp(s, "off") == 0 ||
        strcasecmp(s, "false") == 0 || strcasecmp(s, "no") == 0) {
        *out = false;
        return 0;
    }
    if (strcmp(s, "1") == 0 || strcasecmp(s, "on") == 0 ||
        strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0) {
        *out = true;
        return 0;
    }
    return -1;
}

/** Fill 32-byte key from hex (64 chars) or raw bytes (padded/truncated). */
static int env_parse_key32(const char *s, uint8_t out[32])
{
    if (!s || !out) {
        return -1;
    }
    size_t n = strlen(s);
    memset(out, 0, 32);
    if (n == 64) {
        for (size_t i = 0; i < 32; i++) {
            unsigned int b = 0;
            if (sscanf(s + i * 2, "%2x", &b) != 1) {
                return -1;
            }
            out[i] = (uint8_t)b;
        }
        return 0;
    }
    if (n == 0) {
        return -1;
    }
    memcpy(out, s, n < 32 ? n : 32);
    return 0;
}

/**
 * Overlay deployment knobs from the process environment (never required).
 * Secrets/region/voting for large-cluster topology — see TODO.md Phase C.
 */
static void apply_environ_overrides(DISLMDB_env *env)
{
    bool b;
    const char *voting = getenv("DISLMDB_VOTING");
    if (voting && env_parse_bool(voting, &b) == 0) {
        env->config.consensus.enable_voting = b;
    }

    const char *region = getenv("DISLMDB_REGION");
    if (region && region[0] != '\0') {
        strncpy(env->config.region, region, sizeof(env->config.region) - 1);
        env->config.region[sizeof(env->config.region) - 1] = '\0';
    }
    const char *locality = getenv("DISLMDB_LOCALITY");
    if (locality && locality[0] != '\0') {
        strncpy(env->config.locality, locality, sizeof(env->config.locality) - 1);
        env->config.locality[sizeof(env->config.locality) - 1] = '\0';
    }

    const char *mode = getenv("DISLMDB_TOPOLOGY_MODE");
    if (mode && mode[0] != '\0') {
        if (strcasecmp(mode, "mirror") == 0) {
            env->config.topology_mode = DISLMDB_TOPO_MIRROR;
        } else if (strcasecmp(mode, "shard") == 0) {
            env->config.topology_mode = DISLMDB_TOPO_SHARD;
        } else if (strcasecmp(mode, "hybrid") == 0) {
            env->config.topology_mode = DISLMDB_TOPO_HYBRID;
        }
    }

    const char *mcp = getenv("DISLMDB_MIRROR_CONFLICT");
    if (mcp && mcp[0] != '\0') {
        if (strcasecmp(mcp, "last_write") == 0 || strcasecmp(mcp, "last-write") == 0) {
            env->config.mirror_conflict_policy = DISLMDB_MIRROR_LAST_WRITE;
        } else if (strcasecmp(mcp, "region_priority") == 0 ||
                   strcasecmp(mcp, "region-priority") == 0) {
            env->config.mirror_conflict_policy = DISLMDB_MIRROR_REGION_PRIORITY;
        }
    }
    const char *mpr = getenv("DISLMDB_MIRROR_PRIMARY_REGION");
    if (mpr && mpr[0] != '\0') {
        strncpy(env->config.mirror_primary_region, mpr,
                sizeof(env->config.mirror_primary_region) - 1);
        env->config.mirror_primary_region[sizeof(env->config.mirror_primary_region) - 1] =
            '\0';
    }

    const char *rtt = getenv("DISLMDB_RTT_BUDGET_MS");
    if (rtt && rtt[0] != '\0') {
        char *end = NULL;
        unsigned long v = strtoul(rtt, &end, 10);
        if (end != rtt) {
            env->config.rtt_budget_ms = (uint32_t)v;
        }
    }

    const char *maxp = getenv("DISLMDB_MAX_PEERS");
    if (maxp && maxp[0] != '\0') {
        char *end = NULL;
        unsigned long v = strtoul(maxp, &end, 10);
        if (end != maxp) {
            env->config.max_peers = (uint32_t)v; /* 0 = unlimited */
        }
    }

    uint8_t key[32];
    const char *rk = getenv("DISLMDB_REGION_SECRET");
    if (rk && env_parse_key32(rk, key) == 0) {
        memcpy(env->config.region_key, key, 32);
        env->config.has_region_key = true;
        /* Intra-region secret becomes the active cluster key when none set. */
        if (!env->config.network.has_cluster_key) {
            memcpy(env->config.network.cluster_key, key, 32);
            env->config.network.has_cluster_key = true;
            env->config.network.enable_message_auth = true;
            env->config.network.enable_payload_encryption = true;
        }
    }
    const char *ck = getenv("DISLMDB_CROSS_REGION_SECRET");
    if (ck && env_parse_key32(ck, key) == 0) {
        memcpy(env->config.cross_region_key, key, 32);
        env->config.has_cross_region_key = true;
    }

    const char *seeds = getenv("DISLMDB_SEED_REGIONAL");
    if (seeds && seeds[0] != '\0' && env->config.network.seed_node_count == 0) {
        /* Comma-separated host:port list (up to array capacity). */
        char buf[1024];
        strncpy(buf, seeds, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *save = NULL;
        for (char *tok = strtok_r(buf, ",", &save);
             tok && env->config.network.seed_node_count < 10;
             tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ') {
                tok++;
            }
            strncpy(env->config.network.seed_nodes[env->config.network.seed_node_count],
                    tok, sizeof(env->config.network.seed_nodes[0]) - 1);
            env->config.network.seed_node_count++;
        }
    }
}

int dislmdb_env_open(DISLMDB_env *env, const DISLMDB_env_config *config)
{
    if (!env || !config || !config->path) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    int rc = deep_copy_config(env, config);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    apply_environ_overrides(env);

    if (env->config.network.transport == DISLMDB_TRANSPORT_QUIC) {
        if (!dislmdb_quic_stack_ready()) {
            dislmdb_set_error(env, DISLMDB_ERR_NOT_IMPLEMENTED,
                              "DISLMDB_TRANSPORT_QUIC: %s", dislmdb_quic_status());
            free_config_nodes(env);
            return DISLMDB_ERR_NOT_IMPLEMENTED;
        }
    }

    /* Multi-node / BFT deployments must have a shared cluster key (fail closed). */
    bool multi = (env->config.network.node_count > 0) ||
                 (env->config.network.seed_node_count > 0) ||
                 (env->config.consensus.fault_tolerance > 0);
    if (multi && !env->config.network.has_cluster_key) {
        dislmdb_set_error(env, DISLMDB_ERR_NOT_AUTHORIZED,
                          "Cluster key required for multi-node or f>0 (call dislmdb_set_cluster_key / set network.has_cluster_key)");
        free_config_nodes(env);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }

    rc = mdb_env_set_mapsize(env->mdb_env, config->mapsize);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set map size: %s", mdb_strerror(rc));
        free_config_nodes(env);
        return rc;
    }
    rc = mdb_env_set_maxreaders(env->mdb_env, config->maxreaders);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set max readers: %s", mdb_strerror(rc));
        free_config_nodes(env);
        return rc;
    }
    /* Ensure room for internal bytecode DBI */
    unsigned int maxdbs = config->maxdbs < 2 ? 2 : config->maxdbs;
    rc = mdb_env_set_maxdbs(env->mdb_env, maxdbs);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set max DBs: %s", mdb_strerror(rc));
        free_config_nodes(env);
        return rc;
    }

    rc = mdb_env_open(env->mdb_env, config->path, config->lmdb_flags, config->mode);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to open environment: %s", mdb_strerror(rc));
        free_config_nodes(env);
        return rc;
    }
    env->lmdb_opened = true;

    /* Stable cluster identity BEFORE network/HELLO so peers learn the real id */
    if (env->config.node_name[0] != '\0' &&
        strcmp(env->config.node_name, "DisLMDB Node") != 0) {
        strncpy(env->local_node_id, env->config.node_name, sizeof(env->local_node_id) - 1);
        env->local_node_id[sizeof(env->local_node_id) - 1] = '\0';
    }

    /* Install cluster key on env before network auth + PBFT init */
    if (env->config.network.has_cluster_key) {
        memcpy(env->cluster_key, env->config.network.cluster_key, 32);
        env->has_cluster_key = true;
    }

    if (env->config.network.node_count > 0) {
        env->nodes = calloc(env->config.network.node_count, sizeof(DISLMDB_node_addr));
        env->node_states = calloc(env->config.network.node_count, sizeof(DISLMDB_NODE_STATE));
        if (!env->nodes || !env->node_states) {
            free(env->nodes);
            free(env->node_states);
            env->nodes = NULL;
            env->node_states = NULL;
            env_open_cleanup(env, true, false, false);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(env->nodes, env->config.network.nodes,
               env->config.network.node_count * sizeof(DISLMDB_node_addr));
        env->node_count = (uint32_t)env->config.network.node_count;
        for (uint32_t i = 0; i < env->node_count; i++) {
            env->node_states[i] = DISLMDB_NODE_STATE_UNKNOWN;
        }
    }

    rc = dislmdb_network_init(env, &env->config.network);
    if (rc != DISLMDB_SUCCESS) {
        dislmdb_set_error(env, rc, "Failed to initialize network subsystem");
        env_open_cleanup(env, true, false, false);
        return rc;
    }

    /* Dial every configured peer (not only seeds) so Raft/PBFT have
     * bidirectional paths as soon as each replica comes up. Failures are
     * non-fatal — outbound slots reconnect from the network thread. */
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strncmp(env->nodes[i].node_id, env->local_node_id, 63) == 0) {
            continue;
        }
        (void)dislmdb_network_connect(env, &env->nodes[i],
                                      DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    }

    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        rc = dislmdb_pbft_init(env);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, rc, "Failed to initialize Enhanced PBFT consensus");
            env_open_cleanup(env, true, true, false);
            return rc;
        }
        dislmdb_log(env, DISLMDB_LOG_INFO, "INIT", "Enhanced PBFT consensus initialized");
    } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        /* Stage 1: arm Raft + JOIN handler; elections stay off until mesh engages. */
        rc = dislmdb_raft_init(env);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, rc, "Failed to initialize Raft consensus");
            env_open_cleanup(env, true, true, false);
            return rc;
        }
        dislmdb_log(env, DISLMDB_LOG_INFO, "INIT", "Raft consensus armed (pre-start)");
    } else {
        rc = dislmdb_consensus_init(env, &env->config.consensus);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, rc, "Failed to initialize consensus subsystem");
            env_open_cleanup(env, true, true, false);
            return rc;
        }
    }

    if (env->has_cluster_key) {
        (void)dislmdb_network_set_auth_key(env, env->cluster_key);
        if (env->config.network.enable_payload_encryption || env->config.network.enable_tls) {
            (void)dislmdb_network_set_encryption(env, true);
        }
        /* consensus_context is ConsensusCore* only for PBFT; Raft/solo use other types */
        if (env->consensus_context &&
            env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
            ConsensusCore *core = env->consensus_context;
            security_manager_set_cluster_key(core->security, env->cluster_key);
            core->config.verify_signatures = true;
        }
    }
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_load(env);
        if (env->has_cluster_key) {
            (void)dislmdb_network_set_auth_key(env, env->cluster_key);
            if (env->consensus_context &&
                env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
                ConsensusCore *core = env->consensus_context;
                security_manager_set_cluster_key(core->security, env->cluster_key);
                core->config.verify_signatures = true;
            }
        }
    }

    /* Stage 2: announce on the wire so peers bind real ids before consensus runs. */
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT ||
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        (void)dislmdb_pbft_send_hello(env, "");
    }

    /* Stage 3 (Raft): start elections after HELLO; raft_start waits for mesh. */
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        rc = dislmdb_raft_start(env);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, rc, "Failed to start Raft after cluster engage");
            env_open_cleanup(env, true, true, true);
            return rc;
        }
    }

    dislmdb_log(env, DISLMDB_LOG_INFO, "ENV", "Opened environment at %s", config->path);
    return DISLMDB_SUCCESS;
}

void dislmdb_env_close(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return;
    }

    dislmdb_log(env, DISLMDB_LOG_INFO, "ENV", "Closing environment");

    if (env->lmdb_opened) {
        (void)dislmdb_persist_save(env);
    }

    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        if (env->consensus_context) {
            dislmdb_pbft_shutdown(env);
        }
    } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        if (env->consensus_context) {
            dislmdb_raft_shutdown(env);
        }
    } else if (env->consensus_context) {
        dislmdb_consensus_shutdown(env);
    }

    if (env->network_context) {
        dislmdb_network_shutdown(env);
    }

    if (env->mdb_env) {
        mdb_env_close(env->mdb_env);
        env->mdb_env = NULL;
    }
    env->lmdb_opened = false;

    destroy_mutexes(env);
    free(env->log_messages);
    free(env->oplog);
    free(env->nodes);
    free(env->node_states);
    free_config_nodes(env);
    env->magic = 0;
    free(env);
}

int dislmdb_env_sync(DISLMDB_env *env, int force)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = mdb_env_sync(env->mdb_env, force);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to sync environment: %s", mdb_strerror(rc));
    }
    return rc;
}

int dislmdb_txn_begin(DISLMDB_env *env, DISLMDB_txn *parent,
                      unsigned int flags, DISLMDB_txn **txn)
{
    if (!env || env->magic != DISLMDB_MAGIC || !txn) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    DISLMDB_txn *t = calloc(1, sizeof(DISLMDB_txn));
    if (!t) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    t->magic = DISLMDB_MAGIC;
    t->env = env;
    t->parent = parent;
    t->flags = flags;
    t->is_write_txn = !(flags & MDB_RDONLY);
    t->is_distributed = t->is_write_txn && !env->config.read_only_node;
    t->start_time = dislmdb_get_time_ms();

    char txn_id[64];
    dislmdb_generate_node_id(txn_id);
    strncpy(t->txn_id, txn_id, sizeof(t->txn_id) - 1);

    MDB_txn *parent_mdb_txn = parent ? parent->mdb_txn : NULL;
    int rc = mdb_txn_begin(env->mdb_env, parent_mdb_txn, flags, &t->mdb_txn);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to begin transaction: %s", mdb_strerror(rc));
        free(t);
        return rc;
    }

    pthread_mutex_lock(&env->txn_mutex);
    t->next = env->active_txns;
    env->active_txns = t;
    env->txn_count++;
    pthread_mutex_unlock(&env->txn_mutex);

    *txn = t;
    return DISLMDB_SUCCESS;
}

static void unlink_txn(DISLMDB_env *env, DISLMDB_txn *txn)
{
    pthread_mutex_lock(&env->txn_mutex);
    if (env->active_txns == txn) {
        env->active_txns = txn->next;
    } else {
        DISLMDB_txn *t = env->active_txns;
        while (t && t->next != txn) {
            t = t->next;
        }
        if (t) {
            t->next = txn->next;
        }
    }
    if (env->txn_count > 0) {
        env->txn_count--;
    }
    pthread_mutex_unlock(&env->txn_mutex);
}

int dislmdb_txn_commit(DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_env *env = txn->env;
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    if (env->config.read_only_node && txn->is_write_txn) {
        return DISLMDB_ERR_READ_ONLY;
    }

    if (txn->is_write_txn && txn->is_distributed) {
        int trc = dislmdb_topo_check_txn_writes(txn);
        if (trc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, trc, "Topology mode rejected transaction writes");
            return trc;
        }
    }

    int rc = DISLMDB_SUCCESS;
    bool applied_via_consensus = false;
    /* Auto-forwarded puts/dels leave no local pending ops — skip consensus. */
    bool has_local_ops = (txn->pending_ops != NULL && txn->operation_count > 0);
    if (txn->is_write_txn && txn->is_distributed && has_local_ops) {
        if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
            rc = dislmdb_pbft_propose_transaction(txn);
            if (rc != DISLMDB_SUCCESS) {
                dislmdb_set_error(env, rc, "Failed to achieve consensus for transaction");
                return rc;
            }
            applied_via_consensus = true;
        } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
            rc = dislmdb_raft_propose_transaction(txn);
            if (rc != DISLMDB_SUCCESS) {
                dislmdb_set_error(env, rc, "Failed to achieve Raft consensus for transaction");
                return rc;
            }
            applied_via_consensus = true;
        } else {
            DISLMDB_operation op;
            memset(&op, 0, sizeof(op));
            DISLMDB_consensus_result result;
            rc = dislmdb_consensus_generate_op_id(env, &op.id);
            if (rc != DISLMDB_SUCCESS) {
                return rc;
            }
            op.type = DISLMDB_OP_TYPE_NOP;
            op.timestamp = dislmdb_get_time_ms();
            strncpy(op.node_id, env->local_node_id, sizeof(op.node_id) - 1);
            rc = dislmdb_consensus_propose(env, &op, env->config.consensus.timeout_ms, &result);
            if (rc != DISLMDB_SUCCESS || result.status != DISLMDB_CONSENSUS_COMMITTED) {
                return rc != DISLMDB_SUCCESS ? rc : DISLMDB_ERR_CONSENSUS_FAILED;
            }
        }
    }

    if (applied_via_consensus) {
        /* Staging txn already aborted inside propose after quorum apply */
        if (txn->mdb_txn) {
            mdb_txn_abort(txn->mdb_txn);
            txn->mdb_txn = NULL;
        }
    } else if (txn->mdb_txn) {
        rc = mdb_txn_commit(txn->mdb_txn);
        if (rc != 0) {
            dislmdb_set_error(env, rc, "Failed to commit transaction: %s", mdb_strerror(rc));
            return rc;
        }
        txn->mdb_txn = NULL;
    }

    unlink_txn(env, txn);
    env->total_commits++;
    dislmdb_free_pending_ops(txn);
    txn->magic = 0;
    free(txn);
    (void)dislmdb_persist_save(env);
    return DISLMDB_SUCCESS;
}

void dislmdb_txn_abort(DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return;
    }
    DISLMDB_env *env = txn->env;
    if (!env || env->magic != DISLMDB_MAGIC) {
        return;
    }
    if (txn->mdb_txn) {
        mdb_txn_abort(txn->mdb_txn);
        txn->mdb_txn = NULL;
    }
    unlink_txn(env, txn);
    dislmdb_free_pending_ops(txn);
    txn->magic = 0;
    free(txn);
}

MDB_env *dislmdb_get_lmdb_env(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return NULL;
    }
    return env->mdb_env;
}

MDB_txn *dislmdb_get_lmdb_txn(DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return NULL;
    }
    return txn->mdb_txn;
}

int dislmdb_add_node_internal(DISLMDB_env *env, const DISLMDB_node_addr *node_addr)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_addr) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&env->nodes_mutex);

    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strcmp(env->nodes[i].node_id, node_addr->node_id) == 0) {
            memcpy(&env->nodes[i], node_addr, sizeof(DISLMDB_node_addr));
            pthread_mutex_unlock(&env->nodes_mutex);
            return DISLMDB_SUCCESS;
        }
    }

    if (env->config.max_peers != 0 &&
        env->node_count >= env->config.max_peers) {
        pthread_mutex_unlock(&env->nodes_mutex);
        return DISLMDB_ERR_MAX_NODES;
    }

    DISLMDB_node_addr *new_nodes = realloc(env->nodes,
                                           (env->node_count + 1) * sizeof(DISLMDB_node_addr));
    if (!new_nodes) {
        pthread_mutex_unlock(&env->nodes_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    env->nodes = new_nodes;
    DISLMDB_NODE_STATE *new_states = realloc(env->node_states,
                                             (env->node_count + 1) * sizeof(DISLMDB_NODE_STATE));
    if (!new_states) {
        /* nodes already grown; leave spare slot unused — count unchanged */
        pthread_mutex_unlock(&env->nodes_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    env->node_states = new_states;
    memcpy(&env->nodes[env->node_count], node_addr, sizeof(DISLMDB_node_addr));
    env->node_states[env->node_count] = DISLMDB_NODE_STATE_UNKNOWN;
    env->node_count++;
    pthread_mutex_unlock(&env->nodes_mutex);

    dislmdb_log(env, DISLMDB_LOG_INFO, "NODE", "Added node %s (%s:%u)",
                node_addr->node_id, node_addr->hostname, (unsigned)node_addr->port);
    return DISLMDB_SUCCESS;
}

int dislmdb_add_node(DISLMDB_env *env, const DISLMDB_node_addr *node_addr)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_addr) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = dislmdb_add_node_internal(env, node_addr);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        (void)consensus_core_add_replica(env->consensus_context, node_addr->node_id);
    }
    rc = dislmdb_network_connect(env, node_addr, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    if (rc != DISLMDB_SUCCESS) {
        dislmdb_log(env, DISLMDB_LOG_WARNING, "NODE",
                    "Failed to connect to node %s (%s:%u)",
                    node_addr->node_id, node_addr->hostname, (unsigned)node_addr->port);
    }
    (void)dislmdb_persist_save(env);
    return DISLMDB_SUCCESS;
}

int dislmdb_find_node(DISLMDB_env *env, const char *node_id, uint32_t *index)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_id || !index) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strcmp(env->nodes[i].node_id, node_id) == 0) {
            *index = i;
            pthread_mutex_unlock(&env->nodes_mutex);
            return DISLMDB_SUCCESS;
        }
    }
    pthread_mutex_unlock(&env->nodes_mutex);
    return DISLMDB_ERR_NODE_NOT_FOUND;
}

int dislmdb_update_node_state(DISLMDB_env *env, const char *node_id,
                              DISLMDB_NODE_STATE state)
{
    uint32_t index;
    int rc = dislmdb_find_node(env, node_id, &index);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    pthread_mutex_lock(&env->nodes_mutex);
    DISLMDB_NODE_STATE old_state = env->node_states[index];
    env->node_states[index] = state;
    pthread_mutex_unlock(&env->nodes_mutex);

    pthread_mutex_lock(&env->status_mutex);
    if (env->status_callback) {
        env->status_callback(node_id, old_state, state, env->status_callback_data);
    }
    pthread_mutex_unlock(&env->status_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_remove_node(DISLMDB_env *env, const char *node_id)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_id || node_id[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strncmp(node_id, env->local_node_id, 63) == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uint32_t index;
    int rc = dislmdb_find_node(env, node_id, &index);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    (void)dislmdb_update_node_state(env, node_id, DISLMDB_NODE_STATE_LEAVING);
    (void)dislmdb_pbft_send_leave(env, node_id);
    (void)dislmdb_network_disconnect(env, node_id);

    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        ConsensusError err = consensus_core_remove_replica(env->consensus_context, node_id);
        if (err != CONSENSUS_OK && err != CONSENSUS_ERROR_UNKNOWN_REPLICA) {
            dislmdb_log(env, DISLMDB_LOG_WARNING, "NODE",
                        "consensus_core_remove_replica(%s) -> %d", node_id, (int)err);
        }
    } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        int rrc = dislmdb_raft_remove_peer(env, node_id);
        if (rrc != DISLMDB_SUCCESS && rrc != DISLMDB_ERR_IN_PROGRESS &&
            rrc != DISLMDB_ERR_NO_LEADER) {
            dislmdb_log(env, DISLMDB_LOG_WARNING, "NODE",
                        "raft_remove_peer(%s) -> %d", node_id, rrc);
        }
    }

    /* Re-resolve index — membership propose may have raced with table edits. */
    if (dislmdb_find_node(env, node_id, &index) != DISLMDB_SUCCESS) {
        return dislmdb_persist_save(env);
    }
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
    return DISLMDB_SUCCESS;
}

int dislmdb_get_node_state(DISLMDB_env *env, const char *node_id,
                           DISLMDB_NODE_STATE *state)
{
    uint32_t index;
    int rc = dislmdb_find_node(env, node_id, &index);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    pthread_mutex_lock(&env->nodes_mutex);
    *state = env->node_states[index];
    pthread_mutex_unlock(&env->nodes_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_get_leader(DISLMDB_env *env, char *leader_id, size_t id_size)
{
    if (!env || env->magic != DISLMDB_MAGIC || !leader_id || id_size < 2) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    char primary[64];
    primary[0] = '\0';
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT && env->consensus_context) {
        consensus_core_primary_id(env->consensus_context, primary);
        strncpy(env->pbft_state.primary_id, primary, sizeof(env->pbft_state.primary_id) - 1);
    } else if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        if (dislmdb_raft_current_leader(env, primary, sizeof(primary)) != DISLMDB_SUCCESS) {
            return DISLMDB_ERR_NO_LEADER;
        }
    } else if (env->pbft_state.primary_id[0] != '\0') {
        strncpy(primary, env->pbft_state.primary_id, sizeof(primary) - 1);
    } else {
        strncpy(primary, env->local_node_id, sizeof(primary) - 1);
    }
    if (primary[0] == '\0') {
        return DISLMDB_ERR_NO_LEADER;
    }
    strncpy(leader_id, primary, id_size - 1);
    leader_id[id_size - 1] = '\0';
    return DISLMDB_SUCCESS;
}

int dislmdb_get_region(DISLMDB_env *env, char *out, size_t out_sz)
{
    if (!env || env->magic != DISLMDB_MAGIC || !out || out_sz < 2) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    strncpy(out, env->config.region, out_sz - 1);
    out[out_sz - 1] = '\0';
    return DISLMDB_SUCCESS;
}

int dislmdb_get_locality(DISLMDB_env *env, char *out, size_t out_sz)
{
    if (!env || env->magic != DISLMDB_MAGIC || !out || out_sz < 2) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    strncpy(out, env->config.locality, out_sz - 1);
    out[out_sz - 1] = '\0';
    return DISLMDB_SUCCESS;
}

int dislmdb_get_topology_mode(DISLMDB_env *env, DISLMDB_TOPOLOGY_MODE *out)
{
    if (!env || env->magic != DISLMDB_MAGIC || !out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    *out = env->config.topology_mode;
    return DISLMDB_SUCCESS;
}

bool dislmdb_voting_enabled(DISLMDB_env *env)
{
    return env && env->magic == DISLMDB_MAGIC && env->config.consensus.enable_voting;
}

int dislmdb_force_sync(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = dislmdb_env_sync(env, 1);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    /* Ask peers for any sequences we are missing */
    if (env->consensus_context) {
        (void)dislmdb_request_state_transfer(env);
        /* Re-announce identity so membership stays current */
        (void)dislmdb_pbft_send_hello(env, "");
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_set_status_callback(DISLMDB_env *env,
                                dislmdb_status_callback callback,
                                void *user_data)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->status_mutex);
    env->status_callback = callback;
    env->status_callback_data = user_data;
    pthread_mutex_unlock(&env->status_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_store_bytecode(DISLMDB_env *env,
                           const uint8_t *bytecode,
                           size_t bytecode_size,
                           const char *bytecode_id,
                           unsigned int options)
{
    if (!env || env->magic != DISLMDB_MAGIC || !bytecode || !bytecode_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->mdb_env) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (env->config.read_only_node) {
        return DISLMDB_ERR_READ_ONLY;
    }
    if (options & DISLMDB_BYTECODE_COMPRESS) {
        return DISLMDB_ERR_NOT_IMPLEMENTED;
    }
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        return dislmdb_pbft_store_bytecode(env, bytecode, bytecode_size, bytecode_id, options);
    }
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        return dislmdb_raft_store_bytecode(env, bytecode, bytecode_size, bytecode_id, options);
    }
    /* SOLO: durable local store (same on-disk layout as consensus apply). */
    size_t id_len = strnlen(bytecode_id, 129);
    if (id_len == 0 || id_len > 128 || bytecode_size == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uint8_t *stored = NULL;
    size_t stored_size = 0;
    int rc = dislmdb_bytecode_pack(options, bytecode, bytecode_size, &stored, &stored_size);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    MDB_txn *txn = NULL;
    rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
    if (rc != 0) {
        free(stored);
        return rc;
    }
    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, BYTECODE_DBI_NAME, MDB_CREATE, &dbi);
    if (rc != 0) {
        free(stored);
        mdb_txn_abort(txn);
        return rc;
    }
    MDB_val key = {.mv_size = id_len, .mv_data = (void *)bytecode_id};
    MDB_val val = {.mv_size = stored_size, .mv_data = stored};
    rc = mdb_put(txn, dbi, &key, &val, 0);
    free(stored);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }
    rc = mdb_txn_commit(txn);
    if (rc == 0) {
        env->total_operations++;
    }
    return rc;
}

int dislmdb_set_cluster_key(DISLMDB_env *env, const uint8_t key[32])
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (key) {
        memcpy(env->cluster_key, key, 32);
    } else {
        if (dislmdb_crypto_random_bytes(env->cluster_key, 32) != 0) {
            return DISLMDB_ERR_AUTH_FAILED;
        }
    }
    env->has_cluster_key = true;
    env->config.network.has_cluster_key = true;
    env->config.network.enable_message_auth = true;
    memcpy(env->config.network.cluster_key, env->cluster_key, 32);
    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        ConsensusCore *core = env->consensus_context;
        security_manager_set_cluster_key(core->security, env->cluster_key);
        core->config.verify_signatures = true;
    }
    if (env->network_context) {
        (void)dislmdb_network_set_auth_key(env, env->cluster_key);
        if (env->config.network.enable_payload_encryption || env->config.network.enable_tls) {
            (void)dislmdb_network_set_encryption(env, true);
        }
    }
    return dislmdb_persist_save(env);
}

int dislmdb_get_cluster_key(DISLMDB_env *env, uint8_t out[32])
{
    if (!env || env->magic != DISLMDB_MAGIC || !out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->has_cluster_key) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    memcpy(out, env->cluster_key, 32);
    return DISLMDB_SUCCESS;
}

int dislmdb_checkpoint(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        return dislmdb_raft_checkpoint(env);
    }
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT && env->consensus_context) {
        ConsensusError err = consensus_core_checkpoint(env->consensus_context);
        if (err != CONSENSUS_OK) {
            return DISLMDB_ERR_CHECKPOINT_FAILED;
        }
        env->checkpoints++;
        return dislmdb_persist_save(env);
    }
    /* SOLO / unarmed: flush meta + bump checkpoint counter */
    env->checkpoints++;
    return dislmdb_persist_save(env);
}

int dislmdb_request_state_transfer(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism != DISLMDB_CONSENSUS_PBFT) {
        /* Raft catches up via AppendEntries; HELLO re-announce is enough here */
        env->state_transfers++;
        return DISLMDB_SUCCESS;
    }
    ConsensusCore *core = env->consensus_context;
    ConsensusError err = consensus_core_request_state(core, consensus_core_last_committed(core));
    if (err != CONSENSUS_OK) {
        return DISLMDB_ERR_SYNC_FAILED;
    }
    env->state_transfers++;
    return DISLMDB_SUCCESS;
}

int dislmdb_get_metrics(DISLMDB_env *env, DISLMDB_metrics *metrics)
{
    if (!env || env->magic != DISLMDB_MAGIC || !metrics) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    memset(metrics, 0, sizeof(*metrics));
    metrics->total_commits = env->total_commits;
    metrics->total_operations = env->total_operations;
    metrics->total_sync_bytes = env->total_sync_bytes;
    metrics->consensus_proposes = env->consensus_proposes;
    metrics->consensus_commits = env->consensus_commits;
    metrics->view_changes = env->view_changes;
    metrics->checkpoints = env->checkpoints;
    metrics->state_transfers = env->state_transfers;
    metrics->current_view = env->pbft_state.view;
    metrics->last_committed_seq = env->pbft_state.sequence;
    metrics->replica_count = env->node_count;
    metrics->consensus_mechanism = (uint32_t)env->config.consensus.mechanism;
    metrics->voting_enabled = env->config.consensus.enable_voting;
    metrics->is_leader = env->pbft_state.is_primary;

    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        ConsensusMetrics cm;
        consensus_core_get_metrics(env->consensus_context, &cm);
        metrics->consensus_proposes += cm.proposes;
        metrics->consensus_commits += cm.commits;
        metrics->view_changes += cm.view_changes;
        metrics->checkpoints += cm.checkpoints;
        metrics->state_transfers += cm.state_transfers;
        metrics->current_view = consensus_core_view(env->consensus_context);
        metrics->last_committed_seq = consensus_core_last_committed(env->consensus_context);
        metrics->is_leader = consensus_core_is_primary(env->consensus_context);
    } else if (env->consensus_context &&
               env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        dislmdb_raft_fill_metrics(env, metrics);
    }

    if (env->network_context) {
        DISLMDB_network_stats ns;
        if (dislmdb_network_get_stats(env, &ns) == DISLMDB_SUCCESS) {
            metrics->active_connections = ns.active_connections;
            metrics->total_sync_bytes += ns.total_bytes_received + ns.total_bytes_sent;
            metrics->messages_sent = ns.total_messages_sent;
            metrics->messages_received = ns.total_messages_received;
            metrics->connection_failures = ns.connection_failures;
            metrics->dqgm_packets_rx = ns.dqgm_packets_rx;
            metrics->dqgm_cid_mismatch = ns.dqgm_cid_mismatch;
            metrics->dqgm_replay_drop = ns.dqgm_replay_drop;
            metrics->dqgm_session_rebind = ns.dqgm_session_rebind;
            metrics->dqgm_ack_rx = ns.dqgm_ack_rx;
            metrics->dqgm_ack_advance = ns.dqgm_ack_advance;
            metrics->outbox_enqueued = ns.outbox_enqueued;
            metrics->outbox_drained = ns.outbox_drained;
            metrics->outbox_dropped = ns.outbox_dropped;
        }
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_format_metrics(const DISLMDB_metrics *m,
                           char *buf,
                           size_t buf_sz,
                           size_t *written)
{
    if (!m) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    /*
     * Prometheus text exposition (no HTTP server — callers expose via their
     * own scrape endpoint, log shipper, or file).
     */
    int n = snprintf(buf && buf_sz ? buf : NULL, buf ? buf_sz : 0,
        "# HELP dislmdb_commits_total Committed local transactions\n"
        "# TYPE dislmdb_commits_total counter\n"
        "dislmdb_commits_total %llu\n"
        "# HELP dislmdb_operations_total Recorded operations\n"
        "# TYPE dislmdb_operations_total counter\n"
        "dislmdb_operations_total %llu\n"
        "# HELP dislmdb_sync_bytes_total Bytes synchronized / transferred\n"
        "# TYPE dislmdb_sync_bytes_total counter\n"
        "dislmdb_sync_bytes_total %llu\n"
        "# HELP dislmdb_consensus_proposes_total Consensus proposes\n"
        "# TYPE dislmdb_consensus_proposes_total counter\n"
        "dislmdb_consensus_proposes_total %llu\n"
        "# HELP dislmdb_consensus_commits_total Consensus commits applied\n"
        "# TYPE dislmdb_consensus_commits_total counter\n"
        "dislmdb_consensus_commits_total %llu\n"
        "# HELP dislmdb_view_changes_total View changes / elections stepped\n"
        "# TYPE dislmdb_view_changes_total counter\n"
        "dislmdb_view_changes_total %llu\n"
        "# HELP dislmdb_checkpoints_total Checkpoints taken\n"
        "# TYPE dislmdb_checkpoints_total counter\n"
        "dislmdb_checkpoints_total %llu\n"
        "# HELP dislmdb_state_transfers_total State transfer requests\n"
        "# TYPE dislmdb_state_transfers_total counter\n"
        "dislmdb_state_transfers_total %llu\n"
        "# HELP dislmdb_replica_count Known replicas\n"
        "# TYPE dislmdb_replica_count gauge\n"
        "dislmdb_replica_count %u\n"
        "# HELP dislmdb_active_connections Live CONNECTED peers\n"
        "# TYPE dislmdb_active_connections gauge\n"
        "dislmdb_active_connections %u\n"
        "# HELP dislmdb_is_leader 1 if this node is primary/leader\n"
        "# TYPE dislmdb_is_leader gauge\n"
        "dislmdb_is_leader %u\n"
        "# HELP dislmdb_voting_enabled 1 if this node votes\n"
        "# TYPE dislmdb_voting_enabled gauge\n"
        "dislmdb_voting_enabled %u\n"
        "# HELP dislmdb_consensus_mechanism 0=pbft 1=raft 2=solo\n"
        "# TYPE dislmdb_consensus_mechanism gauge\n"
        "dislmdb_consensus_mechanism %u\n"
        "# HELP dislmdb_raft_term Current Raft term\n"
        "# TYPE dislmdb_raft_term gauge\n"
        "dislmdb_raft_term %llu\n"
        "# HELP dislmdb_raft_commit_index Raft commit index\n"
        "# TYPE dislmdb_raft_commit_index gauge\n"
        "dislmdb_raft_commit_index %llu\n"
        "# HELP dislmdb_raft_peer_count Raft peer count\n"
        "# TYPE dislmdb_raft_peer_count gauge\n"
        "dislmdb_raft_peer_count %u\n"
        "# HELP dislmdb_messages_sent_total Network messages sent\n"
        "# TYPE dislmdb_messages_sent_total counter\n"
        "dislmdb_messages_sent_total %llu\n"
        "# HELP dislmdb_messages_received_total Network messages received\n"
        "# TYPE dislmdb_messages_received_total counter\n"
        "dislmdb_messages_received_total %llu\n"
        "# HELP dislmdb_connection_failures_total Connection failures\n"
        "# TYPE dislmdb_connection_failures_total counter\n"
        "dislmdb_connection_failures_total %u\n"
        "# HELP dislmdb_dqgm_packets_rx_total DQGM envelopes accepted\n"
        "# TYPE dislmdb_dqgm_packets_rx_total counter\n"
        "dislmdb_dqgm_packets_rx_total %llu\n"
        "# HELP dislmdb_dqgm_cid_mismatch_total DQGM CID mismatches\n"
        "# TYPE dislmdb_dqgm_cid_mismatch_total counter\n"
        "dislmdb_dqgm_cid_mismatch_total %llu\n"
        "# HELP dislmdb_dqgm_replay_drop_total DQGM replay drops\n"
        "# TYPE dislmdb_dqgm_replay_drop_total counter\n"
        "dislmdb_dqgm_replay_drop_total %llu\n"
        "# HELP dislmdb_dqgm_session_rebind_total DQGM session rebinds\n"
        "# TYPE dislmdb_dqgm_session_rebind_total counter\n"
        "dislmdb_dqgm_session_rebind_total %llu\n"
        "# HELP dislmdb_dqgm_ack_rx_total DQGM ACKs observed\n"
        "# TYPE dislmdb_dqgm_ack_rx_total counter\n"
        "dislmdb_dqgm_ack_rx_total %llu\n"
        "# HELP dislmdb_dqgm_ack_advance_total DQGM ACK advances\n"
        "# TYPE dislmdb_dqgm_ack_advance_total counter\n"
        "dislmdb_dqgm_ack_advance_total %llu\n"
        "# HELP dislmdb_outbox_enqueued_total Outbox enqueues\n"
        "# TYPE dislmdb_outbox_enqueued_total counter\n"
        "dislmdb_outbox_enqueued_total %llu\n"
        "# HELP dislmdb_outbox_drained_total Outbox drains\n"
        "# TYPE dislmdb_outbox_drained_total counter\n"
        "dislmdb_outbox_drained_total %llu\n"
        "# HELP dislmdb_outbox_dropped_total Outbox drops\n"
        "# TYPE dislmdb_outbox_dropped_total counter\n"
        "dislmdb_outbox_dropped_total %llu\n",
        (unsigned long long)m->total_commits,
        (unsigned long long)m->total_operations,
        (unsigned long long)m->total_sync_bytes,
        (unsigned long long)m->consensus_proposes,
        (unsigned long long)m->consensus_commits,
        (unsigned long long)m->view_changes,
        (unsigned long long)m->checkpoints,
        (unsigned long long)m->state_transfers,
        (unsigned)m->replica_count,
        (unsigned)m->active_connections,
        m->is_leader ? 1u : 0u,
        m->voting_enabled ? 1u : 0u,
        (unsigned)m->consensus_mechanism,
        (unsigned long long)m->raft_term,
        (unsigned long long)m->raft_commit_index,
        (unsigned)m->raft_peer_count,
        (unsigned long long)m->messages_sent,
        (unsigned long long)m->messages_received,
        (unsigned)m->connection_failures,
        (unsigned long long)m->dqgm_packets_rx,
        (unsigned long long)m->dqgm_cid_mismatch,
        (unsigned long long)m->dqgm_replay_drop,
        (unsigned long long)m->dqgm_session_rebind,
        (unsigned long long)m->dqgm_ack_rx,
        (unsigned long long)m->dqgm_ack_advance,
        (unsigned long long)m->outbox_enqueued,
        (unsigned long long)m->outbox_drained,
        (unsigned long long)m->outbox_dropped);

    if (n < 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (written) {
        *written = (size_t)n;
    }
    if (buf && buf_sz > 0 && (size_t)n >= buf_sz) {
        buf[buf_sz - 1] = '\0';
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_reconfigure_replicas(DISLMDB_env *env,
                                 const DISLMDB_node_addr *nodes,
                                 size_t node_count)
{
    if (!env || env->magic != DISLMDB_MAGIC || !nodes || node_count == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.max_peers != 0 && node_count > env->config.max_peers) {
        return DISLMDB_ERR_MAX_NODES;
    }
    if (env->consensus_context &&
        env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
        return dislmdb_raft_reconfigure(env, nodes, node_count);
    }
    for (size_t i = 0; i < node_count; i++) {
        int rc = dislmdb_add_node(env, &nodes[i]);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
        if (env->consensus_context &&
            env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
            (void)consensus_core_add_replica(env->consensus_context, nodes[i].node_id);
        }
    }
    return dislmdb_persist_save(env);
}

int dislmdb_get_bytecode(DISLMDB_env *env,
                         const char *bytecode_id,
                         uint8_t *bytecode,
                         size_t *bytecode_size,
                         unsigned int *options)
{
    if (!env || env->magic != DISLMDB_MAGIC || !bytecode_id || !bytecode_size) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->mdb_env) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }

    size_t id_len = strnlen(bytecode_id, 129);
    if (id_len == 0 || id_len > 128) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }

    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, BYTECODE_DBI_NAME, 0, &dbi);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc == MDB_NOTFOUND ? DISLMDB_ERR_NODE_NOT_FOUND : rc;
    }

    MDB_val key = {.mv_size = id_len, .mv_data = (void *)bytecode_id};
    MDB_val val;
    rc = mdb_get(txn, dbi, &key, &val);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc == MDB_NOTFOUND ? DISLMDB_ERR_NODE_NOT_FOUND : rc;
    }
    if (val.mv_size < 4) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_DATA_CORRUPTION;
    }

    unsigned int opts = 0;
    const uint8_t *payload = NULL;
    size_t data_size = 0;
    rc = dislmdb_bytecode_unpack(val.mv_data, val.mv_size, &opts, &payload, &data_size);
    if (rc != DISLMDB_SUCCESS) {
        mdb_txn_abort(txn);
        return rc;
    }
    if (options) {
        *options = opts;
    }
    if (!bytecode) {
        *bytecode_size = data_size;
        mdb_txn_abort(txn);
        return DISLMDB_SUCCESS;
    }
    if (*bytecode_size < data_size) {
        *bytecode_size = data_size;
        mdb_txn_abort(txn);
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    memcpy(bytecode, payload, data_size);
    *bytecode_size = data_size;
    mdb_txn_abort(txn);
    return DISLMDB_SUCCESS;
}
