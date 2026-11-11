/**
 * @file dislmdb_shard.c
 * @brief Native shard map: key-prefix → owner affinity with longest-prefix match
 */
#include <stdlib.h>
#include <string.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "consensus/pbft_adapter.h"
#include "consensus/raft_adapter.h"
#include "../../Enhanced-PBFT-mechanism/epdft.h"

#define SHARD_PACK_SIZE_V1 (DISLMDB_SHARD_ID_LEN + DISLMDB_SHARD_PREFIX_LEN + 64)
#define SHARD_PACK_SIZE_V2 (SHARD_PACK_SIZE_V1 + 4)
#define SHARD_PACK_SIZE SHARD_PACK_SIZE_V2
#define SMAP_VERSION 2

static bool prefix_match(const char *prefix, size_t plen,
                         const void *key, size_t key_len)
{
    if (plen == 0 || plen > key_len) {
        return false;
    }
    return memcmp(prefix, key, plen) == 0;
}

static int find_best_shard_locked(const DISLMDB_env *env,
                                  const void *key,
                                  size_t key_len,
                                  uint32_t *best_out)
{
    int best = -1;
    size_t best_len = 0;
    for (uint32_t i = 0; i < env->shard_count; i++) {
        size_t plen = strnlen(env->shards[i].key_prefix, DISLMDB_SHARD_PREFIX_LEN);
        if (prefix_match(env->shards[i].key_prefix, plen, key, key_len) &&
            plen >= best_len) {
            best = (int)i;
            best_len = plen;
        }
    }
    if (best < 0) {
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    *best_out = (uint32_t)best;
    return DISLMDB_SUCCESS;
}

static int validate_shards(const DISLMDB_shard_desc *shards, size_t count,
                           DISLMDB_shard_desc *tmp)
{
    if (count > DISLMDB_MAX_SHARDS) {
        return DISLMDB_ERR_MAX_NODES;
    }
    if (count > 0 && !shards) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    memset(tmp, 0, sizeof(DISLMDB_shard_desc) * DISLMDB_MAX_SHARDS);
    for (size_t i = 0; i < count; i++) {
        size_t id_len = strnlen(shards[i].shard_id, DISLMDB_SHARD_ID_LEN);
        size_t p_len = strnlen(shards[i].key_prefix, DISLMDB_SHARD_PREFIX_LEN);
        size_t o_len = strnlen(shards[i].owner_node_id, 64);
        if (id_len == 0 || id_len >= DISLMDB_SHARD_ID_LEN ||
            p_len == 0 || p_len >= DISLMDB_SHARD_PREFIX_LEN ||
            o_len == 0 || o_len >= 64) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        for (size_t j = 0; j < i; j++) {
            if (strncmp(tmp[j].shard_id, shards[i].shard_id, DISLMDB_SHARD_ID_LEN) == 0) {
                return DISLMDB_ERR_INVALID_PARAMETER;
            }
            if (strncmp(tmp[j].key_prefix, shards[i].key_prefix,
                        DISLMDB_SHARD_PREFIX_LEN) == 0) {
                return DISLMDB_ERR_INVALID_PARAMETER;
            }
        }
        memcpy(&tmp[i], &shards[i], sizeof(DISLMDB_shard_desc));
        tmp[i].shard_id[DISLMDB_SHARD_ID_LEN - 1] = '\0';
        tmp[i].key_prefix[DISLMDB_SHARD_PREFIX_LEN - 1] = '\0';
        tmp[i].owner_node_id[63] = '\0';
        tmp[i].flags = shards[i].flags & DISLMDB_SHARD_FLAG_MIRRORED;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_shard_map_encode(const DISLMDB_shard_desc *shards,
                             size_t count,
                             uint8_t **out,
                             size_t *out_len)
{
    if (!out || !out_len || (count > 0 && !shards) || count > DISLMDB_MAX_SHARDS) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t need = 4 + 4 + 4 + count * SHARD_PACK_SIZE_V2;
    uint8_t *buf = calloc(1, need);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, DISLMDB_SMAP_MAGIC); o += 4;
    dislmdb_write_u32(buf + o, SMAP_VERSION); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)count); o += 4;
    for (size_t i = 0; i < count; i++) {
        memcpy(buf + o, shards[i].shard_id, DISLMDB_SHARD_ID_LEN); o += DISLMDB_SHARD_ID_LEN;
        memcpy(buf + o, shards[i].key_prefix, DISLMDB_SHARD_PREFIX_LEN);
        o += DISLMDB_SHARD_PREFIX_LEN;
        memcpy(buf + o, shards[i].owner_node_id, 64); o += 64;
        dislmdb_write_u32(buf + o, shards[i].flags); o += 4;
    }
    *out = buf;
    *out_len = o;
    return DISLMDB_SUCCESS;
}

int dislmdb_shard_map_install(DISLMDB_env *env,
                              const DISLMDB_shard_desc *shards,
                              size_t count)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_shard_desc tmp[DISLMDB_MAX_SHARDS];
    int rc = validate_shards(shards, count, tmp);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }

    pthread_mutex_lock(&env->shard_mutex);
    memset(env->shards, 0, sizeof(env->shards));
    if (count > 0) {
        memcpy(env->shards, tmp, count * sizeof(DISLMDB_shard_desc));
    }
    env->shard_count = (uint32_t)count;
    pthread_mutex_unlock(&env->shard_mutex);

    if (env->mdb_env && env->config.consensus.persist_state) {
        return dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_shard_map_apply_payload(DISLMDB_env *env, const uint8_t *data, size_t size)
{
    if (!env || !data || size < 12) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (dislmdb_read_u32(data) != DISLMDB_SMAP_MAGIC) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    uint32_t ver = dislmdb_read_u32(data + 4);
    if (ver != 1 && ver != 2) {
        return DISLMDB_ERR_VERSION_MISMATCH;
    }
    uint32_t count = dislmdb_read_u32(data + 8);
    size_t pack = (ver >= 2) ? SHARD_PACK_SIZE_V2 : SHARD_PACK_SIZE_V1;
    size_t need = 12 + (size_t)count * pack;
    if (count > DISLMDB_MAX_SHARDS || size < need) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    DISLMDB_shard_desc shards[DISLMDB_MAX_SHARDS];
    memset(shards, 0, sizeof(shards));
    size_t o = 12;
    for (uint32_t i = 0; i < count; i++) {
        memcpy(shards[i].shard_id, data + o, DISLMDB_SHARD_ID_LEN);
        shards[i].shard_id[DISLMDB_SHARD_ID_LEN - 1] = '\0';
        o += DISLMDB_SHARD_ID_LEN;
        memcpy(shards[i].key_prefix, data + o, DISLMDB_SHARD_PREFIX_LEN);
        shards[i].key_prefix[DISLMDB_SHARD_PREFIX_LEN - 1] = '\0';
        o += DISLMDB_SHARD_PREFIX_LEN;
        memcpy(shards[i].owner_node_id, data + o, 64);
        shards[i].owner_node_id[63] = '\0';
        o += 64;
        if (ver >= 2) {
            shards[i].flags = dislmdb_read_u32(data + o) & DISLMDB_SHARD_FLAG_MIRRORED;
            o += 4;
        }
    }
    return dislmdb_shard_map_install(env, shards, count);
}

int dislmdb_shard_map_set(DISLMDB_env *env,
                          const DISLMDB_shard_desc *shards,
                          size_t count)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_shard_desc tmp[DISLMDB_MAX_SHARDS];
    int rc = validate_shards(shards, count, tmp);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }

    /* Replicate through consensus when a cluster is live. */
    if (env->consensus_running && env->consensus_context &&
        (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT ||
         env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT)) {
        uint8_t *buf = NULL;
        size_t len = 0;
        rc = dislmdb_shard_map_encode(tmp, count, &buf, &len);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
        if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
            rc = dislmdb_raft_propose_raw(env, buf, len);
            /* raft_propose_raw takes ownership on all paths */
            return rc;
        }
        ConsensusCore *core = env->consensus_context;
        ConsensusError err = consensus_core_propose(core, buf, len);
        if (err != CONSENSUS_OK) {
            free(buf);
            switch (err) {
                case CONSENSUS_ERROR_NOT_LEADER: return DISLMDB_ERR_NO_LEADER;
                case CONSENSUS_ERROR_TIMEOUT: return DISLMDB_ERR_CONSENSUS_TIMEOUT;
                case CONSENSUS_ERROR_MEMORY_ERROR: return DISLMDB_ERR_MEMORY_ERROR;
                default: return DISLMDB_ERR_CONSENSUS_FAILED;
            }
        }
        rc = dislmdb_shard_map_apply_payload(env, buf, len);
        free(buf);
        if (rc == DISLMDB_SUCCESS) {
            env->consensus_commits++;
        }
        return rc;
    }

    return dislmdb_shard_map_install(env, tmp, count);
}

int dislmdb_shard_map_get(DISLMDB_env *env,
                          DISLMDB_shard_desc *out,
                          size_t max_out,
                          size_t *out_count)
{
    if (!env || env->magic != DISLMDB_MAGIC || !out_count) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->shard_mutex);
    *out_count = env->shard_count;
    size_t n = env->shard_count;
    if (out && max_out > 0 && n > 0) {
        if (n > max_out) {
            n = max_out;
        }
        memcpy(out, env->shards, n * sizeof(DISLMDB_shard_desc));
    }
    pthread_mutex_unlock(&env->shard_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_shard_lookup(DISLMDB_env *env,
                         const void *key,
                         size_t key_len,
                         char owner_node_id[64])
{
    if (!env || env->magic != DISLMDB_MAGIC || !key || key_len == 0 || !owner_node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->shard_mutex);
    uint32_t best = 0;
    int rc = find_best_shard_locked(env, key, key_len, &best);
    if (rc == DISLMDB_SUCCESS) {
        strncpy(owner_node_id, env->shards[best].owner_node_id, 63);
        owner_node_id[63] = '\0';
    }
    pthread_mutex_unlock(&env->shard_mutex);
    return rc;
}

int dislmdb_shard_lookup_id(DISLMDB_env *env,
                            const void *key,
                            size_t key_len,
                            char shard_id[DISLMDB_SHARD_ID_LEN])
{
    if (!env || env->magic != DISLMDB_MAGIC || !key || key_len == 0 || !shard_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->shard_mutex);
    uint32_t best = 0;
    int rc = find_best_shard_locked(env, key, key_len, &best);
    if (rc == DISLMDB_SUCCESS) {
        strncpy(shard_id, env->shards[best].shard_id, DISLMDB_SHARD_ID_LEN - 1);
        shard_id[DISLMDB_SHARD_ID_LEN - 1] = '\0';
    }
    pthread_mutex_unlock(&env->shard_mutex);
    return rc;
}

int dislmdb_topo_resolve_owner(DISLMDB_env *env,
                               const void *key,
                               size_t key_len,
                               char owner_node_id[64])
{
    if (!env || env->magic != DISLMDB_MAGIC || !key || key_len == 0 ||
        !owner_node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.topology_mode == DISLMDB_TOPO_MIRROR) {
        strncpy(owner_node_id, env->local_node_id, 63);
        owner_node_id[63] = '\0';
        return DISLMDB_SUCCESS;
    }
    return dislmdb_shard_lookup(env, key, key_len, owner_node_id);
}

int dislmdb_topo_key_writable(DISLMDB_env *env,
                              const void *key,
                              size_t key_len)
{
    if (!env || env->magic != DISLMDB_MAGIC || !key || key_len == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    DISLMDB_TOPOLOGY_MODE mode = env->config.topology_mode;
    if (mode == DISLMDB_TOPO_MIRROR) {
        return DISLMDB_SUCCESS;
    }

    pthread_mutex_lock(&env->shard_mutex);
    uint32_t best = 0;
    int rc = find_best_shard_locked(env, key, key_len, &best);
    if (rc != DISLMDB_SUCCESS) {
        pthread_mutex_unlock(&env->shard_mutex);
        /* Shard/hybrid with no matching prefix: reject (fail closed). */
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }

    uint32_t flags = env->shards[best].flags;
    char owner[64];
    strncpy(owner, env->shards[best].owner_node_id, sizeof(owner) - 1);
    owner[sizeof(owner) - 1] = '\0';
    pthread_mutex_unlock(&env->shard_mutex);

    if (mode == DISLMDB_TOPO_HYBRID && (flags & DISLMDB_SHARD_FLAG_MIRRORED)) {
        return DISLMDB_SUCCESS;
    }

    if (strncmp(owner, env->local_node_id, sizeof(owner)) == 0) {
        return DISLMDB_SUCCESS;
    }
    return DISLMDB_ERR_OPERATION_REJECTED;
}

int dislmdb_topo_check_txn_writes(const DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !txn->env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (txn->env->config.topology_mode == DISLMDB_TOPO_MIRROR) {
        return DISLMDB_SUCCESS;
    }
    for (const DISLMDB_pending_op *op = txn->pending_ops; op; op = op->next) {
        if (op->type != DISLMDB_OP_TYPE_PUT && op->type != DISLMDB_OP_TYPE_DEL) {
            continue;
        }
        if (!op->key || op->key_len == 0) {
            continue;
        }
        int rc = dislmdb_topo_key_writable(txn->env, op->key, op->key_len);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
    }
    return DISLMDB_SUCCESS;
}
