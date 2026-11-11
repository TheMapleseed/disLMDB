/**
 * @file dislmdb_persist.c
 * @brief Persist consensus view/sequence, replica set, and cluster key
 */

#include <stdlib.h>
#include <string.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "../../Enhanced-PBFT-mechanism/epdft.h"

#define META_KEY_VIEW "view"
#define META_KEY_SEQ "last_committed_seq"
#define META_KEY_CK "cluster_key"
#define META_KEY_REPLICAS "replicas"
#define META_KEY_SHARDS "shard_map"
#define META_KEY_REGION "region"
#define META_KEY_LOCALITY "locality"
#define META_KEY_TOPO_MODE "topo_mode"

/* Packed shard: count u32 + N * (64 + 128 + 64) */
#define SHARD_PACK_SIZE (DISLMDB_SHARD_ID_LEN + DISLMDB_SHARD_PREFIX_LEN + 64)

int dislmdb_persist_save(DISLMDB_env *env)
{
    if (!env || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.consensus.persist_state) {
        return DISLMDB_SUCCESS;
    }

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, DISLMDB_META_DBI, MDB_CREATE, &dbi);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    uint8_t buf[8];
    dislmdb_write_u64(buf, env->pbft_state.view);
    MDB_val k = {.mv_size = strlen(META_KEY_VIEW), .mv_data = (void *)META_KEY_VIEW};
    MDB_val v = {.mv_size = 8, .mv_data = buf};
    rc = mdb_put(txn, dbi, &k, &v, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    dislmdb_write_u64(buf, env->pbft_state.sequence);
    k.mv_size = strlen(META_KEY_SEQ);
    k.mv_data = (void *)META_KEY_SEQ;
    rc = mdb_put(txn, dbi, &k, &v, 0);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    if (env->has_cluster_key && env->config.consensus.persist_cluster_key) {
        k.mv_size = strlen(META_KEY_CK);
        k.mv_data = (void *)META_KEY_CK;
        v.mv_size = 32;
        v.mv_data = env->cluster_key;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    /* Pack replicas: count u32 + N * 64 */
    size_t rsize = 4 + (size_t)env->node_count * 64;
    uint8_t *rbuf = calloc(1, rsize ? rsize : 4);
    if (!rbuf) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(rbuf, env->node_count);
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        memcpy(rbuf + 4 + i * 64, env->nodes[i].node_id, 64);
    }
    pthread_mutex_unlock(&env->nodes_mutex);
    k.mv_size = strlen(META_KEY_REPLICAS);
    k.mv_data = (void *)META_KEY_REPLICAS;
    v.mv_size = rsize;
    v.mv_data = rbuf;
    rc = mdb_put(txn, dbi, &k, &v, 0);
    free(rbuf);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    pthread_mutex_lock(&env->shard_mutex);
    uint32_t sc = env->shard_count;
    size_t ssize = 4 + (size_t)sc * SHARD_PACK_SIZE;
    uint8_t *sbuf = calloc(1, ssize ? ssize : 4);
    if (!sbuf) {
        pthread_mutex_unlock(&env->shard_mutex);
        mdb_txn_abort(txn);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(sbuf, sc);
    for (uint32_t i = 0; i < sc; i++) {
        size_t o = 4 + (size_t)i * SHARD_PACK_SIZE;
        memcpy(sbuf + o, env->shards[i].shard_id, DISLMDB_SHARD_ID_LEN);
        memcpy(sbuf + o + DISLMDB_SHARD_ID_LEN, env->shards[i].key_prefix,
               DISLMDB_SHARD_PREFIX_LEN);
        memcpy(sbuf + o + DISLMDB_SHARD_ID_LEN + DISLMDB_SHARD_PREFIX_LEN,
               env->shards[i].owner_node_id, 64);
    }
    pthread_mutex_unlock(&env->shard_mutex);
    k.mv_size = strlen(META_KEY_SHARDS);
    k.mv_data = (void *)META_KEY_SHARDS;
    v.mv_size = ssize;
    v.mv_data = sbuf;
    rc = mdb_put(txn, dbi, &k, &v, 0);
    free(sbuf);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    /* Regional topology metadata (dedicated plane inside meta DBI). */
    if (env->config.region[0] != '\0') {
        k.mv_size = strlen(META_KEY_REGION);
        k.mv_data = (void *)META_KEY_REGION;
        v.mv_size = strnlen(env->config.region, sizeof(env->config.region));
        v.mv_data = env->config.region;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
    }
    if (env->config.locality[0] != '\0') {
        k.mv_size = strlen(META_KEY_LOCALITY);
        k.mv_data = (void *)META_KEY_LOCALITY;
        v.mv_size = strnlen(env->config.locality, sizeof(env->config.locality));
        v.mv_data = env->config.locality;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
    }
    {
        uint8_t mode = (uint8_t)env->config.topology_mode;
        k.mv_size = strlen(META_KEY_TOPO_MODE);
        k.mv_data = (void *)META_KEY_TOPO_MODE;
        v.mv_size = 1;
        v.mv_data = &mode;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
    }
    return mdb_txn_commit(txn);
}

int dislmdb_persist_load(DISLMDB_env *env)
{
    if (!env || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = mdb_dbi_open(txn, DISLMDB_META_DBI, 0, &dbi);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return DISLMDB_SUCCESS;
    }
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    MDB_val k, v;
    k.mv_size = strlen(META_KEY_VIEW);
    k.mv_data = (void *)META_KEY_VIEW;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 8) {
        env->pbft_state.view = (uint32_t)dislmdb_read_u64(v.mv_data);
    }
    k.mv_size = strlen(META_KEY_SEQ);
    k.mv_data = (void *)META_KEY_SEQ;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 8) {
        env->pbft_state.sequence = (uint32_t)dislmdb_read_u64(v.mv_data);
    }
    k.mv_size = strlen(META_KEY_CK);
    k.mv_data = (void *)META_KEY_CK;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 32) {
        memcpy(env->cluster_key, v.mv_data, 32);
        env->has_cluster_key = true;
        env->config.network.has_cluster_key = true;
        env->config.network.enable_message_auth = true;
        memcpy(env->config.network.cluster_key, env->cluster_key, 32);
    }
    k.mv_size = strlen(META_KEY_SHARDS);
    k.mv_data = (void *)META_KEY_SHARDS;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 4) {
        uint32_t sc = dislmdb_read_u32(v.mv_data);
        size_t need = 4 + (size_t)sc * SHARD_PACK_SIZE;
        if (sc <= DISLMDB_MAX_SHARDS && v.mv_size >= need) {
            pthread_mutex_lock(&env->shard_mutex);
            memset(env->shards, 0, sizeof(env->shards));
            env->shard_count = sc;
            for (uint32_t i = 0; i < sc; i++) {
                size_t o = 4 + (size_t)i * SHARD_PACK_SIZE;
                memcpy(env->shards[i].shard_id, (uint8_t *)v.mv_data + o,
                       DISLMDB_SHARD_ID_LEN);
                env->shards[i].shard_id[DISLMDB_SHARD_ID_LEN - 1] = '\0';
                memcpy(env->shards[i].key_prefix,
                       (uint8_t *)v.mv_data + o + DISLMDB_SHARD_ID_LEN,
                       DISLMDB_SHARD_PREFIX_LEN);
                env->shards[i].key_prefix[DISLMDB_SHARD_PREFIX_LEN - 1] = '\0';
                memcpy(env->shards[i].owner_node_id,
                       (uint8_t *)v.mv_data + o + DISLMDB_SHARD_ID_LEN +
                           DISLMDB_SHARD_PREFIX_LEN,
                       64);
                env->shards[i].owner_node_id[63] = '\0';
            }
            pthread_mutex_unlock(&env->shard_mutex);
        }
    }
    /* Env-configured region wins over disk; otherwise restore persisted topo. */
    k.mv_size = strlen(META_KEY_REGION);
    k.mv_data = (void *)META_KEY_REGION;
    if (env->config.region[0] == '\0' &&
        mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size > 0) {
        size_t n = v.mv_size < sizeof(env->config.region) - 1
                       ? v.mv_size
                       : sizeof(env->config.region) - 1;
        memcpy(env->config.region, v.mv_data, n);
        env->config.region[n] = '\0';
    }
    k.mv_size = strlen(META_KEY_LOCALITY);
    k.mv_data = (void *)META_KEY_LOCALITY;
    if (env->config.locality[0] == '\0' &&
        mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size > 0) {
        size_t n = v.mv_size < sizeof(env->config.locality) - 1
                       ? v.mv_size
                       : sizeof(env->config.locality) - 1;
        memcpy(env->config.locality, v.mv_data, n);
        env->config.locality[n] = '\0';
    }
    k.mv_size = strlen(META_KEY_TOPO_MODE);
    k.mv_data = (void *)META_KEY_TOPO_MODE;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 1) {
        uint8_t mode = ((const uint8_t *)v.mv_data)[0];
        if (mode <= (uint8_t)DISLMDB_TOPO_HYBRID) {
            /* Only restore if env did not explicitly set hybrid/shard via env. */
            const char *emode = getenv("DISLMDB_TOPOLOGY_MODE");
            if (!emode || emode[0] == '\0') {
                env->config.topology_mode = (DISLMDB_TOPOLOGY_MODE)mode;
            }
        }
    }
    mdb_txn_abort(txn);

    if (env->consensus_context && env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        ConsensusCore *core = env->consensus_context;
        consensus_core_restore(core, env->pbft_state.view, env->pbft_state.sequence);
        if (env->has_cluster_key) {
            security_manager_set_cluster_key(core->security, env->cluster_key);
            core->config.verify_signatures = true;
        }
        consensus_core_normalize_replicas(core);
    }
    return DISLMDB_SUCCESS;
}
