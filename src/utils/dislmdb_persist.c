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
    mdb_txn_abort(txn);

    if (env->consensus_context && env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        ConsensusCore *core = env->consensus_context;
        consensus_core_restore(core, env->pbft_state.view, env->pbft_state.sequence);
    }
    return DISLMDB_SUCCESS;
}
