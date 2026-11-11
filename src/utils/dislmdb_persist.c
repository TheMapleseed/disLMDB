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
#define META_KEY_PEER_TOPO "peer_topo"

/* Packed shard: count u32 + N * (id + prefix + owner [+ flags v2]) */
#define SHARD_PACK_SIZE_V1 (DISLMDB_SHARD_ID_LEN + DISLMDB_SHARD_PREFIX_LEN + 64)
#define SHARD_PACK_SIZE (SHARD_PACK_SIZE_V1 + 4)
/* Peer topo: id[64] + region[64] + locality[64] + host[256] + port u16 */
/* v1: id+region+locality+host+port; v2 adds rtt_ewma_ms */
#define PEER_TOPO_REC_V1 (64 + 64 + 64 + 256 + 2)
#define PEER_TOPO_REC_V2 (PEER_TOPO_REC_V1 + 4)
#define PEER_TOPO_FMT_V2 2u

int dislmdb_persist_save(DISLMDB_env *env)
{
    if (!env || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->lmdb_opened) {
        return DISLMDB_ERR_NOT_INITIALIZED;
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

    /*
     * Length-prefixed replica stream (REPL v2): no fixed-N packing limit.
     * Each record: id_len u16 + id, host_len u16 + host, port u16,
     * region_len u16 + region, locality_len u16 + locality.
     */
    pthread_mutex_lock(&env->nodes_mutex);
    size_t rneed = 12; /* magic + ver + count */
    for (uint32_t i = 0; i < env->node_count; i++) {
        rneed += 2 + strnlen(env->nodes[i].node_id, 63);
        rneed += 2 + strnlen(env->nodes[i].hostname, 255);
        rneed += 2; /* port */
        rneed += 2 + strnlen(env->nodes[i].region, 63);
        rneed += 2 + strnlen(env->nodes[i].locality, 63);
    }
    uint8_t *rbuf = calloc(1, rneed ? rneed : 12);
    if (!rbuf) {
        pthread_mutex_unlock(&env->nodes_mutex);
        mdb_txn_abort(txn);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t ro = 0;
    dislmdb_write_u32(rbuf + ro, DISLMDB_REPL_MAGIC); ro += 4;
    dislmdb_write_u32(rbuf + ro, 2); ro += 4;
    dislmdb_write_u32(rbuf + ro, env->node_count); ro += 4;
    for (uint32_t i = 0; i < env->node_count; i++) {
        size_t idl = strnlen(env->nodes[i].node_id, 63);
        size_t hl = strnlen(env->nodes[i].hostname, 255);
        size_t rl = strnlen(env->nodes[i].region, 63);
        size_t ll = strnlen(env->nodes[i].locality, 63);
        dislmdb_write_u16(rbuf + ro, (uint16_t)idl); ro += 2;
        memcpy(rbuf + ro, env->nodes[i].node_id, idl); ro += idl;
        dislmdb_write_u16(rbuf + ro, (uint16_t)hl); ro += 2;
        memcpy(rbuf + ro, env->nodes[i].hostname, hl); ro += hl;
        dislmdb_write_u16(rbuf + ro, env->nodes[i].port); ro += 2;
        dislmdb_write_u16(rbuf + ro, (uint16_t)rl); ro += 2;
        memcpy(rbuf + ro, env->nodes[i].region, rl); ro += rl;
        dislmdb_write_u16(rbuf + ro, (uint16_t)ll); ro += 2;
        memcpy(rbuf + ro, env->nodes[i].locality, ll); ro += ll;
    }
    pthread_mutex_unlock(&env->nodes_mutex);
    k.mv_size = strlen(META_KEY_REPLICAS);
    k.mv_data = (void *)META_KEY_REPLICAS;
    v.mv_size = ro;
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
        dislmdb_write_u32(sbuf + o + SHARD_PACK_SIZE_V1, env->shards[i].flags);
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

    /* Peer topology map v2: endpoints + region/locality + RTT EWMA. */
    {
        pthread_mutex_lock(&env->nodes_mutex);
        uint32_t nc = env->node_count;
        size_t tsize = 8 + (size_t)nc * PEER_TOPO_REC_V2;
        uint8_t *tbuf = calloc(1, tsize ? tsize : 8);
        if (!tbuf) {
            pthread_mutex_unlock(&env->nodes_mutex);
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        dislmdb_write_u32(tbuf, nc);
        dislmdb_write_u32(tbuf + 4, PEER_TOPO_FMT_V2);
        for (uint32_t i = 0; i < nc; i++) {
            size_t o = 8 + (size_t)i * PEER_TOPO_REC_V2;
            memcpy(tbuf + o, env->nodes[i].node_id, 64);
            memcpy(tbuf + o + 64, env->nodes[i].region, 64);
            memcpy(tbuf + o + 128, env->nodes[i].locality, 64);
            memcpy(tbuf + o + 192, env->nodes[i].hostname, 256);
            dislmdb_write_u16(tbuf + o + 448, env->nodes[i].port);
            uint32_t rtt = env->nodes[i].rtt_ewma_ms;
            DISLMDB_connection_info ci;
            if (dislmdb_network_get_connection_info(env, env->nodes[i].node_id, &ci) ==
                DISLMDB_SUCCESS) {
                rtt = ci.rtt_ewma_ms;
                env->nodes[i].rtt_ewma_ms = rtt;
            }
            dislmdb_write_u32(tbuf + o + 450, rtt);
        }
        pthread_mutex_unlock(&env->nodes_mutex);
        k.mv_size = strlen(META_KEY_PEER_TOPO);
        k.mv_data = (void *)META_KEY_PEER_TOPO;
        v.mv_size = tsize;
        v.mv_data = tbuf;
        rc = mdb_put(txn, dbi, &k, &v, 0);
        free(tbuf);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
    }
    return mdb_txn_commit(txn);
}

int dislmdb_persist_load(DISLMDB_env *env)
{
    if (!env || !env->mdb_env || !env->lmdb_opened) {
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
    /* Replicas: prefer REPL v2; fall back to legacy count + N*64 ids. */
    k.mv_size = strlen(META_KEY_REPLICAS);
    k.mv_data = (void *)META_KEY_REPLICAS;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 4) {
        const uint8_t *rp = v.mv_data;
        if (v.mv_size >= 12 && dislmdb_read_u32(rp) == DISLMDB_REPL_MAGIC) {
            uint32_t ver = dislmdb_read_u32(rp + 4);
            uint32_t nc = dislmdb_read_u32(rp + 8);
            size_t o = 12;
            if (ver == 2) {
                for (uint32_t i = 0; i < nc && o + 2 <= v.mv_size; i++) {
                    DISLMDB_node_addr na;
                    memset(&na, 0, sizeof(na));
                    uint16_t idl = dislmdb_read_u16(rp + o); o += 2;
                    if (o + idl + 2 > v.mv_size || idl >= sizeof(na.node_id)) {
                        break;
                    }
                    memcpy(na.node_id, rp + o, idl); o += idl;
                    uint16_t hl = dislmdb_read_u16(rp + o); o += 2;
                    if (o + hl + 2 > v.mv_size || hl >= sizeof(na.hostname)) {
                        break;
                    }
                    memcpy(na.hostname, rp + o, hl); o += hl;
                    if (o + 2 > v.mv_size) {
                        break;
                    }
                    na.port = dislmdb_read_u16(rp + o); o += 2;
                    if (o + 2 > v.mv_size) {
                        break;
                    }
                    uint16_t rl = dislmdb_read_u16(rp + o); o += 2;
                    if (o + rl + 2 > v.mv_size || rl >= sizeof(na.region)) {
                        break;
                    }
                    memcpy(na.region, rp + o, rl); o += rl;
                    uint16_t ll = dislmdb_read_u16(rp + o); o += 2;
                    if (o + ll > v.mv_size || ll >= sizeof(na.locality)) {
                        break;
                    }
                    memcpy(na.locality, rp + o, ll); o += ll;
                    if (na.node_id[0] == '\0' ||
                        strncmp(na.node_id, env->local_node_id, 63) == 0) {
                        continue;
                    }
                    (void)dislmdb_add_node_internal(env, &na);
                }
            }
        } else {
            /* Legacy: count u32 + N * 64 node ids (no endpoints). */
            uint32_t nc = dislmdb_read_u32(rp);
            if (v.mv_size >= 4 + (size_t)nc * 64) {
                for (uint32_t i = 0; i < nc; i++) {
                    DISLMDB_node_addr na;
                    memset(&na, 0, sizeof(na));
                    memcpy(na.node_id, rp + 4 + (size_t)i * 64, 64);
                    na.node_id[63] = '\0';
                    if (na.node_id[0] == '\0' ||
                        strncmp(na.node_id, env->local_node_id, 63) == 0) {
                        continue;
                    }
                    (void)dislmdb_add_node_internal(env, &na);
                }
            }
        }
    }

    k.mv_size = strlen(META_KEY_SHARDS);
    k.mv_data = (void *)META_KEY_SHARDS;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 4) {
        uint32_t sc = dislmdb_read_u32(v.mv_data);
        size_t need_v2 = 4 + (size_t)sc * SHARD_PACK_SIZE;
        size_t need_v1 = 4 + (size_t)sc * SHARD_PACK_SIZE_V1;
        bool v2 = (sc <= DISLMDB_MAX_SHARDS && v.mv_size >= need_v2);
        bool v1 = (!v2 && sc <= DISLMDB_MAX_SHARDS && v.mv_size >= need_v1);
        if (v2 || v1) {
            size_t pack = v2 ? SHARD_PACK_SIZE : SHARD_PACK_SIZE_V1;
            pthread_mutex_lock(&env->shard_mutex);
            memset(env->shards, 0, sizeof(env->shards));
            env->shard_count = sc;
            for (uint32_t i = 0; i < sc; i++) {
                size_t o = 4 + (size_t)i * pack;
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
                if (v2) {
                    env->shards[i].flags =
                        dislmdb_read_u32((uint8_t *)v.mv_data + o + SHARD_PACK_SIZE_V1) &
                        DISLMDB_SHARD_FLAG_MIRRORED;
                }
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
    k.mv_size = strlen(META_KEY_PEER_TOPO);
    k.mv_data = (void *)META_KEY_PEER_TOPO;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= 4) {
        uint32_t nc = dislmdb_read_u32(v.mv_data);
        uint32_t fmt = 1;
        size_t hdr = 4;
        size_t rec_sz = PEER_TOPO_REC_V1;
        if (v.mv_size >= 8) {
            uint32_t maybe = dislmdb_read_u32((const uint8_t *)v.mv_data + 4);
            if (maybe == PEER_TOPO_FMT_V2) {
                fmt = 2;
                hdr = 8;
                rec_sz = PEER_TOPO_REC_V2;
            }
        }
        size_t need = hdr + (size_t)nc * rec_sz;
        if (v.mv_size >= need) {
            for (uint32_t i = 0; i < nc; i++) {
                const uint8_t *rec =
                    (const uint8_t *)v.mv_data + hdr + (size_t)i * rec_sz;
                DISLMDB_node_addr na;
                memset(&na, 0, sizeof(na));
                memcpy(na.node_id, rec, 64);
                na.node_id[63] = '\0';
                memcpy(na.region, rec + 64, 64);
                na.region[63] = '\0';
                memcpy(na.locality, rec + 128, 64);
                na.locality[63] = '\0';
                memcpy(na.hostname, rec + 192, 256);
                na.hostname[255] = '\0';
                na.port = dislmdb_read_u16(rec + 448);
                if (fmt >= 2) {
                    na.rtt_ewma_ms = dislmdb_read_u32(rec + 450);
                }
                if (na.node_id[0] == '\0') {
                    continue;
                }
                if (strncmp(na.node_id, env->local_node_id, 63) == 0) {
                    continue;
                }
                (void)dislmdb_add_node_internal(env, &na);
                if (na.rtt_ewma_ms > 0) {
                    (void)dislmdb_network_set_rtt_ewma(env, na.node_id, na.rtt_ewma_ms);
                }
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
