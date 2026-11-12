/**
 * @file dislmdb_topo.c
 * @brief Consensus-replicated peer topology map (TOPO blob)
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_network.h"
#include "consensus/pbft_adapter.h"
#include "consensus/raft_adapter.h"
#include "../../Enhanced-PBFT-mechanism/epdft.h"

/* Same layout as meta peer_topo records. */
#define TOPO_REC_SIZE (64 + 64 + 64 + 256 + 2)

static int topo_encode(DISLMDB_env *env, uint8_t **out, size_t *out_len)
{
    pthread_mutex_lock(&env->nodes_mutex);
    uint32_t nc = env->node_count;
    size_t need = 12 + (size_t)nc * TOPO_REC_SIZE;
    uint8_t *buf = calloc(1, need);
    if (!buf) {
        pthread_mutex_unlock(&env->nodes_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, DISLMDB_TOPO_MAGIC); o += 4;
    dislmdb_write_u32(buf + o, 1); o += 4;
    dislmdb_write_u32(buf + o, nc); o += 4;
    for (uint32_t i = 0; i < nc; i++) {
        memcpy(buf + o, env->nodes[i].node_id, 64); o += 64;
        memcpy(buf + o, env->nodes[i].region, 64); o += 64;
        memcpy(buf + o, env->nodes[i].locality, 64); o += 64;
        memcpy(buf + o, env->nodes[i].hostname, 256); o += 256;
        dislmdb_write_u16(buf + o, env->nodes[i].port); o += 2;
    }
    pthread_mutex_unlock(&env->nodes_mutex);
    *out = buf;
    *out_len = o;
    return DISLMDB_SUCCESS;
}

int dislmdb_topo_map_apply_payload(DISLMDB_env *env, const uint8_t *data, size_t size)
{
    if (!env || !data || size < 12) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (dislmdb_read_u32(data) != DISLMDB_TOPO_MAGIC) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    uint32_t ver = dislmdb_read_u32(data + 4);
    if (ver != 1) {
        return DISLMDB_ERR_VERSION_MISMATCH;
    }
    uint32_t count = dislmdb_read_u32(data + 8);
    size_t need = 12 + (size_t)count * TOPO_REC_SIZE;
    if (size < need) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    size_t o = 12;
    for (uint32_t i = 0; i < count; i++) {
        DISLMDB_node_addr na;
        memset(&na, 0, sizeof(na));
        memcpy(na.node_id, data + o, 64);
        na.node_id[63] = '\0';
        o += 64;
        memcpy(na.region, data + o, 64);
        na.region[63] = '\0';
        o += 64;
        memcpy(na.locality, data + o, 64);
        na.locality[63] = '\0';
        o += 64;
        memcpy(na.hostname, data + o, 256);
        na.hostname[255] = '\0';
        o += 256;
        na.port = dislmdb_read_u16(data + o);
        o += 2;
        if (na.node_id[0] == '\0') {
            continue;
        }
        if (strncmp(na.node_id, env->local_node_id, 63) == 0) {
            continue;
        }
        (void)dislmdb_add_node_internal(env, &na);
        (void)dislmdb_network_set_peer_topo(env, na.node_id, na.region, na.locality,
                                            true);
    }
    if (env->mdb_env && env->config.consensus.persist_state) {
        return dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_topo_map_publish(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int arc = dislmdb_acl_require(env, DISLMDB_ACL_ADMIN);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = topo_encode(env, &buf, &len);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }

    if (env->consensus_running && env->consensus_context &&
        (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT ||
         env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT)) {
        if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_RAFT) {
            return dislmdb_raft_propose_raw(env, buf, len);
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
        rc = dislmdb_topo_map_apply_payload(env, buf, len);
        free(buf);
        if (rc == DISLMDB_SUCCESS) {
            env->consensus_commits++;
        }
        return rc;
    }

    rc = dislmdb_topo_map_apply_payload(env, buf, len);
    free(buf);
    return rc;
}

#define FWD_REQ_MAGIC 0x33445746u /* 'FWD3' — origin+principal-bound forward RPC */
#define FWD_REP_MAGIC 0x46574452u /* 'FWDR' */
#define FWD_OP_PUT 1u
#define FWD_OP_DEL 2u
#define FWD_OP_GET 3u
#define FWD_OP_TXN 4u /* multi-op atomic apply (index_put/del, …) */
#define FWD_MAX_GET_BYTES (4u * 1024u * 1024u)
#define FWD_MAX_PUT_BYTES FWD_MAX_GET_BYTES
#define FWD_MAX_TXN_OPS 16u

/**
 * Run @p fn under the origin principal (TLS only). Restores prior TLS after.
 * Empty/NULL principal clears TLS so ACL require fails when enable_acl.
 */
static int forward_with_principal(DISLMDB_env *env, const char *principal,
                                  int (*fn)(DISLMDB_env *, void *), void *arg)
{
    char saved[DISLMDB_ACL_PRINCIPAL_MAX + 1];
    memset(saved, 0, sizeof(saved));
    const char *cur = dislmdb_acl_current_principal(env);
    if (cur && cur[0] != '\0') {
        strncpy(saved, cur, DISLMDB_ACL_PRINCIPAL_MAX);
    }
    int prc = dislmdb_acl_set_thread_principal(
        env, (principal && principal[0] != '\0') ? principal : NULL);
    if (prc != DISLMDB_SUCCESS) {
        return prc;
    }
    int rc = fn(env, arg);
    (void)dislmdb_acl_set_thread_principal(
        env, saved[0] != '\0' ? saved : NULL);
    return rc;
}

typedef struct {
    uint32_t op;
    const char *dbname;
    const uint8_t *key;
    uint32_t klen;
    const uint8_t *val;
    uint32_t vlen;
} forward_apply_args;

static int forward_apply_one(DISLMDB_txn *txn, uint32_t op, const char *dbname,
                             const uint8_t *key, uint32_t klen,
                             const uint8_t *val, uint32_t vlen)
{
    if (dislmdb_dbname_is_reserved(dbname)) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    MDB_dbi dbi;
    int rc = dislmdb_dbi_open(txn, dbname, MDB_CREATE, &dbi);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    MDB_val k = {.mv_size = klen, .mv_data = (void *)key};
    if (op == FWD_OP_PUT) {
        MDB_val v = {.mv_size = vlen, .mv_data = (void *)val};
        return dislmdb_put(txn, dbi, &k, &v, 0);
    }
    rc = dislmdb_del(txn, dbi, &k, NULL);
    if (rc == MDB_NOTFOUND) {
        return DISLMDB_SUCCESS;
    }
    return rc;
}

static int forward_apply_local_body(DISLMDB_env *env, void *arg)
{
    forward_apply_args *a = arg;
    /* Retry across brief leader changes / inbox scheduling.
     * dislmdb_txn_commit always consumes the handle. */
    int last = DISLMDB_ERR_CONSENSUS_FAILED;
    for (int attempt = 0; attempt < 8; attempt++) {
        DISLMDB_txn *txn = NULL;
        int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
        if (rc != DISLMDB_SUCCESS) {
            last = rc;
            usleep(20 * 1000);
            continue;
        }
        rc = forward_apply_one(txn, a->op, a->dbname, a->key, a->klen, a->val,
                               a->vlen);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_txn_abort(txn);
            return rc;
        }
        rc = dislmdb_txn_commit(txn);
        if (rc == DISLMDB_SUCCESS) {
            return DISLMDB_SUCCESS;
        }
        last = rc;
        if (rc != DISLMDB_ERR_NO_LEADER && rc != DISLMDB_ERR_CONSENSUS_TIMEOUT &&
            rc != DISLMDB_ERR_LEADER_CHANGE && rc != DISLMDB_ERR_CONSENSUS_FAILED) {
            return rc;
        }
        usleep(50 * 1000);
    }
    return last;
}

typedef struct {
    const uint8_t *blob;
    uint32_t blob_len;
} forward_txn_args;

static int forward_txn_local_body(DISLMDB_env *env, void *arg)
{
    forward_txn_args *a = arg;
    if (a->blob_len < 4) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    uint32_t count = dislmdb_read_u32(a->blob);
    if (count == 0 || count > FWD_MAX_TXN_OPS) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    size_t o = 4;
    int last = DISLMDB_ERR_CONSENSUS_FAILED;
    for (int attempt = 0; attempt < 8; attempt++) {
        DISLMDB_txn *txn = NULL;
        int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
        if (rc != DISLMDB_SUCCESS) {
            last = rc;
            usleep(20 * 1000);
            continue;
        }
        size_t pos = o;
        for (uint32_t i = 0; i < count; i++) {
            if (pos + 16 > a->blob_len) {
                dislmdb_txn_abort(txn);
                return DISLMDB_ERR_MESSAGE_VALIDATION;
            }
            uint32_t sop = dislmdb_read_u32(a->blob + pos); pos += 4;
            uint32_t nlen = dislmdb_read_u32(a->blob + pos); pos += 4;
            uint32_t klen = dislmdb_read_u32(a->blob + pos); pos += 4;
            uint32_t vlen = dislmdb_read_u32(a->blob + pos); pos += 4;
            if (sop != FWD_OP_PUT && sop != FWD_OP_DEL) {
                dislmdb_txn_abort(txn);
                return DISLMDB_ERR_INVALID_PARAMETER;
            }
            if (nlen >= 64 ||
                pos + (size_t)nlen + (size_t)klen + (size_t)vlen > a->blob_len ||
                (sop == FWD_OP_DEL && vlen != 0) ||
                (sop == FWD_OP_PUT && vlen > FWD_MAX_PUT_BYTES)) {
                dislmdb_txn_abort(txn);
                return DISLMDB_ERR_MESSAGE_VALIDATION;
            }
            char dbname[64];
            memset(dbname, 0, sizeof(dbname));
            if (nlen) {
                memcpy(dbname, a->blob + pos, nlen);
            }
            pos += nlen;
            const uint8_t *key = a->blob + pos;
            pos += klen;
            const uint8_t *val = a->blob + pos;
            pos += vlen;
            rc = forward_apply_one(txn, sop, nlen ? dbname : NULL, key, klen, val,
                                   vlen);
            if (rc != DISLMDB_SUCCESS) {
                dislmdb_txn_abort(txn);
                return rc;
            }
        }
        rc = dislmdb_txn_commit(txn);
        if (rc == DISLMDB_SUCCESS) {
            return DISLMDB_SUCCESS;
        }
        last = rc;
        if (rc != DISLMDB_ERR_NO_LEADER && rc != DISLMDB_ERR_CONSENSUS_TIMEOUT &&
            rc != DISLMDB_ERR_LEADER_CHANGE && rc != DISLMDB_ERR_CONSENSUS_FAILED) {
            return rc;
        }
        usleep(50 * 1000);
    }
    return last;
}

static int forward_txn_local(DISLMDB_env *env, const uint8_t *blob, uint32_t blob_len,
                             const char *principal)
{
    forward_txn_args a = {.blob = blob, .blob_len = blob_len};
    return forward_with_principal(env, principal, forward_txn_local_body, &a);
}

static int forward_apply_local(DISLMDB_env *env, uint32_t op, const char *dbname,
                               const uint8_t *key, uint32_t klen,
                               const uint8_t *val, uint32_t vlen,
                               const char *principal)
{
    forward_apply_args a = {
        .op = op,
        .dbname = dbname,
        .key = key,
        .klen = klen,
        .val = val,
        .vlen = vlen,
    };
    return forward_with_principal(env, principal, forward_apply_local_body, &a);
}

typedef struct {
    const char *dbname;
    const uint8_t *key;
    uint32_t klen;
    uint8_t **out;
    size_t *out_len;
} forward_get_args;

/** Local readonly get for FWD_OP_GET. Caller frees *@p out on success. */
static int forward_get_local_body(DISLMDB_env *env, void *arg)
{
    forward_get_args *a = arg;
    if (dislmdb_dbname_is_reserved(a->dbname)) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int arc = dislmdb_acl_require_key(env, DISLMDB_ACL_READ, a->key, a->klen);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, a->dbname, 0, &dbi);
    if (rc != DISLMDB_SUCCESS) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val k = {.mv_size = a->klen, .mv_data = (void *)a->key};
    MDB_val v;
    rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &k, &v);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    if (v.mv_size > FWD_MAX_GET_BYTES) {
        dislmdb_txn_abort(txn);
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    uint8_t *copy = malloc(v.mv_size ? v.mv_size : 1);
    if (!copy) {
        dislmdb_txn_abort(txn);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    if (v.mv_size) {
        memcpy(copy, v.mv_data, v.mv_size);
    }
    *a->out = copy;
    *a->out_len = v.mv_size;
    dislmdb_txn_abort(txn);
    return DISLMDB_SUCCESS;
}

static int forward_get_local(DISLMDB_env *env, const char *dbname,
                             const uint8_t *key, uint32_t klen,
                             uint8_t **out, size_t *out_len,
                             const char *principal)
{
    forward_get_args a = {
        .dbname = dbname,
        .key = key,
        .klen = klen,
        .out = out,
        .out_len = out_len,
    };
    return forward_with_principal(env, principal, forward_get_local_body, &a);
}

static int forward_send_reply_ex(DISLMDB_env *env, const char *to, uint64_t corr,
                                 int status, const uint8_t *val, size_t vlen)
{
    size_t need = 4 + 8 + 4 + 4 + (status == DISLMDB_SUCCESS ? vlen : 0);
    uint8_t *buf = malloc(need);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, FWD_REP_MAGIC); o += 4;
    dislmdb_write_u64(buf + o, corr); o += 8;
    dislmdb_write_u32(buf + o, (uint32_t)status); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)(status == DISLMDB_SUCCESS ? vlen : 0));
    o += 4;
    if (status == DISLMDB_SUCCESS && vlen > 0 && val) {
        memcpy(buf + o, val, vlen);
        o += vlen;
    }
    DISLMDB_network_message nm;
    int rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_FORWARD_REPLY, buf,
                                            (uint32_t)o, to);
    free(buf);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);
    rc = dislmdb_network_send(env, &nm, to, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    dislmdb_network_free_message(&nm);
    return rc;
}

static int forward_send_reply(DISLMDB_env *env, const char *to, uint64_t corr, int status)
{
    return forward_send_reply_ex(env, to, corr, status, NULL, 0);
}

typedef struct {
    DISLMDB_env *env;
    char reply_to[64];
    uint64_t corr;
    uint32_t op;
    char dbname[64];
    bool has_dbname;
    char principal[DISLMDB_ACL_PRINCIPAL_MAX + 1];
    uint8_t *key;
    uint32_t klen;
    uint8_t *val;
    uint32_t vlen;
} forward_job;

static int forward_txn_keys_writable(DISLMDB_env *env, const uint8_t *blob,
                                     uint32_t blob_len)
{
    if (blob_len < 4) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    uint32_t count = dislmdb_read_u32(blob);
    if (count == 0 || count > FWD_MAX_TXN_OPS) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    size_t pos = 4;
    for (uint32_t i = 0; i < count; i++) {
        if (pos + 16 > blob_len) {
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        uint32_t sop = dislmdb_read_u32(blob + pos); pos += 4;
        uint32_t nlen = dislmdb_read_u32(blob + pos); pos += 4;
        uint32_t klen = dislmdb_read_u32(blob + pos); pos += 4;
        uint32_t vlen = dislmdb_read_u32(blob + pos); pos += 4;
        (void)sop;
        if (nlen >= 64 ||
            pos + (size_t)nlen + (size_t)klen + (size_t)vlen > blob_len) {
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        pos += nlen;
        int wrc = dislmdb_topo_key_writable(env, blob + pos, klen);
        if (wrc != DISLMDB_SUCCESS) {
            return wrc;
        }
        pos += (size_t)klen + (size_t)vlen;
    }
    return DISLMDB_SUCCESS;
}

static void *forward_job_main(void *arg)
{
    forward_job *job = arg;
    const char *dbname = job->has_dbname ? job->dbname : NULL;
    const char *principal =
        job->principal[0] != '\0' ? job->principal : NULL;
    if (job->op == FWD_OP_TXN) {
        int wrc = forward_txn_keys_writable(job->env, job->val, job->vlen);
        if (wrc != DISLMDB_SUCCESS) {
            (void)forward_send_reply(job->env, job->reply_to, job->corr, wrc);
            free(job->key);
            free(job->val);
            free(job);
            return NULL;
        }
    } else {
        int wrc = dislmdb_topo_key_writable(job->env, job->key, job->klen);
        if (wrc != DISLMDB_SUCCESS) {
            (void)forward_send_reply(job->env, job->reply_to, job->corr, wrc);
            free(job->key);
            free(job->val);
            free(job);
            return NULL;
        }
    }
    if (job->op == FWD_OP_GET) {
        uint8_t *got = NULL;
        size_t glen = 0;
        int status = forward_get_local(job->env, dbname, job->key, job->klen, &got,
                                       &glen, principal);
        (void)forward_send_reply_ex(job->env, job->reply_to, job->corr, status, got, glen);
        free(got);
    } else if (job->op == FWD_OP_TXN) {
        int status = forward_txn_local(job->env, job->val, job->vlen, principal);
        (void)forward_send_reply(job->env, job->reply_to, job->corr, status);
    } else {
        int status = forward_apply_local(job->env, job->op, dbname, job->key, job->klen,
                                         job->val, job->vlen, principal);
        (void)forward_send_reply(job->env, job->reply_to, job->corr, status);
    }
    free(job->key);
    free(job->val);
    free(job);
    return NULL;
}

bool dislmdb_topo_handle_forward_message(DISLMDB_env *env,
                                         const DISLMDB_network_message *message)
{
    if (!env || !message || !message->payload) {
        return false;
    }
    if (message->header.type == DISLMDB_MESSAGE_FORWARD_REPLY) {
        /* Legacy 16-byte replies (status only) or extended (status + vlen [+ val]). */
        if (message->header.payload_size < 16) {
            return true;
        }
        const uint8_t *p = message->payload;
        if (dislmdb_read_u32(p) != FWD_REP_MAGIC) {
            return true;
        }
        uint64_t corr = dislmdb_read_u64(p + 4);
        int status = (int)(int32_t)dislmdb_read_u32(p + 12);
        uint32_t vlen = 0;
        const uint8_t *vptr = NULL;
        if (message->header.payload_size >= 20) {
            vlen = dislmdb_read_u32(p + 16);
            if (20u + (size_t)vlen > message->header.payload_size) {
                return true;
            }
            if (vlen > 0) {
                vptr = p + 20;
            }
        }
        pthread_mutex_lock(&env->forward_mutex);
        for (size_t i = 0; i < 16; i++) {
            if (env->forward_waiters[i].active &&
                env->forward_waiters[i].corr_id == corr) {
                free(env->forward_waiters[i].reply_val);
                env->forward_waiters[i].reply_val = NULL;
                env->forward_waiters[i].reply_vlen = 0;
                if (status == DISLMDB_SUCCESS && vlen > 0 && vptr) {
                    if (vlen > FWD_MAX_GET_BYTES) {
                        status = DISLMDB_ERR_BUFFER_OVERFLOW;
                    } else {
                        uint8_t *copy = malloc(vlen);
                        if (copy) {
                            memcpy(copy, vptr, vlen);
                            env->forward_waiters[i].reply_val = copy;
                            env->forward_waiters[i].reply_vlen = vlen;
                        } else {
                            status = DISLMDB_ERR_MEMORY_ERROR;
                        }
                    }
                }
                env->forward_waiters[i].status = status;
                env->forward_waiters[i].done = true;
                pthread_cond_broadcast(&env->forward_cv);
                break;
            }
        }
        pthread_mutex_unlock(&env->forward_mutex);
        return true;
    }
    if (message->header.type != DISLMDB_MESSAGE_FORWARD) {
        return false;
    }
    /* magic + corr + op + olen + plen + nlen + klen + vlen */
    if (message->header.payload_size < 4 + 8 + 4 + 4 + 4 + 4 + 4 + 4) {
        return true;
    }
    const uint8_t *p = message->payload;
    size_t o = 0;
    if (dislmdb_read_u32(p + o) != FWD_REQ_MAGIC) {
        return true;
    }
    o += 4;
    uint64_t corr = dislmdb_read_u64(p + o); o += 8;
    uint32_t op = dislmdb_read_u32(p + o); o += 4;
    uint32_t olen = dislmdb_read_u32(p + o); o += 4;
    uint32_t plen = dislmdb_read_u32(p + o); o += 4;
    uint32_t nlen = dislmdb_read_u32(p + o); o += 4;
    uint32_t klen = dislmdb_read_u32(p + o); o += 4;
    uint32_t vlen = dislmdb_read_u32(p + o); o += 4;
    if (olen >= 64 || plen > DISLMDB_ACL_PRINCIPAL_MAX || nlen >= 64 ||
        o + (size_t)olen + (size_t)plen + (size_t)nlen + (size_t)klen +
                (size_t)vlen >
            message->header.payload_size ||
        (op != FWD_OP_PUT && op != FWD_OP_DEL && op != FWD_OP_GET &&
         op != FWD_OP_TXN) ||
        (op == FWD_OP_GET && vlen != 0) ||
        (op == FWD_OP_TXN && (klen != 0 || nlen != 0)) ||
        ((op == FWD_OP_PUT || op == FWD_OP_TXN) && vlen > FWD_MAX_PUT_BYTES)) {
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_INVALID_PARAMETER);
        return true;
    }
    char origin[64];
    memset(origin, 0, sizeof(origin));
    if (olen > 0) {
        memcpy(origin, p + o, olen);
    }
    o += olen;
    /* Origin must match authenticated wire sender (HMAC covers header). */
    if (message->header.sender_id[0] == '\0' ||
        strncmp(origin, message->header.sender_id, 63) != 0) {
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_NOT_AUTHORIZED);
        return true;
    }
    /* Apply on a worker — Raft commit must not block the network thread. */
    forward_job *job = calloc(1, sizeof(*job));
    if (!job) {
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_MEMORY_ERROR);
        return true;
    }
    job->env = env;
    strncpy(job->reply_to, message->header.sender_id, sizeof(job->reply_to) - 1);
    job->corr = corr;
    job->op = op;
    if (plen > 0) {
        memcpy(job->principal, p + o, plen);
        job->principal[plen] = '\0';
    }
    o += plen;
    {
        int arc = dislmdb_acl_authorize_asserted_principal(
            env, origin, job->principal[0] ? job->principal : NULL);
        if (arc != DISLMDB_SUCCESS) {
            free(job);
            (void)forward_send_reply(env, message->header.sender_id, corr, arc);
            return true;
        }
    }
    if (nlen > 0) {
        memcpy(job->dbname, p + o, nlen);
        job->dbname[nlen] = '\0';
        job->has_dbname = true;
    }
    o += nlen;
    if (dislmdb_dbname_is_reserved(job->has_dbname ? job->dbname : NULL)) {
        free(job);
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_NOT_AUTHORIZED);
        return true;
    }
    job->key = malloc(klen ? klen : 1);
    if (!job->key) {
        free(job);
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_MEMORY_ERROR);
        return true;
    }
    if (klen) {
        memcpy(job->key, p + o, klen);
    }
    job->klen = klen;
    o += klen;
    if (op == FWD_OP_PUT || op == FWD_OP_TXN) {
        job->val = malloc(vlen ? vlen : 1);
        if (!job->val) {
            free(job->key);
            free(job);
            (void)forward_send_reply(env, message->header.sender_id, corr,
                                     DISLMDB_ERR_MEMORY_ERROR);
            return true;
        }
        if (vlen) {
            memcpy(job->val, p + o, vlen);
        }
        job->vlen = vlen;
    }
    pthread_t th;
    if (pthread_create(&th, NULL, forward_job_main, job) != 0) {
        free(job->key);
        free(job->val);
        free(job);
        (void)forward_send_reply(env, message->header.sender_id, corr,
                                 DISLMDB_ERR_THREAD_ERROR);
        return true;
    }
    pthread_detach(th);
    return true;
}

/**
 * @p owner_override NULL → resolve from @p key. FWD_OP_TXN uses empty key and
 * puts the txn blob in the value field (requires @p owner_override).
 */
static int forward_rpc_to(DISLMDB_env *env, const char *owner_override,
                          uint32_t op, const char *dbname, const void *key,
                          size_t key_len, const void *data, size_t data_len,
                          uint32_t timeout_ms, void **out_data, size_t *out_len)
{
    bool is_txn = (op == FWD_OP_TXN);
    if (!env || env->magic != DISLMDB_MAGIC || data_len > UINT32_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!is_txn && (!key || key_len == 0 || key_len > UINT32_MAX)) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (is_txn && (key_len != 0 || !data || data_len == 0 || !owner_override ||
                   owner_override[0] == '\0')) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if ((op == FWD_OP_PUT || is_txn) && !data && data_len > 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if ((op == FWD_OP_PUT || is_txn) && data_len > FWD_MAX_PUT_BYTES) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    if (op == FWD_OP_GET && (!out_data || !out_len)) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (dbname && dislmdb_dbname_is_reserved(dbname)) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    if (out_data) {
        *out_data = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    char owner[64] = {0};
    int rc;
    if (owner_override && owner_override[0] != '\0') {
        strncpy(owner, owner_override, sizeof(owner) - 1);
    } else {
        rc = dislmdb_topo_resolve_owner(env, key, key_len, owner);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
    }
    if (strncmp(owner, env->local_node_id, sizeof(owner)) == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    const char *who = dislmdb_acl_current_principal(env);
    size_t plen = 0;
    if (who && who[0] != '\0') {
        plen = strnlen(who, DISLMDB_ACL_PRINCIPAL_MAX);
    }
    size_t olen = strnlen(env->local_node_id, 63);
    size_t nlen = dbname ? strnlen(dbname, 63) : 0;
    size_t wire_vlen = (op == FWD_OP_PUT || is_txn) ? data_len : 0;
    size_t need = 4 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + olen + plen + nlen + key_len +
                  wire_vlen;
    uint8_t *buf = malloc(need);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    pthread_mutex_lock(&env->forward_mutex);
    env->forward_corr_seq++;
    uint64_t corr = env->forward_corr_seq;
    int slot = -1;
    for (size_t i = 0; i < 16; i++) {
        if (!env->forward_waiters[i].active) {
            slot = (int)i;
            env->forward_waiters[i].active = true;
            env->forward_waiters[i].done = false;
            env->forward_waiters[i].corr_id = corr;
            env->forward_waiters[i].status = DISLMDB_ERR_CONSENSUS_TIMEOUT;
            free(env->forward_waiters[i].reply_val);
            env->forward_waiters[i].reply_val = NULL;
            env->forward_waiters[i].reply_vlen = 0;
            break;
        }
    }
    pthread_mutex_unlock(&env->forward_mutex);
    if (slot < 0) {
        free(buf);
        return DISLMDB_ERR_IN_PROGRESS;
    }

    size_t o = 0;
    dislmdb_write_u32(buf + o, FWD_REQ_MAGIC); o += 4;
    dislmdb_write_u64(buf + o, corr); o += 8;
    dislmdb_write_u32(buf + o, op); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)olen); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)plen); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)nlen); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)key_len); o += 4;
    dislmdb_write_u32(buf + o, (uint32_t)wire_vlen); o += 4;
    if (olen) {
        memcpy(buf + o, env->local_node_id, olen);
        o += olen;
    }
    if (plen) {
        memcpy(buf + o, who, plen);
        o += plen;
    }
    if (nlen) {
        memcpy(buf + o, dbname, nlen);
        o += nlen;
    }
    if (key_len && key) {
        memcpy(buf + o, key, key_len);
        o += key_len;
    }
    if (wire_vlen > 0 && data) {
        memcpy(buf + o, data, wire_vlen);
        o += wire_vlen;
    }

    DISLMDB_network_message nm;
    rc = dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_FORWARD, buf, (uint32_t)o,
                                        owner);
    free(buf);
    if (rc != DISLMDB_SUCCESS) {
        pthread_mutex_lock(&env->forward_mutex);
        env->forward_waiters[slot].active = false;
        pthread_mutex_unlock(&env->forward_mutex);
        return rc;
    }
    strncpy(nm.header.sender_id, env->local_node_id, sizeof(nm.header.sender_id) - 1);
    uint32_t to = timeout_ms ? timeout_ms : env->config.consensus.timeout_ms;
    if (to == 0) {
        to = 5000;
    }
    rc = dislmdb_network_send(env, &nm, owner, to);
    dislmdb_network_free_message(&nm);
    if (rc != DISLMDB_SUCCESS) {
        pthread_mutex_lock(&env->forward_mutex);
        env->forward_waiters[slot].active = false;
        pthread_mutex_unlock(&env->forward_mutex);
        return rc;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += (time_t)(to / 1000u);
    deadline.tv_nsec += (long)(to % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&env->forward_mutex);
    while (!env->forward_waiters[slot].done) {
        int wr = pthread_cond_timedwait(&env->forward_cv, &env->forward_mutex, &deadline);
        if (wr == ETIMEDOUT) {
            break;
        }
    }
    int status = env->forward_waiters[slot].done ? env->forward_waiters[slot].status
                                                : DISLMDB_ERR_CONSENSUS_TIMEOUT;
    uint8_t *got = env->forward_waiters[slot].reply_val;
    size_t glen = env->forward_waiters[slot].reply_vlen;
    env->forward_waiters[slot].reply_val = NULL;
    env->forward_waiters[slot].reply_vlen = 0;
    env->forward_waiters[slot].active = false;
    pthread_mutex_unlock(&env->forward_mutex);
    if (status == DISLMDB_SUCCESS && op == FWD_OP_GET) {
        *out_data = got;
        *out_len = glen;
        got = NULL;
    }
    free(got);
    return status;
}

static int forward_rpc(DISLMDB_env *env, uint32_t op, const char *dbname,
                       const void *key, size_t key_len, const void *data,
                       size_t data_len, uint32_t timeout_ms,
                       void **out_data, size_t *out_len)
{
    return forward_rpc_to(env, NULL, op, dbname, key, key_len, data, data_len,
                          timeout_ms, out_data, out_len);
}

int dislmdb_topo_forward_txn(DISLMDB_env *env, const DISLMDB_fwd_op *ops,
                             size_t nop, uint32_t timeout_ms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !ops || nop == 0 ||
        nop > FWD_MAX_TXN_OPS) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t blob_need = 4;
    char owner0[64] = {0};
    for (size_t i = 0; i < nop; i++) {
        if ((ops[i].op != FWD_OP_PUT && ops[i].op != FWD_OP_DEL) || !ops[i].key ||
            ops[i].key_len == 0 || ops[i].key_len > UINT32_MAX ||
            ops[i].val_len > UINT32_MAX ||
            (ops[i].op == FWD_OP_PUT && ops[i].val_len > FWD_MAX_PUT_BYTES) ||
            (ops[i].op == FWD_OP_DEL && ops[i].val_len != 0) ||
            (ops[i].dbname && dislmdb_dbname_is_reserved(ops[i].dbname))) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        size_t nlen = ops[i].dbname ? strnlen(ops[i].dbname, 63) : 0;
        blob_need += 16 + nlen + ops[i].key_len +
                     (ops[i].op == FWD_OP_PUT ? ops[i].val_len : 0);
        char owner[64] = {0};
        int rc = dislmdb_topo_resolve_owner(env, ops[i].key, ops[i].key_len, owner);
        if (rc != DISLMDB_SUCCESS) {
            return rc;
        }
        if (i == 0) {
            memcpy(owner0, owner, sizeof(owner0));
        } else if (strncmp(owner0, owner, 63) != 0) {
            return DISLMDB_ERR_OPERATION_REJECTED;
        }
    }
    if (strncmp(owner0, env->local_node_id, 63) == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uint8_t *blob = malloc(blob_need);
    if (!blob) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t bo = 0;
    dislmdb_write_u32(blob + bo, (uint32_t)nop);
    bo += 4;
    for (size_t i = 0; i < nop; i++) {
        size_t nlen = ops[i].dbname ? strnlen(ops[i].dbname, 63) : 0;
        size_t vlen = (ops[i].op == FWD_OP_PUT) ? ops[i].val_len : 0;
        dislmdb_write_u32(blob + bo, ops[i].op); bo += 4;
        dislmdb_write_u32(blob + bo, (uint32_t)nlen); bo += 4;
        dislmdb_write_u32(blob + bo, (uint32_t)ops[i].key_len); bo += 4;
        dislmdb_write_u32(blob + bo, (uint32_t)vlen); bo += 4;
        if (nlen) {
            memcpy(blob + bo, ops[i].dbname, nlen);
            bo += nlen;
        }
        memcpy(blob + bo, ops[i].key, ops[i].key_len);
        bo += ops[i].key_len;
        if (vlen) {
            memcpy(blob + bo, ops[i].val, vlen);
            bo += vlen;
        }
    }
    int rc = forward_rpc_to(env, owner0, FWD_OP_TXN, NULL, NULL, 0, blob, bo,
                            timeout_ms, NULL, NULL);
    free(blob);
    return rc;
}

int dislmdb_topo_forward_put(DISLMDB_env *env, const char *dbname, const void *key,
                             size_t key_len, const void *data, size_t data_len,
                             uint32_t timeout_ms)
{
    return forward_rpc(env, FWD_OP_PUT, dbname, key, key_len, data, data_len, timeout_ms,
                       NULL, NULL);
}

int dislmdb_topo_forward_del(DISLMDB_env *env, const char *dbname, const void *key,
                             size_t key_len, uint32_t timeout_ms)
{
    return forward_rpc(env, FWD_OP_DEL, dbname, key, key_len, NULL, 0, timeout_ms, NULL,
                       NULL);
}

int dislmdb_topo_forward_get(DISLMDB_env *env, const char *dbname, const void *key,
                             size_t key_len, void **out_data, size_t *out_len,
                             uint32_t timeout_ms)
{
    return forward_rpc(env, FWD_OP_GET, dbname, key, key_len, NULL, 0, timeout_ms,
                       out_data, out_len);
}

int dislmdb_topo_get(DISLMDB_env *env, const char *dbname, const void *key,
                     size_t key_len, void **out_data, size_t *out_len,
                     uint32_t timeout_ms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !key || key_len == 0 || !out_data ||
        !out_len) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    *out_data = NULL;
    *out_len = 0;

    const char *principal = dislmdb_acl_current_principal(env);
    int wrc = dislmdb_topo_key_writable(env, key, key_len);
    if (wrc == DISLMDB_SUCCESS || env->config.topology_mode == DISLMDB_TOPO_MIRROR) {
        return forward_get_local(env, dbname, (const uint8_t *)key, (uint32_t)key_len,
                                 (uint8_t **)out_data, out_len, principal);
    }
    if (wrc == DISLMDB_ERR_NODE_NOT_FOUND) {
        return wrc;
    }

    char owner[64] = {0};
    int rc = dislmdb_topo_resolve_owner(env, key, key_len, owner);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    if (strncmp(owner, env->local_node_id, sizeof(owner)) == 0) {
        return forward_get_local(env, dbname, (const uint8_t *)key, (uint32_t)key_len,
                                 (uint8_t **)out_data, out_len, principal);
    }
    return dislmdb_topo_forward_get(env, dbname, key, key_len, out_data, out_len,
                                    timeout_ms);
}
