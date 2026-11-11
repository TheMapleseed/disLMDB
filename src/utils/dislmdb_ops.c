/**
 * @file dislmdb_ops.c
 * @brief Distributed put/del with operation-log replication
 */

#include <stdlib.h>
#include <string.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_consensus.h"

void dislmdb_free_pending_ops(DISLMDB_txn *txn)
{
    if (!txn) {
        return;
    }
    DISLMDB_pending_op *op = txn->pending_ops;
    while (op) {
        DISLMDB_pending_op *n = op->next;
        free(op->key);
        free(op->val);
        free(op);
        op = n;
    }
    txn->pending_ops = NULL;
    txn->operation_count = 0;
}

static int record_op(DISLMDB_txn *txn, DISLMDB_OP_TYPE type, const char *dbname,
                     const MDB_val *key, const MDB_val *val, unsigned int flags)
{
    DISLMDB_pending_op *op = calloc(1, sizeof(*op));
    if (!op) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    op->type = type;
    op->flags = flags;
    if (dbname) {
        strncpy(op->dbname, dbname, sizeof(op->dbname) - 1);
    }
    if (key && key->mv_size > 0 && key->mv_data) {
        op->key = malloc(key->mv_size);
        if (!op->key) {
            free(op);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(op->key, key->mv_data, key->mv_size);
        op->key_len = key->mv_size;
    }
    if (val && val->mv_size > 0 && val->mv_data) {
        op->val = malloc(val->mv_size);
        if (!op->val) {
            free(op->key);
            free(op);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(op->val, val->mv_data, val->mv_size);
        op->val_len = val->mv_size;
    }
    op->next = NULL;
    if (!txn->pending_ops) {
        txn->pending_ops = op;
    } else {
        DISLMDB_pending_op *t = txn->pending_ops;
        while (t->next) {
            t = t->next;
        }
        t->next = op;
    }
    txn->operation_count++;
    txn->env->total_operations++;
    return DISLMDB_SUCCESS;
}

static const char *dbname_for_dbi(DISLMDB_txn *txn, MDB_dbi dbi)
{
    for (uint32_t i = 0; i < txn->open_db_count; i++) {
        if (txn->open_db_handles[i] == dbi) {
            return txn->open_db_names[i];
        }
    }
    return "";
}

/** True when @p owner_id has a live CONNECTED network session. */
static bool owner_peer_connected(DISLMDB_env *env, const char *owner_id)
{
    DISLMDB_connection_info ci;
    memset(&ci, 0, sizeof(ci));
    if (dislmdb_network_get_connection_info(env, owner_id, &ci) != DISLMDB_SUCCESS) {
        return false;
    }
    return ci.state == DISLMDB_CONNECTION_CONNECTED;
}

/**
 * On local write-gate reject: RPC to owner when auto-forward is enabled and
 * the owner is connected. Returns gate_rc unchanged when forwarding is not
 * attempted; otherwise the forward RPC status (SUCCESS = remote write done,
 * no local LMDB mutation / pending-op record).
 *
 * The staging LMDB write txn is aborted around the RPC: if this node is the
 * Raft leader, the owner may redirect the propose back here, and apply needs
 * the write lock. Mixed local+forward ops in one txn are rejected.
 */
static int maybe_auto_forward(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key,
                              MDB_val *data, bool is_put, int gate_rc)
{
    if (gate_rc != DISLMDB_ERR_OPERATION_REJECTED) {
        return gate_rc;
    }
    if (!txn->env->config.enable_auto_forward) {
        return gate_rc;
    }
    if (txn->pending_ops != NULL || txn->operation_count > 0) {
        return gate_rc;
    }
    char owner[64] = {0};
    if (dislmdb_topo_resolve_owner(txn->env, key->mv_data, key->mv_size, owner) !=
        DISLMDB_SUCCESS) {
        return gate_rc;
    }
    if (strncmp(owner, txn->env->local_node_id, sizeof(owner)) == 0) {
        return gate_rc;
    }
    if (!owner_peer_connected(txn->env, owner)) {
        return gate_rc;
    }
    const char *dbname = dbname_for_dbi(txn, dbi);
    const char *name = (dbname && dbname[0] != '\0') ? dbname : "kv";
    /* Owner may need to redirect the propose to the Raft leader — allow headroom. */
    uint32_t to = txn->env->config.consensus.timeout_ms;
    if (to < 10000u) {
        to = 10000u;
    }

    if (txn->mdb_txn) {
        mdb_txn_abort(txn->mdb_txn);
        txn->mdb_txn = NULL;
    }

    int rc;
    if (is_put) {
        rc = dislmdb_topo_forward_put(txn->env, name, key->mv_data, key->mv_size,
                                      data ? data->mv_data : NULL,
                                      data ? data->mv_size : 0, to);
    } else {
        rc = dislmdb_topo_forward_del(txn->env, name, key->mv_data, key->mv_size, to);
    }

    /* Restore an empty write txn so a later commit/abort still has a handle. */
    if (txn->is_write_txn && txn->env->mdb_env) {
        MDB_txn *fresh = NULL;
        int brc = mdb_txn_begin(txn->env->mdb_env, NULL, 0, &fresh);
        if (brc == 0) {
            txn->mdb_txn = fresh;
        }
    }
    return rc;
}

int dislmdb_dbi_open(DISLMDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !dbi) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = mdb_dbi_open(txn->mdb_txn, name, flags, dbi);
    if (rc != 0) {
        return rc;
    }
    if (txn->open_db_count < 32) {
        if (name) {
            strncpy(txn->open_db_names[txn->open_db_count], name, 63);
        } else {
            txn->open_db_names[txn->open_db_count][0] = '\0';
        }
        txn->open_db_handles[txn->open_db_count] = *dbi;
        txn->open_db_count++;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_put(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data, unsigned int flags)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int arc = dislmdb_acl_require(txn->env, DISLMDB_ACL_WRITE);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    if (txn->is_distributed && txn->is_write_txn && key->mv_data && key->mv_size > 0) {
        int trc = dislmdb_topo_key_writable(txn->env, key->mv_data, key->mv_size);
        if (trc != DISLMDB_SUCCESS) {
            /* Auto-forward only for plain puts (no special LMDB flags). */
            if (flags == 0) {
                return maybe_auto_forward(txn, dbi, key, data, true, trc);
            }
            return trc;
        }
    }
    int rc = mdb_put(txn->mdb_txn, dbi, key, data, flags);
    if (rc != 0) {
        return rc;
    }
    if (txn->is_distributed && txn->is_write_txn) {
        rc = record_op(txn, DISLMDB_OP_TYPE_PUT, dbname_for_dbi(txn, dbi), key, data, flags);
    }
    return rc;
}

int dislmdb_del(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int arc = dislmdb_acl_require(txn->env, DISLMDB_ACL_WRITE);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    if (txn->is_distributed && txn->is_write_txn && key->mv_data && key->mv_size > 0) {
        int trc = dislmdb_topo_key_writable(txn->env, key->mv_data, key->mv_size);
        if (trc != DISLMDB_SUCCESS) {
            /* Dupsort data-targeted deletes stay local-gate only. */
            if (data == NULL) {
                return maybe_auto_forward(txn, dbi, key, NULL, false, trc);
            }
            return trc;
        }
    }
    int rc = mdb_del(txn->mdb_txn, dbi, key, data);
    if (rc != 0) {
        return rc;
    }
    if (txn->is_distributed && txn->is_write_txn) {
        rc = record_op(txn, DISLMDB_OP_TYPE_DEL, dbname_for_dbi(txn, dbi), key, data, 0);
    }
    return rc;
}

int dislmdb_serialize_pending_ops(const DISLMDB_txn *txn, uint8_t **out, size_t *out_len)
{
    if (!txn || !out || !out_len) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t need = 4 + 4 + 4; /* magic, ver, count */
    for (DISLMDB_pending_op *op = txn->pending_ops; op; op = op->next) {
        need += 4 + 2 + strnlen(op->dbname, 64) + 4 + op->key_len + 4 + op->val_len + 4;
    }
    uint8_t *buf = malloc(need);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, DISLMDB_OPLOG_MAGIC); o += 4;
    dislmdb_write_u32(buf + o, 1); o += 4;
    dislmdb_write_u32(buf + o, txn->operation_count); o += 4;
    for (DISLMDB_pending_op *op = txn->pending_ops; op; op = op->next) {
        dislmdb_write_u32(buf + o, (uint32_t)op->type); o += 4;
        uint16_t nlen = (uint16_t)strnlen(op->dbname, 64);
        dislmdb_write_u16(buf + o, nlen); o += 2;
        memcpy(buf + o, op->dbname, nlen); o += nlen;
        dislmdb_write_u32(buf + o, (uint32_t)op->key_len); o += 4;
        if (op->key_len) {
            memcpy(buf + o, op->key, op->key_len); o += op->key_len;
        }
        dislmdb_write_u32(buf + o, (uint32_t)op->val_len); o += 4;
        if (op->val_len) {
            memcpy(buf + o, op->val, op->val_len); o += op->val_len;
        }
        dislmdb_write_u32(buf + o, op->flags); o += 4;
    }
    *out = buf;
    *out_len = o;
    return DISLMDB_SUCCESS;
}

int dislmdb_apply_oplog_payload(DISLMDB_env *env, const uint8_t *data, size_t size)
{
    if (!env || !data || size < 12) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (dislmdb_read_u32(data) != DISLMDB_OPLOG_MAGIC) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    uint32_t ver = dislmdb_read_u32(data + 4);
    if (ver != 1) {
        return DISLMDB_ERR_VERSION_MISMATCH;
    }
    uint32_t count = dislmdb_read_u32(data + 8);
    size_t o = 12;

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (o + 4 + 2 > size) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        DISLMDB_OP_TYPE type = (DISLMDB_OP_TYPE)dislmdb_read_u32(data + o); o += 4;
        uint16_t nlen = dislmdb_read_u16(data + o); o += 2;
        if (o + nlen + 4 > size || nlen >= 64) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        char dbname[64];
        memset(dbname, 0, sizeof(dbname));
        memcpy(dbname, data + o, nlen); o += nlen;
        uint32_t klen = dislmdb_read_u32(data + o); o += 4;
        if (o + klen + 4 > size) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        MDB_val key = {.mv_size = klen, .mv_data = (void *)(data + o)};
        o += klen;
        uint32_t vlen = dislmdb_read_u32(data + o); o += 4;
        if (o + vlen + 4 > size) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_MESSAGE_VALIDATION;
        }
        MDB_val val = {.mv_size = vlen, .mv_data = (void *)(data + o)};
        o += vlen;
        unsigned int flags = dislmdb_read_u32(data + o); o += 4;

        MDB_dbi dbi;
        rc = mdb_dbi_open(txn, nlen ? dbname : NULL, MDB_CREATE, &dbi);
        if (rc != 0) {
            mdb_txn_abort(txn);
            return rc;
        }
        if (type == DISLMDB_OP_TYPE_PUT) {
            rc = mdb_put(txn, dbi, &key, &val, flags);
            /* Idempotent replay after primary already committed locally */
            if (rc == MDB_KEYEXIST) {
                rc = 0;
            }
        } else if (type == DISLMDB_OP_TYPE_DEL) {
            rc = mdb_del(txn, dbi, &key, vlen ? &val : NULL);
        } else {
            continue;
        }
        if (rc != 0 && rc != MDB_NOTFOUND) {
            mdb_txn_abort(txn);
            return rc;
        }
    }
    return mdb_txn_commit(txn);
}

int dislmdb_add_operation_log_entry(DISLMDB_env *env,
                                    const DISLMDB_operation_log_entry *entry)
{
    if (!env || env->magic != DISLMDB_MAGIC || !entry || !env->oplog ||
        env->oplog_size == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&env->oplog_mutex);
    uint32_t idx;
    if (env->oplog_count < env->oplog_size) {
        idx = (env->oplog_head + env->oplog_count) % env->oplog_size;
        env->oplog_count++;
    } else {
        /* Ring full — drop oldest */
        idx = env->oplog_head;
        env->oplog_head = (env->oplog_head + 1) % env->oplog_size;
    }
    env->oplog[idx] = *entry;
    /* Caller retains ownership of operation.data */
    env->oplog[idx].operation.data = NULL;
    env->oplog[idx].operation.data_size = 0;
    env->last_op_id = entry->operation.id;
    env->has_last_op_id = true;
    pthread_mutex_unlock(&env->oplog_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_find_operation_log_entry(DISLMDB_env *env,
                                     const DISLMDB_op_id *op_id,
                                     DISLMDB_operation_log_entry *entry)
{
    if (!env || env->magic != DISLMDB_MAGIC || !op_id || !entry || !env->oplog) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&env->oplog_mutex);
    for (uint32_t i = 0; i < env->oplog_count; i++) {
        uint32_t idx = (env->oplog_head + i) % env->oplog_size;
        if (dislmdb_crypto_secure_eq(env->oplog[idx].operation.id.bytes,
                                     op_id->bytes, DISLMDB_OP_ID_SIZE)) {
            *entry = env->oplog[idx];
            entry->operation.data = NULL;
            entry->operation.data_size = 0;
            pthread_mutex_unlock(&env->oplog_mutex);
            return DISLMDB_SUCCESS;
        }
    }
    pthread_mutex_unlock(&env->oplog_mutex);
    return DISLMDB_ERR_NODE_NOT_FOUND;
}

void dislmdb_record_consensus_result(DISLMDB_env *env,
                                     const DISLMDB_op_id *op_id,
                                     DISLMDB_OP_TYPE type,
                                     const DISLMDB_consensus_result *result)
{
    if (!env || !op_id || !result) {
        return;
    }
    DISLMDB_operation_log_entry entry;
    memset(&entry, 0, sizeof(entry));
    entry.operation.id = *op_id;
    entry.operation.type = type;
    entry.operation.sequence = result->commit_sequence;
    entry.operation.timestamp = result->commit_time ? result->commit_time
                                                    : dislmdb_get_time_ms();
    strncpy(entry.operation.node_id, env->local_node_id,
            sizeof(entry.operation.node_id) - 1);
    entry.result = *result;
    entry.start_time = entry.operation.timestamp;
    entry.end_time = result->commit_time;
    entry.commit_quorum_reached =
        (result->status == DISLMDB_CONSENSUS_COMMITTED);
    entry.prepare_quorum_reached = entry.commit_quorum_reached;
    entry.commit_count = result->agree_count;
    entry.prepare_count = result->agree_count;
    (void)dislmdb_add_operation_log_entry(env, &entry);
}
