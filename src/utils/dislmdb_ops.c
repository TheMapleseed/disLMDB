/**
 * @file dislmdb_ops.c
 * @brief Distributed put/del with operation-log replication
 */

#include <stdbool.h>
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

bool dislmdb_dbname_is_reserved(const char *name)
{
    if (!name || name[0] == '\0') {
        return false;
    }
    /* Internal DBIs use a leading "__" (meta, raft, bytecode, …). */
    if (name[0] == '_' && name[1] == '_') {
        return true;
    }
    return false;
}

static int record_op(DISLMDB_txn *txn, DISLMDB_OP_TYPE type, const char *dbname,
                     const MDB_val *key, const MDB_val *val, unsigned int flags)
{
    if (dislmdb_dbname_is_reserved(dbname)) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
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
    if (dislmdb_dbname_is_reserved(name)) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
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
    int arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_WRITE, key->mv_data,
                                      key->mv_size);
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
    int arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_WRITE, key->mv_data,
                                      key->mv_size);
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

/**
 * When auto-forward would split primary vs index across owners, either forward
 * both atomically to the same remote owner or reject. Local-only path unchanged.
 */
static int index_pair_prepare_forward(DISLMDB_txn *txn, MDB_val *pk, MDB_val *sk,
                                      char owner_out[64], bool *need_fwd)
{
    *need_fwd = false;
    if (!txn->is_distributed || !txn->is_write_txn) {
        return DISLMDB_SUCCESS;
    }
    int prc = dislmdb_topo_key_writable(txn->env, pk->mv_data, pk->mv_size);
    int src = dislmdb_topo_key_writable(txn->env, sk->mv_data, sk->mv_size);
    if (prc == DISLMDB_SUCCESS && src == DISLMDB_SUCCESS) {
        return DISLMDB_SUCCESS;
    }
    if (!txn->env->config.enable_auto_forward) {
        return (prc != DISLMDB_SUCCESS) ? prc : src;
    }
    if (prc != DISLMDB_ERR_OPERATION_REJECTED &&
        src != DISLMDB_ERR_OPERATION_REJECTED) {
        return (prc != DISLMDB_SUCCESS) ? prc : src;
    }
    if (txn->pending_ops != NULL || txn->operation_count > 0) {
        return DISLMDB_ERR_OPERATION_REJECTED;
    }
    char owner_p[64] = {0};
    char owner_s[64] = {0};
    if (dislmdb_topo_resolve_owner(txn->env, pk->mv_data, pk->mv_size, owner_p) !=
            DISLMDB_SUCCESS ||
        dislmdb_topo_resolve_owner(txn->env, sk->mv_data, sk->mv_size, owner_s) !=
            DISLMDB_SUCCESS) {
        return DISLMDB_ERR_OPERATION_REJECTED;
    }
    if (strncmp(owner_p, owner_s, 63) != 0) {
        /* Cross-shard index is not atomically forwardable. */
        return DISLMDB_ERR_OPERATION_REJECTED;
    }
    if (strncmp(owner_p, txn->env->local_node_id, 63) == 0) {
        return (prc != DISLMDB_SUCCESS) ? prc : src;
    }
    if (!owner_peer_connected(txn->env, owner_p)) {
        return DISLMDB_ERR_OPERATION_REJECTED;
    }
    strncpy(owner_out, owner_p, 63);
    owner_out[63] = '\0';
    *need_fwd = true;
    return DISLMDB_SUCCESS;
}

int dislmdb_index_put(DISLMDB_txn *txn, MDB_dbi primary_dbi, MDB_dbi index_dbi,
                      MDB_val *primary_key, MDB_val *primary_val,
                      MDB_val *secondary_key, unsigned int flags)
{
    if (!txn || !primary_key || !primary_val || !secondary_key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    char owner[64];
    bool need_fwd = false;
    int prep = index_pair_prepare_forward(txn, primary_key, secondary_key, owner,
                                          &need_fwd);
    if (prep != DISLMDB_SUCCESS) {
        return prep;
    }
    if (need_fwd) {
        if (flags != 0) {
            return DISLMDB_ERR_OPERATION_REJECTED;
        }
        const char *pdb = dbname_for_dbi(txn, primary_dbi);
        const char *idb = dbname_for_dbi(txn, index_dbi);
        const char *pname = (pdb && pdb[0] != '\0') ? pdb : "kv";
        const char *iname = (idb && idb[0] != '\0') ? idb : "kv";
        DISLMDB_fwd_op ops[2];
        memset(ops, 0, sizeof(ops));
        ops[0].op = 1; /* FWD_OP_PUT */
        ops[0].dbname = pname;
        ops[0].key = primary_key->mv_data;
        ops[0].key_len = primary_key->mv_size;
        ops[0].val = primary_val->mv_data;
        ops[0].val_len = primary_val->mv_size;
        ops[1].op = 1;
        ops[1].dbname = iname;
        ops[1].key = secondary_key->mv_data;
        ops[1].key_len = secondary_key->mv_size;
        ops[1].val = primary_key->mv_data;
        ops[1].val_len = primary_key->mv_size;
        uint32_t to = txn->env->config.consensus.timeout_ms;
        if (to < 10000u) {
            to = 10000u;
        }
        if (txn->mdb_txn) {
            mdb_txn_abort(txn->mdb_txn);
            txn->mdb_txn = NULL;
        }
        int rc = dislmdb_topo_forward_txn(txn->env, ops, 2, to);
        if (txn->is_write_txn && txn->env->mdb_env) {
            MDB_txn *fresh = NULL;
            if (mdb_txn_begin(txn->env->mdb_env, NULL, 0, &fresh) == 0) {
                txn->mdb_txn = fresh;
            }
        }
        return rc;
    }
    int rc = dislmdb_put(txn, primary_dbi, primary_key, primary_val, flags);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    /* Index maps secondary → primary key bytes (opaque). */
    MDB_val idx_val = {.mv_size = primary_key->mv_size,
                       .mv_data = primary_key->mv_data};
    return dislmdb_put(txn, index_dbi, secondary_key, &idx_val, flags);
}

int dislmdb_index_del(DISLMDB_txn *txn, MDB_dbi primary_dbi, MDB_dbi index_dbi,
                      MDB_val *primary_key, MDB_val *secondary_key)
{
    if (!txn || !primary_key || !secondary_key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    char owner[64];
    bool need_fwd = false;
    int prep = index_pair_prepare_forward(txn, primary_key, secondary_key, owner,
                                          &need_fwd);
    if (prep != DISLMDB_SUCCESS) {
        return prep;
    }
    if (need_fwd) {
        const char *pdb = dbname_for_dbi(txn, primary_dbi);
        const char *idb = dbname_for_dbi(txn, index_dbi);
        const char *pname = (pdb && pdb[0] != '\0') ? pdb : "kv";
        const char *iname = (idb && idb[0] != '\0') ? idb : "kv";
        DISLMDB_fwd_op ops[2];
        memset(ops, 0, sizeof(ops));
        ops[0].op = 2; /* FWD_OP_DEL */
        ops[0].dbname = pname;
        ops[0].key = primary_key->mv_data;
        ops[0].key_len = primary_key->mv_size;
        ops[1].op = 2;
        ops[1].dbname = iname;
        ops[1].key = secondary_key->mv_data;
        ops[1].key_len = secondary_key->mv_size;
        uint32_t to = txn->env->config.consensus.timeout_ms;
        if (to < 10000u) {
            to = 10000u;
        }
        if (txn->mdb_txn) {
            mdb_txn_abort(txn->mdb_txn);
            txn->mdb_txn = NULL;
        }
        int rc = dislmdb_topo_forward_txn(txn->env, ops, 2, to);
        if (txn->is_write_txn && txn->env->mdb_env) {
            MDB_txn *fresh = NULL;
            if (mdb_txn_begin(txn->env->mdb_env, NULL, 0, &fresh) == 0) {
                txn->mdb_txn = fresh;
            }
        }
        return rc;
    }
    int rc = dislmdb_del(txn, primary_dbi, primary_key, NULL);
    if (rc != 0 && rc != MDB_NOTFOUND) {
        return rc;
    }
    int irc = dislmdb_del(txn, index_dbi, secondary_key, NULL);
    if (irc != 0 && irc != MDB_NOTFOUND) {
        return irc;
    }
    /* Prefer SUCCESS if either side deleted; NOTFOUND only if both missing. */
    if (rc == MDB_NOTFOUND && irc == MDB_NOTFOUND) {
        return MDB_NOTFOUND;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_index_get(DISLMDB_txn *txn, MDB_dbi primary_dbi, MDB_dbi index_dbi,
                      MDB_val *secondary_key, MDB_val *primary_key_out,
                      MDB_val *primary_val_out)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !secondary_key ||
        !txn->mdb_txn) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_READ,
                                      secondary_key->mv_data,
                                      secondary_key->mv_size);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }

    MDB_val pkey;
    int rc = mdb_get(txn->mdb_txn, index_dbi, secondary_key, &pkey);
    if (rc != 0) {
        return rc;
    }
    if (primary_key_out) {
        *primary_key_out = pkey;
    }
    if (!primary_val_out) {
        return DISLMDB_SUCCESS;
    }
    arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_READ, pkey.mv_data,
                                  pkey.mv_size);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    return mdb_get(txn->mdb_txn, primary_dbi, &pkey, primary_val_out);
}

int dislmdb_index_scan(DISLMDB_txn *txn, MDB_dbi primary_dbi, MDB_dbi index_dbi,
                       const MDB_val *start_key, const MDB_val *prefix,
                       size_t limit, dislmdb_index_scan_cb cb, void *user)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !cb || !txn->mdb_txn) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    /* Env-wide READ for scan entry; per-key checks below. */
    int arc = dislmdb_acl_require(txn->env, DISLMDB_ACL_READ);
    if (arc != DISLMDB_SUCCESS) {
        /* Prefix-only principals: allow scan; filter per key inside. */
        if (arc != DISLMDB_ERR_NOT_AUTHORIZED) {
            return arc;
        }
    }

    MDB_cursor *cur = NULL;
    int rc = mdb_cursor_open(txn->mdb_txn, index_dbi, &cur);
    if (rc != 0) {
        return rc;
    }

    MDB_val k, v;
    MDB_cursor_op op = MDB_FIRST;
    if (start_key && start_key->mv_data && start_key->mv_size > 0) {
        k = *start_key;
        op = MDB_SET_RANGE;
    } else {
        k.mv_size = 0;
        k.mv_data = NULL;
    }
    v.mv_size = 0;
    v.mv_data = NULL;

    size_t seen = 0;
    rc = mdb_cursor_get(cur, &k, &v, op);
    while (rc == 0) {
        if (prefix && prefix->mv_data && prefix->mv_size > 0) {
            if (k.mv_size < prefix->mv_size ||
                memcmp(k.mv_data, prefix->mv_data, prefix->mv_size) != 0) {
                /* Past prefix range when scanning sorted keys with start>=prefix */
                if (k.mv_size >= prefix->mv_size &&
                    memcmp(k.mv_data, prefix->mv_data, prefix->mv_size) > 0) {
                    break;
                }
                rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                continue;
            }
        }

        arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_READ, k.mv_data,
                                      k.mv_size);
        if (arc == DISLMDB_SUCCESS) {
            MDB_val pval = {.mv_size = 0, .mv_data = NULL};
            MDB_val pkey = v;
            int prc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_READ,
                                              pkey.mv_data, pkey.mv_size);
            if (prc == DISLMDB_SUCCESS) {
                (void)mdb_get(txn->mdb_txn, primary_dbi, &pkey, &pval);
            }
            int stop = cb(&k, &pkey, &pval, user);
            seen++;
            if (stop != 0) {
                mdb_cursor_close(cur);
                return DISLMDB_SUCCESS;
            }
            if (limit > 0 && seen >= limit) {
                mdb_cursor_close(cur);
                return DISLMDB_SUCCESS;
            }
        }

        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    if (rc == MDB_NOTFOUND) {
        return DISLMDB_SUCCESS;
    }
    return rc;
}

int dislmdb_put_versioned(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key,
                          MDB_val *data, unsigned int flags, uint64_t version)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !key || !data) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!txn->mdb_txn) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }

    /* Reject stale writes against an existing versioned value. */
    MDB_val existing;
    int grc = mdb_get(txn->mdb_txn, dbi, key, &existing);
    if (grc == 0 && existing.mv_size >= DISLMDB_VERSIONED_HEADER &&
        existing.mv_data) {
        uint64_t have = dislmdb_read_u64((const uint8_t *)existing.mv_data);
        if (have >= version) {
            return DISLMDB_ERR_OPERATION_REJECTED;
        }
    } else if (grc != 0 && grc != MDB_NOTFOUND) {
        return grc;
    }

    size_t total = DISLMDB_VERSIONED_HEADER + data->mv_size;
    uint8_t *buf = malloc(total ? total : 1);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u64(buf, version);
    if (data->mv_size > 0 && data->mv_data) {
        memcpy(buf + DISLMDB_VERSIONED_HEADER, data->mv_data, data->mv_size);
    }
    MDB_val packed = {.mv_size = total, .mv_data = buf};
    int rc = dislmdb_put(txn, dbi, key, &packed, flags);
    free(buf);
    return rc;
}

int dislmdb_get_versioned(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key,
                          uint64_t *version_out, void *data_out, size_t *data_cap)
{
    if (!txn || txn->magic != DISLMDB_MAGIC || !key || !data_cap) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!txn->mdb_txn) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    int arc = dislmdb_acl_require_key(txn->env, DISLMDB_ACL_READ, key->mv_data,
                                      key->mv_size);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }

    MDB_val got;
    int rc = mdb_get(txn->mdb_txn, dbi, key, &got);
    if (rc != 0) {
        return rc;
    }
    if (got.mv_size < DISLMDB_VERSIONED_HEADER || !got.mv_data) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    uint64_t ver = dislmdb_read_u64((const uint8_t *)got.mv_data);
    size_t plen = got.mv_size - DISLMDB_VERSIONED_HEADER;
    if (version_out) {
        *version_out = ver;
    }
    if (!data_out) {
        *data_cap = plen;
        return DISLMDB_SUCCESS;
    }
    if (*data_cap < plen) {
        *data_cap = plen;
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    if (plen > 0) {
        memcpy(data_out, (const uint8_t *)got.mv_data + DISLMDB_VERSIONED_HEADER,
               plen);
    }
    *data_cap = plen;
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_authorize_oplog(DISLMDB_env *env, const char *principal,
                                const uint8_t *data, size_t size)
{
    if (!env || !data || size < 12) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_SUCCESS;
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

    int rc = DISLMDB_SUCCESS;
    for (uint32_t i = 0; i < count; i++) {
        if (o + 4 + 2 > size) {
            rc = DISLMDB_ERR_MESSAGE_VALIDATION;
            break;
        }
        DISLMDB_OP_TYPE type = (DISLMDB_OP_TYPE)dislmdb_read_u32(data + o);
        o += 4;
        uint16_t nlen = dislmdb_read_u16(data + o);
        o += 2;
        if (o + nlen + 4 > size || nlen >= 64) {
            rc = DISLMDB_ERR_MESSAGE_VALIDATION;
            break;
        }
        char dbname[64];
        memset(dbname, 0, sizeof(dbname));
        if (nlen) {
            memcpy(dbname, data + o, nlen);
        }
        o += nlen;
        if (dislmdb_dbname_is_reserved(dbname)) {
            rc = DISLMDB_ERR_NOT_AUTHORIZED;
            break;
        }
        uint32_t klen = dislmdb_read_u32(data + o);
        o += 4;
        if (o + klen + 4 > size) {
            rc = DISLMDB_ERR_MESSAGE_VALIDATION;
            break;
        }
        const uint8_t *key = data + o;
        o += klen;
        uint32_t vlen = dislmdb_read_u32(data + o);
        o += 4;
        if (o + vlen + 4 > size) {
            rc = DISLMDB_ERR_MESSAGE_VALIDATION;
            break;
        }
        o += vlen;
        o += 4; /* flags */
        if (type == DISLMDB_OP_TYPE_PUT || type == DISLMDB_OP_TYPE_DEL) {
            rc = dislmdb_acl_require_key(env, DISLMDB_ACL_WRITE, key, klen);
            if (rc != DISLMDB_SUCCESS) {
                break;
            }
        }
    }
    (void)dislmdb_acl_set_thread_principal(
        env, saved[0] != '\0' ? saved : NULL);
    return rc;
}

int dislmdb_sync_wrap_oplog(DISLMDB_env *env, const uint8_t *oplog, size_t oplog_len,
                            uint8_t **out, size_t *out_len)
{
    if (!env || !oplog || oplog_len == 0 || !out || !out_len) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    const char *origin = env->local_node_id;
    size_t olen = strnlen(origin, 63);
    const char *who = dislmdb_acl_current_principal(env);
    size_t plen = 0;
    if (who && who[0] != '\0') {
        plen = strnlen(who, DISLMDB_ACL_PRINCIPAL_MAX);
    }
    size_t need = 4 + 1 + olen + 1 + plen + oplog_len;
    uint8_t *buf = malloc(need);
    if (!buf) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, DISLMDB_SYNC_WRAP_MAGIC);
    o += 4;
    buf[o++] = (uint8_t)olen;
    if (olen) {
        memcpy(buf + o, origin, olen);
        o += olen;
    }
    buf[o++] = (uint8_t)plen;
    if (plen) {
        memcpy(buf + o, who, plen);
        o += plen;
    }
    memcpy(buf + o, oplog, oplog_len);
    *out = buf;
    *out_len = need;
    return DISLMDB_SUCCESS;
}

int dislmdb_sync_unwrap_authorize(DISLMDB_env *env, const char *sender_id,
                                  const uint8_t *data, size_t size,
                                  const uint8_t **oplog_out, size_t *oplog_len,
                                  bool *oplog_owned)
{
    if (!env || !data || size < 12 || !oplog_out || !oplog_len || !oplog_owned) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    *oplog_out = NULL;
    *oplog_len = 0;
    *oplog_owned = false;

    uint32_t magic = dislmdb_read_u32(data);
    if (magic == DISLMDB_OPLOG_MAGIC) {
        /* Legacy bare OPLG: only when ACL is off (pre-SYN2 peers / solo). */
        if (env->config.enable_acl) {
            return DISLMDB_ERR_NOT_AUTHORIZED;
        }
        *oplog_out = data;
        *oplog_len = size;
        return DISLMDB_SUCCESS;
    }
    if (magic != DISLMDB_SYNC_WRAP_MAGIC || size < 6) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    size_t o = 4;
    uint8_t olen = data[o++];
    if ((size_t)o + olen + 1 > size || olen >= 64) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    char origin[64];
    memset(origin, 0, sizeof(origin));
    if (olen) {
        memcpy(origin, data + o, olen);
    }
    o += olen;
    if (sender_id && sender_id[0] != '\0' &&
        strncmp(origin, sender_id, 63) != 0) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    uint8_t plen = data[o++];
    if ((size_t)o + plen > size || plen > DISLMDB_ACL_PRINCIPAL_MAX) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    char principal[DISLMDB_ACL_PRINCIPAL_MAX + 1];
    memset(principal, 0, sizeof(principal));
    if (plen) {
        memcpy(principal, data + o, plen);
    }
    o += plen;
    {
        int arc = dislmdb_acl_authorize_asserted_principal(
            env, origin, principal[0] ? principal : NULL);
        if (arc != DISLMDB_SUCCESS) {
            return arc;
        }
    }
    if (o >= size) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    const uint8_t *oplog = data + o;
    size_t olen_payload = size - o;
    int arc = dislmdb_acl_authorize_oplog(env, principal[0] ? principal : NULL,
                                         oplog, olen_payload);
    if (arc != DISLMDB_SUCCESS) {
        return arc;
    }
    *oplog_out = oplog;
    *oplog_len = olen_payload;
    return DISLMDB_SUCCESS;
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
        if (dislmdb_dbname_is_reserved(dbname)) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_NOT_AUTHORIZED;
        }
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
