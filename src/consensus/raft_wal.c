/**
 * @file raft_wal.c
 * @brief LMDB-backed Raft WAL: hard state, per-index entries, snapshot meta
 */
#include "raft_wal.h"

#include <stdlib.h>
#include <string.h>

#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "lmdb.h"

#define HS_KEY "hs"
#define SNAP_KEY "snap"
#define ENTRY_KEY_LEN 9 /* 'e' + u64 BE index */

/* hs blob: term u64 + voted_for[64] + commit u64 + last_applied u64 */
#define HS_SIZE (8 + 64 + 8 + 8)
/* snap: last_included_index u64 + last_included_term u64 */
#define SNAP_SIZE 16
/* entry: term u64 + index u64 + len u32 + data */
#define ENTRY_HDR 20

static void entry_key(uint8_t out[ENTRY_KEY_LEN], uint64_t index)
{
    out[0] = 'e';
    dislmdb_write_u64(out + 1, index);
}

static int open_raft_dbi(MDB_txn *txn, MDB_dbi *dbi, unsigned flags)
{
    return mdb_dbi_open(txn, DISLMDB_RAFT_DBI, flags, dbi);
}

static void wal_on_hard_state(uint64_t term, const char *voted_for,
                              uint64_t commit_index, uint64_t last_applied, void *ud)
{
    DISLMDB_env *env = ud;
    if (!env || !env->mdb_env || !env->config.consensus.persist_state) {
        return;
    }
    MDB_txn *txn = NULL;
    if (mdb_txn_begin(env->mdb_env, NULL, 0, &txn) != 0) {
        return;
    }
    MDB_dbi dbi;
    if (open_raft_dbi(txn, &dbi, MDB_CREATE) != 0) {
        mdb_txn_abort(txn);
        return;
    }
    uint8_t buf[HS_SIZE];
    memset(buf, 0, sizeof(buf));
    size_t o = 0;
    dislmdb_write_u64(buf + o, term); o += 8;
    if (voted_for) {
        strncpy((char *)(buf + o), voted_for, 63);
    }
    o += 64;
    dislmdb_write_u64(buf + o, commit_index); o += 8;
    dislmdb_write_u64(buf + o, last_applied);
    MDB_val k = {.mv_size = strlen(HS_KEY), .mv_data = (void *)HS_KEY};
    MDB_val v = {.mv_size = HS_SIZE, .mv_data = buf};
    if (mdb_put(txn, dbi, &k, &v, 0) != 0) {
        mdb_txn_abort(txn);
        return;
    }
    if (mdb_txn_commit(txn) != 0) {
        return;
    }
    /* Hard state is election-critical — always force sync. */
    (void)mdb_env_sync(env->mdb_env, 1);
}

static void wal_maybe_sync_data(DISLMDB_env *env)
{
    uint32_t every = env->config.consensus.raft_wal_sync_every;
    if (every == 0) {
        return; /* checkpoint / close only */
    }
    env->raft_wal_appends++;
    if ((env->raft_wal_appends % every) == 0) {
        (void)mdb_env_sync(env->mdb_env, 1);
    }
}

static void wal_on_log_append(uint64_t index, uint64_t term,
                              const uint8_t *data, size_t len, void *ud)
{
    DISLMDB_env *env = ud;
    if (!env || !env->mdb_env || !env->config.consensus.persist_state || index == 0) {
        return;
    }
    if (len > DISLMDB_MAX_MESSAGE_SIZE) {
        return;
    }
    MDB_txn *txn = NULL;
    if (mdb_txn_begin(env->mdb_env, NULL, 0, &txn) != 0) {
        return;
    }
    MDB_dbi dbi;
    if (open_raft_dbi(txn, &dbi, MDB_CREATE) != 0) {
        mdb_txn_abort(txn);
        return;
    }
    size_t need = ENTRY_HDR + len;
    uint8_t *buf = malloc(need);
    if (!buf) {
        mdb_txn_abort(txn);
        return;
    }
    size_t o = 0;
    dislmdb_write_u64(buf + o, term); o += 8;
    dislmdb_write_u64(buf + o, index); o += 8;
    dislmdb_write_u32(buf + o, (uint32_t)len); o += 4;
    if (len > 0 && data) {
        memcpy(buf + o, data, len);
    }
    uint8_t keyb[ENTRY_KEY_LEN];
    entry_key(keyb, index);
    MDB_val k = {.mv_size = ENTRY_KEY_LEN, .mv_data = keyb};
    MDB_val v = {.mv_size = need, .mv_data = buf};
    int rc = mdb_put(txn, dbi, &k, &v, 0);
    free(buf);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return;
    }
    if (mdb_txn_commit(txn) != 0) {
        return;
    }
    wal_maybe_sync_data(env);
}

static void wal_on_log_truncate(uint64_t from_index, void *ud)
{
    DISLMDB_env *env = ud;
    if (!env || !env->mdb_env || !env->config.consensus.persist_state || from_index == 0) {
        return;
    }
    MDB_txn *txn = NULL;
    if (mdb_txn_begin(env->mdb_env, NULL, 0, &txn) != 0) {
        return;
    }
    MDB_dbi dbi;
    if (open_raft_dbi(txn, &dbi, MDB_CREATE) != 0) {
        mdb_txn_abort(txn);
        return;
    }
    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, dbi, &cur) != 0) {
        mdb_txn_abort(txn);
        return;
    }
    MDB_val k, v;
    uint8_t start[ENTRY_KEY_LEN];
    entry_key(start, from_index);
    k.mv_size = ENTRY_KEY_LEN;
    k.mv_data = start;
    int rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while (rc == 0) {
        if (k.mv_size != ENTRY_KEY_LEN || ((const uint8_t *)k.mv_data)[0] != 'e') {
            break;
        }
        uint64_t idx = dislmdb_read_u64((const uint8_t *)k.mv_data + 1);
        if (idx < from_index) {
            rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
            continue;
        }
        if (mdb_cursor_del(cur, 0) != 0) {
            break;
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    (void)mdb_txn_commit(txn);
}

#define RFSM_MAGIC 0x5246534du /* 'RFSM' */
#define RFSM_VERSION 1u
#define RFSM_MAX_DBIS 64u

static bool fsm_is_internal_name(const char *name, size_t nlen)
{
    return nlen >= 2 && name[0] == '_' && name[1] == '_';
}

/** True if main-DB key is a named sub-DB root (must not dump as user KV). */
static bool fsm_main_key_is_subdb(MDB_txn *txn, const MDB_val *k)
{
    if (!k || k->mv_size == 0 || k->mv_size >= 64 || !k->mv_data) {
        return false;
    }
    char name[64];
    memcpy(name, k->mv_data, k->mv_size);
    name[k->mv_size] = '\0';
    MDB_dbi sub;
    return mdb_dbi_open(txn, name, 0, &sub) == 0;
}

/** Measure KV payload size for an open DBI (cursor walk). */
static int fsm_measure_dbi(MDB_txn *txn, MDB_dbi dbi, bool skip_subdb_roots,
                           size_t *need, uint32_t *count)
{
    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, dbi, &cur) != 0) {
        return -1;
    }
    uint32_t n = 0;
    size_t bytes = 0;
    MDB_val k, v;
    int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
    while (rc == 0) {
        if (!(skip_subdb_roots && fsm_main_key_is_subdb(txn, &k))) {
            bytes += 4 + k.mv_size + 4 + v.mv_size;
            n++;
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    *need += bytes;
    *count = n;
    return 0;
}

static int fsm_write_dbi(MDB_txn *txn, MDB_dbi dbi, bool skip_subdb_roots,
                         uint8_t *buf, size_t *o, uint32_t kv_count)
{
    dislmdb_write_u32(buf + *o, kv_count);
    *o += 4;
    if (kv_count == 0) {
        return 0;
    }
    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, dbi, &cur) != 0) {
        return -1;
    }
    MDB_val k, v;
    int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
    uint32_t written = 0;
    while (rc == 0 && written < kv_count) {
        if (!(skip_subdb_roots && fsm_main_key_is_subdb(txn, &k))) {
            dislmdb_write_u32(buf + *o, (uint32_t)k.mv_size);
            *o += 4;
            memcpy(buf + *o, k.mv_data, k.mv_size);
            *o += k.mv_size;
            dislmdb_write_u32(buf + *o, (uint32_t)v.mv_size);
            *o += 4;
            memcpy(buf + *o, v.mv_data, v.mv_size);
            *o += v.mv_size;
            written++;
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    return 0;
}

/**
 * Collect unnamed + all named user DBIs (skip __* internal namespaces).
 * names[i] empty string = unnamed main DB.
 */
static uint32_t fsm_collect_db_names(MDB_txn *txn, char names[][64], uint32_t cap)
{
    uint32_t n = 0;
    if (n < cap) {
        names[n][0] = '\0'; /* unnamed */
        n++;
    }
    /* Prefer known app DBI. */
    {
        MDB_dbi dbi;
        if (mdb_dbi_open(txn, "kv", 0, &dbi) == 0 && n < cap) {
            strncpy(names[n], "kv", 63);
            names[n][63] = '\0';
            n++;
        }
    }
    MDB_dbi main_dbi;
    if (mdb_dbi_open(txn, NULL, 0, &main_dbi) != 0) {
        return n;
    }
    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, main_dbi, &cur) != 0) {
        return n;
    }
    MDB_val k, v;
    int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
    while (rc == 0 && n < cap) {
        if (k.mv_size > 0 && k.mv_size < 64 && k.mv_data) {
            char name[64];
            memcpy(name, k.mv_data, k.mv_size);
            name[k.mv_size] = '\0';
            if (!fsm_is_internal_name(name, k.mv_size)) {
                MDB_dbi sub;
                if (mdb_dbi_open(txn, name, 0, &sub) == 0) {
                    bool dup = false;
                    for (uint32_t i = 0; i < n; i++) {
                        if (strcmp(names[i], name) == 0) {
                            dup = true;
                            break;
                        }
                    }
                    if (!dup) {
                        memcpy(names[n], name, k.mv_size + 1);
                        n++;
                    }
                }
            }
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    return n;
}

static int fsm_snapshot_all(uint64_t last_included, uint8_t **out, size_t *out_len,
                            void *ud)
{
    (void)last_included;
    DISLMDB_env *env = ud;
    if (!env || !env->mdb_env || !out || !out_len) {
        return -1;
    }
    *out = NULL;
    *out_len = 0;
    MDB_txn *txn = NULL;
    if (mdb_txn_begin(env->mdb_env, NULL, MDB_RDONLY, &txn) != 0) {
        return -1;
    }
    char names[RFSM_MAX_DBIS][64];
    uint32_t db_count = fsm_collect_db_names(txn, names, RFSM_MAX_DBIS);
    uint32_t counts[RFSM_MAX_DBIS];
    memset(counts, 0, sizeof(counts));
    size_t need = 12;
    for (uint32_t i = 0; i < db_count; i++) {
        size_t nlen = strnlen(names[i], 63);
        need += 4 + nlen + 4; /* name_len + name + kv_count */
        MDB_dbi dbi;
        int orc = mdb_dbi_open(txn, nlen ? names[i] : NULL, 0, &dbi);
        if (orc == MDB_NOTFOUND) {
            counts[i] = 0;
            continue;
        }
        if (orc != 0) {
            mdb_txn_abort(txn);
            return -1;
        }
        bool skip_roots = (nlen == 0);
        if (fsm_measure_dbi(txn, dbi, skip_roots, &need, &counts[i]) != 0) {
            mdb_txn_abort(txn);
            return -1;
        }
    }
    uint8_t *buf = malloc(need ? need : 12);
    if (!buf) {
        mdb_txn_abort(txn);
        return -1;
    }
    size_t o = 0;
    dislmdb_write_u32(buf + o, RFSM_MAGIC); o += 4;
    dislmdb_write_u32(buf + o, RFSM_VERSION); o += 4;
    dislmdb_write_u32(buf + o, db_count); o += 4;
    for (uint32_t i = 0; i < db_count; i++) {
        size_t nlen = strnlen(names[i], 63);
        dislmdb_write_u32(buf + o, (uint32_t)nlen); o += 4;
        if (nlen) {
            memcpy(buf + o, names[i], nlen);
            o += nlen;
        }
        MDB_dbi dbi;
        int orc = mdb_dbi_open(txn, nlen ? names[i] : NULL, 0, &dbi);
        if (orc == MDB_NOTFOUND) {
            dislmdb_write_u32(buf + o, 0); o += 4;
            continue;
        }
        bool skip_roots = (nlen == 0);
        if (orc != 0 ||
            fsm_write_dbi(txn, dbi, skip_roots, buf, &o, counts[i]) != 0) {
            free(buf);
            mdb_txn_abort(txn);
            return -1;
        }
    }
    mdb_txn_abort(txn);
    *out = buf;
    *out_len = o;
    return 0;
}

static int fsm_restore_all(uint64_t last_included, uint64_t last_included_term,
                           const uint8_t *data, size_t len, void *ud)
{
    (void)last_included;
    (void)last_included_term;
    DISLMDB_env *env = ud;
    if (!env || !env->mdb_env || !data || len < 12) {
        return -1;
    }
    if (dislmdb_read_u32(data) != RFSM_MAGIC ||
        dislmdb_read_u32(data + 4) != RFSM_VERSION) {
        return -1;
    }
    uint32_t db_count = dislmdb_read_u32(data + 8);
    size_t o = 12;
    MDB_txn *txn = NULL;
    if (mdb_txn_begin(env->mdb_env, NULL, 0, &txn) != 0) {
        return -1;
    }
    for (uint32_t d = 0; d < db_count; d++) {
        if (o + 4 > len) {
            mdb_txn_abort(txn);
            return -1;
        }
        uint32_t nlen = dislmdb_read_u32(data + o); o += 4;
        if (o + nlen + 4 > len || nlen >= 64) {
            mdb_txn_abort(txn);
            return -1;
        }
        char name[64];
        memcpy(name, data + o, nlen);
        name[nlen] = '\0';
        o += nlen;
        /* Skip internal / raft meta namespaces. */
        if (fsm_is_internal_name(name, nlen)) {
            uint32_t kc = dislmdb_read_u32(data + o); o += 4;
            for (uint32_t i = 0; i < kc; i++) {
                if (o + 4 > len) {
                    mdb_txn_abort(txn);
                    return -1;
                }
                uint32_t kl = dislmdb_read_u32(data + o); o += 4;
                if (o + kl + 4 > len) {
                    mdb_txn_abort(txn);
                    return -1;
                }
                o += kl;
                uint32_t vl = dislmdb_read_u32(data + o); o += 4;
                if (o + vl > len) {
                    mdb_txn_abort(txn);
                    return -1;
                }
                o += vl;
            }
            continue;
        }
        MDB_dbi dbi;
        if (mdb_dbi_open(txn, nlen ? name : NULL, MDB_CREATE, &dbi) != 0) {
            mdb_txn_abort(txn);
            return -1;
        }
        /*
         * Clear existing user keys. For the unnamed/main DBI, never delete
         * sub-database root entries — snapshots skip those (and __* internals),
         * so deleting them here would permanently drop meta/ACL/WAL/bytecode.
         */
        MDB_cursor *cur = NULL;
        if (mdb_cursor_open(txn, dbi, &cur) == 0) {
            MDB_val k, v;
            int crc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
            while (crc == 0) {
                if (nlen == 0 && fsm_main_key_is_subdb(txn, &k)) {
                    crc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                    continue;
                }
                if (mdb_cursor_del(cur, 0) != 0) {
                    break;
                }
                crc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
            }
            mdb_cursor_close(cur);
        }
        uint32_t kv_count = dislmdb_read_u32(data + o); o += 4;
        for (uint32_t i = 0; i < kv_count; i++) {
            if (o + 4 > len) {
                mdb_txn_abort(txn);
                return -1;
            }
            uint32_t kl = dislmdb_read_u32(data + o); o += 4;
            if (o + kl + 4 > len) {
                mdb_txn_abort(txn);
                return -1;
            }
            MDB_val key = {.mv_size = kl, .mv_data = (void *)(data + o)};
            o += kl;
            uint32_t vl = dislmdb_read_u32(data + o); o += 4;
            if (o + vl > len) {
                mdb_txn_abort(txn);
                return -1;
            }
            MDB_val val = {.mv_size = vl, .mv_data = (void *)(data + o)};
            o += vl;
            if (mdb_put(txn, dbi, &key, &val, 0) != 0) {
                mdb_txn_abort(txn);
                return -1;
            }
        }
    }
    if (mdb_txn_commit(txn) != 0) {
        return -1;
    }
    return 0;
}

int dislmdb_raft_wal_attach(DISLMDB_env *env, RaftNode *node)
{
    if (!env || !node) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    raft_set_fsm_hooks(node, fsm_snapshot_all, fsm_restore_all, env);
    if (!env->config.consensus.persist_state) {
        return DISLMDB_SUCCESS;
    }
    RaftPersistHooks hooks = {
        .on_hard_state = wal_on_hard_state,
        .on_log_append = wal_on_log_append,
        .on_log_truncate = wal_on_log_truncate,
    };
    raft_set_persist_hooks(node, &hooks, env);
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_wal_load(DISLMDB_env *env, RaftNode *node)
{
    if (!env || !node || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.consensus.persist_state) {
        return DISLMDB_SUCCESS;
    }

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = open_raft_dbi(txn, &dbi, 0);
    if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(txn);
        return DISLMDB_SUCCESS;
    }
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    uint64_t snap_idx = 0;
    uint64_t snap_term = 0;
    MDB_val k, v;
    k.mv_size = strlen(SNAP_KEY);
    k.mv_data = (void *)SNAP_KEY;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= SNAP_SIZE) {
        snap_idx = dislmdb_read_u64(v.mv_data);
        snap_term = dislmdb_read_u64((const uint8_t *)v.mv_data + 8);
        (void)snap_term;
    }

    uint64_t term = 0;
    char voted_for[64];
    memset(voted_for, 0, sizeof(voted_for));
    uint64_t commit_index = 0;
    uint64_t last_applied = 0;
    k.mv_size = strlen(HS_KEY);
    k.mv_data = (void *)HS_KEY;
    if (mdb_get(txn, dbi, &k, &v) == 0 && v.mv_size >= HS_SIZE) {
        const uint8_t *p = v.mv_data;
        term = dislmdb_read_u64(p);
        memcpy(voted_for, p + 8, 63);
        voted_for[63] = '\0';
        commit_index = dislmdb_read_u64(p + 8 + 64);
        last_applied = dislmdb_read_u64(p + 8 + 64 + 8);
    }
    if (snap_idx > last_applied) {
        last_applied = snap_idx;
    }
    if (snap_idx > commit_index) {
        commit_index = snap_idx;
    }

    RaftError rerr = raft_restore_hard_state(node, term, voted_for, commit_index, last_applied);
    if (rerr != RAFT_OK) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_CONSENSUS_FAILED;
    }
    if (snap_idx > 0) {
        rerr = raft_restore_snapshot_meta(node, snap_idx, snap_term);
        if (rerr != RAFT_OK) {
            mdb_txn_abort(txn);
            return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }

    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, dbi, &cur) != 0) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_TXN_FAILED;
    }
    uint8_t start[ENTRY_KEY_LEN];
    entry_key(start, snap_idx + 1);
    k.mv_size = ENTRY_KEY_LEN;
    k.mv_data = start;
    rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while (rc == 0) {
        if (k.mv_size != ENTRY_KEY_LEN || ((const uint8_t *)k.mv_data)[0] != 'e') {
            break;
        }
        if (v.mv_size < ENTRY_HDR) {
            break;
        }
        const uint8_t *p = v.mv_data;
        uint64_t eterm = dislmdb_read_u64(p);
        uint64_t eindex = dislmdb_read_u64(p + 8);
        uint32_t elen = dislmdb_read_u32(p + 16);
        if (ENTRY_HDR + (size_t)elen > v.mv_size) {
            break;
        }
        if (eindex <= snap_idx) {
            rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
            continue;
        }
        rerr = raft_restore_log_entry(node, eindex, eterm,
                                      elen ? p + ENTRY_HDR : NULL, elen);
        if (rerr != RAFT_OK) {
            mdb_cursor_close(cur);
            mdb_txn_abort(txn);
            return DISLMDB_ERR_CONSENSUS_FAILED;
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);

    if (snap_idx > 0) {
        /* Ensure commit/applied reflect snapshot even with empty tail. */
        (void)raft_restore_hard_state(node, term, voted_for, commit_index, last_applied);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_raft_wal_snapshot(DISLMDB_env *env, RaftNode *node)
{
    if (!env || !node || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.consensus.persist_state) {
        return DISLMDB_SUCCESS;
    }
    /* Compact only through indices every peer has already matched (safe). */
    uint64_t applied = raft_safe_compact_index(node);
    if (applied == 0) {
        return DISLMDB_SUCCESS;
    }
    uint64_t snap_term = raft_term(node);

    MDB_txn *txn = NULL;
    int rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = open_raft_dbi(txn, &dbi, MDB_CREATE);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    /* Compact first so log_base_term is known, then persist snap with that term. */
    mdb_txn_abort(txn);
    RaftError cerr = raft_compact_log_through(node, applied);
    if (cerr != RAFT_OK && cerr != RAFT_ERR_INVALID) {
        return DISLMDB_ERR_CHECKPOINT_FAILED;
    }
    snap_term = raft_log_base_term(node);
    if (snap_term == 0) {
        snap_term = raft_term(node);
    }

    rc = mdb_txn_begin(env->mdb_env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    rc = open_raft_dbi(txn, &dbi, MDB_CREATE);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return rc;
    }

    uint8_t sbuf[SNAP_SIZE];
    dislmdb_write_u64(sbuf, applied);
    dislmdb_write_u64(sbuf + 8, snap_term);
    MDB_val k = {.mv_size = strlen(SNAP_KEY), .mv_data = (void *)SNAP_KEY};
    MDB_val v = {.mv_size = SNAP_SIZE, .mv_data = sbuf};
    if (mdb_put(txn, dbi, &k, &v, 0) != 0) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_CHECKPOINT_FAILED;
    }

    /* Delete durable entries with index <= applied */
    MDB_cursor *cur = NULL;
    if (mdb_cursor_open(txn, dbi, &cur) != 0) {
        mdb_txn_abort(txn);
        return DISLMDB_ERR_TXN_FAILED;
    }
    uint8_t start[ENTRY_KEY_LEN];
    entry_key(start, 1);
    k.mv_size = ENTRY_KEY_LEN;
    k.mv_data = start;
    rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while (rc == 0) {
        if (k.mv_size != ENTRY_KEY_LEN || ((const uint8_t *)k.mv_data)[0] != 'e') {
            break;
        }
        uint64_t idx = dislmdb_read_u64((const uint8_t *)k.mv_data + 1);
        if (idx > applied) {
            break;
        }
        if (mdb_cursor_del(cur, 0) != 0) {
            break;
        }
        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    if (mdb_txn_commit(txn) != 0) {
        return DISLMDB_ERR_CHECKPOINT_FAILED;
    }

    return dislmdb_raft_wal_sync(env);
}

int dislmdb_raft_wal_sync(DISLMDB_env *env)
{
    if (!env || !env->mdb_env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = mdb_env_sync(env->mdb_env, 1);
    return rc == 0 ? DISLMDB_SUCCESS : rc;
}
