/**
 * @file e2e_runner.c
 * @brief End-to-end scenario runner with deterministic structured output.
 *
 * Reads a scenario script from argv[1] (or stdin) and writes one result line
 * per command to stdout. Golden files under tests/e2e/expected/ are compared
 * by the e2e harness after a run.
 *
 * Scenario commands (whitespace-separated tokens; '#' starts a comment):
 *   OPEN path=<dir> [mapsize=<n>] [port=<n>]
 *   SET_KEY hex=<64-hex-chars>
 *   PUT db=<name> key=<k> value=<v>
 *   DEL db=<name> key=<k>
 *   GET db=<name> key=<k>
 *   COMMIT
 *   ABORT
 *   BEGIN [readonly]
 *   CHECKPOINT
 *   STATE_TRANSFER
 *   METRICS
 *   SYNC
 *   CLOSE
 *   REOPEN
 *   VERSION
 *   BYTECODE_STORE id=<id> hex=<bytes>
 *   BYTECODE_GET id=<id>
 *   ACL_GRANT principal=<id> perms=read|write|admin|all
 *   ACL_REVOKE principal=<id> perms=...
 *   ACL_GRANT_PREFIX principal=<id> prefix=<p> perms=read|write
 *   ACL_REVOKE_PREFIX principal=<id> prefix=<p> perms=...
 *   ACL_GET_PREFIX principal=<id> prefix=<p>
 *   ACL_ROLE_DEFINE role=<name> [prefix=<p>] perms=read|write|admin|all
 *   ACL_ROLE_UNDEFINE role=<name>
 *   ACL_ROLE_GET role=<name>
 *   ACL_ROLE_ASSIGN principal=<id> role=<name>
 *   ACL_ROLE_UNASSIGN principal=<id> role=<name>
 *   ACL_EFFECTIVE principal=<id>
 *   ACL_PRINCIPAL name=<id>
 *   ACL_GET principal=<id>
 *   INDEX_PUT primary=<db> index=<db> pkey=<k> pval=<v> skey=<k>
 *   INDEX_DEL primary=<db> index=<db> pkey=<k> skey=<k>
 *   INDEX_GET primary=<db> index=<db> skey=<k>
 *   INDEX_SCAN primary=<db> index=<db> [prefix=<p>] [limit=<n>]
 *   PUT_VERSIONED db=<name> key=<k> value=<v> version=<u64>
 *   GET_VERSIONED db=<name> key=<k>
 *   REGION | LOCALITY | TOPO | VOTING
 *   EXPECT_OK | EXPECT_ERR <code>
 *   ECHO <text...>
 */
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    DISLMDB_env_config cfg;
    char path[512];
    int last_rc;
    bool open;
} e2e_state;

static void trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || isspace((unsigned char)s[n - 1]))) {
        s[--n] = '\0';
    }
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static char *tok_key(char *tok, const char *want)
{
    size_t wl = strlen(want);
    if (strncmp(tok, want, wl) == 0 && tok[wl] == '=') {
        return tok + wl + 1;
    }
    return NULL;
}

static int parse_hex(const char *hex, uint8_t *out, size_t max, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    *out_len = n / 2;
    return 0;
}

static void emit(const char *tag, const char *msg)
{
    printf("%s %s\n", tag, msg);
    fflush(stdout);
}

static void emit_rc(const char *tag, int rc)
{
    printf("%s rc=%d err=%s\n", tag, rc, dislmdb_strerror(rc));
    fflush(stdout);
}

typedef struct {
    size_t count;
} e2e_scan_acc;

static int e2e_scan_cb(const MDB_val *secondary_key, const MDB_val *primary_key,
                       const MDB_val *primary_val, void *user)
{
    (void)secondary_key;
    (void)primary_key;
    (void)primary_val;
    e2e_scan_acc *acc = (e2e_scan_acc *)user;
    if (acc) {
        acc->count++;
    }
    return 0;
}

static unsigned parse_perms(const char *v)
{
    unsigned perms = 0;
    if (!v) {
        return 0;
    }
    if (strstr(v, "all")) {
        return DISLMDB_ACL_ALL;
    }
    if (strstr(v, "read")) {
        perms |= DISLMDB_ACL_READ;
    }
    if (strstr(v, "write")) {
        perms |= DISLMDB_ACL_WRITE;
    }
    if (strstr(v, "admin")) {
        perms |= DISLMDB_ACL_ADMIN;
    }
    return perms;
}

static void reset_cfg(e2e_state *st)
{
    dislmdb_env_config_init(&st->cfg);
    st->cfg.path = st->path;
    st->cfg.mapsize = 16 * 1024 * 1024;
    st->cfg.maxdbs = 32;
    st->cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    st->cfg.consensus.fault_tolerance = 0;
    st->cfg.consensus.enable_liveness = true;
    st->cfg.consensus.persist_state = true;
    st->cfg.consensus.persist_cluster_key = false;
    st->cfg.network.enable_message_auth = true;
    st->cfg.network.enable_payload_encryption = true;
    st->cfg.network.local_port = 29765;
}

static int cmd_open(e2e_state *st, char **args, int nargs)
{
    strncpy(st->path, "./e2e_workdir", sizeof(st->path) - 1);
    reset_cfg(st);
    for (int i = 0; i < nargs; i++) {
        char *v;
        if ((v = tok_key(args[i], "path"))) {
            strncpy(st->path, v, sizeof(st->path) - 1);
            st->cfg.path = st->path;
        } else if ((v = tok_key(args[i], "mapsize"))) {
            st->cfg.mapsize = (size_t)strtoull(v, NULL, 10);
        } else if ((v = tok_key(args[i], "port"))) {
            st->cfg.network.local_port = (uint16_t)atoi(v);
        } else if ((v = tok_key(args[i], "persist_key"))) {
            st->cfg.consensus.persist_cluster_key = (atoi(v) != 0);
        } else if ((v = tok_key(args[i], "acl"))) {
            st->cfg.enable_acl = (atoi(v) != 0);
        } else if ((v = tok_key(args[i], "region"))) {
            strncpy(st->cfg.region, v, sizeof(st->cfg.region) - 1);
        } else if ((v = tok_key(args[i], "locality"))) {
            strncpy(st->cfg.locality, v, sizeof(st->cfg.locality) - 1);
        } else if ((v = tok_key(args[i], "topo"))) {
            if (strcmp(v, "mirror") == 0) {
                st->cfg.topology_mode = DISLMDB_TOPO_MIRROR;
            } else if (strcmp(v, "shard") == 0) {
                st->cfg.topology_mode = DISLMDB_TOPO_SHARD;
            } else if (strcmp(v, "hybrid") == 0) {
                st->cfg.topology_mode = DISLMDB_TOPO_HYBRID;
            }
        }
    }
    mkdir(st->path, 0700);
    int rc = dislmdb_env_create(&st->env);
    if (rc) { st->last_rc = rc; emit_rc("OPEN", rc); return rc; }
    rc = dislmdb_env_open(st->env, &st->cfg);
    st->last_rc = rc;
    st->open = (rc == 0);
    emit_rc("OPEN", rc);
    return rc;
}

static int cmd_reopen(e2e_state *st)
{
    if (st->txn) { dislmdb_txn_abort(st->txn); st->txn = NULL; }
    if (st->env) { dislmdb_env_close(st->env); st->env = NULL; st->open = false; }
    /* Preserve path + topology/ACL knobs from the prior OPEN. */
    char path_save[512];
    strncpy(path_save, st->path, sizeof(path_save) - 1);
    path_save[sizeof(path_save) - 1] = '\0';
    bool acl = st->cfg.enable_acl;
    DISLMDB_TOPOLOGY_MODE topo = st->cfg.topology_mode;
    char region[64], locality[64];
    strncpy(region, st->cfg.region, sizeof(region) - 1);
    region[sizeof(region) - 1] = '\0';
    strncpy(locality, st->cfg.locality, sizeof(locality) - 1);
    locality[sizeof(locality) - 1] = '\0';
    uint16_t port = st->cfg.network.local_port;
    bool persist_key = st->cfg.consensus.persist_cluster_key;
    reset_cfg(st);
    strncpy(st->path, path_save, sizeof(st->path) - 1);
    st->cfg.path = st->path;
    st->cfg.enable_acl = acl;
    st->cfg.topology_mode = topo;
    strncpy(st->cfg.region, region, sizeof(st->cfg.region) - 1);
    strncpy(st->cfg.locality, locality, sizeof(st->cfg.locality) - 1);
    st->cfg.network.local_port = port;
    st->cfg.consensus.persist_cluster_key = persist_key;
    int rc = dislmdb_env_create(&st->env);
    if (rc) { st->last_rc = rc; emit_rc("REOPEN", rc); return rc; }
    rc = dislmdb_env_open(st->env, &st->cfg);
    st->last_rc = rc;
    st->open = (rc == 0);
    emit_rc("REOPEN", rc);
    return rc;
}

static int run_line(e2e_state *st, char *line)
{
    trim(line);
    if (!line[0] || line[0] == '#') return 0;

    char *argv[64];
    int argc = 0;
    char *save = NULL;
    for (char *t = strtok_r(line, " \t", &save); t && argc < 64; t = strtok_r(NULL, " \t", &save)) {
        argv[argc++] = t;
    }
    if (argc == 0) return 0;

    const char *cmd = argv[0];
    char **args = argv + 1;
    int nargs = argc - 1;

    if (strcmp(cmd, "ECHO") == 0) {
        printf("ECHO");
        for (int i = 0; i < nargs; i++) printf(" %s", args[i]);
        printf("\n");
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "VERSION") == 0) {
        int maj, min, pat;
        const char *v = dislmdb_version(&maj, &min, &pat);
        printf("VERSION %s major=%d minor=%d patch=%d\n", v, maj, min, pat);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "OPEN") == 0) return cmd_open(st, args, nargs);
    if (strcmp(cmd, "REOPEN") == 0) return cmd_reopen(st);
    if (strcmp(cmd, "CLOSE") == 0) {
        if (st->txn) { dislmdb_txn_abort(st->txn); st->txn = NULL; }
        if (st->env) { dislmdb_env_close(st->env); st->env = NULL; }
        st->open = false;
        emit("CLOSE", "ok");
        return 0;
    }
    if (strcmp(cmd, "SET_KEY") == 0) {
        if (!st->env || !st->open) {
            st->last_rc = DISLMDB_ERR_NOT_INITIALIZED;
            emit_rc("SET_KEY", st->last_rc);
            return st->last_rc;
        }
        uint8_t key[32];
        size_t kl = 0;
        char *hex = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "hex");
            if (v) hex = v;
        }
        if (!hex || parse_hex(hex, key, 32, &kl) || kl != 32) {
            emit("SET_KEY", "rc=-1 err=bad_hex");
            st->last_rc = DISLMDB_ERR_INVALID_PARAMETER;
            return st->last_rc;
        }
        st->last_rc = dislmdb_set_cluster_key(st->env, key);
        emit_rc("SET_KEY", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "BEGIN") == 0) {
        unsigned flags = 0;
        for (int i = 0; i < nargs; i++) {
            if (strcmp(args[i], "readonly") == 0) flags = MDB_RDONLY;
        }
        st->last_rc = dislmdb_txn_begin(st->env, NULL, flags, &st->txn);
        emit_rc("BEGIN", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "COMMIT") == 0) {
        st->last_rc = dislmdb_txn_commit(st->txn);
        st->txn = NULL;
        emit_rc("COMMIT", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ABORT") == 0) {
        dislmdb_txn_abort(st->txn);
        st->txn = NULL;
        emit("ABORT", "ok");
        return 0;
    }
    if (strcmp(cmd, "PUT") == 0 || strcmp(cmd, "DEL") == 0 || strcmp(cmd, "GET") == 0) {
        const char *db = "kv", *key = NULL, *val = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "db"))) db = v;
            else if ((v = tok_key(args[i], "key"))) key = v;
            else if ((v = tok_key(args[i], "value"))) val = v;
        }
        if (!key) {
            emit(cmd, "rc=-1 err=missing_key");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi dbi;
        unsigned oflags = (strcmp(cmd, "GET") == 0) ? 0 : MDB_CREATE;
        st->last_rc = dislmdb_dbi_open(st->txn, db, oflags, &dbi);
        if (st->last_rc) { emit_rc(cmd, st->last_rc); return st->last_rc; }

        MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
        if (strcmp(cmd, "PUT") == 0) {
            if (!val) { emit("PUT", "rc=-1 err=missing_value"); return DISLMDB_ERR_INVALID_PARAMETER; }
            MDB_val v = {.mv_size = strlen(val), .mv_data = (void *)val};
            st->last_rc = dislmdb_put(st->txn, dbi, &k, &v, 0);
            emit_rc("PUT", st->last_rc);
            return st->last_rc;
        }
        if (strcmp(cmd, "DEL") == 0) {
            st->last_rc = dislmdb_del(st->txn, dbi, &k, NULL);
            emit_rc("DEL", st->last_rc);
            return st->last_rc;
        }
        /* GET */
        MDB_txn *mt = dislmdb_get_lmdb_txn(st->txn);
        MDB_val got;
        st->last_rc = mdb_get(mt, dbi, &k, &got);
        if (st->last_rc == 0) {
            char buf[1024];
            size_t n = got.mv_size < sizeof(buf) - 1 ? got.mv_size : sizeof(buf) - 1;
            memcpy(buf, got.mv_data, n);
            buf[n] = '\0';
            printf("GET rc=0 value=%s\n", buf);
        } else {
            emit_rc("GET", st->last_rc);
        }
        fflush(stdout);
        return st->last_rc;
    }
    if (strcmp(cmd, "CHECKPOINT") == 0) {
        st->last_rc = dislmdb_checkpoint(st->env);
        emit_rc("CHECKPOINT", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "STATE_TRANSFER") == 0) {
        st->last_rc = dislmdb_request_state_transfer(st->env);
        emit_rc("STATE_TRANSFER", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "SYNC") == 0) {
        st->last_rc = dislmdb_env_sync(st->env, 1);
        emit_rc("SYNC", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "METRICS") == 0) {
        DISLMDB_metrics m;
        st->last_rc = dislmdb_get_metrics(st->env, &m);
        if (st->last_rc) { emit_rc("METRICS", st->last_rc); return st->last_rc; }
        /* Emit stable boolean-ish fields for golden comparison */
        printf("METRICS commits=%s ops=%s ckpt=%s view=%u seq_nonzero=%s replicas=%u\n",
               m.total_commits > 0 ? "yes" : "no",
               m.total_operations > 0 ? "yes" : "no",
               m.checkpoints > 0 ? "yes" : "no",
               m.current_view,
               m.last_committed_seq > 0 ? "yes" : "no",
               m.replica_count);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "GET_KEY") == 0) {
        uint8_t key[32];
        st->last_rc = dislmdb_get_cluster_key(st->env, key);
        if (st->last_rc) { emit_rc("GET_KEY", st->last_rc); return st->last_rc; }
        printf("GET_KEY rc=0 hex=");
        for (int i = 0; i < 32; i++) printf("%02x", key[i]);
        printf("\n");
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "BYTECODE_STORE") == 0) {
        const char *id = NULL;
        char *hex = NULL;
        unsigned opts = 0;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "id"))) id = v;
            else if ((v = tok_key(args[i], "hex"))) hex = v;
            else if ((v = tok_key(args[i], "opts"))) {
                if (strstr(v, "compress")) {
                    opts |= DISLMDB_BYTECODE_COMPRESS;
                }
                if (strstr(v, "verify")) {
                    opts |= DISLMDB_BYTECODE_VERIFY;
                }
            }
        }
        uint8_t buf[4096];
        size_t bl = 0;
        if (!id || !hex || parse_hex(hex, buf, sizeof(buf), &bl)) {
            emit("BYTECODE_STORE", "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        st->last_rc = dislmdb_store_bytecode(st->env, buf, bl, id, opts);
        emit_rc("BYTECODE_STORE", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "BYTECODE_GET") == 0) {
        const char *id = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "id");
            if (v) id = v;
        }
        uint8_t buf[4096];
        size_t sz = sizeof(buf);
        unsigned opts = 0;
        st->last_rc = dislmdb_get_bytecode(st->env, id, buf, &sz, &opts);
        if (st->last_rc) { emit_rc("BYTECODE_GET", st->last_rc); return st->last_rc; }
        printf("BYTECODE_GET rc=0 size=%zu opts=0x%x hex=", sz, opts);
        for (size_t i = 0; i < sz; i++) printf("%02x", buf[i]);
        printf("\n");
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "ACL_GRANT") == 0 || strcmp(cmd, "ACL_REVOKE") == 0) {
        const char *principal = NULL;
        unsigned perms = 0;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "principal"))) {
                principal = v;
            } else if ((v = tok_key(args[i], "perms"))) {
                perms = parse_perms(v);
            }
        }
        if (!principal) {
            emit(cmd, "rc=-1 err=missing_principal");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        if (strcmp(cmd, "ACL_GRANT") == 0) {
            st->last_rc = dislmdb_acl_grant(st->env, principal, perms);
        } else {
            st->last_rc = dislmdb_acl_revoke(st->env, principal, perms);
        }
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_PRINCIPAL") == 0) {
        const char *name = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "name");
            if (v) {
                name = v;
            }
        }
        st->last_rc = dislmdb_acl_set_principal(st->env, name);
        emit_rc("ACL_PRINCIPAL", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_GET") == 0) {
        const char *principal = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "principal");
            if (v) {
                principal = v;
            }
        }
        unsigned mask = 0;
        st->last_rc = dislmdb_acl_get(st->env, principal, &mask);
        if (st->last_rc) {
            emit_rc("ACL_GET", st->last_rc);
            return st->last_rc;
        }
        printf("ACL_GET rc=0 principal=%s perms=0x%x\n",
               principal ? principal : "", mask);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "ACL_GRANT_PREFIX") == 0 ||
        strcmp(cmd, "ACL_REVOKE_PREFIX") == 0) {
        const char *principal = NULL;
        const char *prefix = NULL;
        unsigned perms = 0;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "principal"))) {
                principal = v;
            } else if ((v = tok_key(args[i], "prefix"))) {
                prefix = v;
            } else if ((v = tok_key(args[i], "perms"))) {
                perms = parse_perms(v) & (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE);
            }
        }
        if (!principal || !prefix) {
            emit(cmd, "rc=-1 err=missing_principal_or_prefix");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        if (strcmp(cmd, "ACL_GRANT_PREFIX") == 0) {
            st->last_rc =
                dislmdb_acl_grant_prefix(st->env, principal, prefix, perms);
        } else {
            st->last_rc =
                dislmdb_acl_revoke_prefix(st->env, principal, prefix, perms);
        }
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_GET_PREFIX") == 0) {
        const char *principal = NULL;
        const char *prefix = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "principal"))) {
                principal = v;
            } else if ((v = tok_key(args[i], "prefix"))) {
                prefix = v;
            }
        }
        unsigned mask = 0;
        st->last_rc =
            dislmdb_acl_get_prefix(st->env, principal, prefix, &mask);
        if (st->last_rc) {
            emit_rc("ACL_GET_PREFIX", st->last_rc);
            return st->last_rc;
        }
        printf("ACL_GET_PREFIX rc=0 principal=%s prefix=%s perms=0x%x\n",
               principal ? principal : "", prefix ? prefix : "", mask);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "ACL_ROLE_DEFINE") == 0) {
        const char *role = NULL, *prefix = NULL;
        unsigned perms = 0;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "role"))) {
                role = v;
            } else if ((v = tok_key(args[i], "prefix"))) {
                prefix = v;
            } else if ((v = tok_key(args[i], "perms"))) {
                perms = parse_perms(v);
            }
        }
        if (!role || perms == 0) {
            emit(cmd, "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        st->last_rc =
            dislmdb_acl_role_define(st->env, role, prefix, perms);
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_ROLE_UNDEFINE") == 0) {
        const char *role = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "role");
            if (v) {
                role = v;
            }
        }
        if (!role) {
            emit(cmd, "rc=-1 err=missing_role");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        st->last_rc = dislmdb_acl_role_undefine(st->env, role);
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_ROLE_GET") == 0) {
        const char *role = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "role");
            if (v) {
                role = v;
            }
        }
        if (!role) {
            emit(cmd, "rc=-1 err=missing_role");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        unsigned mask = 0;
        char pfx[128] = {0};
        st->last_rc =
            dislmdb_acl_role_get(st->env, role, &mask, pfx, sizeof(pfx));
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        printf("ACL_ROLE_GET rc=0 role=%s prefix=%s perms=0x%x\n", role, pfx,
               mask);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "ACL_ROLE_ASSIGN") == 0 ||
        strcmp(cmd, "ACL_ROLE_UNASSIGN") == 0) {
        const char *principal = NULL, *role = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "principal"))) {
                principal = v;
            } else if ((v = tok_key(args[i], "role"))) {
                role = v;
            }
        }
        if (!principal || !role) {
            emit(cmd, "rc=-1 err=missing_principal_or_role");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        if (strcmp(cmd, "ACL_ROLE_ASSIGN") == 0) {
            st->last_rc =
                dislmdb_acl_role_assign(st->env, principal, role);
        } else {
            st->last_rc =
                dislmdb_acl_role_unassign(st->env, principal, role);
        }
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "ACL_EFFECTIVE") == 0) {
        const char *principal = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v = tok_key(args[i], "principal");
            if (v) {
                principal = v;
            }
        }
        if (!principal) {
            emit(cmd, "rc=-1 err=missing_principal");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        unsigned mask = 0;
        st->last_rc = dislmdb_acl_effective(st->env, principal, &mask);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        printf("ACL_EFFECTIVE rc=0 principal=%s perms=0x%x\n", principal,
               mask);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "INDEX_PUT") == 0 || strcmp(cmd, "INDEX_DEL") == 0) {
        const char *primary = NULL, *index = NULL, *pkey = NULL, *pval = NULL,
                   *skey = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "primary"))) {
                primary = v;
            } else if ((v = tok_key(args[i], "index"))) {
                index = v;
            } else if ((v = tok_key(args[i], "pkey"))) {
                pkey = v;
            } else if ((v = tok_key(args[i], "pval"))) {
                pval = v;
            } else if ((v = tok_key(args[i], "skey"))) {
                skey = v;
            }
        }
        if (!primary || !index || !pkey || !skey ||
            (strcmp(cmd, "INDEX_PUT") == 0 && !pval)) {
            emit(cmd, "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi pdbi, idbi;
        st->last_rc =
            dislmdb_dbi_open(st->txn, primary, MDB_CREATE, &pdbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        st->last_rc = dislmdb_dbi_open(st->txn, index, MDB_CREATE, &idbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        MDB_val pk = {.mv_size = strlen(pkey), .mv_data = (void *)pkey};
        MDB_val sk = {.mv_size = strlen(skey), .mv_data = (void *)skey};
        if (strcmp(cmd, "INDEX_PUT") == 0) {
            MDB_val pv = {.mv_size = strlen(pval), .mv_data = (void *)pval};
            st->last_rc =
                dislmdb_index_put(st->txn, pdbi, idbi, &pk, &pv, &sk, 0);
        } else {
            st->last_rc = dislmdb_index_del(st->txn, pdbi, idbi, &pk, &sk);
        }
        emit_rc(cmd, st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "INDEX_GET") == 0) {
        const char *primary = NULL, *index = NULL, *skey = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "primary"))) {
                primary = v;
            } else if ((v = tok_key(args[i], "index"))) {
                index = v;
            } else if ((v = tok_key(args[i], "skey"))) {
                skey = v;
            }
        }
        if (!primary || !index || !skey || !st->txn) {
            emit(cmd, "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi pdbi, idbi;
        st->last_rc = dislmdb_dbi_open(st->txn, primary, 0, &pdbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        st->last_rc = dislmdb_dbi_open(st->txn, index, 0, &idbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        MDB_val sk = {.mv_size = strlen(skey), .mv_data = (void *)skey};
        MDB_val pk = {0}, pv = {0};
        st->last_rc =
            dislmdb_index_get(st->txn, pdbi, idbi, &sk, &pk, &pv);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        printf("INDEX_GET rc=0 pkey=%.*s pval=%.*s\n", (int)pk.mv_size,
               (const char *)pk.mv_data, (int)pv.mv_size,
               (const char *)pv.mv_data);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "INDEX_SCAN") == 0) {
        const char *primary = NULL, *index = NULL, *prefix = NULL;
        size_t limit = 0;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "primary"))) {
                primary = v;
            } else if ((v = tok_key(args[i], "index"))) {
                index = v;
            } else if ((v = tok_key(args[i], "prefix"))) {
                prefix = v;
            } else if ((v = tok_key(args[i], "limit"))) {
                limit = (size_t)strtoull(v, NULL, 10);
            }
        }
        if (!primary || !index || !st->txn) {
            emit(cmd, "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi pdbi, idbi;
        st->last_rc = dislmdb_dbi_open(st->txn, primary, 0, &pdbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        st->last_rc = dislmdb_dbi_open(st->txn, index, 0, &idbi);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        MDB_val pfx_val;
        const MDB_val *pfx_ptr = NULL;
        if (prefix) {
            pfx_val.mv_size = strlen(prefix);
            pfx_val.mv_data = (void *)prefix;
            pfx_ptr = &pfx_val;
        }
        e2e_scan_acc acc = {.count = 0};
        st->last_rc = dislmdb_index_scan(st->txn, pdbi, idbi, NULL, pfx_ptr,
                                         limit, e2e_scan_cb, &acc);
        if (st->last_rc) {
            emit_rc(cmd, st->last_rc);
            return st->last_rc;
        }
        printf("INDEX_SCAN rc=0 count=%zu\n", acc.count);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "PUT_VERSIONED") == 0) {
        const char *db = "kv", *key = NULL, *val = NULL;
        uint64_t version = 0;
        bool have_ver = false;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "db"))) {
                db = v;
            } else if ((v = tok_key(args[i], "key"))) {
                key = v;
            } else if ((v = tok_key(args[i], "value"))) {
                val = v;
            } else if ((v = tok_key(args[i], "version"))) {
                version = strtoull(v, NULL, 10);
                have_ver = true;
            }
        }
        if (!key || !val || !have_ver) {
            emit("PUT_VERSIONED", "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi dbi;
        st->last_rc = dislmdb_dbi_open(st->txn, db, MDB_CREATE, &dbi);
        if (st->last_rc) {
            emit_rc("PUT_VERSIONED", st->last_rc);
            return st->last_rc;
        }
        MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
        MDB_val v = {.mv_size = strlen(val), .mv_data = (void *)val};
        st->last_rc =
            dislmdb_put_versioned(st->txn, dbi, &k, &v, 0, version);
        emit_rc("PUT_VERSIONED", st->last_rc);
        return st->last_rc;
    }
    if (strcmp(cmd, "GET_VERSIONED") == 0) {
        const char *db = "kv", *key = NULL;
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "db"))) {
                db = v;
            } else if ((v = tok_key(args[i], "key"))) {
                key = v;
            }
        }
        if (!key) {
            emit("GET_VERSIONED", "rc=-1 err=missing_key");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        MDB_dbi dbi;
        st->last_rc = dislmdb_dbi_open(st->txn, db, 0, &dbi);
        if (st->last_rc) {
            emit_rc("GET_VERSIONED", st->last_rc);
            return st->last_rc;
        }
        MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
        uint64_t ver = 0;
        char buf[1024];
        size_t cap = sizeof(buf);
        st->last_rc =
            dislmdb_get_versioned(st->txn, dbi, &k, &ver, buf, &cap);
        if (st->last_rc == 0) {
            if (cap >= sizeof(buf)) {
                cap = sizeof(buf) - 1;
            }
            buf[cap] = '\0';
            printf("GET_VERSIONED rc=0 version=%llu value=%s\n",
                   (unsigned long long)ver, buf);
        } else {
            emit_rc("GET_VERSIONED", st->last_rc);
        }
        fflush(stdout);
        return st->last_rc;
    }
    if (strcmp(cmd, "REGION") == 0) {
        char buf[64] = {0};
        st->last_rc = dislmdb_get_region(st->env, buf, sizeof(buf));
        if (st->last_rc) {
            emit_rc("REGION", st->last_rc);
            return st->last_rc;
        }
        printf("REGION rc=0 value=%s\n", buf);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "LOCALITY") == 0) {
        char buf[64] = {0};
        st->last_rc = dislmdb_get_locality(st->env, buf, sizeof(buf));
        if (st->last_rc) {
            emit_rc("LOCALITY", st->last_rc);
            return st->last_rc;
        }
        printf("LOCALITY rc=0 value=%s\n", buf);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "TOPO") == 0) {
        DISLMDB_TOPOLOGY_MODE mode = DISLMDB_TOPO_MIRROR;
        st->last_rc = dislmdb_get_topology_mode(st->env, &mode);
        if (st->last_rc) {
            emit_rc("TOPO", st->last_rc);
            return st->last_rc;
        }
        const char *name = "mirror";
        if (mode == DISLMDB_TOPO_SHARD) {
            name = "shard";
        } else if (mode == DISLMDB_TOPO_HYBRID) {
            name = "hybrid";
        }
        printf("TOPO rc=0 value=%s\n", name);
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "VOTING") == 0) {
        printf("VOTING rc=0 value=%s\n",
               dislmdb_voting_enabled(st->env) ? "on" : "off");
        fflush(stdout);
        return 0;
    }
    if (strcmp(cmd, "EXPECT_OK") == 0) {
        bool ok = (st->last_rc == 0);
        emit("EXPECT_OK", ok ? "pass" : "fail");
        return ok ? 0 : 1;
    }
    if (strcmp(cmd, "EXPECT_ERR") == 0) {
        int want = nargs > 0 ? atoi(args[0]) : -1;
        bool ok = (st->last_rc == want);
        printf("EXPECT_ERR want=%d got=%d %s\n", want, st->last_rc, ok ? "pass" : "fail");
        fflush(stdout);
        return ok ? 0 : 1;
    }

    printf("UNKNOWN cmd=%s\n", cmd);
    fflush(stdout);
    return DISLMDB_ERR_INVALID_OPERATION;
}

int main(int argc, char **argv)
{
    FILE *in = stdin;
    if (argc >= 2) {
        in = fopen(argv[1], "r");
        if (!in) {
            fprintf(stderr, "cannot open scenario: %s\n", argv[1]);
            return 2;
        }
    }

    e2e_state st;
    memset(&st, 0, sizeof(st));
    strncpy(st.path, "./e2e_workdir", sizeof(st.path) - 1);
    reset_cfg(&st);

    char line[2048];
    int failures = 0;
    while (fgets(line, sizeof(line), in)) {
        int rc = run_line(&st, line);
        if (rc != 0 && strncmp(line, "EXPECT_", 7) != 0) {
            /* non-zero from operational cmds is recorded via last_rc; EXPECT_* counts */
        }
        if (strncmp(line, "EXPECT_", 7) == 0 && rc != 0) {
            failures++;
        }
    }

    if (st.txn) dislmdb_txn_abort(st.txn);
    if (st.env) dislmdb_env_close(st.env);
    if (in != stdin) fclose(in);

    printf("E2E_DONE failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
