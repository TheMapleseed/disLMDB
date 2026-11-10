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
    reset_cfg(st);
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
        for (int i = 0; i < nargs; i++) {
            char *v;
            if ((v = tok_key(args[i], "id"))) id = v;
            else if ((v = tok_key(args[i], "hex"))) hex = v;
        }
        uint8_t buf[4096];
        size_t bl = 0;
        if (!id || !hex || parse_hex(hex, buf, sizeof(buf), &bl)) {
            emit("BYTECODE_STORE", "rc=-1 err=bad_args");
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        st->last_rc = dislmdb_store_bytecode(st->env, buf, bl, id, 0);
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
        printf("BYTECODE_GET rc=0 size=%zu hex=", sz);
        for (size_t i = 0; i < sz; i++) printf("%02x", buf[i]);
        printf("\n");
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
