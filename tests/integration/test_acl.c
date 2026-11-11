/**
 * @file test_acl.c
 * @brief Integration: enable_acl gates put/admin; bootstrap grant
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DBPATH "./it_acl_db"

static void rm_rf(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    (void)system(cmd);
}

static int try_put(DISLMDB_env *env, const char *ks, const char *vs)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val k = {.mv_size = strlen(ks), .mv_data = (void *)ks};
    MDB_val v = {.mv_size = strlen(vs), .mv_data = (void *)vs};
    rc = dislmdb_put(txn, dbi, &k, &v, 0);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    return dislmdb_txn_commit(txn);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/acl");

    rm_rf(DBPATH);
    mkdir(DBPATH, 0700);

    DISLMDB_env *env = NULL;
    EXPECT_EQ_INT(&ctx, "create", dislmdb_env_create(&env), 0);

    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.persist_state = true;
    cfg.enable_acl = true;
    EXPECT_EQ_INT(&ctx, "open", dislmdb_env_open(env, &cfg), 0);

    EXPECT_EQ_INT(&ctx, "put_no_principal", try_put(env, "k", "v"),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    EXPECT_EQ_INT(&ctx, "set_prin", dislmdb_acl_set_principal(env, "alice"), 0);
    EXPECT_EQ_INT(&ctx, "put_no_grant", try_put(env, "k", "v"),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    EXPECT_EQ_INT(&ctx, "bootstrap_grant",
                  dislmdb_acl_grant(env, "alice", DISLMDB_ACL_ALL), 0);
    unsigned int mask = 0;
    EXPECT_EQ_INT(&ctx, "get_mask", dislmdb_acl_get(env, "alice", &mask), 0);
    EXPECT_TRUE(&ctx, "mask_all", (mask & DISLMDB_ACL_ALL) == DISLMDB_ACL_ALL);

    EXPECT_EQ_INT(&ctx, "put_ok", try_put(env, "k", "v"), 0);

    EXPECT_EQ_INT(&ctx, "grant_bob_read",
                  dislmdb_acl_grant(env, "bob", DISLMDB_ACL_READ), 0);
    EXPECT_EQ_INT(&ctx, "as_bob", dislmdb_acl_set_principal(env, "bob"), 0);
    EXPECT_EQ_INT(&ctx, "bob_put_deny", try_put(env, "k2", "v2"),
                  DISLMDB_ERR_NOT_AUTHORIZED);
    EXPECT_EQ_INT(&ctx, "bob_ckpt_deny", dislmdb_checkpoint(env),
                  DISLMDB_ERR_NOT_AUTHORIZED);
    EXPECT_EQ_INT(&ctx, "bob_grant_deny",
                  dislmdb_acl_grant(env, "carol", DISLMDB_ACL_READ),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    const uint8_t bc[] = {0x0A, 0x0B, 0x0C};
    EXPECT_EQ_INT(&ctx, "bob_bc_store_deny",
                  dislmdb_store_bytecode(env, bc, sizeof(bc), "acl-bc", 0),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    EXPECT_EQ_INT(&ctx, "as_alice", dislmdb_acl_set_principal(env, "alice"), 0);
    EXPECT_EQ_INT(&ctx, "ckpt", dislmdb_checkpoint(env), 0);
    EXPECT_EQ_INT(&ctx, "alice_bc_store",
                  dislmdb_store_bytecode(env, bc, sizeof(bc), "acl-bc",
                                         DISLMDB_BYTECODE_COMPRESS),
                  0);
    EXPECT_EQ_INT(&ctx, "as_bob2", dislmdb_acl_set_principal(env, "bob"), 0);
    {
        uint8_t out[8];
        size_t osz = sizeof(out);
        unsigned oopts = 0;
        EXPECT_EQ_INT(&ctx, "bob_bc_get_ok",
                      dislmdb_get_bytecode(env, "acl-bc", out, &osz, &oopts), 0);
        EXPECT_EQ_INT(&ctx, "bob_bc_len", (int)osz, (int)sizeof(bc));
        EXPECT_MEMEQ(&ctx, "bob_bc_bytes", out, bc, sizeof(bc));
    }

    EXPECT_EQ_INT(&ctx, "as_alice2", dislmdb_acl_set_principal(env, "alice"), 0);
    EXPECT_EQ_INT(&ctx, "revoke_bob",
                  dislmdb_acl_revoke(env, "bob", DISLMDB_ACL_READ), 0);
    mask = 0xff;
    EXPECT_EQ_INT(&ctx, "bob_gone", dislmdb_acl_get(env, "bob", &mask), 0);
    EXPECT_EQ_INT(&ctx, "bob_zero", (int)mask, 0);

    EXPECT_EQ_INT(&ctx, "as_bob3", dislmdb_acl_set_principal(env, "bob"), 0);
    {
        uint8_t out[8];
        size_t osz = sizeof(out);
        unsigned oopts = 0;
        EXPECT_EQ_INT(&ctx, "bob_bc_get_deny",
                      dislmdb_get_bytecode(env, "acl-bc", out, &osz, &oopts),
                      DISLMDB_ERR_NOT_AUTHORIZED);
    }

    /* Persist grants across close/reopen (meta DBI). */
    dislmdb_env_close(env);
    env = NULL;
    EXPECT_EQ_INT(&ctx, "create_re", dislmdb_env_create(&env), 0);
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.persist_state = true;
    cfg.enable_acl = true;
    EXPECT_EQ_INT(&ctx, "open_re", dislmdb_env_open(env, &cfg), 0);
    mask = 0;
    EXPECT_EQ_INT(&ctx, "alice_re", dislmdb_acl_get(env, "alice", &mask), 0);
    EXPECT_TRUE(&ctx, "alice_re_all",
                (mask & DISLMDB_ACL_ALL) == DISLMDB_ACL_ALL);
    EXPECT_EQ_INT(&ctx, "set_alice_re", dislmdb_acl_set_principal(env, "alice"),
                  0);
    EXPECT_EQ_INT(&ctx, "put_re", try_put(env, "k3", "v3"), 0);

    /* Prefix ACL: carol may write only under user/carol/ */
    EXPECT_EQ_INT(&ctx, "grant_carol_pfx",
                  dislmdb_acl_grant_prefix(env, "carol", "user/carol/",
                                           DISLMDB_ACL_WRITE | DISLMDB_ACL_READ),
                  0);
    unsigned int pfx = 0;
    EXPECT_EQ_INT(&ctx, "get_pfx",
                  dislmdb_acl_get_prefix(env, "carol", "user/carol/", &pfx), 0);
    EXPECT_TRUE(&ctx, "pfx_rw",
                (pfx & (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) ==
                    (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE));
    EXPECT_EQ_INT(&ctx, "pfx_admin_rej",
                  dislmdb_acl_grant_prefix(env, "carol", "user/carol/",
                                           DISLMDB_ACL_ADMIN),
                  DISLMDB_ERR_INVALID_PARAMETER);

    EXPECT_EQ_INT(&ctx, "as_carol", dislmdb_acl_set_principal(env, "carol"), 0);
    EXPECT_EQ_INT(&ctx, "carol_other_deny", try_put(env, "user/alice/x", "no"),
                  DISLMDB_ERR_NOT_AUTHORIZED);
    EXPECT_EQ_INT(&ctx, "carol_own_ok", try_put(env, "user/carol/inbox", "yes"),
                  0);
    EXPECT_EQ_INT(&ctx, "carol_ckpt_deny", dislmdb_checkpoint(env),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    /* Persist prefix grants across reopen. */
    dislmdb_env_close(env);
    env = NULL;
    EXPECT_EQ_INT(&ctx, "create_pfx", dislmdb_env_create(&env), 0);
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.persist_state = true;
    cfg.enable_acl = true;
    EXPECT_EQ_INT(&ctx, "open_pfx", dislmdb_env_open(env, &cfg), 0);
    pfx = 0;
    EXPECT_EQ_INT(&ctx, "pfx_re",
                  dislmdb_acl_get_prefix(env, "carol", "user/carol/", &pfx), 0);
    EXPECT_TRUE(&ctx, "pfx_re_rw", (pfx & DISLMDB_ACL_WRITE) != 0);
    EXPECT_EQ_INT(&ctx, "as_carol_re", dislmdb_acl_set_principal(env, "carol"),
                  0);
    EXPECT_EQ_INT(&ctx, "carol_re_ok", try_put(env, "user/carol/out", "y"), 0);
    EXPECT_EQ_INT(&ctx, "as_alice_rev", dislmdb_acl_set_principal(env, "alice"),
                  0);
    EXPECT_EQ_INT(&ctx, "revoke_pfx",
                  dislmdb_acl_revoke_prefix(env, "carol", "user/carol/",
                                            DISLMDB_ACL_WRITE | DISLMDB_ACL_READ),
                  0);
    EXPECT_EQ_INT(&ctx, "as_carol_gone", dislmdb_acl_set_principal(env, "carol"),
                  0);
    EXPECT_EQ_INT(&ctx, "carol_gone_deny",
                  try_put(env, "user/carol/z", "n"), DISLMDB_ERR_NOT_AUTHORIZED);

    /* RBAC: global writer role + prefix-scoped reader role */
    EXPECT_EQ_INT(&ctx, "as_alice_rbac", dislmdb_acl_set_principal(env, "alice"),
                  0);
    EXPECT_EQ_INT(&ctx, "role_writer",
                  dislmdb_acl_role_define(env, "writer", NULL,
                                          DISLMDB_ACL_READ | DISLMDB_ACL_WRITE),
                  0);
    EXPECT_EQ_INT(&ctx, "role_tenant",
                  dislmdb_acl_role_define(env, "tenant_dave", "dave/",
                                          DISLMDB_ACL_READ | DISLMDB_ACL_WRITE),
                  0);
    EXPECT_EQ_INT(&ctx, "assign_eve",
                  dislmdb_acl_role_assign(env, "eve", "writer"), 0);
    EXPECT_EQ_INT(&ctx, "assign_dave",
                  dislmdb_acl_role_assign(env, "dave", "tenant_dave"), 0);
    unsigned int eff = 0;
    EXPECT_EQ_INT(&ctx, "eff_eve", dislmdb_acl_effective(env, "eve", &eff), 0);
    EXPECT_TRUE(&ctx, "eve_rw",
                (eff & (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) ==
                    (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE));
    EXPECT_EQ_INT(&ctx, "as_eve", dislmdb_acl_set_principal(env, "eve"), 0);
    EXPECT_EQ_INT(&ctx, "eve_put", try_put(env, "anywhere", "1"), 0);
    EXPECT_EQ_INT(&ctx, "as_dave", dislmdb_acl_set_principal(env, "dave"), 0);
    EXPECT_EQ_INT(&ctx, "dave_other", try_put(env, "eve/x", "n"),
                  DISLMDB_ERR_NOT_AUTHORIZED);
    EXPECT_EQ_INT(&ctx, "dave_own", try_put(env, "dave/inbox", "y"), 0);

    dislmdb_env_close(env);
    env = NULL;
    EXPECT_EQ_INT(&ctx, "create_rbac", dislmdb_env_create(&env), 0);
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.consensus.persist_state = true;
    cfg.enable_acl = true;
    EXPECT_EQ_INT(&ctx, "open_rbac", dislmdb_env_open(env, &cfg), 0);
    unsigned int rperms = 0;
    char rpfx[64] = {0};
    EXPECT_EQ_INT(&ctx, "role_get",
                  dislmdb_acl_role_get(env, "tenant_dave", &rperms, rpfx,
                                       sizeof(rpfx)),
                  0);
    EXPECT_STREQ(&ctx, "role_pfx", rpfx, "dave/");
    EXPECT_EQ_INT(&ctx, "as_dave_re", dislmdb_acl_set_principal(env, "dave"),
                  0);
    EXPECT_EQ_INT(&ctx, "dave_re_ok", try_put(env, "dave/out", "z"), 0);
    EXPECT_EQ_INT(&ctx, "as_alice_un", dislmdb_acl_set_principal(env, "alice"),
                  0);
    EXPECT_EQ_INT(&ctx, "unassign",
                  dislmdb_acl_role_unassign(env, "dave", "tenant_dave"), 0);
    EXPECT_EQ_INT(&ctx, "as_dave_gone", dislmdb_acl_set_principal(env, "dave"),
                  0);
    EXPECT_EQ_INT(&ctx, "dave_gone", try_put(env, "dave/z", "n"),
                  DISLMDB_ERR_NOT_AUTHORIZED);

    dislmdb_env_close(env);
    rm_rf(DBPATH);

    /* ACL off: grant rejected; put works without principal. */
    mkdir(DBPATH, 0700);
    EXPECT_EQ_INT(&ctx, "create2", dislmdb_env_create(&env), 0);
    dislmdb_env_config_init(&cfg);
    cfg.path = DBPATH;
    cfg.mapsize = 8 * 1024 * 1024;
    cfg.maxdbs = 8;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = 0;
    cfg.enable_acl = false;
    EXPECT_EQ_INT(&ctx, "open_off", dislmdb_env_open(env, &cfg), 0);
    EXPECT_EQ_INT(&ctx, "grant_off",
                  dislmdb_acl_grant(env, "x", DISLMDB_ACL_ALL),
                  DISLMDB_ERR_INVALID_OPERATION);
    EXPECT_EQ_INT(&ctx, "put_off", try_put(env, "k", "v"), 0);
    dislmdb_env_close(env);
    rm_rf(DBPATH);
    return test_end(&ctx);
}
