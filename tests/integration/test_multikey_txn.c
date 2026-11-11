/**
 * @file test_multikey_txn.c
 * @brief Multi-key + multi-DBI in one txn: atomic Raft apply; binary UUID-like keys
 *
 * Locks Phase K documentation: one commit → one oplog → one apply txn.
 * Does not change engine behavior — only asserts the existing contract.
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30890
#define PORT_B 30891

static int get_named_bin(DISLMDB_env *env, const char *db, const void *k,
                         size_t klen, char *out, size_t out_sz)
{
    DISLMDB_txn *txn = NULL;
    if (dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn) != 0) {
        return -1;
    }
    MDB_dbi dbi;
    if (dislmdb_dbi_open(txn, db, 0, &dbi) != 0) {
        dislmdb_txn_abort(txn);
        return -1;
    }
    MDB_val key = {.mv_size = klen, .mv_data = (void *)k};
    MDB_val val;
    int rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &key, &val);
    if (rc == 0) {
        size_t n = val.mv_size < out_sz - 1 ? val.mv_size : out_sz - 1;
        memcpy(out, val.mv_data, n);
        out[n] = '\0';
    }
    dislmdb_txn_abort(txn);
    return rc == 0 ? 0 : -1;
}

static int wait_named_bin(DISLMDB_env *env, const char *db, const void *k,
                          size_t klen, const char *expect, int ms)
{
    int w = 0;
    while (w < ms) {
        (void)dislmdb_force_sync(env);
        char got[128];
        if (get_named_bin(env, db, k, klen, got, sizeof(got)) == 0 &&
            strcmp(got, expect) == 0) {
            return 0;
        }
        usleep(50 * 1000);
        w += 50;
    }
    return -1;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/multikey_txn");

    it_rm_rf("./it_mk_a");
    it_rm_rf("./it_mk_b");
    it_mkdir("./it_mk_a");
    it_mkdir("./it_mk_b");

    uint8_t key[32];
    memset(key, 0x4D, sizeof(key));

    DISLMDB_node_addr peer_a, peer_b;
    it_peer(&peer_a, "mk-b", PORT_B);
    it_peer(&peer_b, "mk-a", PORT_A);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_mk_a";
    oa.name = "mk-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = &peer_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_TCP;

    it_raft_opts ob = oa;
    ob.path = "./it_mk_b";
    ob.name = "mk-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = &peer_b;

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 25);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 2, leader, sizeof(leader), 10000),
                  0);
    DISLMDB_env *writer = (strcmp(leader, "mk-b") == 0) ? b : a;

    /* 16-byte binary key (UUIDv7-shaped) + ASCII key across two named DBIs */
    uint8_t uuid[16] = {0x01, 0x8f, 0x2a, 0xb0, 0x00, 0x00, 0x70, 0x00,
                        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
    const char *idx_k = "by-name/alice";

    DISLMDB_txn *txn = NULL;
    EXPECT_EQ_INT(&ctx, "begin", dislmdb_txn_begin(writer, NULL, 0, &txn), 0);
    MDB_dbi primary, index;
    EXPECT_EQ_INT(&ctx, "dbi_primary",
                  dislmdb_dbi_open(txn, "entities", MDB_CREATE, &primary), 0);
    EXPECT_EQ_INT(&ctx, "dbi_index",
                  dislmdb_dbi_open(txn, "idx_name", MDB_CREATE, &index), 0);

    MDB_val uk = {.mv_size = sizeof(uuid), .mv_data = uuid};
    MDB_val uv = {.mv_size = 5, .mv_data = (void *)"alice"};
    MDB_val ik = {.mv_size = strlen(idx_k), .mv_data = (void *)idx_k};
    MDB_val iv = {.mv_size = sizeof(uuid), .mv_data = uuid};

    EXPECT_EQ_INT(&ctx, "put_primary", dislmdb_put(txn, primary, &uk, &uv, 0), 0);
    EXPECT_EQ_INT(&ctx, "put_index", dislmdb_put(txn, index, &ik, &iv, 0), 0);
    EXPECT_EQ_INT(&ctx, "commit", dislmdb_txn_commit(txn), 0);
    txn = NULL;

    /* Both sides must observe both writes (atomic apply of the batch). */
    EXPECT_EQ_INT(&ctx, "see_a_primary",
                  wait_named_bin(a, "entities", uuid, sizeof(uuid), "alice", 10000),
                  0);
    EXPECT_EQ_INT(&ctx, "see_b_primary",
                  wait_named_bin(b, "entities", uuid, sizeof(uuid), "alice", 10000),
                  0);

    /* Index value is binary UUID — wait until follower matches. */
    {
        int ok_a = -1, ok_b = -1;
        for (int w = 0; w < 200 && (ok_a != 0 || ok_b != 0); w++) {
            DISLMDB_env *nodes[2] = {a, b};
            int *oks[2] = {&ok_a, &ok_b};
            for (int n = 0; n < 2; n++) {
                if (*oks[n] == 0) {
                    continue;
                }
                DISLMDB_txn *rt = NULL;
                if (dislmdb_txn_begin(nodes[n], NULL, MDB_RDONLY, &rt) == 0) {
                    MDB_dbi dbi;
                    if (dislmdb_dbi_open(rt, "idx_name", 0, &dbi) == 0) {
                        MDB_val k = {.mv_size = strlen(idx_k),
                                     .mv_data = (void *)idx_k};
                        MDB_val v;
                        if (mdb_get(dislmdb_get_lmdb_txn(rt), dbi, &k, &v) == 0 &&
                            v.mv_size == sizeof(uuid) &&
                            memcmp(v.mv_data, uuid, sizeof(uuid)) == 0) {
                            *oks[n] = 0;
                        }
                    }
                    dislmdb_txn_abort(rt);
                }
            }
            if (ok_a != 0 || ok_b != 0) {
                usleep(50 * 1000);
            }
        }
        EXPECT_EQ_INT(&ctx, "see_a_index_uuid", ok_a, 0);
        EXPECT_EQ_INT(&ctx, "see_b_index_uuid", ok_b, 0);
    }

    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_mk_a");
    it_rm_rf("./it_mk_b");
    return test_end(&ctx);
}
