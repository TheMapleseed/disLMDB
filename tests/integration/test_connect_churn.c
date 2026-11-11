/**
 * @file test_connect_churn.c
 * @brief Real LMDB: spontaneous close/reopen of a peer under Raft BOTH
 *
 * Exercises connect/disconnect paths (HELLO revive, TCP dial, outbox drain)
 * without Docker — host integration lane.
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30730
#define PORT_B 30731
#define PORT_C 30732

static int open_node(DISLMDB_env **out, const char *path, const char *name,
                     uint16_t port, const char *seed, const uint8_t key[32],
                     const DISLMDB_node_addr *peers, size_t npeers)
{
    it_raft_opts o = it_raft_opts_default();
    o.path = path;
    o.name = name;
    o.port = port;
    o.seed = seed;
    o.cluster_key = key;
    o.peers = peers;
    o.npeers = npeers;
    o.transport = DISLMDB_TRANSPORT_BOTH;
    o.enable_mtls = false;
    return it_open_raft(out, &o);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/connect_churn");

    it_rm_rf("./it_cc_a");
    it_rm_rf("./it_cc_b");
    it_rm_rf("./it_cc_c");
    it_mkdir("./it_cc_a");
    it_mkdir("./it_cc_b");
    it_mkdir("./it_cc_c");

    uint8_t key[32];
    memset(key, 0x52, 32);

    DISLMDB_node_addr peers_a[2], peers_b[2], peers_c[2];
    it_peer(&peers_a[0], "cc-b", PORT_B);
    it_peer(&peers_a[1], "cc-c", PORT_C);
    it_peer(&peers_b[0], "cc-a", PORT_A);
    it_peer(&peers_b[1], "cc-c", PORT_C);
    it_peer(&peers_c[0], "cc-a", PORT_A);
    it_peer(&peers_c[1], "cc-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_node(&a, "./it_cc_a", "cc-a", PORT_A, NULL, key, peers_a, 2),
                  0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_node(&b, "./it_cc_b", "cc-b", PORT_B, seed, key, peers_b, 2),
                  0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_node(&c, "./it_cc_c", "cc-c", PORT_C, seed, key, peers_c, 2),
                  0);

    DISLMDB_env *envs[3] = {a, b, c};
    it_mesh_warmup(envs, 3, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect0",
                  it_wait_leader(envs, 3, leader, sizeof(leader), 20000), 0);

    DISLMDB_env *writer = a;
    if (strcmp(leader, "cc-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "cc-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put0", it_put_kv(writer, "stable", "yes"), 0);
    EXPECT_EQ_INT(&ctx, "see0_a", it_wait_val(a, "stable", "yes", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see0_b", it_wait_val(b, "stable", "yes", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see0_c", it_wait_val(c, "stable", "yes", 10000), 0);

    int rounds_ok = 0;
    for (int round = 0; round < 6; round++) {
        /* Spontaneous disconnect: tear down B */
        if (b) {
            dislmdb_env_close(b);
            b = NULL;
            envs[1] = NULL;
        }
        usleep(200 * 1000);

        /* Writes must still commit on remaining quorum (A+C) */
        char k[32], v[32];
        snprintf(k, sizeof(k), "churn_%d", round);
        snprintf(v, sizeof(v), "v%d", round);
        DISLMDB_env *live[2] = {a, c};
        char lid[64] = {0};
        if (it_wait_leader(live, 2, lid, sizeof(lid), 12000) != 0) {
            continue;
        }
        DISLMDB_env *w = (strcmp(lid, "cc-c") == 0) ? c : a;
        if (it_put_kv(w, k, v) != 0) {
            continue;
        }
        if (it_wait_val(a, k, v, 10000) != 0 || it_wait_val(c, k, v, 10000) != 0) {
            continue;
        }

        /* Spontaneous reconnect */
        if (open_node(&b, "./it_cc_b", "cc-b", PORT_B, seed, key, peers_b, 2) != 0) {
            b = NULL;
            continue;
        }
        envs[1] = b;
        it_mesh_warmup(envs, 3, 20);

        char k2[32], v2[32];
        snprintf(k2, sizeof(k2), "rejoin_%d", round);
        snprintf(v2, sizeof(v2), "r%d", round);
        live[0] = a;
        live[1] = c;
        if (it_wait_leader(envs, 3, lid, sizeof(lid), 15000) != 0) {
            continue;
        }
        w = a;
        if (strcmp(lid, "cc-b") == 0) {
            w = b;
        } else if (strcmp(lid, "cc-c") == 0) {
            w = c;
        }
        if (it_put_kv(w, k2, v2) != 0) {
            continue;
        }
        if (it_wait_val(a, k2, v2, 12000) == 0 &&
            it_wait_val(b, k2, v2, 12000) == 0 &&
            it_wait_val(c, k2, v2, 12000) == 0) {
            rounds_ok++;
        }
    }

    EXPECT_TRUE(&ctx, "churn_rounds_ok", rounds_ok >= 4);

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_cc_a");
    it_rm_rf("./it_cc_b");
    it_rm_rf("./it_cc_c");
    return test_end(&ctx);
}
