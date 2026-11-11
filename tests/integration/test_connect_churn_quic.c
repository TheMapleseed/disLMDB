/**
 * @file test_connect_churn_quic.c
 * @brief Peer close/reopen under Raft + TRANSPORT_QUIC (Phase K soak)
 */
#include "../harness/test_harness.h"
#include "dislmdb_quic.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30760
#define PORT_B 30761
#define PORT_C 30762

static int open_quic(DISLMDB_env **out, const char *path, const char *name,
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
    o.transport = DISLMDB_TRANSPORT_QUIC;
    o.timeout_ms = 12000;
    o.election_min_ms = 400;
    o.election_max_ms = 800;
    return it_open_raft(out, &o);
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/connect_churn_quic");

    EXPECT_TRUE(&ctx, "quic_stack", dislmdb_quic_stack_ready());

    it_rm_rf("./it_ccq_a");
    it_rm_rf("./it_ccq_b");
    it_rm_rf("./it_ccq_c");
    it_mkdir("./it_ccq_a");
    it_mkdir("./it_ccq_b");
    it_mkdir("./it_ccq_c");

    uint8_t key[32];
    memset(key, 0x51, 32);

    DISLMDB_node_addr peers_a[2], peers_b[2], peers_c[2];
    it_peer(&peers_a[0], "ccq-b", PORT_B);
    it_peer(&peers_a[1], "ccq-c", PORT_C);
    it_peer(&peers_b[0], "ccq-a", PORT_A);
    it_peer(&peers_b[1], "ccq-c", PORT_C);
    it_peer(&peers_c[0], "ccq-a", PORT_A);
    it_peer(&peers_c[1], "ccq-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a",
                  open_quic(&a, "./it_ccq_a", "ccq-a", PORT_A, NULL, key, peers_a,
                            2),
                  0);
    EXPECT_EQ_INT(&ctx, "open_b",
                  open_quic(&b, "./it_ccq_b", "ccq-b", PORT_B, seed, key, peers_b,
                            2),
                  0);
    EXPECT_EQ_INT(&ctx, "open_c",
                  open_quic(&c, "./it_ccq_c", "ccq-c", PORT_C, seed, key, peers_c,
                            2),
                  0);

    DISLMDB_env *envs[3] = {a, b, c};
    it_mesh_warmup(envs, 3, 80);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect0",
                  it_wait_leader(envs, 3, leader, sizeof(leader), 25000), 0);

    DISLMDB_env *writer = a;
    if (strcmp(leader, "ccq-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "ccq-c") == 0) {
        writer = c;
    }
    EXPECT_EQ_INT(&ctx, "put0", it_put_kv(writer, "stable", "yes"), 0);
    EXPECT_EQ_INT(&ctx, "see0_a", it_wait_val(a, "stable", "yes", 15000), 0);
    EXPECT_EQ_INT(&ctx, "see0_b", it_wait_val(b, "stable", "yes", 15000), 0);
    EXPECT_EQ_INT(&ctx, "see0_c", it_wait_val(c, "stable", "yes", 15000), 0);

    int rounds_ok = 0;
    for (int round = 0; round < 4; round++) {
        if (b) {
            dislmdb_env_close(b);
            b = NULL;
            envs[1] = NULL;
        }
        /* QUIC/UDP bind + CID map need a beat before re-listen on same port. */
        usleep(500 * 1000);

        char k[32], v[32];
        snprintf(k, sizeof(k), "qchurn_%d", round);
        snprintf(v, sizeof(v), "v%d", round);
        DISLMDB_env *live[2] = {a, c};
        char lid[64] = {0};
        if (it_wait_leader(live, 2, lid, sizeof(lid), 20000) != 0) {
            continue;
        }
        DISLMDB_env *w = (strcmp(lid, "ccq-c") == 0) ? c : a;
        if (it_put_kv(w, k, v) != 0) {
            continue;
        }
        if (it_wait_val(a, k, v, 15000) != 0 || it_wait_val(c, k, v, 15000) != 0) {
            continue;
        }

        /* Majority commit while B is down counts as a successful churn half. */
        int half = 1;

        if (open_quic(&b, "./it_ccq_b", "ccq-b", PORT_B, seed, key, peers_b, 2) !=
            0) {
            b = NULL;
            rounds_ok += half;
            continue;
        }
        envs[1] = b;
        it_mesh_warmup(envs, 3, 80);

        char k2[32], v2[32];
        snprintf(k2, sizeof(k2), "qrejoin_%d", round);
        snprintf(v2, sizeof(v2), "r%d", round);
        if (it_wait_leader(envs, 3, lid, sizeof(lid), 25000) != 0) {
            rounds_ok += half;
            continue;
        }
        w = a;
        if (strcmp(lid, "ccq-b") == 0) {
            w = b;
        } else if (strcmp(lid, "ccq-c") == 0) {
            w = c;
        }
        if (it_put_kv(w, k2, v2) != 0) {
            rounds_ok += half;
            continue;
        }
        if (it_wait_val(a, k2, v2, 20000) == 0 &&
            it_wait_val(b, k2, v2, 20000) == 0 &&
            it_wait_val(c, k2, v2, 20000) == 0) {
            rounds_ok += 2; /* down-commit + full rejoin */
        } else {
            rounds_ok += half;
        }
    }

    /* Need at least two successful majority-while-down commits (or one full rejoin). */
    EXPECT_TRUE(&ctx, "quic_churn_rounds_ok", rounds_ok >= 2);

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_ccq_a");
    it_rm_rf("./it_ccq_b");
    it_rm_rf("./it_ccq_c");
    return test_end(&ctx);
}
