/**
 * @file test_raft_matrix.c
 * @brief Parameterized Raft transport × mTLS matrix (shared it_cluster fixture)
 *
 * Cells: UDP / TCP / BOTH × plain; BOTH+mTLS; TCP+mTLS.
 * Same elect → put → see assertions; asserts outbox stats stay sane.
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

typedef struct matrix_cell {
    const char *label;
    DISLMDB_TRANSPORT transport;
    bool mtls;
    uint16_t port_a;
    uint16_t port_b;
} matrix_cell;

static int run_cell(test_ctx_t *ctx, const matrix_cell *cell, const uint8_t key[32],
                    const char *cert_dir)
{
    char dir_a[64], dir_b[64], tag[96];
    snprintf(dir_a, sizeof(dir_a), "./it_mx_%s_a", cell->label);
    snprintf(dir_b, sizeof(dir_b), "./it_mx_%s_b", cell->label);
    it_rm_rf(dir_a);
    it_rm_rf(dir_b);
    it_mkdir(dir_a);
    it_mkdir(dir_b);

    DISLMDB_node_addr peers_a, peers_b;
    it_peer(&peers_a, "raft-b", cell->port_b);
    it_peer(&peers_b, "raft-a", cell->port_a);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)cell->port_a);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = dir_a;
    oa.name = "raft-a";
    oa.port = cell->port_a;
    oa.cluster_key = key;
    oa.peers = &peers_a;
    oa.npeers = 1;
    oa.transport = cell->transport;
    oa.enable_mtls = cell->mtls;
    oa.cert_dir = cert_dir;
    if (cell->transport == DISLMDB_TRANSPORT_QUIC) {
        oa.timeout_ms = 12000;
        oa.election_min_ms = 400;
        oa.election_max_ms = 800;
    }

    it_raft_opts ob = oa;
    ob.path = dir_b;
    ob.name = "raft-b";
    ob.port = cell->port_b;
    ob.seed = seed;
    ob.peers = &peers_b;

    DISLMDB_env *a = NULL, *b = NULL;
    snprintf(tag, sizeof(tag), "%s_open_a", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_open_raft(&a, &oa), 0);
    snprintf(tag, sizeof(tag), "%s_open_b", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_open_raft(&b, &ob), 0);
    if (!a || !b) {
        if (b) {
            dislmdb_env_close(b);
        }
        if (a) {
            dislmdb_env_close(a);
        }
        it_rm_rf(dir_a);
        it_rm_rf(dir_b);
        return -1;
    }

    DISLMDB_env *envs[2] = {a, b};
    int warm = cell->mtls ? 60 : 30;
    if (cell->transport == DISLMDB_TRANSPORT_QUIC) {
        warm = 50;
    }
    it_mesh_warmup(envs, 2, warm);

    char leader[64] = {0};
    snprintf(tag, sizeof(tag), "%s_elect", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_wait_leader(envs, 2, leader, sizeof(leader), 20000), 0);
    snprintf(tag, sizeof(tag), "%s_leader", cell->label);
    EXPECT_TRUE(ctx, tag, leader[0] != '\0');

    DISLMDB_env *writer = (strcmp(leader, "raft-b") == 0) ? b : a;
    char k[32], v[32];
    snprintf(k, sizeof(k), "k_%s", cell->label);
    snprintf(v, sizeof(v), "v_%s", cell->label);
    snprintf(tag, sizeof(tag), "%s_put", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_put_kv(writer, k, v), 0);
    snprintf(tag, sizeof(tag), "%s_see_a", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_wait_val(a, k, v, 10000), 0);
    snprintf(tag, sizeof(tag), "%s_see_b", cell->label);
    EXPECT_EQ_INT(ctx, tag, it_wait_val(b, k, v, 10000), 0);

    DISLMDB_network_stats st;
    memset(&st, 0, sizeof(st));
    snprintf(tag, sizeof(tag), "%s_stats", cell->label);
    EXPECT_EQ_INT(ctx, tag, dislmdb_network_get_stats(a, &st), 0);
    /* Outbox may enqueue under BOTH+mTLS; must not thrash-drop. */
    snprintf(tag, sizeof(tag), "%s_outbox_sane", cell->label);
    EXPECT_TRUE(ctx, tag, st.outbox_dropped <= st.outbox_enqueued + 8ull);

    dislmdb_env_close(b);
    dislmdb_env_close(a);
    it_rm_rf(dir_a);
    it_rm_rf(dir_b);
    return 0;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_matrix");

    it_rm_rf("./it_mx_certs");
    EXPECT_EQ_INT(&ctx, "gen_certs", it_gen_certs("./it_mx_certs"), 0);

    uint8_t key[32];
    memset(key, 0x51, 32);

    static const matrix_cell cells[] = {
        {"udp", DISLMDB_TRANSPORT_UDP, false, 30710, 30711},
        {"tcp", DISLMDB_TRANSPORT_TCP, false, 30712, 30713},
        {"both", DISLMDB_TRANSPORT_BOTH, false, 30714, 30715},
        {"both_mtls", DISLMDB_TRANSPORT_BOTH, true, 30716, 30717},
        {"tcp_mtls", DISLMDB_TRANSPORT_TCP, true, 30718, 30719},
        {"quic", DISLMDB_TRANSPORT_QUIC, false, 30720, 30721},
    };

    for (size_t i = 0; i < sizeof(cells) / sizeof(cells[0]); i++) {
        (void)run_cell(&ctx, &cells[i], key, "./it_mx_certs");
    }

    it_rm_rf("./it_mx_certs");
    return test_end(&ctx);
}
