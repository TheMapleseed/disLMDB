/**
 * @file test_raft_udp.c
 * @brief Raft election + replication over UDP datagram transport
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30410
#define PORT_B 30411
#define PORT_C 30412

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_udp");

    it_rm_rf("./it_ru_a");
    it_rm_rf("./it_ru_b");
    it_rm_rf("./it_ru_c");
    it_mkdir("./it_ru_a");
    it_mkdir("./it_ru_b");
    it_mkdir("./it_ru_c");

    uint8_t key[32];
    memset(key, 0x44, 32);

    DISLMDB_node_addr peers_a[2], peers_b[2], peers_c[2];
    it_peer(&peers_a[0], "raft-b", PORT_B);
    it_peer(&peers_a[1], "raft-c", PORT_C);
    it_peer(&peers_b[0], "raft-a", PORT_A);
    it_peer(&peers_b[1], "raft-c", PORT_C);
    it_peer(&peers_c[0], "raft-a", PORT_A);
    it_peer(&peers_c[1], "raft-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_ru_a";
    oa.name = "raft-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_ru_b";
    ob.name = "raft-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_ru_c";
    oc.name = "raft-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);
    EXPECT_EQ_INT(&ctx, "open_c", it_open_raft(&c, &oc), 0);

    DISLMDB_env *envs[3] = {a, b, c};
    /* UDP HELLO + reconnect need a longer warm-up than TCP. */
    it_mesh_warmup(envs, 3, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 3, leader, sizeof(leader), 12000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    DISLMDB_env *writer = a;
    if (strcmp(leader, "raft-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "raft-c") == 0) {
        writer = c;
    }

    EXPECT_EQ_INT(&ctx, "put_raft_udp", it_put_kv(writer, "raftk", "udpv"), 0);
    EXPECT_EQ_INT(&ctx, "see_a", it_wait_val(a, "raftk", "udpv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_b", it_wait_val(b, "raftk", "udpv", 10000), 0);
    EXPECT_EQ_INT(&ctx, "see_c", it_wait_val(c, "raftk", "udpv", 10000), 0);

    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_ru_a");
    it_rm_rf("./it_ru_b");
    it_rm_rf("./it_ru_c");
    return test_end(&ctx);
}
