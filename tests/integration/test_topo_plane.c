/**
 * @file test_topo_plane.c
 * @brief Cross-region crypto plane fail-closed + RTT budget soft-reject
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30750
#define PORT_B 30751

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/topo_plane");

    it_rm_rf("./it_tp_a");
    it_rm_rf("./it_tp_b");
    it_mkdir("./it_tp_a");
    it_mkdir("./it_tp_b");

    uint8_t cluster[32], region_k[32], cross_a[32], cross_b[32];
    memset(cluster, 0x41, 32);
    memset(region_k, 0x52, 32);
    memset(cross_a, 0xCA, 32);
    memset(cross_b, 0xCB, 32);

    DISLMDB_node_addr peers_a, peers_b;
    it_peer_region(&peers_a, "tp-b", PORT_B, "west");
    it_peer_region(&peers_b, "tp-a", PORT_A, "east");

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_tp_a";
    oa.name = "tp-a";
    oa.port = PORT_A;
    oa.cluster_key = cluster;
    oa.peers = &peers_a;
    oa.npeers = 1;
    oa.transport = DISLMDB_TRANSPORT_UDP;
    oa.region = "east";
    oa.region_key = region_k;
    oa.cross_region_key = cross_a;
    oa.rtt_budget_ms = 50;

    it_raft_opts ob = oa;
    ob.path = "./it_tp_b";
    ob.name = "tp-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = &peers_b;
    ob.region = "west";
    ob.cross_region_key = cross_b; /* mismatch → plane fail */

    DISLMDB_env *a = NULL, *b = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);

    DISLMDB_env *envs[2] = {a, b};
    it_mesh_warmup(envs, 2, 30);

    DISLMDB_network_stats st_a, st_b;
    memset(&st_a, 0, sizeof(st_a));
    memset(&st_b, 0, sizeof(st_b));
    (void)dislmdb_network_get_stats(a, &st_a);
    (void)dislmdb_network_get_stats(b, &st_b);
    EXPECT_TRUE(&ctx, "plane_fail_seen",
                st_a.plane_auth_fail > 0 || st_b.plane_auth_fail > 0 ||
                    st_a.total_errors > 0 || st_b.total_errors > 0);

    /* B must not observe A's local-only put under broken cross plane. */
    int put_rc = it_put_kv(a, "plane-k", "v");
    EXPECT_TRUE(&ctx, "put_local_or_fail",
                put_rc == 0 || put_rc == DISLMDB_ERR_CONSENSUS_TIMEOUT ||
                    put_rc == DISLMDB_ERR_CONSENSUS_FAILED ||
                    put_rc == DISLMDB_ERR_NO_LEADER ||
                    put_rc == DISLMDB_ERR_NOT_AUTHORIZED);
    EXPECT_EQ_INT(&ctx, "b_miss_plane", it_wait_val(b, "plane-k", "v", 800), -1);

    /*
     * RTT budget: align cross keys so a connection can exist, inject high EWMA,
     * and confirm soft-reject counters / within_budget helper.
     */
    if (a) {
        dislmdb_env_close(a);
        a = NULL;
    }
    if (b) {
        dislmdb_env_close(b);
        b = NULL;
    }
    it_rm_rf("./it_tp_a");
    it_rm_rf("./it_tp_b");
    it_mkdir("./it_tp_a");
    it_mkdir("./it_tp_b");

    oa.cross_region_key = cross_a;
    ob.cross_region_key = cross_a; /* match */
    EXPECT_EQ_INT(&ctx, "reopen_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "reopen_b", it_open_raft(&b, &ob), 0);
    envs[0] = a;
    envs[1] = b;
    it_mesh_warmup(envs, 2, 40);

    EXPECT_EQ_INT(&ctx, "set_rtt",
                  dislmdb_network_set_rtt_ewma(a, "tp-b", 500), 0);
    EXPECT_TRUE(&ctx, "rtt_over_budget",
                !dislmdb_network_rtt_within_budget(a, "tp-b"));

    DISLMDB_network_message nm;
    memset(&nm, 0, sizeof(nm));
    uint8_t payload[4] = {1, 2, 3, 4};
    EXPECT_EQ_INT(&ctx, "mk_hb",
                  dislmdb_network_create_message(&nm, DISLMDB_MESSAGE_HEARTBEAT,
                                                 payload, sizeof(payload), "tp-b"),
                  0);
    strncpy(nm.header.sender_id, "tp-a", sizeof(nm.header.sender_id) - 1);
    int send_rc = dislmdb_network_send(a, &nm, "tp-b", 500);
    dislmdb_network_free_message(&nm);
    EXPECT_EQ_INT(&ctx, "send_rtt_reject", send_rc, DISLMDB_ERR_NODE_UNREACHABLE);

    memset(&st_a, 0, sizeof(st_a));
    EXPECT_EQ_INT(&ctx, "stats_rtt", dislmdb_network_get_stats(a, &st_a), 0);
    EXPECT_TRUE(&ctx, "rtt_rejects", st_a.rtt_rejects > 0);

    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_tp_a");
    it_rm_rf("./it_tp_b");
    return test_end(&ctx);
}
