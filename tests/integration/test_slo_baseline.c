/**
 * @file test_slo_baseline.c
 * @brief Measure hub election + leaf catchup (east hub / west learner).
 *
 * Prints machine-readable summary for docs/soak_slos.kdl. Not a flake gate:
 * failures abort; timings are informational. Override rounds via
 * DISLMDB_SLO_ROUNDS (default 10).
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT_E 30870
#define PORT_W 30871

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t percentile_ms(uint64_t *sorted, int n, int pct)
{
    if (n <= 0) {
        return 0;
    }
    int idx = (pct * (n - 1)) / 100;
    if (idx < 0) {
        idx = 0;
    }
    if (idx >= n) {
        idx = n - 1;
    }
    return sorted[idx];
}

static int one_round(test_ctx_t *ctx, int round, uint64_t *elect_out,
                     uint64_t *catchup_out)
{
    char pe[64], pw[64];
    snprintf(pe, sizeof(pe), "./it_slo_e_%d", round);
    snprintf(pw, sizeof(pw), "./it_slo_w_%d", round);
    it_rm_rf(pe);
    it_rm_rf(pw);
    it_mkdir(pe);
    it_mkdir(pw);

    uint8_t cluster[32], region_k[32], cross[32];
    memset(cluster, 0x53, 32);
    memset(region_k, 0x4C, 32);
    memset(cross, 0x4F, 32);

    DISLMDB_node_addr peer_e, peer_w;
    it_peer_region(&peer_e, "slo-w", PORT_W, "west");
    it_peer_region(&peer_w, "slo-e", PORT_E, "east");

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_E);

    it_raft_opts oe = it_raft_opts_default();
    oe.path = pe;
    oe.name = "slo-e";
    oe.port = PORT_E;
    oe.cluster_key = cluster;
    oe.peers = &peer_e;
    oe.npeers = 1;
    oe.transport = DISLMDB_TRANSPORT_UDP;
    oe.region = "east";
    oe.locality = "az-1";
    oe.region_key = region_k;
    oe.cross_region_key = cross;
    oe.set_topology_mode = true;
    oe.topology_mode = DISLMDB_TOPO_MIRROR;
    oe.set_enable_voting = true;
    oe.enable_voting = true;
    oe.election_min_ms = 150;
    oe.election_max_ms = 300;
    oe.heartbeat_ms = 60;
    oe.timeout_ms = 8000;

    it_raft_opts ow = oe;
    ow.path = pw;
    ow.name = "slo-w";
    ow.port = PORT_W;
    ow.seed = seed;
    ow.peers = &peer_w;
    ow.region = "west";
    ow.locality = "az-2";
    ow.set_enable_voting = true;
    ow.enable_voting = false;

    DISLMDB_env *east = NULL, *west = NULL;
    int rc = it_open_raft(&east, &oe);
    if (rc != 0) {
        return rc;
    }
    rc = it_open_raft(&west, &ow);
    if (rc != 0) {
        dislmdb_env_close(east);
        return rc;
    }

    DISLMDB_env *envs[2] = {east, west};
    /* Time open→leader (includes HELLO/mesh engage; no pre-warmup). */
    uint64_t t0 = it_mono_ms();
    char leader[64] = {0};
    rc = it_wait_leader(envs, 2, leader, sizeof(leader), 15000);
    uint64_t t_elect = it_mono_ms() - t0;
    if (rc != 0) {
        dislmdb_env_close(west);
        dislmdb_env_close(east);
        it_rm_rf(pe);
        it_rm_rf(pw);
        return -1;
    }
    if (strcmp(leader, "slo-e") != 0) {
        EXPECT_STREQ(ctx, "hub_leader", leader, "slo-e");
    }

    /* Brief settle so AE path is ready before catchup sample. */
    it_mesh_warmup(envs, 2, 10);

    char key[32], val[32];
    snprintf(key, sizeof(key), "slo/k%d", round);
    snprintf(val, sizeof(val), "v%d", round);

    uint64_t t1 = it_mono_ms();
    rc = it_put_kv(east, key, val);
    if (rc != 0) {
        dislmdb_env_close(west);
        dislmdb_env_close(east);
        it_rm_rf(pe);
        it_rm_rf(pw);
        return rc;
    }
    rc = it_wait_val(west, key, val, 15000);
    uint64_t t_catch = it_mono_ms() - t1;

    dislmdb_env_close(west);
    dislmdb_env_close(east);
    it_rm_rf(pe);
    it_rm_rf(pw);

    if (rc != 0) {
        return -1;
    }
    *elect_out = t_elect;
    *catchup_out = t_catch;
    return 0;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/slo_baseline");

    int rounds = 10;
    const char *envr = getenv("DISLMDB_SLO_ROUNDS");
    if (envr && envr[0]) {
        int v = atoi(envr);
        if (v >= 3 && v <= 100) {
            rounds = v;
        }
    }

    uint64_t *elect = calloc((size_t)rounds, sizeof(uint64_t));
    uint64_t *catchup = calloc((size_t)rounds, sizeof(uint64_t));
    EXPECT_TRUE(&ctx, "alloc", elect && catchup);
    if (!elect || !catchup) {
        free(elect);
        free(catchup);
        return test_end(&ctx);
    }

    int ok = 0;
    for (int i = 0; i < rounds; i++) {
        uint64_t e = 0, c = 0;
        int rc = one_round(&ctx, i, &e, &c);
        char label[32];
        snprintf(label, sizeof(label), "round_%d", i);
        EXPECT_EQ_INT(&ctx, label, rc, 0);
        if (rc == 0) {
            elect[ok] = e;
            catchup[ok] = c;
            fprintf(stderr, "slo_round %d elect_ms=%llu catchup_ms=%llu\n", i,
                    (unsigned long long)e, (unsigned long long)c);
            ok++;
        }
        /* Port reuse: brief pause so TIME_WAIT / bind settles. */
        usleep(200 * 1000);
    }

    EXPECT_TRUE(&ctx, "enough_samples", ok >= 3);
    if (ok >= 3) {
        qsort(elect, (size_t)ok, sizeof(uint64_t), cmp_u64);
        qsort(catchup, (size_t)ok, sizeof(uint64_t), cmp_u64);
        uint64_t e50 = percentile_ms(elect, ok, 50);
        uint64_t e99 = percentile_ms(elect, ok, 99);
        uint64_t c50 = percentile_ms(catchup, ok, 50);
        uint64_t c99 = percentile_ms(catchup, ok, 99);

        printf("slo_baseline samples=%d\n", ok);
        printf("hub_election_p50_ms=%llu\n", (unsigned long long)e50);
        printf("hub_election_p99_ms=%llu\n", (unsigned long long)e99);
        printf("leaf_catchup_p50_ms=%llu\n", (unsigned long long)c50);
        printf("leaf_catchup_p99_ms=%llu\n", (unsigned long long)c99);
        printf("topology=east_hub+west_learner transport=UDP election=150-300ms\n");

        /* Soft budgets: election within ~ election_max * few + mesh; catchup < 5s. */
        EXPECT_TRUE(&ctx, "elect_p99_lt_5s", e99 < 5000);
        EXPECT_TRUE(&ctx, "catchup_p99_lt_5s", c99 < 5000);
    }

    free(elect);
    free(catchup);
    return test_end(&ctx);
}
