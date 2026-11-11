/**
 * @file test_raft_wal_chaos.c
 * @brief Kill/reopen mid-cluster: committed KV + Raft WAL must not diverge
 */
#include "../harness/test_harness.h"
#include "it_cluster.h"

#include <stdio.h>
#include <string.h>

#define PORT_A 30930
#define PORT_B 30931
#define PORT_C 30932

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "integration/raft_wal_chaos");

    it_rm_rf("./it_rwc_a");
    it_rm_rf("./it_rwc_b");
    it_rm_rf("./it_rwc_c");
    it_mkdir("./it_rwc_a");
    it_mkdir("./it_rwc_b");
    it_mkdir("./it_rwc_c");

    uint8_t key[32];
    memset(key, 0x5A, 32);

    DISLMDB_node_addr peers_a[2], peers_b[2], peers_c[2];
    it_peer(&peers_a[0], "rwc-b", PORT_B);
    it_peer(&peers_a[1], "rwc-c", PORT_C);
    it_peer(&peers_b[0], "rwc-a", PORT_A);
    it_peer(&peers_b[1], "rwc-c", PORT_C);
    it_peer(&peers_c[0], "rwc-a", PORT_A);
    it_peer(&peers_c[1], "rwc-b", PORT_B);

    char seed[64];
    snprintf(seed, sizeof(seed), "127.0.0.1:%u", (unsigned)PORT_A);

    it_raft_opts oa = it_raft_opts_default();
    oa.path = "./it_rwc_a";
    oa.name = "rwc-a";
    oa.port = PORT_A;
    oa.cluster_key = key;
    oa.peers = peers_a;
    oa.npeers = 2;
    oa.transport = DISLMDB_TRANSPORT_UDP;

    it_raft_opts ob = oa;
    ob.path = "./it_rwc_b";
    ob.name = "rwc-b";
    ob.port = PORT_B;
    ob.seed = seed;
    ob.peers = peers_b;

    it_raft_opts oc = oa;
    oc.path = "./it_rwc_c";
    oc.name = "rwc-c";
    oc.port = PORT_C;
    oc.seed = seed;
    oc.peers = peers_c;

    DISLMDB_env *a = NULL, *b = NULL, *c = NULL;
    EXPECT_EQ_INT(&ctx, "open_a", it_open_raft(&a, &oa), 0);
    EXPECT_EQ_INT(&ctx, "open_b", it_open_raft(&b, &ob), 0);
    EXPECT_EQ_INT(&ctx, "open_c", it_open_raft(&c, &oc), 0);

    DISLMDB_env *envs[3] = {a, b, c};
    it_mesh_warmup(envs, 3, 40);

    char leader[64] = {0};
    EXPECT_EQ_INT(&ctx, "elect", it_wait_leader(envs, 3, leader, sizeof(leader), 5000), 0);

    DISLMDB_env *writer = a;
    if (strcmp(leader, "rwc-b") == 0) {
        writer = b;
    } else if (strcmp(leader, "rwc-c") == 0) {
        writer = c;
    }

    EXPECT_EQ_INT(&ctx, "put_pre", it_put_kv(writer, "pre", "ok"), 0);
    EXPECT_EQ_INT(&ctx, "see_a_pre", it_wait_val(a, "pre", "ok", 3000), 0);
    EXPECT_EQ_INT(&ctx, "see_b_pre", it_wait_val(b, "pre", "ok", 3000), 0);
    EXPECT_EQ_INT(&ctx, "see_c_pre", it_wait_val(c, "pre", "ok", 3000), 0);

    /* Checkpoint (safe compact) then crash-restart the leader. */
    EXPECT_EQ_INT(&ctx, "ckpt", dislmdb_checkpoint(writer), 0);

    char killed[64];
    strncpy(killed, leader, sizeof(killed) - 1);
    killed[sizeof(killed) - 1] = '\0';
    if (writer == a) {
        dislmdb_env_close(a);
        a = NULL;
        envs[0] = NULL;
    } else if (writer == b) {
        dislmdb_env_close(b);
        b = NULL;
        envs[1] = NULL;
    } else {
        dislmdb_env_close(c);
        c = NULL;
        envs[2] = NULL;
    }

    /* Survivors elect a new leader and accept a new write. */
    DISLMDB_env *live[2];
    int nl = 0;
    if (a) {
        live[nl++] = a;
    }
    if (b) {
        live[nl++] = b;
    }
    if (c) {
        live[nl++] = c;
    }
    EXPECT_TRUE(&ctx, "two_live", nl == 2);

    /* Wait until a *live* node is leader (ignore stale leader_id of the dead node). */
    char leader2[64] = {0};
    int got_live_leader = -1;
    for (int w = 0; w < 10000 && got_live_leader != 0; w += 50) {
        for (int i = 0; i < nl; i++) {
            char lid[64] = {0};
            if (dislmdb_get_leader(live[i], lid, sizeof(lid)) != 0 || lid[0] == '\0') {
                continue;
            }
            if (strcmp(lid, killed) == 0) {
                continue;
            }
            for (int j = 0; j < nl; j++) {
                const char *id =
                    (live[j] == a) ? "rwc-a" : (live[j] == b) ? "rwc-b" : "rwc-c";
                if (strcmp(lid, id) == 0) {
                    strncpy(leader2, lid, sizeof(leader2) - 1);
                    got_live_leader = 0;
                    break;
                }
            }
            if (got_live_leader == 0) {
                break;
            }
        }
        usleep(50 * 1000);
    }
    EXPECT_EQ_INT(&ctx, "reelect", got_live_leader, 0);
    EXPECT_TRUE(&ctx, "new_leader", leader2[0] != '\0' && strcmp(leader2, killed) != 0);

    DISLMDB_env *w2 = live[0];
    if (strcmp(leader2, "rwc-b") == 0 && b) {
        w2 = b;
    } else if (strcmp(leader2, "rwc-c") == 0 && c) {
        w2 = c;
    } else if (strcmp(leader2, "rwc-a") == 0 && a) {
        w2 = a;
    }

    EXPECT_EQ_INT(&ctx, "put_post", it_put_kv(w2, "post", "alive"), 0);
    for (int i = 0; i < nl; i++) {
        char np[32], nq[32];
        snprintf(np, sizeof(np), "see_post_%d", i);
        snprintf(nq, sizeof(nq), "see_pre2_%d", i);
        EXPECT_EQ_INT(&ctx, np, it_wait_val(live[i], "post", "alive", 4000), 0);
        EXPECT_EQ_INT(&ctx, nq, it_wait_val(live[i], "pre", "ok", 1000), 0);
    }

    /* Restart killed node — WAL + catch-up must restore pre and eventually post. */
    it_raft_opts ok = oa;
    if (strcmp(killed, "rwc-b") == 0) {
        ok = ob;
    } else if (strcmp(killed, "rwc-c") == 0) {
        ok = oc;
    }
    DISLMDB_env *revived = NULL;
    EXPECT_EQ_INT(&ctx, "reopen_killed", it_open_raft(&revived, &ok), 0);
    DISLMDB_env *mesh2[3];
    int nm = 0;
    mesh2[nm++] = revived;
    for (int i = 0; i < nl; i++) {
        mesh2[nm++] = live[i];
    }
    it_mesh_warmup(mesh2, nm, 60);
    EXPECT_EQ_INT(&ctx, "revived_pre", it_wait_val(revived, "pre", "ok", 5000), 0);
    EXPECT_EQ_INT(&ctx, "revived_post", it_wait_val(revived, "post", "alive", 12000), 0);

    if (revived) {
        dislmdb_env_close(revived);
    }
    if (c) {
        dislmdb_env_close(c);
    }
    if (b) {
        dislmdb_env_close(b);
    }
    if (a) {
        dislmdb_env_close(a);
    }
    it_rm_rf("./it_rwc_a");
    it_rm_rf("./it_rwc_b");
    it_rm_rf("./it_rwc_c");
    return test_end(&ctx);
}
