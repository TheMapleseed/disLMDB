/**
 * @file test_raft_peer_growth.c
 * @brief Unit: Raft peer tables grow past historical 64/512 fixed caps.
 */
#include "../harness/test_harness.h"
#include "../../Enhanced-Raft-mechanism/raft.h"
#include <stdio.h>
#include <string.h>

static void on_out(const RaftMessage *msg, void *ud)
{
    (void)msg;
    (void)ud;
}

static void on_apply(uint64_t index, const uint8_t *data, size_t len, void *ud)
{
    (void)index;
    (void)data;
    (void)len;
    (void)ud;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/raft_peer_growth");

    RaftConfig cfg = raft_config_default();
    strncpy(cfg.node_id, "hub", sizeof(cfg.node_id) - 1);
    cfg.peer_count = 0;

    RaftNode *n = raft_create(&cfg, on_out, on_apply, NULL);
    EXPECT_TRUE(&ctx, "create", n != NULL);

    const uint32_t N = 128; /* past historical DISLMDB_MAX_NODES=64 */
    for (uint32_t i = 0; i < N; i++) {
        char id[RAFT_NODE_ID_LEN];
        snprintf(id, sizeof(id), "peer-%u", i);
        RaftError err = raft_add_peer(n, id);
        EXPECT_EQ_INT(&ctx, "add", (int)err, (int)RAFT_OK);
    }
    EXPECT_EQ_INT(&ctx, "count", (int)raft_peer_count(n), (int)N);

    char out[16][RAFT_NODE_ID_LEN];
    uint32_t copied = raft_copy_peers(n, out, 16);
    EXPECT_EQ_INT(&ctx, "copy_cap", (int)copied, 16);
    EXPECT_TRUE(&ctx, "copy0", strncmp(out[0], "peer-0", RAFT_NODE_ID_LEN) == 0);

    EXPECT_EQ_INT(&ctx, "rm", (int)raft_remove_peer(n, "peer-7"), (int)RAFT_OK);
    EXPECT_EQ_INT(&ctx, "count_after_rm", (int)raft_peer_count(n), (int)(N - 1));

    EXPECT_EQ_INT(&ctx, "learner", (int)raft_add_learner(n, "edge-1"), (int)RAFT_OK);
    EXPECT_EQ_INT(&ctx, "count_learner", (int)raft_peer_count(n), (int)N);

    raft_destroy(n);
    return test_end(&ctx);
}
