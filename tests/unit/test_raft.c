/**
 * @file test_raft.c
 * @brief Unit: local Raft election + solo propose/commit
 */
#include "../harness/test_harness.h"
#include "../../Enhanced-Raft-mechanism/raft.h"
#include <string.h>
#include <unistd.h>

static int applied;
static uint8_t last_payload[64];
static size_t last_len;

static void on_out(const RaftMessage *msg, void *ud)
{
    (void)ud;
    (void)msg; /* solo: no peers */
}

static void on_apply(uint64_t index, const uint8_t *data, size_t len, void *ud)
{
    (void)ud;
    (void)index;
    applied++;
    last_len = len < sizeof(last_payload) ? len : sizeof(last_payload);
    if (data && last_len) {
        memcpy(last_payload, data, last_len);
    }
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/raft");

    RaftConfig cfg = raft_config_default();
    strncpy(cfg.node_id, "n1", sizeof(cfg.node_id) - 1);
    cfg.peer_count = 0;
    cfg.election_timeout_min_ms = 50;
    cfg.election_timeout_max_ms = 100;
    cfg.heartbeat_ms = 30;

    RaftNode *n = raft_create(&cfg, on_out, on_apply, NULL);
    EXPECT_TRUE(&ctx, "create", n != NULL);
    raft_start(n);

    for (int i = 0; i < 40 && !raft_is_leader(n); i++) {
        usleep(20 * 1000);
    }
    EXPECT_TRUE(&ctx, "became_leader", raft_is_leader(n));

    const char *payload = "raft-op-1";
    RaftError err = raft_propose(n, (const uint8_t *)payload, strlen(payload), 2000);
    EXPECT_EQ_INT(&ctx, "propose", (int)err, (int)RAFT_OK);
    EXPECT_TRUE(&ctx, "applied", applied >= 1);
    EXPECT_TRUE(&ctx, "payload",
                last_len == strlen(payload) && memcmp(last_payload, payload, last_len) == 0);
    EXPECT_TRUE(&ctx, "commit_idx", raft_commit_index(n) >= 1);
    EXPECT_TRUE(&ctx, "voting_on", raft_voting_enabled(n));

    raft_stop(n);
    raft_destroy(n);

    /* Voting off: learner never campaigns / becomes leader. */
    RaftConfig leaf = raft_config_default();
    strncpy(leaf.node_id, "learner", sizeof(leaf.node_id) - 1);
    leaf.enable_voting = false;
    leaf.election_timeout_min_ms = 30;
    leaf.election_timeout_max_ms = 60;
    RaftNode *L = raft_create(&leaf, on_out, on_apply, NULL);
    EXPECT_TRUE(&ctx, "learner_create", L != NULL);
    EXPECT_TRUE(&ctx, "voting_off", !raft_voting_enabled(L));
    raft_start(L);
    usleep(250 * 1000);
    EXPECT_TRUE(&ctx, "learner_not_leader", !raft_is_leader(L));
    raft_stop(L);
    raft_destroy(L);

    return test_end(&ctx);
}
