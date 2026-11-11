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
static int ae_voter;
static int ae_learner;
static int ae_empty_learner;

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

static void lane_out(const RaftMessage *msg, void *ud)
{
    (void)ud;
    if (!msg || msg->type != RAFT_MSG_APPEND_ENTRIES) {
        return;
    }
    if (strcmp(msg->to, "hub-v") == 0) {
        ae_voter++;
    } else if (strcmp(msg->to, "edge-l") == 0) {
        ae_learner++;
        if (msg->entry_count == 0) {
            ae_empty_learner++;
        }
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

    /*
     * Learner AE lane: voter heartbeats must not fan out empty AE to learners;
     * learners still receive AppendEntries that carry log data.
     */
    ae_voter = ae_learner = ae_empty_learner = 0;
    applied = 0;

    RaftConfig hub = raft_config_default();
    strncpy(hub.node_id, "hub", sizeof(hub.node_id) - 1);
    hub.heartbeat_ms = 40;
    hub.learner_ae_ms = 200; /* slower than voter HB */
    hub.election_timeout_min_ms = 40;
    hub.election_timeout_max_ms = 80;
    RaftNode *H = raft_create(&hub, lane_out, on_apply, NULL);
    EXPECT_TRUE(&ctx, "hub_create", H != NULL);
    /* Learner first so solo election can win; add voter peer after lead. */
    EXPECT_EQ_INT(&ctx, "add_learner", (int)raft_add_learner(H, "edge-l"), (int)RAFT_OK);
    raft_start(H);
    for (int i = 0; i < 50 && !raft_is_leader(H); i++) {
        usleep(20 * 1000);
    }
    EXPECT_TRUE(&ctx, "hub_leader", raft_is_leader(H));
    ae_voter = ae_learner = ae_empty_learner = 0;
    usleep(180 * 1000); /* under one learner cadence — must stay quiet to edge */
    EXPECT_EQ_INT(&ctx, "idle_no_learner_ae", ae_learner, 0);
    EXPECT_EQ_INT(&ctx, "no_empty_learner_hb", ae_empty_learner, 0);

    const char *p2 = "lane-op";
    EXPECT_EQ_INT(&ctx, "propose_lane",
                  (int)raft_propose(H, (const uint8_t *)p2, strlen(p2), 2000),
                  (int)RAFT_OK);
    usleep(50 * 1000);
    /* Opportunistic learner push on propose (entries only, never empty). */
    EXPECT_TRUE(&ctx, "learner_got_entries", ae_learner >= 1);
    EXPECT_EQ_INT(&ctx, "still_no_empty_learner", ae_empty_learner, 0);

    /* After lead: add a voter peer and confirm HB lane hits voters. */
    ae_voter = 0;
    EXPECT_EQ_INT(&ctx, "add_voter", (int)raft_add_peer(H, "hub-v"), (int)RAFT_OK);
    usleep(150 * 1000);
    EXPECT_TRUE(&ctx, "voter_hb", ae_voter >= 2);
    raft_stop(H);
    raft_destroy(H);

    return test_end(&ctx);
}
