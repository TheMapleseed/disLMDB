/**
 * @file test_metrics_format.c
 * @brief Unit: Prometheus text formatting of DISLMDB_metrics (no LMDB).
 */
#include "../harness/test_harness.h"
#include "../../include/dislmdb.h"
#include <string.h>

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/metrics_format");

    DISLMDB_metrics m;
    memset(&m, 0, sizeof(m));
    m.total_commits = 3;
    m.total_operations = 7;
    m.consensus_proposes = 2;
    m.consensus_commits = 2;
    m.replica_count = 3;
    m.active_connections = 2;
    m.is_leader = true;
    m.voting_enabled = true;
    m.consensus_mechanism = DISLMDB_CONSENSUS_RAFT;
    m.raft_term = 5;
    m.raft_commit_index = 42;
    m.raft_peer_count = 2;
    m.dqgm_packets_rx = 11;
    m.outbox_enqueued = 4;
    m.outbox_drained = 3;
    m.outbox_dropped = 1;

    char buf[8192];
    size_t written = 0;
    EXPECT_EQ_INT(&ctx, "format",
                  dislmdb_format_metrics(&m, buf, sizeof(buf), &written), 0);
    EXPECT_TRUE(&ctx, "written", written > 200);
    EXPECT_TRUE(&ctx, "nul", buf[written] == '\0' || buf[sizeof(buf) - 1] == '\0');
    EXPECT_TRUE(&ctx, "commits", strstr(buf, "dislmdb_commits_total 3") != NULL);
    EXPECT_TRUE(&ctx, "raft_term", strstr(buf, "dislmdb_raft_term 5") != NULL);
    EXPECT_TRUE(&ctx, "outbox", strstr(buf, "dislmdb_outbox_dropped_total 1") != NULL);
    EXPECT_TRUE(&ctx, "leader", strstr(buf, "dislmdb_is_leader 1") != NULL);

    size_t need = 0;
    EXPECT_EQ_INT(&ctx, "size_query",
                  dislmdb_format_metrics(&m, NULL, 0, &need), 0);
    EXPECT_EQ_INT(&ctx, "size_match", (int)need, (int)written);

    char tiny[32];
    size_t tw = 0;
    EXPECT_EQ_INT(&ctx, "trunc",
                  dislmdb_format_metrics(&m, tiny, sizeof(tiny), &tw),
                  DISLMDB_ERR_BUFFER_OVERFLOW);
    EXPECT_EQ_INT(&ctx, "trunc_written", (int)tw, (int)written);

    return test_end(&ctx);
}
