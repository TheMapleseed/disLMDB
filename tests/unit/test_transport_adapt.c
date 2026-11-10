/**
 * @file test_transport_adapt.c
 * @brief Sandbox-safe: signalling vs data classification for BOTH transport
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_network.h"

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/transport_adapt");

    EXPECT_TRUE(&ctx, "hb_signal",
                dislmdb_network_is_signalling(DISLMDB_MESSAGE_HEARTBEAT));
    EXPECT_TRUE(&ctx, "join_signal",
                dislmdb_network_is_signalling(DISLMDB_MESSAGE_JOIN));
    EXPECT_TRUE(&ctx, "leave_signal",
                dislmdb_network_is_signalling(DISLMDB_MESSAGE_LEAVE));
    EXPECT_TRUE(&ctx, "elect_signal",
                dislmdb_network_is_signalling(DISLMDB_MESSAGE_ELECTION));

    EXPECT_TRUE(&ctx, "prepare_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_PREPARE));
    EXPECT_TRUE(&ctx, "commit_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_COMMIT));
    EXPECT_TRUE(&ctx, "sync_req_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_SYNC_REQUEST));
    EXPECT_TRUE(&ctx, "sync_rsp_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_SYNC_RESPONSE));
    EXPECT_TRUE(&ctx, "reply_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_REPLY));
    EXPECT_TRUE(&ctx, "ckpt_data",
                !dislmdb_network_is_signalling(DISLMDB_MESSAGE_CHECKPOINT));

    EXPECT_EQ_INT(&ctx, "both_enum", (int)DISLMDB_TRANSPORT_BOTH, 2);
    EXPECT_EQ_INT(&ctx, "tcp_enum", (int)DISLMDB_TRANSPORT_TCP, 0);
    EXPECT_EQ_INT(&ctx, "udp_enum", (int)DISLMDB_TRANSPORT_UDP, 1);

    return test_end(&ctx);
}
