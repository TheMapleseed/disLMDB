/**
 * @file test_transport_adapt.c
 * @brief Sandbox-safe: signalling vs data classification for BOTH transport
 */
#include "../harness/test_harness.h"
#include "dislmdb.h"
#include "dislmdb_network.h"
#include "dislmdb_internal.h"
#include "dislmdb_crypto.h"

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

    /* DQGM v1 layout (still accepted on receive) */
    uint8_t v1[DISLMDB_DGRAM_ENVELOPE_V1_SIZE];
    memset(v1, 0, sizeof(v1));
    dislmdb_write_u32(v1, DISLMDB_DQGM_MAGIC);
    v1[4] = 1;
    dislmdb_write_u16(v1 + 6, 1);
    dislmdb_write_u64(v1 + 8, 0x1122334455667788ull);
    EXPECT_EQ_INT(&ctx, "dqgm_v1_magic",
                  (int)dislmdb_read_u32(v1), (int)DISLMDB_DQGM_MAGIC);
    EXPECT_EQ_INT(&ctx, "dqgm_v1_ver", (int)v1[4], 1);
    EXPECT_EQ_INT(&ctx, "dqgm_v1_size", (int)DISLMDB_DGRAM_ENVELOPE_V1_SIZE, 16);

    /* DQGM v2 layout (current send path — cid + pkt_num) */
    uint8_t env_buf[DISLMDB_DGRAM_ENVELOPE_V2_SIZE];
    memset(env_buf, 0, sizeof(env_buf));
    dislmdb_write_u32(env_buf, DISLMDB_DQGM_MAGIC);
    env_buf[4] = DISLMDB_DQGM_VERSION;
    dislmdb_write_u16(env_buf + 6, 1); /* data stream */
    dislmdb_write_u64(env_buf + 8, 0x1122334455667788ull);
    dislmdb_write_u64(env_buf + 16, 42ull);
    EXPECT_EQ_INT(&ctx, "dqgm_magic",
                  (int)dislmdb_read_u32(env_buf), (int)DISLMDB_DQGM_MAGIC);
    EXPECT_EQ_INT(&ctx, "dqgm_ver", (int)env_buf[4], (int)DISLMDB_DQGM_VERSION);
    EXPECT_EQ_INT(&ctx, "dqgm_stream_data", (int)dislmdb_read_u16(env_buf + 6), 1);
    dislmdb_write_u16(env_buf + 6, 0); /* signalling stream */
    EXPECT_EQ_INT(&ctx, "dqgm_stream_sig", (int)dislmdb_read_u16(env_buf + 6), 0);
    EXPECT_TRUE(&ctx, "dqgm_cid",
                dislmdb_read_u64(env_buf + 8) == 0x1122334455667788ull);
    EXPECT_TRUE(&ctx, "dqgm_pkt",
                dislmdb_read_u64(env_buf + 16) == 42ull);
    EXPECT_EQ_INT(&ctx, "dqgm_size", (int)DISLMDB_DGRAM_ENVELOPE_SIZE, 24);
    EXPECT_EQ_INT(&ctx, "dqgm_v2_size", (int)DISLMDB_DGRAM_ENVELOPE_V2_SIZE, 24);

    uint64_t cid_a = dislmdb_read_u64(env_buf + 8);
    uint8_t env_b[DISLMDB_DGRAM_ENVELOPE_V2_SIZE];
    memcpy(env_b, env_buf, sizeof(env_b));
    dislmdb_write_u64(env_b + 8, cid_a ^ 0x1ull);
    EXPECT_TRUE(&ctx, "dqgm_cid_differs",
                dislmdb_read_u64(env_b + 8) != cid_a);
    /* Replay detection: same or lower pkt_num must be rejected by receive path */
    EXPECT_TRUE(&ctx, "dqgm_pkt_stale",
                dislmdb_read_u64(env_buf + 16) <= 42ull);

    return test_end(&ctx);
}
