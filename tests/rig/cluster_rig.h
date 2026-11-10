/**
 * @file cluster_rig.h
 * @brief Sandbox-safe multi-node cluster harness (no LMDB / no mmap)
 *
 * In-memory KV + message bus + Raft. Mirrors integration scenarios:
 * multinode replicate, UDP-style bus delivery, fault after kill, Raft election.
 */
#ifndef DISLMDB_CLUSTER_RIG_H
#define DISLMDB_CLUSTER_RIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIG_MAX_NODES 8
#define RIG_ID_LEN 64
#define RIG_KEY_LEN 64
#define RIG_VAL_LEN 256
#define RIG_KV_SLOTS 128

typedef struct RigCluster RigCluster;

typedef enum RigTransport {
    RIG_TRANSPORT_BUS = 0,    /**< Reliable in-order bus (TCP stand-in) */
    RIG_TRANSPORT_DGRAM = 1,  /**< Same bus; labeled for UDP/WebTransport substrate tests */
    /**
     * Dual-path stand-in for DISLMDB_TRANSPORT_BOTH: Raft RequestVote /
     * heartbeats ride a signalling lane; AppendEntries ride the data lane.
     * Both are in-memory; the split proves adaptation without LMDB.
     */
    RIG_TRANSPORT_MIXED = 2
} RigTransport;

typedef struct RigConfig {
    uint32_t node_count;           /* 2..RIG_MAX_NODES */
    RigTransport transport;
    uint32_t election_timeout_min_ms;
    uint32_t election_timeout_max_ms;
    uint32_t heartbeat_ms;
    const char *id_prefix;         /* e.g. "n" → n0,n1,… ; NULL → "rig" */
} RigConfig;

RigConfig rig_config_default(void);

/** Create and start a Raft cluster. Returns NULL on failure. */
RigCluster *rig_cluster_create(const RigConfig *cfg);
void rig_cluster_destroy(RigCluster *c);

/** Mark node dead (bus drops traffic to/from it). */
void rig_kill(RigCluster *c, uint32_t index);
void rig_revive(RigCluster *c, uint32_t index);
bool rig_alive(const RigCluster *c, uint32_t index);

/** Wait until some alive node reports a leader. 0 on success. */
int rig_wait_leader(RigCluster *c, char *out_id, size_t out_len, int timeout_ms);

/** Propose put on the current leader (or on node_index if it is leader). */
int rig_put(RigCluster *c, const char *key, const char *value, int timeout_ms);

/** Read local KV on node_index (applied state). 0 if found. */
int rig_get(const RigCluster *c, uint32_t node_index, const char *key,
            char *out, size_t out_len);

/** Poll until key==expect on node, or timeout. */
int rig_wait_get(RigCluster *c, uint32_t node_index, const char *key,
                 const char *expect, int timeout_ms);

uint32_t rig_node_count(const RigCluster *c);
const char *rig_node_id(const RigCluster *c, uint32_t index);

/** Counters for MIXED dual-lane delivery (0 on BUS/DGRAM). */
uint64_t rig_signal_msgs(const RigCluster *c);
uint64_t rig_data_msgs(const RigCluster *c);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_CLUSTER_RIG_H */
