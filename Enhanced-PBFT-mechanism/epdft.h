/**
 * @file epdft.h
 * @brief Enhanced PBFT consensus core — C port of TheMapleseed/Enhanced-PBFT-mechanism
 *
 * Spec / Rust: https://github.com/TheMapleseed/Enhanced-PBFT-mechanism
 * TV-B3 paper: https://github.com/TheMapleseed/Time-VariantBlake3
 */

#ifndef EPDFT_H
#define EPDFT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#include "messaging.h"
#include "security_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EPDFT_MAX_REPLICAS 64
#define EPDFT_MAX_SLOTS 128
#define EPDFT_NODE_ID_LEN 64

typedef enum ConsensusError {
    CONSENSUS_OK = 0,
    CONSENSUS_ERROR_INVALID_PARAMETER,
    CONSENSUS_ERROR_MEMORY_ERROR,
    CONSENSUS_ERROR_TIMEOUT,
    CONSENSUS_ERROR_NOT_LEADER,
    CONSENSUS_ERROR_QUORUM_FAILED,
    CONSENSUS_ERROR_SIGNATURE,
    CONSENSUS_ERROR_STATE,
    CONSENSUS_ERROR_MESSAGE_TOO_LARGE,
    CONSENSUS_ERROR_INSUFFICIENT_REPLICAS,
    CONSENSUS_ERROR_UNKNOWN_REPLICA,
    CONSENSUS_ERROR_SEND
} ConsensusError;

typedef struct ConsensusTimeouts {
    struct timespec prepare_timeout;
    struct timespec commit_timeout;
    struct timespec view_change_timeout;
    uint32_t wait_pre_prepare_ms;
    uint32_t prepare_certificate_ms;
    uint32_t commit_certificate_ms;
    uint32_t view_change_resend_ms;
    bool enabled;
} ConsensusTimeouts;

typedef struct ConsensusConfig {
    uint32_t fault_tolerance;
    uint32_t min_nodes;
    ConsensusTimeouts timeouts;
    size_t max_message_size;
    bool verify_signatures;
    char replica_ids[EPDFT_MAX_REPLICAS][EPDFT_NODE_ID_LEN];
    uint32_t replica_count;
} ConsensusConfig;

typedef struct NodeId {
    char id[EPDFT_NODE_ID_LEN];
} NodeId;

typedef struct PbftMessage {
    MessageType type;
    char from[EPDFT_NODE_ID_LEN];
    uint64_t view;
    uint64_t sequence;
    uint8_t digest[SECURITY_DIGEST_LEN];
    uint8_t auth[SECURITY_AUTH_LEN]; /**< TV-BLAKE3 keyed MAC (zero if unsigned) */
    bool has_auth;
    uint64_t last_stable_seq;
    uint8_t *data;
    size_t data_len;
} PbftMessage;

typedef void (*pbft_outbound_fn)(const PbftMessage *msg, void *user_data);

typedef struct ConsensusCore ConsensusCore;

ConsensusConfig consensus_config_default(void);
uint32_t consensus_config_quorum(const ConsensusConfig *cfg);
int consensus_config_validate(const ConsensusConfig *cfg);

NodeId *node_id_create(const char *id);
void node_id_destroy(NodeId *node_id);

ConsensusCore *consensus_core_create(NodeId *node_id,
                                     const ConsensusConfig *config,
                                     SecurityManager *security);
void consensus_core_set_outbound(ConsensusCore *core,
                                 pbft_outbound_fn outbound,
                                 void *user_data);
void consensus_core_destroy(ConsensusCore *core);

/**
 * Propose `data` and block until a commit certificate is formed for its
 * sequence (or timeout). Solo (f=0) completes synchronously inside dispatch.
 */
ConsensusError consensus_core_propose(ConsensusCore *core,
                                      const uint8_t *data,
                                      size_t size);

/** Copy the current primary replica id for `core->view` into out (NUL-terminated). */
void consensus_core_primary_id(const ConsensusCore *core, char out[EPDFT_NODE_ID_LEN]);

/** Recompute fault_tolerance to the largest f with 3f+1 <= replica_count (capped by prefer_f if >0). */
void consensus_core_recompute_faults(ConsensusCore *core, uint32_t prefer_f);

ConsensusError consensus_core_handle_message(ConsensusCore *core,
                                             MessageType type,
                                             const char *from_node,
                                             const uint8_t *data,
                                             size_t size);

ConsensusError consensus_core_handle_pbft(ConsensusCore *core, const PbftMessage *msg);

bool consensus_core_is_primary(const ConsensusCore *core);
uint32_t consensus_core_view(const ConsensusCore *core);
uint32_t consensus_core_sequence(const ConsensusCore *core);
uint64_t consensus_core_last_committed(const ConsensusCore *core);
BroadcastChannel *consensus_core_commit_channel(ConsensusCore *core);

/** Start background liveness watcher (view-change on stall). */
void consensus_core_start_liveness(ConsensusCore *core);
void consensus_core_stop_liveness(ConsensusCore *core);

/** Emit a checkpoint for last_committed_seq. */
ConsensusError consensus_core_checkpoint(ConsensusCore *core);

/** Request state starting after `after_seq` from peers. */
ConsensusError consensus_core_request_state(ConsensusCore *core, uint64_t after_seq);

/** Dynamically add/remove a replica id (membership change; caller must keep 3f+1). */
ConsensusError consensus_core_add_replica(ConsensusCore *core, const char *replica_id);
ConsensusError consensus_core_remove_replica(ConsensusCore *core, const char *replica_id);

/** Lexicographically sort replica_ids so every node shares the same primary rotation. */
void consensus_core_normalize_replicas(ConsensusCore *core);

/** Restore durable consensus counters after restart. */
void consensus_core_restore(ConsensusCore *core, uint64_t view, uint64_t last_committed);

typedef struct ConsensusMetrics {
    uint64_t proposes;
    uint64_t commits;
    uint64_t view_changes;
    uint64_t checkpoints;
    uint64_t state_transfers;
} ConsensusMetrics;

void consensus_core_get_metrics(const ConsensusCore *core, ConsensusMetrics *out);

int pbft_message_serialize(const PbftMessage *msg, uint8_t **out, size_t *out_len);
int pbft_message_deserialize(const uint8_t *buf, size_t len, PbftMessage *out);
void pbft_message_clear(PbftMessage *msg);

/* Public layout for adapter compatibility (config + commit_channel). */
struct ConsensusCore {
    NodeId *node_id;
    ConsensusConfig config;
    SecurityManager *security;
    BroadcastChannel *commit_channel;
    pbft_outbound_fn outbound;
    void *outbound_user;
    uint64_t view;
    uint64_t last_committed_seq;
    uint64_t stable_checkpoint;
    bool is_primary;
    pthread_mutex_t lock;
    void *impl; /* internal slot / VC / liveness state */
    ConsensusMetrics metrics;
};

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_H */
