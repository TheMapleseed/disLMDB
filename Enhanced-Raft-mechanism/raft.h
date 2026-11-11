/**
 * @file raft.h
 * @brief Local Raft consensus core for DisLMDB (leader election + log replication)
 *
 * Implements the Raft paper essentials: RequestVote, AppendEntries, majority
 * commit, and applied-index delivery. Transport is supplied by the integrator.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#ifndef DISLMDB_RAFT_H
#define DISLMDB_RAFT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bootstrap peer array size in RaftConfig (create-time convenience).
 * Runtime peer tables on RaftNode are heap-growable past this; soft guard
 * is RAFT_PEER_SOFT_MAX inside raft.c.
 */
#define RAFT_MAX_PEERS 512
#define RAFT_MAX_LOG 4096
#define RAFT_NODE_ID_LEN 64
#define RAFT_DIGEST_LEN 32

typedef enum RaftRole {
    RAFT_FOLLOWER = 0,
    RAFT_CANDIDATE = 1,
    RAFT_LEADER = 2
} RaftRole;

typedef enum RaftError {
    RAFT_OK = 0,
    RAFT_ERR_INVALID,
    RAFT_ERR_MEMORY,
    RAFT_ERR_TIMEOUT,
    RAFT_ERR_NOT_LEADER,
    RAFT_ERR_STATE,
    RAFT_ERR_FULL
} RaftError;

typedef enum RaftMsgType {
    RAFT_MSG_REQUEST_VOTE = 1,
    RAFT_MSG_REQUEST_VOTE_REPLY = 2,
    RAFT_MSG_APPEND_ENTRIES = 3,
    RAFT_MSG_APPEND_ENTRIES_REPLY = 4,
    RAFT_MSG_INSTALL_SNAPSHOT = 5,
    RAFT_MSG_INSTALL_SNAPSHOT_REPLY = 6
} RaftMsgType;

typedef struct RaftLogEntry {
    uint64_t term;
    uint64_t index; /* 1-based */
    uint8_t *data;
    size_t data_len;
} RaftLogEntry;

typedef struct RaftMessage {
    RaftMsgType type;
    uint64_t term;
    char from[RAFT_NODE_ID_LEN];
    char to[RAFT_NODE_ID_LEN];
    /* RequestVote / InstallSnapshot included index+term */
    uint64_t last_log_index;
    uint64_t last_log_term;
    /* AppendEntries */
    uint64_t prev_log_index;
    uint64_t prev_log_term;
    uint64_t leader_commit;
    RaftLogEntry *entries;
    size_t entry_count;
    /**
     * InstallSnapshot: optional FSM blob (also carried as entries[0].data on
     * the wire for backward-compatible framing).
     */
    uint8_t *snapshot_data;
    size_t snapshot_len;
    /* Replies */
    bool success;
    bool vote_granted;
    uint64_t match_index;
} RaftMessage;

typedef void (*raft_outbound_fn)(const RaftMessage *msg, void *user_data);
typedef void (*raft_apply_fn)(uint64_t index, const uint8_t *data, size_t len, void *user_data);
/**
 * Produce an owned FSM snapshot blob for InstallSnapshot when a follower’s
 * last_applied is behind last_included. Return 0 and set out/out_len, or
 * non-zero to send meta-only (follower will reject if behind).
 */
typedef int (*raft_fsm_snapshot_fn)(uint64_t last_included_index, uint8_t **out,
                                    size_t *out_len, void *user_data);
/** Install FSM bytes; return 0 on success. */
typedef int (*raft_fsm_restore_fn)(uint64_t last_included_index,
                                   uint64_t last_included_term,
                                   const uint8_t *data, size_t len,
                                   void *user_data);

typedef struct RaftConfig {
    char node_id[RAFT_NODE_ID_LEN];
    /** Copied into a growable heap table at raft_create(); not used afterward. */
    char peer_ids[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t peer_count;
    uint32_t election_timeout_min_ms;
    uint32_t election_timeout_max_ms;
    uint32_t heartbeat_ms;
    /**
     * Cross-region / learner AppendEntries cadence (ms). 0 = 4× heartbeat_ms.
     * Voter heartbeats stay on heartbeat_ms; learners are paced on this lane
     * so mirror fan-out does not stall the local quorum path.
     */
    uint32_t learner_ae_ms;
    /**
     * When false, this node is a learner/replicate-only member: it never
     * campaigns and never grants votes. Large clusters turn this off via
     * DISLMDB_VOTING=0 while regional hubs keep voting on.
     */
    bool enable_voting;
} RaftConfig;

typedef struct RaftNode RaftNode;

/**
 * @brief Optional durability hooks (DisLMDB Raft WAL). Invoked under the node lock.
 * Implementations must not call back into Raft (no propose/handle/start).
 */
typedef struct RaftPersistHooks {
    void (*on_hard_state)(uint64_t term, const char *voted_for,
                          uint64_t commit_index, uint64_t last_applied, void *ud);
    void (*on_log_append)(uint64_t index, uint64_t term,
                          const uint8_t *data, size_t len, void *ud);
    /** Drop durable entries with index >= from_index (inclusive). */
    void (*on_log_truncate)(uint64_t from_index, void *ud);
} RaftPersistHooks;

RaftConfig raft_config_default(void);
RaftNode *raft_create(const RaftConfig *cfg,
                      raft_outbound_fn outbound,
                      raft_apply_fn apply,
                      void *user_data);
void raft_destroy(RaftNode *node);

/** Install persist hooks (NULL hooks disables). Call before raft_start. */
void raft_set_persist_hooks(RaftNode *node, const RaftPersistHooks *hooks, void *ud);

/**
 * @brief Optional FSM dump/restore for InstallSnapshot when followers lag past
 * compacted log_base. Call before raft_start.
 */
void raft_set_fsm_hooks(RaftNode *node, raft_fsm_snapshot_fn snapshot,
                        raft_fsm_restore_fn restore, void *ud);

/**
 * @brief Restore hard state before raft_start (idempotent overwrite).
 * Does not invoke apply callbacks.
 */
RaftError raft_restore_hard_state(RaftNode *node, uint64_t term, const char *voted_for,
                                  uint64_t commit_index, uint64_t last_applied);

/**
 * @brief Append one restored log entry (must be contiguous from 1, or after snapshot).
 * Takes a copy of data. Does not invoke apply or persist hooks.
 */
RaftError raft_restore_log_entry(RaftNode *node, uint64_t index, uint64_t term,
                                 const uint8_t *data, size_t len);

/**
 * @brief Drop in-memory log prefix through last_included_index (inclusive).
 * Used after installing a snapshot descriptor; entries must already be durable-truncated.
 */
RaftError raft_compact_log_through(RaftNode *node, uint64_t last_included_index);

/** Install snapshot boundary before restoring post-snapshot log entries. */
RaftError raft_restore_snapshot_meta(RaftNode *node, uint64_t last_included_index,
                                     uint64_t last_included_term);

/**
 * @brief Highest index that may be compacted without starving peers.
 * min(last_applied, min match_index among peers that have matched > 0).
 * Solo (no peers): last_applied.
 */
uint64_t raft_safe_compact_index(const RaftNode *node);

void raft_start(RaftNode *node);
void raft_stop(RaftNode *node);

/**
 * @brief Register a peer locally (idempotent). Bootstrap / HELLO only —
 * durable membership changes must use raft_propose_membership().
 */
RaftError raft_add_peer(RaftNode *node, const char *peer_id);

/**
 * @brief Register a non-voting peer (learner). Receives log replication but
 * is excluded from election/commit quorum. Idempotent; upgrades existing.
 */
RaftError raft_add_learner(RaftNode *node, const char *peer_id);

/**
 * @brief Mark an existing peer as voter (true) or learner (false).
 */
RaftError raft_set_peer_voting(RaftNode *node, const char *peer_id, bool voting);

/**
 * @brief Drop a peer locally (idempotent). Bootstrap / cleanup only.
 */
RaftError raft_remove_peer(RaftNode *node, const char *peer_id);

/** @brief True if this node participates in elections/quorum. */
bool raft_voting_enabled(const RaftNode *node);

/**
 * @brief Joint-consensus membership change to the given peer set (excluding self).
 *
 * Proposes Cold,new then Cnew per the Raft dissertation. Blocks until Cnew
 * commits or timeout_ms elapses. Caller must be leader.
 */
RaftError raft_propose_membership(RaftNode *node,
                                  const char peer_ids[][RAFT_NODE_ID_LEN],
                                  uint32_t peer_count,
                                  uint32_t timeout_ms);

RaftError raft_propose(RaftNode *node, const uint8_t *data, size_t len, uint32_t timeout_ms);
RaftError raft_handle_message(RaftNode *node, const RaftMessage *msg);

/**
 * @brief Step down to follower and arm an immediate election timeout.
 * Used by dislmdb_consensus_trigger_view_change under Raft.
 */
RaftError raft_step_down(RaftNode *node);

RaftRole raft_role(const RaftNode *node);
uint64_t raft_term(const RaftNode *node);
uint64_t raft_commit_index(const RaftNode *node);
uint64_t raft_last_applied(const RaftNode *node);
uint64_t raft_log_base(const RaftNode *node);
uint64_t raft_log_base_term(const RaftNode *node);
bool raft_is_leader(const RaftNode *node);
void raft_leader_id(const RaftNode *node, char out[RAFT_NODE_ID_LEN]);
uint32_t raft_peer_count(const RaftNode *node);
bool raft_in_joint_consensus(const RaftNode *node);
/** @brief Copy current voter peer ids (excluding self). Returns count written. */
uint32_t raft_copy_peers(const RaftNode *node,
                         char out[][RAFT_NODE_ID_LEN],
                         uint32_t max_out);

int raft_message_serialize(const RaftMessage *msg, uint8_t **out, size_t *out_len);
int raft_message_deserialize(const uint8_t *buf, size_t len, RaftMessage *out);
void raft_message_clear(RaftMessage *msg);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_RAFT_H */
