/**
 * @file dislmdb.h
 * @brief Distributed Lightning Memory-Mapped Database (DisLMDB)
 *
 * DisLMDB is a distributed version of LMDB (Lightning Memory-Mapped Database)
 * which supports synchronization of database operations across multiple nodes
 * using a consensus protocol based on Practical Byzantine Fault Tolerance (PBFT).
 *
 * DisLMDB inherits LMDB's core features:
 * - ACID transactions
 * - Zero-copy memory-mapped design for high performance
 * - B+tree data structure for efficient data storage and retrieval
 *
 * And adds:
 * - Multi-node distribution with consensus
 * - Node discovery and synchronization
 * - Byzantine fault tolerance
 * - Support for ML model/bytecode distribution
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_H
#define DISLMDB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Import original LMDB types */
#include "lmdb.h"
#include "dislmdb_errors.h"

/** @brief Version information for DisLMDB */
#define DISLMDB_VERSION_MAJOR 0
#define DISLMDB_VERSION_MINOR 1
#define DISLMDB_VERSION_PATCH 0

/** @brief The consensus mechanisms supported by DisLMDB */
typedef enum DISLMDB_CONSENSUS_MECHANISM {
    DISLMDB_CONSENSUS_PBFT,        /**< Practical Byzantine Fault Tolerance */
    DISLMDB_CONSENSUS_RAFT,        /**< Raft consensus (local Enhanced-Raft-mechanism) */
    DISLMDB_CONSENSUS_SOLO         /**< Single node mode (no distribution) */
} DISLMDB_CONSENSUS_MECHANISM;

/** @brief Node states in the consensus algorithm */
typedef enum DISLMDB_NODE_STATE {
    DISLMDB_NODE_STATE_UNKNOWN,    /**< Node state is unknown */
    DISLMDB_NODE_STATE_JOINING,    /**< Node is in the process of joining the network */
    DISLMDB_NODE_STATE_SYNCING,    /**< Node is syncing data from other nodes */
    DISLMDB_NODE_STATE_NORMAL,     /**< Node is operating normally */
    DISLMDB_NODE_STATE_LEADER,     /**< Node is the current leader */
    DISLMDB_NODE_STATE_FOLLOWER,   /**< Node is a follower */
    DISLMDB_NODE_STATE_CANDIDATE,  /**< Node is a candidate for leadership */
    DISLMDB_NODE_STATE_LEAVING     /**< Node is in the process of leaving the network */
} DISLMDB_NODE_STATE;

/** @brief Types of messages for inter-node communication */
typedef enum DISLMDB_MESSAGE_TYPE {
    DISLMDB_MESSAGE_PREPARE,       /**< PBFT prepare message */
    DISLMDB_MESSAGE_COMMIT,        /**< PBFT commit message */
    DISLMDB_MESSAGE_REPLY,         /**< PBFT reply message */
    DISLMDB_MESSAGE_CHECKPOINT,    /**< Checkpoint message for recovery */
    DISLMDB_MESSAGE_SYNC_REQUEST,  /**< Request to sync data */
    DISLMDB_MESSAGE_SYNC_RESPONSE, /**< Response to sync request */
    DISLMDB_MESSAGE_JOIN,          /**< Request to join the network */
    DISLMDB_MESSAGE_LEAVE,         /**< Notification that a node is leaving */
    DISLMDB_MESSAGE_HEARTBEAT,     /**< Heartbeat message to check node status */
    DISLMDB_MESSAGE_ELECTION,      /**< Leader election message */
    DISLMDB_MESSAGE_FORWARD,       /**< Shard owner forward (put/del/get) */
    DISLMDB_MESSAGE_FORWARD_REPLY  /**< Owner ack/nack (+ value for get) */
} DISLMDB_MESSAGE_TYPE;

/** @brief Network address information for nodes */
typedef struct DISLMDB_node_addr {
    char hostname[256];            /**< Hostname or IP address */
    uint16_t port;                 /**< Port number */
    char node_id[64];              /**< Unique node identifier */
    char region[64];               /**< Optional region id (affinity / nearest dial) */
    char locality[64];             /**< Optional AZ / rack / zone */
    uint32_t rtt_ewma_ms;          /**< Persisted RTT EWMA (0 = unknown) */
} DISLMDB_node_addr;

/** @brief Mirror-mode write conflict / authority policy */
typedef enum DISLMDB_MIRROR_CONFLICT_POLICY {
    /** Consensus log order wins (default). Any voting replica may write. */
    DISLMDB_MIRROR_LAST_WRITE = 0,
    /**
     * Only the primary mirror region may write; others are rejected.
     * Set @ref DISLMDB_env_config.mirror_primary_region (or env
     * `DISLMDB_MIRROR_PRIMARY_REGION`). Empty primary ⇒ last-write behavior.
     */
    DISLMDB_MIRROR_REGION_PRIORITY = 1
} DISLMDB_MIRROR_CONFLICT_POLICY;

/** @brief Wire transport for cluster traffic */
typedef enum DISLMDB_TRANSPORT {
    DISLMDB_TRANSPORT_TCP = 0,     /**< Reliable stream (default) */
    DISLMDB_TRANSPORT_UDP = 1,     /**< Datagram path with DQGM v2 session envelope (QUIC/WT substrate) */
    /**
     * Dual listen (TCP + UDP). Signalling (HELLO/JOIN, HEARTBEAT, ELECTION,
     * LEAVE) prefers UDP; bulk/consensus data prefers TCP. Each path falls
     * back to the other when the preferred medium is unavailable.
     */
    DISLMDB_TRANSPORT_BOTH = 2,
    /**
     * QUIC / WebTransport (TLS 1.3 over UDP) atop DQGM.
     * Substrate ships (long-header parse + version negotiation on UDP).
     * Full handshake gated — @ref dislmdb_env_open returns
     * Requires @c dislmdb_quic_stack_ready() (UDP + QUIC HS/1-RTT).
     */
    DISLMDB_TRANSPORT_QUIC = 3
} DISLMDB_TRANSPORT;

/** @brief Network configuration for DisLMDB */
typedef struct DISLMDB_network_config {
    DISLMDB_node_addr *nodes;      /**< Array of known node addresses */
    size_t node_count;             /**< Number of nodes in the array */
    uint16_t local_port;           /**< Port for this node to listen on */
    bool is_seed_node;             /**< Whether this node is a seed node */
    char seed_nodes[10][256];      /**< List of seed node addresses */
    size_t seed_node_count;        /**< Number of seed nodes */
    bool enable_message_auth;      /**< HMAC-authenticate framed messages */
    uint8_t cluster_key[32];       /**< Shared cluster HMAC/AEAD key */
    bool has_cluster_key;          /**< Whether cluster_key is populated */
    bool enable_payload_encryption;/**< AEAD payload seal/open with cluster_key (default on) */
    bool enable_tls;               /**< Legacy alias: enables payload AEAD when mTLS off */
    bool enable_mtls;              /**< Real mutual TLS 1.3 on the TCP path */
    DISLMDB_TRANSPORT transport;   /**< TCP, UDP, or both */
    char tls_cert_path[512];       /**< PEM leaf certificate (mTLS) */
    char tls_key_path[512];        /**< PEM private key (mTLS) */
    char tls_ca_path[512];         /**< PEM CA bundle for peer verification (mTLS) */
    /**
     * Phase G: threads for blocking mTLS handshakes (0 = default 2).
     * Keeps the net thread on select/bytes while workers finish TLS 1.3.
     */
    uint32_t handshake_workers;
} DISLMDB_network_config;

/** @brief Consensus configuration parameters */
typedef struct DISLMDB_consensus_config {
    DISLMDB_CONSENSUS_MECHANISM mechanism; /**< Consensus mechanism to use */
    uint32_t timeout_ms;                   /**< Base timeout in milliseconds */
    uint32_t heartbeat_interval_ms;        /**< Interval between heartbeats */
    uint32_t election_timeout_min_ms;      /**< Minimum election timeout */
    uint32_t election_timeout_max_ms;      /**< Maximum election timeout */
    uint32_t max_batch_size;               /**< Maximum operations in a batch */
    uint32_t checkpoint_interval;          /**< Operations between checkpoints */
    uint32_t fault_tolerance;              /**< PBFT f — tolerate f faulty nodes (needs 3f+1) */
    bool enable_liveness;                  /**< Enable view-change timeouts */
    bool persist_state;                    /**< Persist view/sequence/replicas to meta DB */
    bool persist_cluster_key;              /**< Persist raw cluster key in meta DB (off by default) */
    /**
     * Participate in elections / quorum (default true). Set false for large-cluster
     * leaf/learner nodes — still replicate, never campaign or grant votes.
     * Overridable by env `DISLMDB_VOTING=0|off|false` (or 1|on|true).
     */
    bool enable_voting;
    /**
     * Raft WAL: fsync LMDB every N durable appends (1 = every append; 0 = rely on
     * checkpoint / env close only). Hard-state (term/vote) still syncs every write.
     */
    uint32_t raft_wal_sync_every;
} DISLMDB_consensus_config;

/** @brief Runtime metrics for DisLMDB (snapshot via dislmdb_get_metrics) */
typedef struct DISLMDB_metrics {
    uint64_t total_commits;
    uint64_t total_operations;
    uint64_t total_sync_bytes;
    uint64_t consensus_proposes;
    uint64_t consensus_commits;
    uint64_t view_changes;
    uint64_t checkpoints;
    uint64_t state_transfers;
    uint32_t current_view;           /**< PBFT view, or Raft term (cast) */
    uint64_t last_committed_seq;     /**< PBFT seq / Raft commit index */
    uint32_t replica_count;
    uint32_t active_connections; /**< Live CONNECTED peers (from network stats) */
    /** Consensus / role */
    uint32_t consensus_mechanism; /**< DISLMDB_CONSENSUS_* */
    bool is_leader;
    bool voting_enabled;
    uint64_t raft_term;
    uint64_t raft_commit_index;
    uint32_t raft_peer_count;
    /** Network */
    uint64_t messages_sent;
    uint64_t messages_received;
    uint32_t connection_failures;
    /** DQGM (UDP) substrate — copied from network stats when available */
    uint64_t dqgm_packets_rx;
    uint64_t dqgm_cid_mismatch;
    uint64_t dqgm_replay_drop;
    uint64_t dqgm_session_rebind;
    uint64_t dqgm_ack_rx;
    uint64_t dqgm_ack_advance;
    /** Per-peer outbound reliability queue */
    uint64_t outbox_enqueued;
    uint64_t outbox_drained;
    uint64_t outbox_dropped;
} DISLMDB_metrics;

/** @brief Maximum entries in a shard map */
#define DISLMDB_MAX_SHARDS 64
/** @brief Shard id / key-prefix field sizes */
#define DISLMDB_SHARD_ID_LEN 64
#define DISLMDB_SHARD_PREFIX_LEN 128

/** @brief Shard descriptor flags (OR into DISLMDB_shard_desc.flags) */
#define DISLMDB_SHARD_FLAG_MIRRORED 0x0001u /**< Hybrid: prefix fully replicated; any node may write */

/**
 * @brief One shard: keys matching key_prefix (longest match wins) affinity to owner.
 *
 * Replaces the orb key-prefix convention with an explicit, queryable map.
 * In `DISLMDB_TOPO_SHARD`, writes for a key must land on `owner_node_id`.
 * In `DISLMDB_TOPO_HYBRID`, prefixes with `DISLMDB_SHARD_FLAG_MIRRORED` skip
 * ownership checks; other prefixes behave like shard mode.
 */
typedef struct DISLMDB_shard_desc {
    char shard_id[DISLMDB_SHARD_ID_LEN];       /**< Stable shard identifier */
    char key_prefix[DISLMDB_SHARD_PREFIX_LEN]; /**< Key prefix owned by this shard */
    char owner_node_id[64];                    /**< Affinity / primary owner node */
    uint32_t flags;                            /**< DISLMDB_SHARD_FLAG_* */
} DISLMDB_shard_desc;

/** @brief Opaque structure for a distributed environment */
typedef struct DISLMDB_env DISLMDB_env;

/** @brief Opaque structure for a distributed transaction */
typedef struct DISLMDB_txn DISLMDB_txn;

/** @brief Cross-region / multi-region data placement */
typedef enum DISLMDB_TOPOLOGY_MODE {
    DISLMDB_TOPO_MIRROR = 0, /**< Full KV everywhere; cross-region = Raft learners */
    DISLMDB_TOPO_SHARD = 1,  /**< Writes only on shard owner; cross-region not in Raft */
    DISLMDB_TOPO_HYBRID = 2  /**< Mirrored prefixes + sharded cold prefixes */
} DISLMDB_TOPOLOGY_MODE;

/**
 * @brief Configuration for a DisLMDB environment
 *
 * Combines LMDB parameters with distribution. Region/locality/voting/secrets
 * may also come from process env at open (`DISLMDB_REGION`, `DISLMDB_VOTING`, …).
 */
typedef struct DISLMDB_env_config {
    /* Base LMDB configuration */
    const char *path;                  /**< Database directory path */
    unsigned int lmdb_flags;           /**< Original LMDB flags */
    mdb_mode_t mode;                   /**< File mode */
    size_t mapsize;                    /**< Maximum database size */
    unsigned int maxreaders;           /**< Maximum number of reader slots */
    unsigned int maxdbs;               /**< Maximum number of databases */
    
    /* Distribution configuration */
    DISLMDB_network_config network;    /**< Network configuration */
    DISLMDB_consensus_config consensus; /**< Consensus configuration */
    bool read_only_node;               /**< Whether this node accepts writes */
    uint32_t sync_interval_ms;         /**< Interval between sync attempts */
    uint32_t max_sync_batch_size;      /**< Maximum batch size for sync */
    char node_name[64];                /**< Human-readable node name */

    /* Regional topology (env-overridable) */
    char region[64];                   /**< e.g. us-east — local voter plane */
    char locality[64];                 /**< AZ / rack / city */
    DISLMDB_TOPOLOGY_MODE topology_mode; /**< mirror | shard | hybrid */
    uint32_t rtt_budget_ms;            /**< Soft reject peers slower than this (0=off) */
    uint8_t region_key[32];            /**< Intra-region HMAC/AEAD (optional) */
    bool has_region_key;
    uint8_t cross_region_key[32];      /**< Inter-region plane key (optional) */
    bool has_cross_region_key;
    /** Soft peer ceiling (0 = unlimited). No hard deny at 64. */
    uint32_t max_peers;
    /**
     * When true (default), @ref dislmdb_put / @ref dislmdb_del that fail the
     * local shard write gate automatically RPC to the owner if that peer is
     * connected (same path as @ref dislmdb_topo_forward_put / `_del`).
     * Unreachable owners still return DISLMDB_ERR_OPERATION_REJECTED.
     * Auto-forward runs only when the txn has no prior local pending ops
     * (staging write lock is released around the RPC so a redirected Raft
     * propose can apply if this node is leader).
     */
    bool enable_auto_forward;
    /** Mirror write authority (ignored unless topology_mode is mirror). */
    DISLMDB_MIRROR_CONFLICT_POLICY mirror_conflict_policy;
    /** Region id allowed to write under REGION_PRIORITY (see policy enum). */
    char mirror_primary_region[64];
    /**
     * When true, put/get/admin paths require a principal with matching ACL
     * bits (@ref DISLMDB_ACL_*). Off by default (transport crypto unchanged).
     */
    bool enable_acl;
} DISLMDB_env_config;

/**
 * @brief Get the version of the DisLMDB library
 * 
 * @param major If non-NULL, the major version is stored here
 * @param minor If non-NULL, the minor version is stored here
 * @param patch If non-NULL, the patch version is stored here
 * @return A string describing the version
 */
const char *dislmdb_version(int *major, int *minor, int *patch);

/**
 * @brief Return a string describing a given error code
 * 
 * @param err The error code
 * @return A string describing the error
 */
const char *dislmdb_strerror(int err);

/**
 * @brief Initialize a default configuration
 * 
 * @param config The configuration structure to initialize
 * @return 0 on success, non-zero on error
 */
int dislmdb_env_config_init(DISLMDB_env_config *config);

/**
 * @brief Create a distributed environment
 * 
 * @param env Output: The environment handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_env_create(DISLMDB_env **env);

/**
 * @brief Open a distributed environment
 * 
 * @param env The environment handle
 * @param config The environment configuration
 * @return 0 on success, non-zero on error
 */
int dislmdb_env_open(DISLMDB_env *env, const DISLMDB_env_config *config);

/**
 * @brief Close a distributed environment
 * 
 * @param env The environment handle
 */
void dislmdb_env_close(DISLMDB_env *env);

/**
 * @brief Synchronize environment data to disk
 * 
 * @param env The environment handle
 * @param force If non-zero, force a flush even if no writes are pending
 * @return 0 on success, non-zero on error
 */
int dislmdb_env_sync(DISLMDB_env *env, int force);

/**
 * @brief Begin a transaction
 * 
 * @param env The environment handle
 * @param parent Parent transaction for nested transactions, or NULL
 * @param flags Transaction flags
 * @param txn Output: The transaction handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_txn_begin(DISLMDB_env *env, DISLMDB_txn *parent, 
                      unsigned int flags, DISLMDB_txn **txn);

/**
 * @brief Commit a transaction
 * 
 * @param txn The transaction handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_txn_commit(DISLMDB_txn *txn);

/**
 * @brief Abort a transaction
 * 
 * @param txn The transaction handle
 */
void dislmdb_txn_abort(DISLMDB_txn *txn);

/**
 * @brief Get the underlying LMDB environment from a distributed environment
 * 
 * This is useful for operations that don't need to be distributed
 * or for advanced use cases.
 * 
 * @param env The distributed environment handle
 * @return The underlying LMDB environment handle
 */
MDB_env *dislmdb_get_lmdb_env(DISLMDB_env *env);

/**
 * @brief Get the underlying LMDB transaction from a distributed transaction
 * 
 * @param txn The distributed transaction handle
 * @return The underlying LMDB transaction handle
 */
MDB_txn *dislmdb_get_lmdb_txn(DISLMDB_txn *txn);

/**
 * @brief Add a node to the cluster
 * 
 * @param env The environment handle
 * @param node_addr The address of the node to add
 * @return 0 on success, non-zero on error
 */
int dislmdb_add_node(DISLMDB_env *env, const DISLMDB_node_addr *node_addr);

/**
 * @brief Remove a node from the cluster
 * 
 * @param env The environment handle
 * @param node_id The ID of the node to remove
 * @return 0 on success, non-zero on error
 */
/**
 * @brief Remove a peer: broadcast LEAVE, disconnect, update consensus membership.
 * Raft leaders also run joint-consensus shrink; PBFT drops the replica locally.
 */
int dislmdb_remove_node(DISLMDB_env *env, const char *node_id);

/**
 * @brief Get the status of a node
 * 
 * @param env The environment handle
 * @param node_id The ID of the node
 * @param state Output: The state of the node
 * @return 0 on success, non-zero on error
 */
int dislmdb_get_node_state(DISLMDB_env *env, const char *node_id, 
                           DISLMDB_NODE_STATE *state);

/**
 * @brief Get the current leader node ID
 * 
 * @param env The environment handle
 * @param leader_id Output: Buffer for the leader ID
 * @param id_size Size of the leader_id buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_get_leader(DISLMDB_env *env, char *leader_id, size_t id_size);

/** @brief Copy configured region id (may be empty). */
int dislmdb_get_region(DISLMDB_env *env, char *out, size_t out_sz);
/** @brief Copy configured locality (may be empty). */
int dislmdb_get_locality(DISLMDB_env *env, char *out, size_t out_sz);
/** @brief Current topology mode (mirror/shard/hybrid). */
int dislmdb_get_topology_mode(DISLMDB_env *env, DISLMDB_TOPOLOGY_MODE *out);
/** @brief Whether this node participates in elections/quorum. */
bool dislmdb_voting_enabled(DISLMDB_env *env);

/**
 * @brief Force sync with other nodes
 * 
 * @param env The environment handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_force_sync(DISLMDB_env *env);

/**
 * @brief Set a callback function for node status changes
 * 
 * @param env The environment handle
 * @param callback The callback function
 * @param user_data User data to pass to the callback
 * @return 0 on success, non-zero on error
 */
typedef void (*dislmdb_status_callback)(const char *node_id, 
                                        DISLMDB_NODE_STATE old_state,
                                        DISLMDB_NODE_STATE new_state,
                                        void *user_data);
int dislmdb_set_status_callback(DISLMDB_env *env, 
                               dislmdb_status_callback callback,
                               void *user_data);

/**
 * @brief Store bytecode with consensus
 *
 * Stores bytecode data using the consensus mechanism to ensure it is distributed
 * to all nodes in the network. Requires Enhanced PBFT consensus to be enabled.
 *
 * @param[in] env The environment handle
 * @param[in] bytecode The bytecode data to store
 * @param[in] bytecode_size Size of the bytecode data
 * @param[in] bytecode_id Identifier for the bytecode
 * @param[in] options Additional options for bytecode storage
 *            0 - Default behavior
 *            DISLMDB_BYTECODE_VERIFY - Persist SHA-256 and verify on get/apply
 *            DISLMDB_BYTECODE_COMPRESS - zlib-compress payload on durable store
 * @return #DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_store_bytecode(DISLMDB_env *env, 
                         const uint8_t *bytecode, 
                         size_t bytecode_size,
                         const char *bytecode_id,
                         unsigned int options);

/**
 * @brief Retrieve stored bytecode
 *
 * Retrieves previously stored bytecode data by its identifier.
 *
 * @param[in] env The environment handle
 * @param[in] bytecode_id Identifier for the bytecode
 * @param[out] bytecode Buffer to receive the bytecode data
 * @param[in,out] bytecode_size On input, the size of the buffer; on output, the actual size of the bytecode
 * @param[out] options Pointer to receive the bytecode options (can be NULL)
 * @return #DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_get_bytecode(DISLMDB_env *env,
                        const char *bytecode_id,
                        uint8_t *bytecode,
                        size_t *bytecode_size,
                        unsigned int *options);

/**
 * @brief Generate or install a shared cluster key (enables message auth)
 *
 * If key is NULL, a random 32-byte key is generated. The key is stored in the
 * environment config and optionally persisted when consensus.persist_state is set.
 */
int dislmdb_set_cluster_key(DISLMDB_env *env, const uint8_t key[32]);

/** @brief Copy the current cluster key (returns DISLMDB_ERR_NOT_INITIALIZED if unset) */
int dislmdb_get_cluster_key(DISLMDB_env *env, uint8_t out[32]);

/**
 * @brief Set the calling principal for subsequent ACL checks (thread-local to env).
 *
 * When @ref DISLMDB_env_config.enable_acl is false this is a no-op success.
 * Pass NULL or "" to clear the principal.
 */
int dislmdb_acl_set_principal(DISLMDB_env *env, const char *principal);

/**
 * @brief Grant @p perms bits to @p principal (requires ADMIN, or empty table bootstrap).
 *
 * Bootstrap: if the grant table is empty, any caller may grant once (typically
 * DISLMDB_ACL_ALL to themselves). Afterwards only ADMIN principals may grant.
 */
int dislmdb_acl_grant(DISLMDB_env *env, const char *principal, unsigned int perms);

/** @brief Revoke bits from @p principal (requires ADMIN). Zero bits removes the entry. */
int dislmdb_acl_revoke(DISLMDB_env *env, const char *principal, unsigned int perms);

/** @brief Query effective mask for @p principal (0 if unknown / ACL off). */
int dislmdb_acl_get(DISLMDB_env *env, const char *principal, unsigned int *perms_out);

/**
 * @brief Distributed put — records the op for consensus replication.
 *
 * Under shard/hybrid, if this node is not the owner and
 * @ref DISLMDB_env_config.enable_auto_forward is set, forwards to the owner
 * when connected (no local mutation). Otherwise returns the write-gate error.
 */
int dislmdb_put(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data,
                unsigned int flags);

/**
 * @brief Distributed delete — records the op for consensus replication.
 *
 * See @ref dislmdb_put for shard auto-forward behavior.
 */
int dislmdb_del(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data);

/**
 * @brief Open a named DBI within a distributed transaction (tracks name for replication)
 */
int dislmdb_dbi_open(DISLMDB_txn *txn, const char *name, unsigned int flags, MDB_dbi *dbi);

/** @brief Trigger a checkpoint of committed state */
int dislmdb_checkpoint(DISLMDB_env *env);

/** @brief Request state transfer from the current primary (or any peer) */
int dislmdb_request_state_transfer(DISLMDB_env *env);

/** @brief Read runtime metrics snapshot */
int dislmdb_get_metrics(DISLMDB_env *env, DISLMDB_metrics *metrics);

/**
 * @brief Format a metrics snapshot as Prometheus text exposition.
 *
 * Writes into @p buf (NUL-terminated when buf_sz > 0). @p written receives
 * the byte count excluding the trailing NUL (or would-be size if truncated).
 * Safe to call with a stack-filled DISLMDB_metrics from dislmdb_get_metrics.
 */
int dislmdb_format_metrics(const DISLMDB_metrics *metrics,
                           char *buf,
                           size_t buf_sz,
                           size_t *written);

/**
 * @brief Reconfigure replica membership
 *
 * PBFT: adds replicas to the local / consensus tables.
 * Raft: joint-consensus membership change (Cold,new → Cnew) on the leader.
 */
int dislmdb_reconfigure_replicas(DISLMDB_env *env,
                                 const DISLMDB_node_addr *nodes,
                                 size_t node_count);

/**
 * @brief Install / propose a shard map.
 *
 * Solo: local install + meta persist.
 * Raft/PBFT (running): consensus blob (SMAP); apply on commit.
 * Empty prefixes and duplicate shard_ids are rejected. Longest prefix wins on lookup.
 */
int dislmdb_shard_map_set(DISLMDB_env *env,
                          const DISLMDB_shard_desc *shards,
                          size_t count);

/** @brief Copy up to max_out shard descriptors; writes total count to *out_count. */
int dislmdb_shard_map_get(DISLMDB_env *env,
                          DISLMDB_shard_desc *out,
                          size_t max_out,
                          size_t *out_count);

/**
 * @brief Resolve owner node id for a key via longest-prefix shard match.
 * @return DISLMDB_ERR_NODE_NOT_FOUND when no shard matches.
 */
int dislmdb_shard_lookup(DISLMDB_env *env,
                         const void *key,
                         size_t key_len,
                         char owner_node_id[64]);

/**
 * @brief Resolve shard_id for a key via longest-prefix match.
 * @return DISLMDB_ERR_NODE_NOT_FOUND when no shard matches.
 */
int dislmdb_shard_lookup_id(DISLMDB_env *env,
                            const void *key,
                            size_t key_len,
                            char shard_id[DISLMDB_SHARD_ID_LEN]);

/**
 * @brief Whether this node may locally write @p key under the current topology mode.
 *
 * Mirror: always yes. Shard: key must match a shard owned by this node.
 * Hybrid: mirrored prefixes always yes; others same as shard.
 * @return DISLMDB_SUCCESS, DISLMDB_ERR_OPERATION_REJECTED, or DISLMDB_ERR_NODE_NOT_FOUND.
 */
int dislmdb_topo_key_writable(DISLMDB_env *env,
                              const void *key,
                              size_t key_len);

/**
 * @brief Resolve the owning node id for @p key under the current topology mode.
 *
 * Mirror: returns the local node id. Shard/hybrid: longest-prefix shard owner
 * (mirrored hybrid prefixes still report their advisory owner).
 * @return DISLMDB_SUCCESS or DISLMDB_ERR_NODE_NOT_FOUND when no shard matches.
 */
int dislmdb_topo_resolve_owner(DISLMDB_env *env,
                               const void *key,
                               size_t key_len,
                               char owner_node_id[64]);

/**
 * @brief Forward a put to the shard owner when this node cannot write locally.
 *
 * Resolves owner via @ref dislmdb_topo_resolve_owner. If this node is the
 * owner, returns DISLMDB_ERR_INVALID_PARAMETER (use @ref dislmdb_put).
 * Otherwise sends DISLMDB_MESSAGE_FORWARD and waits up to @p timeout_ms for
 * FORWARD_REPLY. Does not mutate the caller's local LMDB (shard isolation).
 *
 * @param dbname Named DBI (NULL = default unnamed DB).
 */
int dislmdb_topo_forward_put(DISLMDB_env *env,
                             const char *dbname,
                             const void *key,
                             size_t key_len,
                             const void *data,
                             size_t data_len,
                             uint32_t timeout_ms);

/**
 * @brief Forward a delete to the shard owner (see @ref dislmdb_topo_forward_put).
 */
int dislmdb_topo_forward_del(DISLMDB_env *env,
                             const char *dbname,
                             const void *key,
                             size_t key_len,
                             uint32_t timeout_ms);

/**
 * @brief Forward a get to the shard owner (read proxy).
 *
 * On success, allocates *@p out_data (caller frees) with *@p out_len bytes.
 * Returns MDB_NOTFOUND when the owner has no such key.
 */
int dislmdb_topo_forward_get(DISLMDB_env *env,
                             const char *dbname,
                             const void *key,
                             size_t key_len,
                             void **out_data,
                             size_t *out_len,
                             uint32_t timeout_ms);

/**
 * @brief Topology-aware get: local when this node may serve the key, else
 * forward to the shard owner (see @ref dislmdb_topo_forward_get).
 *
 * Mirror / local owner / hybrid mirrored prefixes: LMDB read on this node.
 * Otherwise RPC to the owner when connected.
 */
int dislmdb_topo_get(DISLMDB_env *env,
                     const char *dbname,
                     const void *key,
                     size_t key_len,
                     void **out_data,
                     size_t *out_len,
                     uint32_t timeout_ms);

/**
 * @brief Publish the current peer topology map via consensus (TOPO blob).
 *
 * Solo: persist peer_topo only. Raft/PBFT: propose; apply on commit merges
 * endpoints into the node table on every replica.
 */
int dislmdb_topo_map_publish(DISLMDB_env *env);

#endif /* DISLMDB_H */
