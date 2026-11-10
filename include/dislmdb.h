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
    DISLMDB_CONSENSUS_RAFT,        /**< Raft consensus algorithm (future support) */
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
    DISLMDB_MESSAGE_ELECTION       /**< Leader election message */
} DISLMDB_MESSAGE_TYPE;

/** @brief Network address information for nodes */
typedef struct DISLMDB_node_addr {
    char hostname[256];            /**< Hostname or IP address */
    uint16_t port;                 /**< Port number */
    char node_id[64];              /**< Unique node identifier */
} DISLMDB_node_addr;

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
    bool enable_payload_encryption;/**< AES-CBC+HMAC payload encryption with cluster_key */
    bool enable_tls;               /**< Request TLS (OpenSSL builds) or AEAD fallback */
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
} DISLMDB_consensus_config;

/** @brief Runtime metrics for DisLMDB */
typedef struct DISLMDB_metrics {
    uint64_t total_commits;
    uint64_t total_operations;
    uint64_t total_sync_bytes;
    uint64_t consensus_proposes;
    uint64_t consensus_commits;
    uint64_t view_changes;
    uint64_t checkpoints;
    uint64_t state_transfers;
    uint32_t current_view;
    uint64_t last_committed_seq;
    uint32_t replica_count;
    uint32_t active_connections;
} DISLMDB_metrics;

/** @brief Opaque structure for a distributed environment */
typedef struct DISLMDB_env DISLMDB_env;

/** @brief Opaque structure for a distributed transaction */
typedef struct DISLMDB_txn DISLMDB_txn;

/**
 * @brief Configuration for a DisLMDB environment
 * 
 * Combines the original LMDB configuration with distribution parameters
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
 *            DISLMDB_BYTECODE_VERIFY - Verify bytecode integrity before storage
 *            DISLMDB_BYTECODE_COMPRESS - Compress bytecode before storage
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
 * @brief Distributed put — records the op for consensus replication
 */
int dislmdb_put(DISLMDB_txn *txn, MDB_dbi dbi, MDB_val *key, MDB_val *data,
                unsigned int flags);

/**
 * @brief Distributed delete — records the op for consensus replication
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

/** @brief Read runtime metrics */
int dislmdb_get_metrics(DISLMDB_env *env, DISLMDB_metrics *metrics);

/** @brief Reconfigure replica membership (propose CONFIG op when PBFT) */
int dislmdb_reconfigure_replicas(DISLMDB_env *env,
                                 const DISLMDB_node_addr *nodes,
                                 size_t node_count);

#endif /* DISLMDB_H */ 