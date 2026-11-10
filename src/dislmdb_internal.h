/**
 * @file dislmdb_internal.h
 * @brief Internal definitions for Distributed LMDB
 *
 * This file contains internal structures and function declarations that
 * are shared between the different components of DisLMDB but are not
 * part of the public API.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_INTERNAL_H
#define DISLMDB_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>

#include "lmdb.h"
#include "dislmdb.h"
#include "dislmdb_errors.h"
#include "dislmdb_consensus.h"
#include "dislmdb_network.h"

/** @brief Magic number for validation */
#define DISLMDB_MAGIC DISLMDB_MAGIC_NUMBER

/** @brief Maximum number of log messages to keep */
#define DISLMDB_MAX_LOG_MESSAGES 1000

/** @brief Maximum length of a log message */
#define DISLMDB_MAX_LOG_LENGTH 1024

/** @brief Log levels for internal logging */
typedef enum DISLMDB_LOG_LEVEL {
    DISLMDB_LOG_DEBUG,    /**< Debug information */
    DISLMDB_LOG_INFO,     /**< General information */
    DISLMDB_LOG_WARNING,  /**< Warnings */
    DISLMDB_LOG_ERROR,    /**< Errors */
    DISLMDB_LOG_FATAL     /**< Fatal errors */
} DISLMDB_LOG_LEVEL;

/** @brief Log message structure */
typedef struct DISLMDB_log_message {
    DISLMDB_LOG_LEVEL level;     /**< Log level */
    uint64_t timestamp;          /**< Timestamp in milliseconds */
    char module[32];             /**< Module that generated the message */
    char message[DISLMDB_MAX_LOG_LENGTH]; /**< Log message text */
} DISLMDB_log_message;

/** @brief Operation log entry for PBFT consensus */
typedef struct DISLMDB_operation_log_entry {
    DISLMDB_operation operation;         /**< The operation */
    DISLMDB_consensus_result result;     /**< Result of the consensus process */
    uint64_t start_time;                 /**< Time when the operation was started */
    uint64_t end_time;                   /**< Time when the operation completed */
    uint32_t prepare_count;              /**< Number of prepare messages received */
    uint32_t commit_count;               /**< Number of commit messages received */
    bool prepare_quorum_reached;         /**< Whether prepare quorum was reached */
    bool commit_quorum_reached;          /**< Whether commit quorum was reached */
    char prepare_nodes[DISLMDB_MAX_NODES][64]; /**< Nodes that sent prepare messages */
    char commit_nodes[DISLMDB_MAX_NODES][64];  /**< Nodes that sent commit messages */
} DISLMDB_operation_log_entry;

/** @brief Internal environment structure */
struct DISLMDB_env {
    uint32_t magic;                          /**< Magic number for validation */
    MDB_env *mdb_env;                        /**< The underlying LMDB environment */
    DISLMDB_env_config config;               /**< Configuration parameters */
    
    /* Network state */
    pthread_t network_thread;                /**< Network thread handle */
    bool network_running;                    /**< Whether the network thread is running */
    void *network_context;                   /**< Context for the network subsystem */
    dislmdb_message_callback msg_callback;   /**< Callback for received messages */
    void *msg_callback_data;                 /**< User data for message callback */
    dislmdb_connection_callback conn_callback; /**< Callback for connection state changes */
    void *conn_callback_data;                /**< User data for connection callback */
    
    /* Consensus state */
    pthread_t consensus_thread;              /**< Consensus thread handle */
    bool consensus_running;                  /**< Whether the consensus thread is running */
    void *consensus_context;                 /**< Context for the consensus subsystem */
    int pbft_subscriber_id;                  /**< Broadcast channel subscriber id */
    DISLMDB_pbft_state pbft_state;           /**< Current PBFT state */
    dislmdb_consensus_callback cons_callback; /**< Callback for consensus events */
    void *cons_callback_data;                /**< User data for consensus callback */
    
    /* Transaction state */
    pthread_mutex_t txn_mutex;               /**< Mutex for transaction operations */
    DISLMDB_txn *active_txns;                /**< List of active transactions */
    uint32_t txn_count;                      /**< Number of active transactions */
    
    /* Operation log */
    pthread_mutex_t oplog_mutex;             /**< Mutex for operation log */
    DISLMDB_operation_log_entry *oplog;      /**< Operation log */
    uint32_t oplog_size;                     /**< Maximum number of operation log entries */
    uint32_t oplog_count;                    /**< Current number of operation log entries */
    uint32_t oplog_head;                     /**< Index of the oldest entry */
    
    /* Node state tracking */
    pthread_mutex_t nodes_mutex;             /**< Mutex for node state */
    DISLMDB_node_addr *nodes;                /**< Array of known nodes */
    DISLMDB_NODE_STATE *node_states;         /**< Array of node states */
    uint32_t node_count;                     /**< Number of known nodes */
    char local_node_id[64];                  /**< ID of this node */
    
    /* Status tracking */
    pthread_mutex_t status_mutex;            /**< Mutex for status updates */
    dislmdb_status_callback status_callback; /**< Callback for node status changes */
    void *status_callback_data;              /**< User data for status callback */
    
    /* Logging */
    pthread_mutex_t log_mutex;               /**< Mutex for logging */
    DISLMDB_log_message *log_messages;       /**< Array of log messages */
    uint32_t log_count;                      /**< Number of log messages */
    uint32_t log_head;                       /**< Index of the oldest log message */
    
    /* Error tracking */
    char last_error[DISLMDB_MAX_ERROR_LENGTH]; /**< Last error message */
    int last_error_code;                     /**< Last error code */
    
    /* Statistics */
    uint64_t start_time;                     /**< Time when the environment was opened */
    uint64_t total_commits;                  /**< Total number of committed transactions */
    uint64_t total_operations;               /**< Total number of operations */
    uint64_t total_sync_bytes;               /**< Total bytes synchronized */
    uint64_t consensus_proposes;
    uint64_t consensus_commits;
    uint64_t view_changes;
    uint64_t checkpoints;
    uint64_t state_transfers;

    /* Last recorded consensus op (for get_last_op_id / status follow-up) */
    DISLMDB_op_id last_op_id;
    bool has_last_op_id;

    /* Cluster crypto */
    uint8_t cluster_key[32];
    bool has_cluster_key;

    /* Shard map (key-prefix → owner affinity) */
    pthread_mutex_t shard_mutex;
    DISLMDB_shard_desc shards[DISLMDB_MAX_SHARDS];
    uint32_t shard_count;
};

/** @brief Pending op recorded for replication */
typedef struct DISLMDB_pending_op {
    DISLMDB_OP_TYPE type;
    char dbname[64];
    uint8_t *key;
    size_t key_len;
    uint8_t *val;
    size_t val_len;
    unsigned int flags;
    struct DISLMDB_pending_op *next;
} DISLMDB_pending_op;

/** @brief Internal transaction structure */
struct DISLMDB_txn {
    uint32_t magic;              /**< Magic number for validation */
    DISLMDB_env *env;            /**< The environment */
    MDB_txn *mdb_txn;            /**< The underlying LMDB transaction */
    DISLMDB_txn *parent;         /**< Parent transaction for nested transactions */
    DISLMDB_txn *next;           /**< Next transaction in linked list */
    uint32_t flags;              /**< Transaction flags */
    bool is_write_txn;           /**< Whether this is a write transaction */
    bool is_distributed;         /**< Whether this transaction affects distributed state */
    uint64_t start_time;         /**< Time when transaction was started */
    uint32_t operation_count;    /**< Number of operations in this transaction */
    char txn_id[64];             /**< Unique transaction ID */
    DISLMDB_pending_op *pending_ops; /**< Ops to replicate */
    char open_db_names[32][64];  /**< Names for opened DBIs */
    MDB_dbi open_db_handles[32];
    uint32_t open_db_count;
};

#define DISLMDB_META_DBI "__dislmdb_meta__"
#define DISLMDB_OPLOG_MAGIC 0x4F504C47u /* OPLG */
#define DISLMDB_SMAP_MAGIC 0x534D4150u  /* SMAP — shard map consensus blob */
#define DISLMDB_LEAV_MAGIC 0x4C454156u  /* LEAV — graceful leave */
#define DISLMDB_DQGM_MAGIC 0x4451474Du  /* DQGM — UDP datagram session envelope */
#define DISLMDB_DGRAM_ENVELOPE_V1_SIZE 16 /* magic+ver+flags+stream+cid */
#define DISLMDB_DGRAM_ENVELOPE_V2_SIZE 24 /* v1 + pkt_num (QUIC-oriented) */
#define DISLMDB_DGRAM_ENVELOPE_SIZE DISLMDB_DGRAM_ENVELOPE_V2_SIZE
#define DISLMDB_DQGM_VERSION 2

int dislmdb_persist_save(DISLMDB_env *env);
int dislmdb_persist_load(DISLMDB_env *env);
int dislmdb_serialize_pending_ops(const DISLMDB_txn *txn, uint8_t **out, size_t *out_len);
int dislmdb_apply_oplog_payload(DISLMDB_env *env, const uint8_t *data, size_t size);
/** Install shard map locally (no consensus propose). */
int dislmdb_shard_map_install(DISLMDB_env *env,
                              const DISLMDB_shard_desc *shards,
                              size_t count);
/** Apply a committed SMAP consensus payload. */
int dislmdb_shard_map_apply_payload(DISLMDB_env *env, const uint8_t *data, size_t size);
/** Encode shard descriptors into an owned SMAP buffer. */
int dislmdb_shard_map_encode(const DISLMDB_shard_desc *shards,
                             size_t count,
                             uint8_t **out,
                             size_t *out_len);
void dislmdb_free_pending_ops(DISLMDB_txn *txn);
/** Record a consensus outcome into the env operation-status ring. */
void dislmdb_record_consensus_result(DISLMDB_env *env,
                                     const DISLMDB_op_id *op_id,
                                     DISLMDB_OP_TYPE type,
                                     const DISLMDB_consensus_result *result);
int dislmdb_network_set_auth_key(DISLMDB_env *env, const uint8_t key[32]);
int dislmdb_network_set_encryption(DISLMDB_env *env, bool enable);

/**
 * @brief Log a message to the environment's log
 * 
 * @param env The environment
 * @param level Log level
 * @param module Module name
 * @param format Format string
 * @param ... Format arguments
 */
void dislmdb_log(DISLMDB_env *env, DISLMDB_LOG_LEVEL level, 
                const char *module, const char *format, ...);

/**
 * @brief Set the last error message and code
 * 
 * @param env The environment
 * @param code Error code
 * @param format Format string
 * @param ... Format arguments
 */
void dislmdb_set_error(DISLMDB_env *env, int code, 
                      const char *format, ...);

/**
 * @brief Get the current time in milliseconds
 * 
 * @return Current time in milliseconds
 */
uint64_t dislmdb_get_time_ms(void);

/**
 * @brief Generate a unique node ID
 * 
 * @param node_id Buffer to store the node ID (must be at least 64 bytes)
 * @return 0 on success, non-zero on error
 */
int dislmdb_generate_node_id(char *node_id);

/**
 * @brief Calculate SHA-256 digest of data
 * 
 * @param data Input data
 * @param size Size of input data
 * @param digest Output digest (must be at least 32 bytes)
 * @return 0 on success, non-zero on error
 */
int dislmdb_sha256(const void *data, size_t size, uint8_t *digest);

/**
 * @brief Add a node to the environment's node list
 * 
 * @param env The environment
 * @param node_addr Node address information
 * @return 0 on success, non-zero on error
 */
int dislmdb_add_node_internal(DISLMDB_env *env, 
                             const DISLMDB_node_addr *node_addr);

/**
 * @brief Update the state of a node
 * 
 * @param env The environment
 * @param node_id ID of the node
 * @param state New state
 * @return 0 on success, non-zero on error
 */
int dislmdb_update_node_state(DISLMDB_env *env, 
                             const char *node_id,
                             DISLMDB_NODE_STATE state);

/**
 * @brief Find a node by its ID
 * 
 * @param env The environment
 * @param node_id ID of the node
 * @param index Output: Index of the node in the nodes array
 * @return 0 on success, non-zero on error
 */
int dislmdb_find_node(DISLMDB_env *env, 
                     const char *node_id,
                     uint32_t *index);

/**
 * @brief Process a consensus operation
 * 
 * @param env The environment
 * @param operation The operation to process
 * @param result Output: Result of the operation
 * @return 0 on success, non-zero on error
 */
int dislmdb_process_operation(DISLMDB_env *env,
                             const DISLMDB_operation *operation,
                             DISLMDB_consensus_result *result);

/**
 * @brief Handle a received PBFT message
 * 
 * @param env The environment
 * @param message The received message
 * @return 0 on success, non-zero on error
 */
int dislmdb_handle_pbft_message(DISLMDB_env *env,
                               const DISLMDB_pbft_message *message);

/**
 * @brief Add an entry to the operation log
 * 
 * @param env The environment
 * @param entry The operation log entry to add
 * @return 0 on success, non-zero on error
 */
int dislmdb_add_operation_log_entry(DISLMDB_env *env,
                                   const DISLMDB_operation_log_entry *entry);

/**
 * @brief Find an operation log entry by operation ID
 * 
 * @param env The environment
 * @param op_id Operation ID to find
 * @param entry Output: The found operation log entry
 * @return 0 on success, non-zero on error
 */
int dislmdb_find_operation_log_entry(DISLMDB_env *env,
                                    const DISLMDB_op_id *op_id,
                                    DISLMDB_operation_log_entry *entry);

/**
 * @brief Parse a consensus operation from a byte buffer
 * 
 * @param buffer The buffer containing the operation data
 * @param size Size of the buffer
 * @param operation Output: The parsed operation
 * @return 0 on success, non-zero on error
 */
int dislmdb_parse_operation(const uint8_t *buffer,
                           size_t size,
                           DISLMDB_operation *operation);

/**
 * @brief Serialize a consensus operation to a byte buffer
 * 
 * @param operation The operation to serialize
 * @param buffer Output: Buffer to store the serialized operation
 * @param size Size of the buffer
 * @param bytes_written Output: Number of bytes written to the buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_serialize_operation(const DISLMDB_operation *operation,
                               uint8_t *buffer,
                               size_t size,
                               size_t *bytes_written);

#endif /* DISLMDB_INTERNAL_H */ 