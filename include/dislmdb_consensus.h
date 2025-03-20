/**
 * @file dislmdb_consensus.h
 * @brief Consensus mechanisms for Distributed LMDB
 *
 * This file defines the interfaces and data structures for the consensus
 * mechanisms used by DisLMDB, with a primary focus on the PBFT
 * (Practical Byzantine Fault Tolerance) implementation.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_CONSENSUS_H
#define DISLMDB_CONSENSUS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dislmdb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Maximum size of a consensus message */
#define DISLMDB_MAX_MESSAGE_SIZE 65536

/** @brief Maximum number of nodes in a consensus group */
#define DISLMDB_MAX_NODES 64

/** @brief Size of the operation ID in bytes */
#define DISLMDB_OP_ID_SIZE 16

/** @brief Types of operations for consensus */
typedef enum DISLMDB_OP_TYPE {
    DISLMDB_OP_TYPE_UNKNOWN = 0,
    DISLMDB_OP_TYPE_PUT,       /**< Insert or update a key-value pair */
    DISLMDB_OP_TYPE_DEL,       /**< Delete a key-value pair */
    DISLMDB_OP_TYPE_CONFIG,    /**< Configuration change */
    DISLMDB_OP_TYPE_SYNC,      /**< Data synchronization */
    DISLMDB_OP_TYPE_SNAPSHOT,  /**< Create a snapshot */
    DISLMDB_OP_TYPE_NOP        /**< No operation (often used for leadership keepalive) */
} DISLMDB_OP_TYPE;

/** @brief Unique identifier for a consensus operation */
typedef struct DISLMDB_op_id {
    uint8_t bytes[DISLMDB_OP_ID_SIZE];  /**< Operation ID bytes */
} DISLMDB_op_id;

/** @brief Operation data for consensus */
typedef struct DISLMDB_operation {
    DISLMDB_op_id id;           /**< Unique operation ID */
    DISLMDB_OP_TYPE type;       /**< Type of operation */
    uint32_t sequence;          /**< Sequence number */
    uint64_t timestamp;         /**< Timestamp in milliseconds */
    char node_id[64];           /**< ID of the node that initiated the operation */
    uint32_t data_size;         /**< Size of operation data */
    uint8_t *data;              /**< Operation data */
    uint8_t digest[32];         /**< SHA-256 digest of operation data */
} DISLMDB_operation;

/** @brief PBFT message with consensus data */
typedef struct DISLMDB_pbft_message {
    DISLMDB_MESSAGE_TYPE type;  /**< Type of PBFT message */
    uint32_t view;              /**< Current view number */
    uint32_t sequence;          /**< Sequence number */
    char node_id[64];           /**< ID of the node sending the message */
    DISLMDB_op_id op_id;        /**< Operation ID */
    uint32_t data_size;         /**< Size of message data */
    uint8_t *data;              /**< Message data */
    uint8_t digest[32];         /**< SHA-256 digest of message data */
    uint8_t signature[64];      /**< Signature of the message */
} DISLMDB_pbft_message;

/** @brief PBFT consensus state for a node */
typedef struct DISLMDB_pbft_state {
    uint32_t view;                      /**< Current view number */
    uint32_t sequence;                  /**< Current sequence number */
    char primary_id[64];                /**< ID of the primary node */
    uint32_t f;                         /**< Maximum number of faulty nodes tolerated */
    uint32_t node_count;                /**< Total number of nodes */
    bool is_primary;                    /**< Whether this node is the primary */
    uint64_t last_checkpoint_time;      /**< Time of the last checkpoint */
    uint32_t last_checkpoint_sequence;  /**< Sequence number of the last checkpoint */
    uint32_t watermark_low;             /**< Low watermark for garbage collection */
    uint32_t watermark_high;            /**< High watermark for flow control */
    uint32_t view_change_timeout_ms;    /**< Timeout for view changes */
    uint64_t view_change_start_time;    /**< Time when the view change started */
    bool view_change_in_progress;       /**< Whether a view change is in progress */
} DISLMDB_pbft_state;

/** @brief Status of a consensus operation */
typedef enum DISLMDB_CONSENSUS_STATUS {
    DISLMDB_CONSENSUS_UNKNOWN,     /**< Status unknown */
    DISLMDB_CONSENSUS_PENDING,     /**< Operation is pending consensus */
    DISLMDB_CONSENSUS_COMMITTED,   /**< Operation has been committed */
    DISLMDB_CONSENSUS_REJECTED,    /**< Operation has been rejected */
    DISLMDB_CONSENSUS_TIMEOUT      /**< Operation timed out */
} DISLMDB_CONSENSUS_STATUS;

/** @brief Result of a consensus operation */
typedef struct DISLMDB_consensus_result {
    DISLMDB_CONSENSUS_STATUS status;  /**< Status of the operation */
    int error_code;                  /**< Error code if status is not COMMITTED */
    uint32_t commit_view;            /**< View in which the operation was committed */
    uint32_t commit_sequence;        /**< Sequence number of the commit */
    uint64_t commit_time;            /**< Time when the operation was committed */
    uint32_t node_count;             /**< Number of nodes that participated */
    uint32_t agree_count;            /**< Number of nodes that agreed */
} DISLMDB_consensus_result;

/** @brief Callback for consensus events */
typedef void (*dislmdb_consensus_callback)(DISLMDB_operation *operation,
                                          DISLMDB_consensus_result *result,
                                          void *user_data);

/**
 * @brief Initialize the consensus subsystem
 * 
 * @param env The distributed environment handle
 * @param config Consensus configuration
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_init(DISLMDB_env *env, 
                          const DISLMDB_consensus_config *config);

/**
 * @brief Shutdown the consensus subsystem
 * 
 * @param env The distributed environment handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_shutdown(DISLMDB_env *env);

/**
 * @brief Propose an operation for consensus
 * 
 * @param env The distributed environment handle
 * @param operation The operation to propose
 * @param timeout_ms Timeout in milliseconds
 * @param result Output: Result of the consensus process
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_propose(DISLMDB_env *env,
                             DISLMDB_operation *operation,
                             uint32_t timeout_ms,
                             DISLMDB_consensus_result *result);

/**
 * @brief Set a callback for consensus events
 * 
 * @param env The distributed environment handle
 * @param callback The callback function
 * @param user_data User data to pass to the callback
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_set_callback(DISLMDB_env *env,
                                  dislmdb_consensus_callback callback,
                                  void *user_data);

/**
 * @brief Get the current consensus state
 * 
 * @param env The distributed environment handle
 * @param state Output: The consensus state
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_get_state(DISLMDB_env *env,
                               DISLMDB_pbft_state *state);

/**
 * @brief Generate a unique operation ID
 * 
 * @param env The distributed environment handle
 * @param id Output: The generated operation ID
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_generate_op_id(DISLMDB_env *env,
                                    DISLMDB_op_id *id);

/**
 * @brief Trigger a view change (leader election)
 * 
 * @param env The distributed environment handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_trigger_view_change(DISLMDB_env *env);

/**
 * @brief Get the status of a specific operation
 * 
 * @param env The distributed environment handle
 * @param id The operation ID
 * @param result Output: Result of the consensus process
 * @return 0 on success, non-zero on error
 */
int dislmdb_consensus_get_operation_status(DISLMDB_env *env,
                                          const DISLMDB_op_id *id,
                                          DISLMDB_consensus_result *result);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_CONSENSUS_H */ 