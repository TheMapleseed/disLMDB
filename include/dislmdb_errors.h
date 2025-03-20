/**
 * @file dislmdb_errors.h
 * @brief Error codes and constants for Distributed LMDB
 *
 * This file defines the error codes and constants that are specific to
 * the DisLMDB library, extending the error codes provided by LMDB.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_ERRORS_H
#define DISLMDB_ERRORS_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Base value for DisLMDB-specific error codes */
#define DISLMDB_ERR_BASE 1000

/** @brief Error codes specific to DisLMDB */
enum {
    /** Operation completed successfully */
    DISLMDB_SUCCESS = 0,
    
    /** No error occurred, but no changes were made */
    DISLMDB_NOOP = DISLMDB_ERR_BASE,
    
    /** Network error */
    DISLMDB_ERR_NETWORK,
    
    /** Connection error */
    DISLMDB_ERR_CONNECTION,
    
    /** Node not found */
    DISLMDB_ERR_NODE_NOT_FOUND,
    
    /** Node unreachable */
    DISLMDB_ERR_NODE_UNREACHABLE,
    
    /** Leader not available */
    DISLMDB_ERR_NO_LEADER,
    
    /** Leader change in progress */
    DISLMDB_ERR_LEADER_CHANGE,
    
    /** Consensus could not be reached */
    DISLMDB_ERR_CONSENSUS_FAILED,
    
    /** Consensus timeout */
    DISLMDB_ERR_CONSENSUS_TIMEOUT,
    
    /** Operation rejected by consensus */
    DISLMDB_ERR_OPERATION_REJECTED,
    
    /** Protocol version mismatch */
    DISLMDB_ERR_VERSION_MISMATCH,
    
    /** Node ID mismatch */
    DISLMDB_ERR_NODE_ID_MISMATCH,
    
    /** Authentication failed */
    DISLMDB_ERR_AUTH_FAILED,
    
    /** Not authorized for operation */
    DISLMDB_ERR_NOT_AUTHORIZED,
    
    /** Network partition detected */
    DISLMDB_ERR_NETWORK_PARTITION,
    
    /** Synchronization error */
    DISLMDB_ERR_SYNC_FAILED,
    
    /** Data corruption detected */
    DISLMDB_ERR_DATA_CORRUPTION,
    
    /** Checkpoint error */
    DISLMDB_ERR_CHECKPOINT_FAILED,
    
    /** Node already exists */
    DISLMDB_ERR_NODE_EXISTS,
    
    /** Maximum number of nodes reached */
    DISLMDB_ERR_MAX_NODES,
    
    /** Read-only node */
    DISLMDB_ERR_READ_ONLY,
    
    /** Operation in progress */
    DISLMDB_ERR_IN_PROGRESS,
    
    /** Invalid operation */
    DISLMDB_ERR_INVALID_OPERATION,
    
    /** Operation already exists */
    DISLMDB_ERR_OPERATION_EXISTS,
    
    /** Distributed transaction failed */
    DISLMDB_ERR_TXN_FAILED,
    
    /** Configuration error */
    DISLMDB_ERR_CONFIG,
    
    /** Feature not implemented */
    DISLMDB_ERR_NOT_IMPLEMENTED,
    
    /** Out of sequence */
    DISLMDB_ERR_OUT_OF_SEQUENCE,
    
    /** View number mismatch */
    DISLMDB_ERR_VIEW_MISMATCH,
    
    /** Message validation failed */
    DISLMDB_ERR_MESSAGE_VALIDATION,
    
    /** Message signature verification failed */
    DISLMDB_ERR_SIGNATURE_VERIFICATION,
    
    /** Distributed environment not initialized */
    DISLMDB_ERR_NOT_INITIALIZED,
    
    /** Distributed environment already initialized */
    DISLMDB_ERR_ALREADY_INITIALIZED,
    
    /** Byzantine behavior detected */
    DISLMDB_ERR_BYZANTINE,
    
    /** Too many faults detected */
    DISLMDB_ERR_TOO_MANY_FAULTS,
    
    /** Digest mismatch */
    DISLMDB_ERR_DIGEST_MISMATCH,
    
    /** State transfer required */
    DISLMDB_ERR_STATE_TRANSFER_REQUIRED,
    
    /** Operation batching failed */
    DISLMDB_ERR_BATCH_FAILED,
    
    /** Unreachable consensus state */
    DISLMDB_ERR_UNREACHABLE_STATE
};

/** @brief Magic number used for validation */
#define DISLMDB_MAGIC_NUMBER 0x44697344  /* "DisD" in ASCII, little-endian */

/** @brief Protocol version */
#define DISLMDB_PROTOCOL_VERSION_MAJOR 1
#define DISLMDB_PROTOCOL_VERSION_MINOR 0
#define DISLMDB_PROTOCOL_VERSION ((DISLMDB_PROTOCOL_VERSION_MAJOR << 16) | DISLMDB_PROTOCOL_VERSION_MINOR)

/** @brief Default port for DisLMDB */
#define DISLMDB_DEFAULT_PORT 9876

/** @brief Maximum number of nodes in a cluster */
#define DISLMDB_MAX_NODES 64

/** @brief Maximum number of databases */
#define DISLMDB_MAX_DBS 256

/** @brief Default operation timeout in milliseconds */
#define DISLMDB_DEFAULT_TIMEOUT_MS 5000

/** @brief Maximum size of a node ID */
#define DISLMDB_MAX_NODE_ID_SIZE 64

/** @brief Maximum size of a hostname */
#define DISLMDB_MAX_HOSTNAME_SIZE 256

/** @brief Maximum size of a message */
#define DISLMDB_MAX_MESSAGE_SIZE 16777216  /* 16 MB */

/** @brief Base size of message header */
#define DISLMDB_MESSAGE_HEADER_SIZE 128

/** @brief Maximum length of error message */
#define DISLMDB_MAX_ERROR_LENGTH 256

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_ERRORS_H */ 