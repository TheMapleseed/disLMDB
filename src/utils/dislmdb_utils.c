/**
 * @file dislmdb_utils.c
 * @brief Utility functions for Distributed LMDB
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <string.h>
#include <errno.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"

const char *dislmdb_error_string(int err)
{
    if (err == DISLMDB_SUCCESS) {
        return "Success";
    }
    if (err < DISLMDB_ERR_BASE) {
        return strerror(err);
    }
    switch (err) {
        case DISLMDB_NOOP: return "No operation performed";
        case DISLMDB_ERR_NETWORK: return "Network error";
        case DISLMDB_ERR_CONNECTION: return "Connection error";
        case DISLMDB_ERR_NODE_NOT_FOUND: return "Node not found";
        case DISLMDB_ERR_NODE_UNREACHABLE: return "Node unreachable";
        case DISLMDB_ERR_NO_LEADER: return "Leader not available";
        case DISLMDB_ERR_LEADER_CHANGE: return "Leader change in progress";
        case DISLMDB_ERR_CONSENSUS_FAILED: return "Consensus failed";
        case DISLMDB_ERR_CONSENSUS_TIMEOUT: return "Consensus timeout";
        case DISLMDB_ERR_OPERATION_REJECTED: return "Operation rejected by consensus";
        case DISLMDB_ERR_VERSION_MISMATCH: return "Protocol version mismatch";
        case DISLMDB_ERR_NODE_ID_MISMATCH: return "Node ID mismatch";
        case DISLMDB_ERR_AUTH_FAILED: return "Authentication failed";
        case DISLMDB_ERR_NOT_AUTHORIZED: return "Not authorized for operation";
        case DISLMDB_ERR_NETWORK_PARTITION: return "Network partition detected";
        case DISLMDB_ERR_SYNC_FAILED: return "Synchronization failed";
        case DISLMDB_ERR_DATA_CORRUPTION: return "Data corruption detected";
        case DISLMDB_ERR_CHECKPOINT_FAILED: return "Checkpoint failed";
        case DISLMDB_ERR_NODE_EXISTS: return "Node already exists";
        case DISLMDB_ERR_MAX_NODES: return "Maximum number of nodes reached";
        case DISLMDB_ERR_READ_ONLY: return "Read-only node";
        case DISLMDB_ERR_IN_PROGRESS: return "Operation in progress";
        case DISLMDB_ERR_INVALID_OPERATION: return "Invalid operation";
        case DISLMDB_ERR_OPERATION_EXISTS: return "Operation already exists";
        case DISLMDB_ERR_TXN_FAILED: return "Distributed transaction failed";
        case DISLMDB_ERR_CONFIG: return "Configuration error";
        case DISLMDB_ERR_NOT_IMPLEMENTED: return "Feature not implemented";
        case DISLMDB_ERR_OUT_OF_SEQUENCE: return "Out of sequence";
        case DISLMDB_ERR_VIEW_MISMATCH: return "View number mismatch";
        case DISLMDB_ERR_MESSAGE_VALIDATION: return "Message validation failed";
        case DISLMDB_ERR_SIGNATURE_VERIFICATION: return "Signature verification failed";
        case DISLMDB_ERR_NOT_INITIALIZED: return "Distributed environment not initialized";
        case DISLMDB_ERR_ALREADY_INITIALIZED: return "Distributed environment already initialized";
        case DISLMDB_ERR_BYZANTINE: return "Byzantine behavior detected";
        case DISLMDB_ERR_TOO_MANY_FAULTS: return "Too many faults detected";
        case DISLMDB_ERR_DIGEST_MISMATCH: return "Digest mismatch";
        case DISLMDB_ERR_STATE_TRANSFER_REQUIRED: return "State transfer required";
        case DISLMDB_ERR_BATCH_FAILED: return "Operation batching failed";
        case DISLMDB_ERR_UNREACHABLE_STATE: return "Unreachable consensus state";
        case DISLMDB_ERR_INVALID_PARAMETER: return "Invalid parameter";
        case DISLMDB_ERR_MEMORY_ERROR: return "Memory allocation error";
        case DISLMDB_ERR_THREAD_ERROR: return "Thread error";
        case DISLMDB_ERR_BUFFER_OVERFLOW: return "Buffer overflow";
        default: return "Unknown DisLMDB error";
    }
}
