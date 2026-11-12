/**
 * @file dislmdb_errors.h
 * @brief Error codes and constants for Distributed LMDB
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
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
    DISLMDB_SUCCESS = 0,
    DISLMDB_NOOP = DISLMDB_ERR_BASE,
    DISLMDB_ERR_NETWORK,
    DISLMDB_ERR_CONNECTION,
    DISLMDB_ERR_NODE_NOT_FOUND,
    DISLMDB_ERR_NODE_UNREACHABLE,
    DISLMDB_ERR_NO_LEADER,
    DISLMDB_ERR_LEADER_CHANGE,
    DISLMDB_ERR_CONSENSUS_FAILED,
    DISLMDB_ERR_CONSENSUS_TIMEOUT,
    DISLMDB_ERR_OPERATION_REJECTED,
    DISLMDB_ERR_VERSION_MISMATCH,
    DISLMDB_ERR_NODE_ID_MISMATCH,
    DISLMDB_ERR_AUTH_FAILED,
    DISLMDB_ERR_NOT_AUTHORIZED,
    DISLMDB_ERR_NETWORK_PARTITION,
    DISLMDB_ERR_SYNC_FAILED,
    DISLMDB_ERR_DATA_CORRUPTION,
    DISLMDB_ERR_CHECKPOINT_FAILED,
    DISLMDB_ERR_NODE_EXISTS,
    DISLMDB_ERR_MAX_NODES,
    DISLMDB_ERR_READ_ONLY,
    DISLMDB_ERR_IN_PROGRESS,
    DISLMDB_ERR_INVALID_OPERATION,
    DISLMDB_ERR_OPERATION_EXISTS,
    DISLMDB_ERR_TXN_FAILED,
    DISLMDB_ERR_CONFIG,
    DISLMDB_ERR_NOT_IMPLEMENTED,
    DISLMDB_ERR_OUT_OF_SEQUENCE,
    DISLMDB_ERR_VIEW_MISMATCH,
    DISLMDB_ERR_MESSAGE_VALIDATION,
    DISLMDB_ERR_SIGNATURE_VERIFICATION,
    DISLMDB_ERR_NOT_INITIALIZED,
    DISLMDB_ERR_ALREADY_INITIALIZED,
    DISLMDB_ERR_BYZANTINE,
    DISLMDB_ERR_TOO_MANY_FAULTS,
    DISLMDB_ERR_DIGEST_MISMATCH,
    DISLMDB_ERR_STATE_TRANSFER_REQUIRED,
    DISLMDB_ERR_BATCH_FAILED,
    DISLMDB_ERR_UNREACHABLE_STATE,
    DISLMDB_ERR_INVALID_PARAMETER,
    DISLMDB_ERR_MEMORY_ERROR,
    DISLMDB_ERR_THREAD_ERROR,
    DISLMDB_ERR_BUFFER_OVERFLOW
};

/** @brief Magic number used for validation ("DisD") */
#define DISLMDB_MAGIC_NUMBER 0x44697344u

/** @brief Protocol version (major << 16 | minor) */
#define DISLMDB_PROTOCOL_VERSION_MAJOR 1
#define DISLMDB_PROTOCOL_VERSION_MINOR 0
#define DISLMDB_PROTOCOL_VERSION \
    ((DISLMDB_PROTOCOL_VERSION_MAJOR << 16) | DISLMDB_PROTOCOL_VERSION_MINOR)

#define DISLMDB_DEFAULT_PORT 9876
/**
 * Historical soft default / initial connection table size. Membership is no
 * longer hard-capped here — use env_config.max_peers (0 = unlimited).
 */
#define DISLMDB_MAX_NODES 64
#define DISLMDB_MAX_DBS 256
#define DISLMDB_DEFAULT_TIMEOUT_MS 5000
#define DISLMDB_MAX_NODE_ID_SIZE 64
#define DISLMDB_MAX_HOSTNAME_SIZE 256
#define DISLMDB_MAX_MESSAGE_SIZE 16777216u  /* 16 MB */
#define DISLMDB_MESSAGE_HEADER_SIZE 128
#define DISLMDB_MAX_ERROR_LENGTH 256

/** @brief Bytecode option flags */
#define DISLMDB_BYTECODE_VERIFY   0x0001u
#define DISLMDB_BYTECODE_COMPRESS 0x0002u

/** @brief ACL capability bits (OR into grant masks) */
#define DISLMDB_ACL_NONE  0x0000u
#define DISLMDB_ACL_READ  0x0001u /**< get / read paths */
#define DISLMDB_ACL_WRITE 0x0002u /**< put / del / store bytecode */
#define DISLMDB_ACL_ADMIN 0x0004u /**< membership, keys, ACL grants, checkpoint */
#define DISLMDB_ACL_ALL   (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE | DISLMDB_ACL_ADMIN)

/** @brief Max ACL principal id length (excluding NUL) */
#define DISLMDB_ACL_PRINCIPAL_MAX 64
/** @brief Max principals in the in-memory ACL table */
#define DISLMDB_ACL_MAX_PRINCIPALS 64
/** @brief Max key-prefix length for prefix ACL grants (excluding NUL) */
#define DISLMDB_ACL_PREFIX_MAX 64
/** @brief Max prefix grants in the in-memory ACL table */
#define DISLMDB_ACL_MAX_PREFIX_GRANTS 128
/** @brief Max RBAC role name length (excluding NUL) */
#define DISLMDB_ACL_ROLE_MAX 64
/** @brief Max roles in the in-memory RBAC table */
#define DISLMDB_ACL_MAX_ROLES 64
/** @brief Max principal→role memberships */
#define DISLMDB_ACL_MAX_ROLE_MEMBERS 256
/** @brief Max peer→principal forward/SYN2 delegation entries */
#define DISLMDB_ACL_MAX_DELEGATES 128

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_ERRORS_H */
