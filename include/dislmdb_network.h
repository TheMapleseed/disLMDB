/**
 * @file dislmdb_network.h
 * @brief Network communication for Distributed LMDB
 *
 * This file defines the interfaces and data structures for the network
 * communication layer of DisLMDB, enabling node discovery, message
 * transmission, and data synchronization between distributed nodes.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_NETWORK_H
#define DISLMDB_NETWORK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dislmdb.h"
#include "dislmdb_consensus.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Maximum number of pending network connections */
#define DISLMDB_MAX_PENDING_CONNECTIONS 64

/** @brief Maximum size of a network message buffer */
#define DISLMDB_MAX_NETWORK_MESSAGE_SIZE 16777216 /* 16 MB */

/** @brief Default network timeout in milliseconds */
#define DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS 30000 /* 30 seconds */

/** @brief Network connection states */
typedef enum DISLMDB_CONNECTION_STATE {
    DISLMDB_CONNECTION_CLOSED,       /**< Connection is closed */
    DISLMDB_CONNECTION_CONNECTING,   /**< Connection is being established */
    DISLMDB_CONNECTION_CONNECTED,    /**< Connection is established */
    DISLMDB_CONNECTION_DISCONNECTING /**< Connection is being closed */
} DISLMDB_CONNECTION_STATE;

/** @brief Network message header structure */
typedef struct DISLMDB_message_header {
    uint32_t magic;           /**< Magic number for validation */
    uint32_t version;         /**< Protocol version */
    DISLMDB_MESSAGE_TYPE type; /**< Message type */
    uint32_t payload_size;    /**< Size of the message payload */
    uint64_t timestamp;       /**< Message timestamp */
    char sender_id[64];       /**< ID of the sender node */
    char target_id[64];       /**< ID of the target node (empty for broadcast) */
    uint32_t flags;           /**< Message flags */
    uint32_t checksum;        /**< Checksum of the payload */
} DISLMDB_message_header;

/** @brief Network message structure */
typedef struct DISLMDB_network_message {
    DISLMDB_message_header header;  /**< Message header */
    uint8_t *payload;              /**< Message payload */
} DISLMDB_network_message;

/** @brief Connection information structure */
typedef struct DISLMDB_connection_info {
    char node_id[64];                /**< ID of the connected node */
    char hostname[256];              /**< Hostname or IP address */
    uint16_t port;                   /**< Port number */
    DISLMDB_CONNECTION_STATE state;   /**< Connection state */
    uint64_t connect_time;           /**< Time when connection was established */
    uint64_t last_activity_time;     /**< Time of last message received */
    uint64_t bytes_sent;             /**< Total bytes sent */
    uint64_t bytes_received;         /**< Total bytes received */
    uint32_t messages_sent;          /**< Total messages sent */
    uint32_t messages_received;      /**< Total messages received */
    uint32_t error_count;            /**< Number of errors encountered */
    DISLMDB_NODE_STATE node_state;    /**< State of the connected node */
} DISLMDB_connection_info;

/** @brief Network statistics structure */
typedef struct DISLMDB_network_stats {
    /** Live CONNECTED slots (recounted on get_stats; not CONNECTING dials). */
    uint32_t active_connections;
    uint32_t total_connections;      /**< Total connections since startup */
    uint64_t total_bytes_sent;       /**< Total bytes sent since startup */
    uint64_t total_bytes_received;   /**< Total bytes received since startup */
    uint32_t total_messages_sent;    /**< Total messages sent since startup */
    uint32_t total_messages_received;/**< Total messages received since startup */
    uint32_t total_errors;           /**< Total errors since startup */
    uint32_t connection_failures;    /**< Total connection failures */
    uint64_t uptime_ms;              /**< Network uptime in milliseconds */
} DISLMDB_network_stats;

/** @brief Callback for handling received messages */
typedef void (*dislmdb_message_callback)(const DISLMDB_network_message *message, 
                                        void *user_data);

/** @brief Callback for handling connection state changes */
typedef void (*dislmdb_connection_callback)(const char *node_id, 
                                           DISLMDB_CONNECTION_STATE old_state,
                                           DISLMDB_CONNECTION_STATE new_state,
                                           void *user_data);

/**
 * @brief Initialize the network subsystem
 * 
 * @param env The distributed environment handle
 * @param config Network configuration
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_init(DISLMDB_env *env, 
                        const DISLMDB_network_config *config);

/**
 * @brief Shutdown the network subsystem
 * 
 * @param env The distributed environment handle
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_shutdown(DISLMDB_env *env);

/**
 * @brief Send a message to a specific node
 * 
 * @param env The distributed environment handle
 * @param message The message to send
 * @param node_id ID of the target node
 * @param timeout_ms Timeout in milliseconds
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_send(DISLMDB_env *env,
                        const DISLMDB_network_message *message,
                        const char *node_id,
                        uint32_t timeout_ms);

/**
 * @brief Broadcast a message to all connected nodes
 * 
 * @param env The distributed environment handle
 * @param message The message to broadcast
 * @param timeout_ms Timeout in milliseconds
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_broadcast(DISLMDB_env *env,
                             const DISLMDB_network_message *message,
                             uint32_t timeout_ms);

/**
 * @brief Set a callback for received messages
 * 
 * @param env The distributed environment handle
 * @param callback The callback function
 * @param user_data User data to pass to the callback
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_set_message_callback(DISLMDB_env *env,
                                        dislmdb_message_callback callback,
                                        void *user_data);

/**
 * @brief Set a callback for connection state changes
 * 
 * @param env The distributed environment handle
 * @param callback The callback function
 * @param user_data User data to pass to the callback
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_set_connection_callback(DISLMDB_env *env,
                                           dislmdb_connection_callback callback,
                                           void *user_data);

/**
 * @brief Get connection information for a specific node
 * 
 * @param env The distributed environment handle
 * @param node_id ID of the node
 * @param info Output: Connection information
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_get_connection_info(DISLMDB_env *env,
                                       const char *node_id,
                                       DISLMDB_connection_info *info);

/**
 * @brief Get network statistics
 * 
 * @param env The distributed environment handle
 * @param stats Output: Network statistics
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_get_stats(DISLMDB_env *env,
                             DISLMDB_network_stats *stats);

/**
 * @brief Get a list of connected node IDs
 * 
 * @param env The distributed environment handle
 * @param node_ids Output: Array of node IDs
 * @param max_count Maximum number of node IDs to retrieve
 * @param count Output: Actual number of node IDs retrieved
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_get_connected_nodes(DISLMDB_env *env,
                                       char node_ids[][64],
                                       size_t max_count,
                                       size_t *count);

/**
 * @brief Count peers in CONNECTED state (excludes CONNECTING / CLOSED slots).
 */
uint32_t dislmdb_network_connected_peer_count(DISLMDB_env *env);

/**
 * @brief Block until at least min_peers are CONNECTED or timeout_ms elapses.
 * @return 0 if the threshold was met, DISLMDB_ERR_TIMEOUT otherwise.
 */
int dislmdb_network_wait_connected(DISLMDB_env *env,
                                   uint32_t min_peers,
                                   uint32_t timeout_ms);

/**
 * @brief Connect to a specific node
 * 
 * @param env The distributed environment handle
 * @param node_addr Address of the node to connect to
 * @param timeout_ms Timeout in milliseconds
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_connect(DISLMDB_env *env,
                           const DISLMDB_node_addr *node_addr,
                           uint32_t timeout_ms);

/**
 * @brief Disconnect from a specific node
 * 
 * @param env The distributed environment handle
 * @param node_id ID of the node to disconnect from
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_disconnect(DISLMDB_env *env,
                              const char *node_id);

/**
 * @brief Bind a connection's node_id once the peer's real identity is known
 *
 * Replaces empty or seed-* placeholders. Optionally updates listen port.
 *
 * @param env The distributed environment handle
 * @param old_or_empty Previous connection label (may be seed-* or empty)
 * @param real_node_id Canonical peer identity from HELLO
 * @param listen_port Peer's listen port (0 to leave unchanged)
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_bind_peer_id(DISLMDB_env *env,
                                 const char *old_or_empty,
                                 const char *real_node_id,
                                 uint16_t listen_port);

/**
 * @brief True for signalling traffic (HELLO/JOIN, HEARTBEAT, ELECTION, LEAVE)
 *
 * Under DISLMDB_TRANSPORT_BOTH these prefer UDP; data/consensus prefer TCP.
 */
bool dislmdb_network_is_signalling(DISLMDB_MESSAGE_TYPE type);

/**
 * @brief Create a network message
 * 
 * @param message Output: The message structure to initialize
 * @param type The type of message
 * @param payload The message payload
 * @param payload_size Size of the payload
 * @param target_id ID of the target node (NULL for broadcast)
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_create_message(DISLMDB_network_message *message,
                                  DISLMDB_MESSAGE_TYPE type,
                                  const uint8_t *payload,
                                  uint32_t payload_size,
                                  const char *target_id);

/**
 * @brief Free a network message
 * 
 * @param message The message to free
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_free_message(DISLMDB_network_message *message);

/**
 * @brief Send a consensus message to a specific node
 * 
 * This is a convenience function that creates a network message
 * from a consensus message and sends it.
 * 
 * @param env The distributed environment handle
 * @param message The consensus message to send
 * @param node_id ID of the target node
 * @param timeout_ms Timeout in milliseconds
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_send_consensus_message(DISLMDB_env *env,
                                          const DISLMDB_pbft_message *message,
                                          const char *node_id,
                                          uint32_t timeout_ms);

/**
 * @brief Broadcast a consensus message to all connected nodes
 * 
 * @param env The distributed environment handle
 * @param message The consensus message to broadcast
 * @param timeout_ms Timeout in milliseconds
 * @return 0 on success, non-zero on error
 */
int dislmdb_network_broadcast_consensus_message(DISLMDB_env *env,
                                               const DISLMDB_pbft_message *message,
                                               uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_NETWORK_H */ 