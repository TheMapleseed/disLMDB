/**
 * @file pbft_adapter.c
 * @brief Implementation of the adapter for Enhanced PBFT Consensus Mechanism
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#include "pbft_adapter.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Subscriber ID for this node in the broadcast channel
static int global_subscriber_id = -1;

/**
 * @brief Callback function for handling committed messages from consensus
 * 
 * This function is called when a message is committed by the consensus protocol.
 * It applies the transaction to the local database.
 * 
 * @param data The committed data
 * @param size Size of the committed data
 * @param user_data User data (pointer to the environment)
 */
static void dislmdb_pbft_commit_callback(const uint8_t *data, size_t size, void *user_data) {
    DISLMDB_env *env = (DISLMDB_env *)user_data;
    
    // Log the commit
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", "Received committed transaction of size %zu", size);
    
    // Apply the transaction
    int rc = dislmdb_pbft_apply_transaction(env, data, size);
    if (rc != DISLMDB_SUCCESS) {
        dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT", 
                   "Failed to apply committed transaction: %s", dislmdb_strerror(rc));
    }
}

/**
 * @brief Thread function for processing consensus broadcasts
 * 
 * This thread waits for committed messages from the broadcast channel
 * and passes them to the commit callback.
 * 
 * @param arg Pointer to the environment
 * @return Thread result code
 */
static int dislmdb_pbft_broadcast_thread(void *arg) {
    DISLMDB_env *env = (DISLMDB_env *)arg;
    ConsensusCore *core = (ConsensusCore *)env->consensus_context;
    
    // Get the subscriber ID
    int subscriber_id = global_subscriber_id;
    
    // Process broadcasts until stopped
    while (env->consensus_running) {
        uint8_t *data = NULL;
        size_t data_size = 0;
        struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0}; // 1-second timeout
        
        // Wait for a broadcast
        ConsensusError err = broadcast_channel_receive(
            core->commit_channel, 
            subscriber_id, 
            &data, 
            &data_size, 
            &timeout
        );
        
        // Check for errors
        if (err == CONSENSUS_OK) {
            // Call the commit callback
            dislmdb_pbft_commit_callback(data, data_size, env);
            
            // Free the data if needed (depends on implementation)
            // free(data);
        } else if (err != CONSENSUS_ERROR_TIMEOUT) {
            // Log non-timeout errors
            dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT", 
                       "Error receiving broadcast: %d", err);
        }
    }
    
    return 0;
}

int dislmdb_pbft_init(DISLMDB_env *env) {
    // Verify environment
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    // Create node ID from environment's node ID
    NodeId *node_id = node_id_create(env->local_node_id);
    if (!node_id) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    
    // Set up consensus configuration based on DisLMDB settings
    ConsensusConfig config = consensus_config_default();
    dislmdb_convert_consensus_config(&env->config.consensus, &config);
    
    // Initialize security manager
    SecurityConfig sec_config = security_config_default();
    SecurityManager *security = security_manager_create(&sec_config);
    if (!security) {
        node_id_destroy(node_id);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    
    // Create consensus core
    ConsensusCore *core = consensus_core_create(node_id, &config, security);
    if (!core) {
        security_manager_destroy(security);
        node_id_destroy(node_id);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    
    // Store in environment
    env->consensus_context = core;
    
    // Subscribe to the broadcast channel
    global_subscriber_id = broadcast_channel_subscribe(core->commit_channel);
    if (global_subscriber_id < 0) {
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        return DISLMDB_ERR_CONSENSUS_FAILED;
    }
    
    // Register network handlers
    int rc = dislmdb_network_set_message_callback(env, dislmdb_pbft_message_handler, env);
    if (rc != DISLMDB_SUCCESS) {
        broadcast_channel_unsubscribe(core->commit_channel, global_subscriber_id);
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        return rc;
    }
    
    // Start the broadcast processing thread
    env->consensus_running = true;
    if (pthread_create(&env->consensus_thread, NULL, 
                      (void *(*)(void *))dislmdb_pbft_broadcast_thread, env) != 0) {
        broadcast_channel_unsubscribe(core->commit_channel, global_subscriber_id);
        consensus_core_destroy(core);
        env->consensus_context = NULL;
        env->consensus_running = false;
        return DISLMDB_ERR_THREAD_ERROR;
    }
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", "Enhanced PBFT consensus initialized");
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_shutdown(DISLMDB_env *env) {
    if (!env || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    ConsensusCore *core = (ConsensusCore *)env->consensus_context;
    
    // Stop the broadcast thread
    env->consensus_running = false;
    pthread_join(env->consensus_thread, NULL);
    
    // Unsubscribe from broadcasts
    if (global_subscriber_id >= 0) {
        broadcast_channel_unsubscribe(core->commit_channel, global_subscriber_id);
        global_subscriber_id = -1;
    }
    
    // Clean up consensus
    consensus_core_destroy(core);
    env->consensus_context = NULL;
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", "Enhanced PBFT consensus shut down");
    return DISLMDB_SUCCESS;
}

void dislmdb_convert_consensus_config(const DISLMDB_consensus_config *dislmdb_config,
                                     ConsensusConfig *pbft_config) {
    if (!dislmdb_config || !pbft_config) {
        return;
    }
    
    // Set fault tolerance (f)
    // In PBFT, we need 3f+1 nodes to tolerate f failures
    pbft_config->fault_tolerance = (dislmdb_config->max_batch_size > 0) 
                                  ? dislmdb_config->max_batch_size 
                                  : 1;
    
    // Calculate minimum nodes
    pbft_config->min_nodes = 3 * pbft_config->fault_tolerance + 1;
    
    // Set timeouts
    pbft_config->timeouts.prepare_timeout.tv_sec = dislmdb_config->timeout_ms / 1000;
    pbft_config->timeouts.prepare_timeout.tv_nsec = (dislmdb_config->timeout_ms % 1000) * 1000000;
    
    pbft_config->timeouts.commit_timeout.tv_sec = dislmdb_config->timeout_ms / 1000;
    pbft_config->timeouts.commit_timeout.tv_nsec = (dislmdb_config->timeout_ms % 1000) * 1000000;
    
    pbft_config->timeouts.view_change_timeout.tv_sec = 
        (dislmdb_config->election_timeout_max_ms / 1000);
    pbft_config->timeouts.view_change_timeout.tv_nsec = 
        (dislmdb_config->election_timeout_max_ms % 1000) * 1000000;
    
    // Set message size limits
    pbft_config->max_message_size = (dislmdb_config->max_batch_size * 1024 * 1024);
    
    // Enable security features
    pbft_config->verify_signatures = true;
}

typedef struct {
    uint32_t txn_id;
    uint32_t op_count;
    uint8_t is_write_txn;
    uint8_t is_distributed;
    uint32_t db_count;
    // Followed by operations data
} TxnHeader;

int dislmdb_pbft_serialize_transaction(DISLMDB_txn *txn, uint8_t **data, size_t *size) {
    if (!txn || !data || !size) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    // Calculate size needed
    size_t header_size = sizeof(TxnHeader);
    size_t ops_size = 0;
    
    // TODO: Calculate size of operations data
    // This will depend on the specific operations in the transaction
    
    // For now, use a simple approach for prototype
    ops_size = txn->operation_count * 256; // Rough estimate
    
    // Allocate memory
    size_t total_size = header_size + ops_size;
    uint8_t *buffer = malloc(total_size);
    if (!buffer) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    
    // Fill header
    TxnHeader *header = (TxnHeader *)buffer;
    header->txn_id = (uint32_t)txn->start_time; // Use timestamp as ID
    header->op_count = txn->operation_count;
    header->is_write_txn = txn->is_write_txn ? 1 : 0;
    header->is_distributed = txn->is_distributed ? 1 : 0;
    header->db_count = txn->env->numdbs;
    
    // TODO: Serialize operations data
    // This will depend on the specific operations in the transaction
    
    // For prototype, just fill with sample data
    memset(buffer + header_size, 0xAA, ops_size);
    
    // Return data
    *data = buffer;
    *size = total_size;
    
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_apply_transaction(DISLMDB_env *env, const uint8_t *data, size_t size) {
    if (!env || !data || size < sizeof(TxnHeader)) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    // Extract header
    const TxnHeader *header = (const TxnHeader *)data;
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", 
               "Applying transaction: id=%u, op_count=%u, is_write=%u", 
               header->txn_id, header->op_count, header->is_write_txn);
    
    // TODO: Apply operations from the transaction data
    // This will depend on the specific operations in the transaction
    
    // For prototype, just log success
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", "Transaction applied successfully");
    
    return DISLMDB_SUCCESS;
}

int dislmdb_pbft_propose_transaction(DISLMDB_txn *txn) {
    if (!txn || !txn->env || !txn->env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    // Only process write transactions
    if (!txn->is_write_txn) {
        // No consensus needed for read-only transactions
        return DISLMDB_SUCCESS;
    }
    
    DISLMDB_env *env = txn->env;
    ConsensusCore *core = (ConsensusCore *)env->consensus_context;
    
    // Serialize the transaction
    uint8_t *txn_data = NULL;
    size_t txn_size = 0;
    int rc = dislmdb_pbft_serialize_transaction(txn, &txn_data, &txn_size);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", 
               "Proposing transaction: size=%zu", txn_size);
    
    // Submit to consensus
    ConsensusError err = consensus_core_propose(core, txn_data, txn_size);
    
    // Free serialized data
    free(txn_data);
    
    // Check result
    if (err != CONSENSUS_OK) {
        dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT", 
                   "Failed to propose transaction: error=%d", err);
        
        // Map consensus error to DisLMDB error
        switch (err) {
            case CONSENSUS_ERROR_NOT_LEADER:
                return DISLMDB_ERR_NO_LEADER;
            case CONSENSUS_ERROR_TIMEOUT:
                return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case CONSENSUS_ERROR_MEMORY_ERROR:
                return DISLMDB_ERR_MEMORY_ERROR;
            default:
                return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }
    
    return DISLMDB_SUCCESS;
}

void dislmdb_pbft_message_handler(const char *node_id, 
                                 DISLMDB_MESSAGE_TYPE type,
                                 const uint8_t *data, 
                                 size_t data_size, 
                                 void *user_data) {
    DISLMDB_env *env = (DISLMDB_env *)user_data;
    if (!env || !env->consensus_context || !node_id || !data) {
        return;
    }
    
    ConsensusCore *core = (ConsensusCore *)env->consensus_context;
    
    // Map DisLMDB message type to PBFT message type
    MessageType pbft_type;
    switch (type) {
        case DISLMDB_MESSAGE_PREPARE:
            pbft_type = MSG_PREPARE;
            break;
        case DISLMDB_MESSAGE_COMMIT:
            pbft_type = MSG_COMMIT;
            break;
        case DISLMDB_MESSAGE_CHECKPOINT:
            // No direct mapping, use PRE_PREPARE as a placeholder
            pbft_type = MSG_PRE_PREPARE;
            break;
        default:
            // Unknown message type
            dislmdb_log(env, DISLMDB_LOG_WARNING, "PBFT", 
                       "Received unsupported message type: %d", type);
            return;
    }
    
    // Log the message
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", 
               "Received message: type=%d, size=%zu, from=%s", 
               type, data_size, node_id);
    
    // TODO: Convert DisLMDB message to PBFT message format
    // This will depend on the specific message formats
    
    // For prototype, just acknowledge receipt
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", "Message processed");
}

int dislmdb_pbft_store_bytecode(DISLMDB_env *env, 
                               const uint8_t *bytecode, 
                               size_t bytecode_size,
                               const char *bytecode_id,
                               unsigned int options) {
    if (!env || !env->consensus_context || !bytecode || !bytecode_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    if (bytecode_size == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    ConsensusCore *core = (ConsensusCore *)env->consensus_context;
    
    // Check size limits
    if (bytecode_size > core->config.max_message_size) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    
    // Create a metadata header for the bytecode
    uint8_t metadata_header[256];
    size_t metadata_size = 0;
    
    // Format: [Magic(4)] [Version(4)] [ID_Length(4)] [ID(var)] [Options(4)] [Timestamp(8)]
    uint32_t magic = 0x42434F44; // "BCOD"
    uint32_t version = 1;
    uint32_t id_len = strlen(bytecode_id);
    uint32_t opts = options;
    uint64_t timestamp = time(NULL);
    
    // Check ID length
    if (id_len > 128) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    // Build metadata
    memcpy(metadata_header + metadata_size, &magic, sizeof(magic));
    metadata_size += sizeof(magic);
    
    memcpy(metadata_header + metadata_size, &version, sizeof(version));
    metadata_size += sizeof(version);
    
    memcpy(metadata_header + metadata_size, &id_len, sizeof(id_len));
    metadata_size += sizeof(id_len);
    
    memcpy(metadata_header + metadata_size, bytecode_id, id_len);
    metadata_size += id_len;
    
    memcpy(metadata_header + metadata_size, &opts, sizeof(opts));
    metadata_size += sizeof(opts);
    
    memcpy(metadata_header + metadata_size, &timestamp, sizeof(timestamp));
    metadata_size += sizeof(timestamp);
    
    // Allocate buffer for complete message
    size_t total_size = metadata_size + bytecode_size;
    uint8_t *buffer = malloc(total_size);
    if (!buffer) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    
    // Combine metadata and bytecode
    memcpy(buffer, metadata_header, metadata_size);
    memcpy(buffer + metadata_size, bytecode, bytecode_size);
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "PBFT", 
               "Storing bytecode: id=%s, size=%zu", 
               bytecode_id, bytecode_size);
    
    // Submit to consensus
    ConsensusError err = consensus_core_propose(core, buffer, total_size);
    
    // Free buffer
    free(buffer);
    
    // Check result
    if (err != CONSENSUS_OK) {
        dislmdb_log(env, DISLMDB_LOG_ERROR, "PBFT", 
                   "Failed to store bytecode: error=%d", err);
        
        // Map consensus error to DisLMDB error
        switch (err) {
            case CONSENSUS_ERROR_NOT_LEADER:
                return DISLMDB_ERR_NO_LEADER;
            case CONSENSUS_ERROR_TIMEOUT:
                return DISLMDB_ERR_CONSENSUS_TIMEOUT;
            case CONSENSUS_ERROR_MEMORY_ERROR:
                return DISLMDB_ERR_MEMORY_ERROR;
            default:
                return DISLMDB_ERR_CONSENSUS_FAILED;
        }
    }
    
    return DISLMDB_SUCCESS;
} 