/**
 * @file pbft_adapter.h
 * @brief Adapter for Enhanced PBFT Consensus Mechanism
 *
 * This file contains the adapter code to connect the Enhanced PBFT
 * consensus mechanism with DisLMDB's internal interfaces.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#ifndef DISLMDB_PBFT_ADAPTER_H
#define DISLMDB_PBFT_ADAPTER_H

#include "dislmdb_internal.h"
#include "../../Enhanced-PBFT-mechanism/epdft.h"
#include "../../Enhanced-PBFT-mechanism/security_manager.h"
#include "../../Enhanced-PBFT-mechanism/messaging.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the Enhanced PBFT consensus mechanism
 *
 * Initializes and connects the Enhanced PBFT consensus mechanism with the
 * DisLMDB environment. Sets up security, messaging, and network handlers.
 *
 * @param env The DisLMDB environment
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_init(DISLMDB_env *env);

/**
 * @brief Shut down the Enhanced PBFT consensus mechanism
 *
 * Cleans up resources associated with the Enhanced PBFT consensus mechanism.
 *
 * @param env The DisLMDB environment
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_shutdown(DISLMDB_env *env);

/**
 * @brief Propose a transaction for consensus
 *
 * Submits a transaction to the PBFT consensus process and waits for
 * the result.
 *
 * @param txn The transaction to propose
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_propose_transaction(DISLMDB_txn *txn);

/**
 * @brief Store bytecode with PBFT consensus
 *
 * Submits bytecode data for storage using the PBFT consensus mechanism.
 *
 * @param env The DisLMDB environment
 * @param bytecode The bytecode data to store
 * @param bytecode_size Size of the bytecode data
 * @param bytecode_id Identifier for the bytecode
 * @param options Additional options for bytecode storage
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_store_bytecode(DISLMDB_env *env, 
                               const uint8_t *bytecode, 
                               size_t bytecode_size,
                               const char *bytecode_id,
                               unsigned int options);

/**
 * @brief Convert DisLMDB consensus config to Enhanced PBFT config
 *
 * Converts the DisLMDB consensus configuration to the format used by
 * the Enhanced PBFT mechanism.
 *
 * @param dislmdb_config Source DisLMDB configuration
 * @param pbft_config Destination Enhanced PBFT configuration
 */
void dislmdb_convert_consensus_config(const DISLMDB_consensus_config *dislmdb_config,
                                     ConsensusConfig *pbft_config);

/**
 * @brief Handle a PBFT message received from the network
 *
 * Callback function that processes PBFT messages received from other nodes.
 *
 * @param node_id ID of the node that sent the message
 * @param type Message type
 * @param data Message data
 * @param data_size Size of the message data
 * @param user_data User data (pointer to the consensus context)
 */
void dislmdb_pbft_message_handler(const char *node_id, 
                                 DISLMDB_MESSAGE_TYPE type,
                                 const uint8_t *data, 
                                 size_t data_size, 
                                 void *user_data);

/**
 * @brief Serialize a DisLMDB transaction for consensus
 *
 * Converts a DisLMDB transaction to a byte array for submission to consensus.
 *
 * @param txn The transaction to serialize
 * @param data Pointer to store the serialized data
 * @param size Pointer to store the size of the serialized data
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_serialize_transaction(DISLMDB_txn *txn, 
                                      uint8_t **data, 
                                      size_t *size);

/**
 * @brief Deserialize and apply a transaction from consensus
 *
 * Converts a byte array from consensus back to a transaction and applies it.
 *
 * @param env The DisLMDB environment
 * @param data The serialized transaction data
 * @param size Size of the serialized data
 * @return DISLMDB_SUCCESS on success, error code on failure
 */
int dislmdb_pbft_apply_transaction(DISLMDB_env *env, 
                                  const uint8_t *data, 
                                  size_t size);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_PBFT_ADAPTER_H */ 