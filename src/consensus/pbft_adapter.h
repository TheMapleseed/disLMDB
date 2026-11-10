/**
 * @file pbft_adapter.h
 * @brief Adapter for Enhanced PBFT Consensus Mechanism
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
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

int dislmdb_pbft_init(DISLMDB_env *env);
int dislmdb_pbft_shutdown(DISLMDB_env *env);
int dislmdb_pbft_propose_transaction(DISLMDB_txn *txn);

int dislmdb_pbft_store_bytecode(DISLMDB_env *env,
                                const uint8_t *bytecode,
                                size_t bytecode_size,
                                const char *bytecode_id,
                                unsigned int options);

void dislmdb_convert_consensus_config(const DISLMDB_consensus_config *dislmdb_config,
                                      ConsensusConfig *pbft_config);

void dislmdb_pbft_message_handler(const DISLMDB_network_message *message,
                                  void *user_data);

/**
 * @brief Process a JOIN/HELLO membership frame (shared by PBFT and Raft).
 * Updates node table + connection labels; PBFT also registers the replica.
 */
void dislmdb_pbft_handle_hello(DISLMDB_env *env, const DISLMDB_network_message *message);

/** Send HELLO (JOIN) announcing our real node_id + listen port. */
int dislmdb_pbft_send_hello(DISLMDB_env *env, const char *target_node_id);

/** Process LEAVE membership frame (shared by PBFT and Raft). */
void dislmdb_pbft_handle_leave(DISLMDB_env *env, const DISLMDB_network_message *message);

/** Broadcast LEAVE for `node_id` (empty → local node). */
int dislmdb_pbft_send_leave(DISLMDB_env *env, const char *node_id);

int dislmdb_pbft_serialize_transaction(DISLMDB_txn *txn,
                                       uint8_t **data,
                                       size_t *size);

int dislmdb_pbft_apply_transaction(DISLMDB_env *env,
                                   const uint8_t *data,
                                   size_t size);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_PBFT_ADAPTER_H */
