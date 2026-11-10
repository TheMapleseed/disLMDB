/**
 * @file raft_adapter.h
 * @brief Bridge DisLMDB ↔ local Raft core
 */
#ifndef DISLMDB_RAFT_ADAPTER_H
#define DISLMDB_RAFT_ADAPTER_H

#include "dislmdb_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

int dislmdb_raft_init(DISLMDB_env *env);
int dislmdb_raft_shutdown(DISLMDB_env *env);
int dislmdb_raft_propose_transaction(DISLMDB_txn *txn);
void dislmdb_raft_message_handler(const DISLMDB_network_message *message, void *user_data);
/** @brief Copy current Raft leader id; returns 0 if a leader is known. */
int dislmdb_raft_current_leader(DISLMDB_env *env, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_RAFT_ADAPTER_H */
