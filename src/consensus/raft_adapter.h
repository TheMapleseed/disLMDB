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

/** Arm Raft + network callback; does not start elections yet. */
int dislmdb_raft_init(DISLMDB_env *env);
/** Start elections after cluster HELLO/mesh engagement. */
int dislmdb_raft_start(DISLMDB_env *env);
int dislmdb_raft_shutdown(DISLMDB_env *env);
int dislmdb_raft_propose_transaction(DISLMDB_txn *txn);
/** Propose bytecode (BCOD) through Raft; same wire format as PBFT. */
int dislmdb_raft_store_bytecode(DISLMDB_env *env,
                                const uint8_t *bytecode,
                                size_t bytecode_size,
                                const char *bytecode_id,
                                unsigned int options);
/** Persist Raft/meta checkpoint (commit index + membership). */
int dislmdb_raft_checkpoint(DISLMDB_env *env);
void dislmdb_raft_message_handler(const DISLMDB_network_message *message, void *user_data);
/** @brief Copy current Raft leader id; returns 0 if a leader is known. */
int dislmdb_raft_current_leader(DISLMDB_env *env, char *out, size_t out_len);
/**
 * @brief Propose joint-consensus membership to match `nodes` (excluding self).
 * Adds/connects any missing peers first, then runs Cold,new → Cnew.
 */
int dislmdb_raft_reconfigure(DISLMDB_env *env,
                             const DISLMDB_node_addr *nodes,
                             size_t node_count);
/**
 * @brief Propose an opaque consensus blob (oplog / BCOD / SMAP).
 * Takes ownership of `data` on all return paths.
 */
int dislmdb_raft_propose_raw(DISLMDB_env *env, uint8_t *data, size_t size);

/**
 * @brief Drop a peer: local raft_remove_peer; if leader, joint-consensus shrink.
 */
int dislmdb_raft_remove_peer(DISLMDB_env *env, const char *node_id);

/** Step down and force a new election (Raft view-change analogue). */
int dislmdb_raft_force_election(DISLMDB_env *env);

/** Fill Raft-specific fields of a metrics snapshot (no-op if not Raft). */
void dislmdb_raft_fill_metrics(DISLMDB_env *env, DISLMDB_metrics *metrics);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_RAFT_ADAPTER_H */
