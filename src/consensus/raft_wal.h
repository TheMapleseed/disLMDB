/**
 * @file raft_wal.h
 * @brief Durable Raft hard-state + log in LMDB (__dislmdb_raft__ DBI)
 */
#ifndef DISLMDB_RAFT_WAL_H
#define DISLMDB_RAFT_WAL_H

#include "dislmdb_internal.h"
#include "../../Enhanced-Raft-mechanism/raft.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISLMDB_RAFT_DBI "__dislmdb_raft__"

/** Register persist hooks on the Raft node (no-op if !persist_state). */
int dislmdb_raft_wal_attach(DISLMDB_env *env, RaftNode *node);

/** Load hard state + log into node before raft_start. */
int dislmdb_raft_wal_load(DISLMDB_env *env, RaftNode *node);

/** Compact WAL through last_applied and record snapshot meta. */
int dislmdb_raft_wal_snapshot(DISLMDB_env *env, RaftNode *node);

/** Force fsync of the LMDB env holding the WAL. */
int dislmdb_raft_wal_sync(DISLMDB_env *env);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_RAFT_WAL_H */
