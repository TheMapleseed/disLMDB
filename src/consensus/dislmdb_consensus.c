/**
 * @file dislmdb_consensus.c
 * @brief Non-PBFT consensus paths (SOLO / future Raft)
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdlib.h>
#include <string.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"

typedef struct solo_consensus_context {
    DISLMDB_pbft_state state;
    dislmdb_consensus_callback callback;
    void *callback_data;
    uint32_t next_sequence;
} solo_consensus_context;

int dislmdb_consensus_init(DISLMDB_env *env, const DISLMDB_consensus_config *config)
{
    if (!env || !config) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->consensus_context) {
        return DISLMDB_ERR_ALREADY_INITIALIZED;
    }

    if (config->mechanism != DISLMDB_CONSENSUS_SOLO) {
        return DISLMDB_ERR_CONFIG;
    }

    solo_consensus_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }

    ctx->state.view = 0;
    ctx->state.sequence = 0;
    ctx->state.f = 0;
    ctx->state.node_count = 1;
    ctx->state.is_primary = true;
    strncpy(ctx->state.primary_id, env->local_node_id, sizeof(ctx->state.primary_id) - 1);
    ctx->next_sequence = 1;

    env->pbft_state = ctx->state;
    env->consensus_context = ctx;
    env->consensus_running = true;

    dislmdb_log(env, DISLMDB_LOG_INFO, "CONSENSUS", "SOLO consensus initialized");
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_shutdown(DISLMDB_env *env)
{
    if (!env || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }
    free(env->consensus_context);
    env->consensus_context = NULL;
    env->consensus_running = false;
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_propose(DISLMDB_env *env,
                              DISLMDB_operation *operation,
                              uint32_t timeout_ms,
                              DISLMDB_consensus_result *result)
{
    (void)timeout_ms;
    if (!env || !env->consensus_context || !operation || !result) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    solo_consensus_context *ctx = env->consensus_context;
    memset(result, 0, sizeof(*result));

    /* Verify digest */
    uint8_t digest[DISLMDB_SHA256_DIGEST_LENGTH];
    if (operation->data_size > 0 && operation->data) {
        if (dislmdb_crypto_sha256(operation->data, operation->data_size, digest) != 0) {
            result->status = DISLMDB_CONSENSUS_REJECTED;
            result->error_code = DISLMDB_ERR_DIGEST_MISMATCH;
            return DISLMDB_ERR_DIGEST_MISMATCH;
        }
        if (!dislmdb_crypto_secure_eq(digest, operation->digest, DISLMDB_SHA256_DIGEST_LENGTH)) {
            result->status = DISLMDB_CONSENSUS_REJECTED;
            result->error_code = DISLMDB_ERR_DIGEST_MISMATCH;
            return DISLMDB_ERR_DIGEST_MISMATCH;
        }
    }

    operation->sequence = ctx->next_sequence++;
    ctx->state.sequence = operation->sequence;
    env->pbft_state = ctx->state;

    result->status = DISLMDB_CONSENSUS_COMMITTED;
    result->error_code = DISLMDB_SUCCESS;
    result->commit_view = ctx->state.view;
    result->commit_sequence = operation->sequence;
    result->commit_time = dislmdb_get_time_ms();
    result->node_count = 1;
    result->agree_count = 1;

    if (ctx->callback) {
        ctx->callback(operation, result, ctx->callback_data);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_set_callback(DISLMDB_env *env,
                                   dislmdb_consensus_callback callback,
                                   void *user_data)
{
    if (!env || !env->consensus_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    solo_consensus_context *ctx = env->consensus_context;
    ctx->callback = callback;
    ctx->callback_data = user_data;
    env->cons_callback = callback;
    env->cons_callback_data = user_data;
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_get_state(DISLMDB_env *env, DISLMDB_pbft_state *state)
{
    if (!env || !state) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    *state = env->pbft_state;
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_generate_op_id(DISLMDB_env *env, DISLMDB_op_id *id)
{
    (void)env;
    if (!id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    return dislmdb_crypto_random_bytes(id->bytes, DISLMDB_OP_ID_SIZE) == 0
               ? DISLMDB_SUCCESS
               : DISLMDB_ERR_MEMORY_ERROR;
}

int dislmdb_consensus_trigger_view_change(DISLMDB_env *env)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    /* SOLO: already primary */
    env->pbft_state.is_primary = true;
    strncpy(env->pbft_state.primary_id, env->local_node_id,
            sizeof(env->pbft_state.primary_id) - 1);
    return DISLMDB_SUCCESS;
}

int dislmdb_consensus_get_operation_status(DISLMDB_env *env,
                                           const DISLMDB_op_id *id,
                                           DISLMDB_consensus_result *result)
{
    (void)env;
    (void)id;
    if (!result) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    memset(result, 0, sizeof(*result));
    result->status = DISLMDB_CONSENSUS_UNKNOWN;
    result->error_code = DISLMDB_ERR_NOT_IMPLEMENTED;
    return DISLMDB_ERR_NOT_IMPLEMENTED;
}
