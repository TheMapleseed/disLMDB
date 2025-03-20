/**
 * @file dislmdb.c
 * @brief Implementation of the Distributed LMDB core API
 *
 * This file implements the core functions for the Distributed LMDB library,
 * including environment management, transaction handling, and distributed
 * operations.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <openssl/sha.h>

#include "dislmdb_internal.h"
#include "consensus/pbft_adapter.h"

/** Library version information */
#define DISLMDB_VERSION_STRING "DisLMDB 0.1.0"

/** Default operation log size */
#define DISLMDB_DEFAULT_OPLOG_SIZE 1000

/** Default environment configuration */
static const DISLMDB_env_config default_env_config = {
    .path = NULL,
    .lmdb_flags = 0,
    .mode = 0644,
    .mapsize = 10485760,  /* 10 MB */
    .maxreaders = 126,
    .maxdbs = 0,
    .network = {
        .nodes = NULL,
        .node_count = 0,
        .local_port = 9876,
        .is_seed_node = false,
        .seed_nodes = {{0}},
        .seed_node_count = 0
    },
    .consensus = {
        .mechanism = DISLMDB_CONSENSUS_PBFT,
        .timeout_ms = 5000,
        .heartbeat_interval_ms = 1000,
        .election_timeout_min_ms = 3000,
        .election_timeout_max_ms = 6000,
        .max_batch_size = 100,
        .checkpoint_interval = 1000
    },
    .read_only_node = false,
    .sync_interval_ms = 60000,  /* 1 minute */
    .max_sync_batch_size = 1000,
    .node_name = "DisLMDB Node"
};

/**
 * Get the library version information
 */
const char *dislmdb_version(int *major, int *minor, int *patch)
{
    if (major) *major = DISLMDB_VERSION_MAJOR;
    if (minor) *minor = DISLMDB_VERSION_MINOR;
    if (patch) *patch = DISLMDB_VERSION_PATCH;
    return DISLMDB_VERSION_STRING;
}

/**
 * Get a string describing an error code
 */
const char *dislmdb_strerror(int err)
{
    /* First check our own error codes (future enhancement) */
    
    /* If not our error, delegate to LMDB */
    return mdb_strerror(err);
}

/**
 * Initialize a configuration with default values
 */
int dislmdb_env_config_init(DISLMDB_env_config *config)
{
    if (!config) {
        return EINVAL;
    }
    
    memcpy(config, &default_env_config, sizeof(DISLMDB_env_config));
    return 0;
}

/**
 * Get the current time in milliseconds
 */
uint64_t dislmdb_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/**
 * Generate a unique node ID
 */
int dislmdb_generate_node_id(char *node_id)
{
    if (!node_id) {
        return EINVAL;
    }
    
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, node_id);
    return 0;
}

/**
 * Calculate SHA-256 digest of data
 */
int dislmdb_sha256(const void *data, size_t size, uint8_t *digest)
{
    if (!data || !digest) {
        return EINVAL;
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(digest, &sha256);
    return 0;
}

/**
 * Log a message to the environment's log
 */
void dislmdb_log(DISLMDB_env *env, DISLMDB_LOG_LEVEL level, 
               const char *module, const char *format, ...)
{
    if (!env || !module || !format) {
        return;
    }
    
    va_list args;
    char message[DISLMDB_MAX_LOG_LENGTH];
    
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    pthread_mutex_lock(&env->log_mutex);
    
    /* Find the index to store the message */
    uint32_t index;
    if (env->log_count < DISLMDB_MAX_LOG_MESSAGES) {
        index = env->log_count++;
    } else {
        index = env->log_head;
        env->log_head = (env->log_head + 1) % DISLMDB_MAX_LOG_MESSAGES;
    }
    
    /* Store the message */
    DISLMDB_log_message *log_msg = &env->log_messages[index];
    log_msg->level = level;
    log_msg->timestamp = dislmdb_get_time_ms();
    strncpy(log_msg->module, module, sizeof(log_msg->module) - 1);
    strncpy(log_msg->message, message, sizeof(log_msg->message) - 1);
    
    pthread_mutex_unlock(&env->log_mutex);
    
    /* Print to stderr for error and fatal messages */
    if (level >= DISLMDB_LOG_ERROR) {
        fprintf(stderr, "[%s] %s: %s\n", module, 
                level == DISLMDB_LOG_ERROR ? "ERROR" : "FATAL", message);
    }
}

/**
 * Set the last error message and code
 */
void dislmdb_set_error(DISLMDB_env *env, int code, const char *format, ...)
{
    if (!env || !format) {
        return;
    }
    
    va_list args;
    
    va_start(args, format);
    vsnprintf(env->last_error, sizeof(env->last_error), format, args);
    va_end(args);
    
    env->last_error_code = code;
    
    /* Log the error */
    dislmdb_log(env, DISLMDB_LOG_ERROR, "ERROR", "%s (code %d)", 
               env->last_error, code);
}

/**
 * Create a distributed LMDB environment
 */
int dislmdb_env_create(DISLMDB_env **env)
{
    int rc;
    
    if (!env) {
        return EINVAL;
    }
    
    /* Allocate and initialize the environment structure */
    DISLMDB_env *e = calloc(1, sizeof(DISLMDB_env));
    if (!e) {
        return ENOMEM;
    }
    
    /* Set magic number */
    e->magic = DISLMDB_MAGIC;
    
    /* Create the underlying LMDB environment */
    rc = mdb_env_create(&e->mdb_env);
    if (rc != 0) {
        free(e);
        return rc;
    }
    
    /* Initialize mutexes */
    pthread_mutex_init(&e->txn_mutex, NULL);
    pthread_mutex_init(&e->oplog_mutex, NULL);
    pthread_mutex_init(&e->nodes_mutex, NULL);
    pthread_mutex_init(&e->status_mutex, NULL);
    pthread_mutex_init(&e->log_mutex, NULL);
    
    /* Allocate log message array */
    e->log_messages = calloc(DISLMDB_MAX_LOG_MESSAGES, sizeof(DISLMDB_log_message));
    if (!e->log_messages) {
        mdb_env_close(e->mdb_env);
        free(e);
        return ENOMEM;
    }
    
    /* Allocate operation log */
    e->oplog = calloc(DISLMDB_DEFAULT_OPLOG_SIZE, sizeof(DISLMDB_operation_log_entry));
    if (!e->oplog) {
        free(e->log_messages);
        mdb_env_close(e->mdb_env);
        free(e);
        return ENOMEM;
    }
    
    e->oplog_size = DISLMDB_DEFAULT_OPLOG_SIZE;
    
    /* Generate a unique node ID */
    dislmdb_generate_node_id(e->local_node_id);
    
    /* Initialize statistics */
    e->start_time = dislmdb_get_time_ms();
    
    /* Log environment creation */
    dislmdb_log(e, DISLMDB_LOG_INFO, "ENV", "Created environment with node ID %s", 
               e->local_node_id);
    
    *env = e;
    return 0;
}

/**
 * Open a distributed LMDB environment
 */
int dislmdb_env_open(DISLMDB_env *env, const DISLMDB_env_config *config)
{
    int rc;
    
    if (!env || !config || !config->path) {
        return EINVAL;
    }
    
    /* Validate magic number */
    if (env->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    /* Copy configuration */
    memcpy(&env->config, config, sizeof(DISLMDB_env_config));
    
    /* Configure the underlying LMDB environment */
    rc = mdb_env_set_mapsize(env->mdb_env, config->mapsize);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set map size: %s", mdb_strerror(rc));
        return rc;
    }
    
    rc = mdb_env_set_maxreaders(env->mdb_env, config->maxreaders);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set max readers: %s", mdb_strerror(rc));
        return rc;
    }
    
    rc = mdb_env_set_maxdbs(env->mdb_env, config->maxdbs);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to set max DBs: %s", mdb_strerror(rc));
        return rc;
    }
    
    /* Open the underlying LMDB environment */
    rc = mdb_env_open(env->mdb_env, config->path, config->lmdb_flags, config->mode);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to open environment: %s", mdb_strerror(rc));
        return rc;
    }
    
    /* Allocate and initialize node arrays */
    if (config->network.node_count > 0 && config->network.nodes != NULL) {
        env->nodes = calloc(config->network.node_count, sizeof(DISLMDB_node_addr));
        env->node_states = calloc(config->network.node_count, sizeof(DISLMDB_NODE_STATE));
        
        if (!env->nodes || !env->node_states) {
            dislmdb_set_error(env, ENOMEM, "Failed to allocate node arrays");
            if (env->nodes) free(env->nodes);
            if (env->node_states) free(env->node_states);
            return ENOMEM;
        }
        
        /* Copy node information */
        memcpy(env->nodes, config->network.nodes, 
               config->network.node_count * sizeof(DISLMDB_node_addr));
        env->node_count = config->network.node_count;
        
        /* Initialize node states */
        for (uint32_t i = 0; i < env->node_count; i++) {
            env->node_states[i] = DISLMDB_NODE_STATE_UNKNOWN;
        }
    }
    
    /* Initialize the network subsystem */
    rc = dislmdb_network_init(env, &config->network);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to initialize network subsystem");
        return rc;
    }
    
    /* Initialize the consensus subsystem */
    if (config->consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        rc = dislmdb_pbft_init(env);
        if (rc != DISLMDB_SUCCESS) {
            dislmdb_set_error(env, rc, "Failed to initialize Enhanced PBFT consensus");
            mdb_env_close(env->mdb_env);
            env->mdb_env = NULL;
            return rc;
        }
        
        dislmdb_log(env, DISLMDB_LOG_INFO, "INIT", "Enhanced PBFT consensus initialized");
    } else {
        rc = dislmdb_consensus_init(env, &config->consensus);
        if (rc != 0) {
            dislmdb_set_error(env, rc, "Failed to initialize consensus subsystem");
            dislmdb_network_shutdown(env);
            return rc;
        }
    }
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "ENV", "Opened environment at %s", config->path);
    return 0;
}

/**
 * Close a distributed LMDB environment
 */
void dislmdb_env_close(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return;
    }
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "ENV", "Closing environment");
    
    /* Shutdown subsystems */
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        dislmdb_pbft_shutdown(env);
    } else {
        dislmdb_consensus_shutdown(env);
    }
    dislmdb_network_shutdown(env);
    
    /* Close the underlying LMDB environment */
    if (env->mdb_env) {
        mdb_env_close(env->mdb_env);
        env->mdb_env = NULL;
    }
    
    /* Destroy mutexes */
    pthread_mutex_destroy(&env->txn_mutex);
    pthread_mutex_destroy(&env->oplog_mutex);
    pthread_mutex_destroy(&env->nodes_mutex);
    pthread_mutex_destroy(&env->status_mutex);
    pthread_mutex_destroy(&env->log_mutex);
    
    /* Free allocated memory */
    if (env->log_messages) free(env->log_messages);
    if (env->oplog) free(env->oplog);
    if (env->nodes) free(env->nodes);
    if (env->node_states) free(env->node_states);
    
    /* Clear magic number to prevent reuse */
    env->magic = 0;
    
    /* Free the environment structure */
    free(env);
}

/**
 * Synchronize environment data to disk
 */
int dislmdb_env_sync(DISLMDB_env *env, int force)
{
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    dislmdb_log(env, DISLMDB_LOG_DEBUG, "ENV", "Syncing environment to disk (force=%d)", force);
    
    /* Sync the underlying LMDB environment */
    rc = mdb_env_sync(env->mdb_env, force);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to sync environment: %s", mdb_strerror(rc));
    }
    
    return rc;
}

/**
 * Begin a transaction
 */
int dislmdb_txn_begin(DISLMDB_env *env, DISLMDB_txn *parent, 
                     unsigned int flags, DISLMDB_txn **txn)
{
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC || !txn) {
        return EINVAL;
    }
    
    /* Allocate and initialize the transaction structure */
    DISLMDB_txn *t = calloc(1, sizeof(DISLMDB_txn));
    if (!t) {
        dislmdb_set_error(env, ENOMEM, "Failed to allocate transaction structure");
        return ENOMEM;
    }
    
    /* Set magic number */
    t->magic = DISLMDB_MAGIC;
    
    /* Set transaction properties */
    t->env = env;
    t->parent = parent;
    t->flags = flags;
    t->is_write_txn = !(flags & MDB_RDONLY);
    t->is_distributed = t->is_write_txn;  /* Assume write txns are distributed by default */
    t->start_time = dislmdb_get_time_ms();
    
    /* Generate a unique transaction ID */
    char txn_id[64];
    dislmdb_generate_node_id(txn_id);
    strncpy(t->txn_id, txn_id, sizeof(t->txn_id) - 1);
    
    /* Begin the underlying LMDB transaction */
    MDB_txn *parent_mdb_txn = parent ? parent->mdb_txn : NULL;
    rc = mdb_txn_begin(env->mdb_env, parent_mdb_txn, flags, &t->mdb_txn);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to begin transaction: %s", mdb_strerror(rc));
        free(t);
        return rc;
    }
    
    /* Add to the active transactions list */
    pthread_mutex_lock(&env->txn_mutex);
    t->next = env->active_txns;
    env->active_txns = t;
    env->txn_count++;
    pthread_mutex_unlock(&env->txn_mutex);
    
    dislmdb_log(env, DISLMDB_LOG_DEBUG, "TXN", "Started transaction %s (write=%d, distributed=%d)", 
               t->txn_id, t->is_write_txn, t->is_distributed);
    
    *txn = t;
    return 0;
}

/**
 * Commit a transaction
 */
int dislmdb_txn_commit(DISLMDB_txn *txn)
{
    int rc;
    
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    DISLMDB_env *env = txn->env;
    if (!env || env->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    dislmdb_log(env, DISLMDB_LOG_DEBUG, "TXN", "Committing transaction %s", txn->txn_id);
    
    /* For distributed write transactions, we need to use consensus */
    if (txn->is_write_txn && txn->is_distributed) {
        /* Use PBFT consensus if configured */
        if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
            rc = dislmdb_pbft_propose_transaction(txn);
            if (rc != DISLMDB_SUCCESS) {
                dislmdb_set_error(env, rc, "Failed to achieve consensus for transaction");
                return rc;
            }
            
            /* The transaction will be applied by the consensus mechanism */
            /* We still need to commit locally */
        } else {
            /* Handle other consensus mechanisms as before */
            // ... existing consensus code ...
        }
    }
    
    /* Commit the underlying LMDB transaction */
    rc = mdb_txn_commit(txn->mdb_txn);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to commit transaction: %s", mdb_strerror(rc));
        return rc;
    }
    
    /* Remove from the active transactions list */
    pthread_mutex_lock(&env->txn_mutex);
    if (env->active_txns == txn) {
        env->active_txns = txn->next;
    } else {
        DISLMDB_txn *t = env->active_txns;
        while (t && t->next != txn) {
            t = t->next;
        }
        if (t) {
            t->next = txn->next;
        }
    }
    env->txn_count--;
    env->total_commits++;
    pthread_mutex_unlock(&env->txn_mutex);
    
    /* Clear magic number to prevent reuse */
    txn->magic = 0;
    
    /* Free the transaction structure */
    free(txn);
    
    return 0;
}

/**
 * Abort a transaction
 */
void dislmdb_txn_abort(DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return;
    }
    
    DISLMDB_env *env = txn->env;
    if (!env || env->magic != DISLMDB_MAGIC) {
        return;
    }
    
    dislmdb_log(env, DISLMDB_LOG_DEBUG, "TXN", "Aborting transaction %s", txn->txn_id);
    
    /* Abort the underlying LMDB transaction */
    mdb_txn_abort(txn->mdb_txn);
    
    /* Remove from the active transactions list */
    pthread_mutex_lock(&env->txn_mutex);
    if (env->active_txns == txn) {
        env->active_txns = txn->next;
    } else {
        DISLMDB_txn *t = env->active_txns;
        while (t && t->next != txn) {
            t = t->next;
        }
        if (t) {
            t->next = txn->next;
        }
    }
    env->txn_count--;
    pthread_mutex_unlock(&env->txn_mutex);
    
    /* Clear magic number to prevent reuse */
    txn->magic = 0;
    
    /* Free the transaction structure */
    free(txn);
}

/**
 * Get the underlying LMDB environment from a distributed environment
 */
MDB_env *dislmdb_get_lmdb_env(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return NULL;
    }
    
    return env->mdb_env;
}

/**
 * Get the underlying LMDB transaction from a distributed transaction
 */
MDB_txn *dislmdb_get_lmdb_txn(DISLMDB_txn *txn)
{
    if (!txn || txn->magic != DISLMDB_MAGIC) {
        return NULL;
    }
    
    return txn->mdb_txn;
}

/**
 * Add a node to the environment's node list
 */
int dislmdb_add_node_internal(DISLMDB_env *env, const DISLMDB_node_addr *node_addr)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_addr) {
        return EINVAL;
    }
    
    pthread_mutex_lock(&env->nodes_mutex);
    
    /* Check if the node already exists */
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strcmp(env->nodes[i].node_id, node_addr->node_id) == 0) {
            /* Update the node information */
            memcpy(&env->nodes[i], node_addr, sizeof(DISLMDB_node_addr));
            pthread_mutex_unlock(&env->nodes_mutex);
            return 0;
        }
    }
    
    /* Resize the node arrays if needed */
    if (env->node_count == 0) {
        env->nodes = calloc(1, sizeof(DISLMDB_node_addr));
        env->node_states = calloc(1, sizeof(DISLMDB_NODE_STATE));
        if (!env->nodes || !env->node_states) {
            pthread_mutex_unlock(&env->nodes_mutex);
            return ENOMEM;
        }
    } else {
        DISLMDB_node_addr *new_nodes = realloc(env->nodes, 
                                             (env->node_count + 1) * sizeof(DISLMDB_node_addr));
        DISLMDB_NODE_STATE *new_states = realloc(env->node_states, 
                                               (env->node_count + 1) * sizeof(DISLMDB_NODE_STATE));
        if (!new_nodes || !new_states) {
            if (new_nodes) env->nodes = new_nodes;
            if (new_states) env->node_states = new_states;
            pthread_mutex_unlock(&env->nodes_mutex);
            return ENOMEM;
        }
        env->nodes = new_nodes;
        env->node_states = new_states;
    }
    
    /* Add the new node */
    memcpy(&env->nodes[env->node_count], node_addr, sizeof(DISLMDB_node_addr));
    env->node_states[env->node_count] = DISLMDB_NODE_STATE_UNKNOWN;
    env->node_count++;
    
    pthread_mutex_unlock(&env->nodes_mutex);
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "NODE", "Added node %s (%s:%d)", 
               node_addr->node_id, node_addr->hostname, node_addr->port);
    
    return 0;
}

/**
 * Add a node to the cluster
 */
int dislmdb_add_node(DISLMDB_env *env, const DISLMDB_node_addr *node_addr)
{
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC || !node_addr) {
        return EINVAL;
    }
    
    /* Add the node to the internal list */
    rc = dislmdb_add_node_internal(env, node_addr);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Failed to add node to internal list");
        return rc;
    }
    
    /* Attempt to connect to the node */
    rc = dislmdb_network_connect(env, node_addr, 
                                DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    if (rc != 0) {
        dislmdb_log(env, DISLMDB_LOG_WARNING, "NODE", 
                   "Failed to connect to node %s (%s:%d)", 
                   node_addr->node_id, node_addr->hostname, node_addr->port);
        /* Continue anyway, as we might connect later */
    }
    
    return 0;
}

/**
 * Find a node by its ID
 */
int dislmdb_find_node(DISLMDB_env *env, const char *node_id, uint32_t *index)
{
    if (!env || env->magic != DISLMDB_MAGIC || !node_id || !index) {
        return EINVAL;
    }
    
    pthread_mutex_lock(&env->nodes_mutex);
    
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strcmp(env->nodes[i].node_id, node_id) == 0) {
            *index = i;
            pthread_mutex_unlock(&env->nodes_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&env->nodes_mutex);
    return ENOENT;
}

/**
 * Update the state of a node
 */
int dislmdb_update_node_state(DISLMDB_env *env, const char *node_id, 
                             DISLMDB_NODE_STATE state)
{
    uint32_t index;
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC || !node_id) {
        return EINVAL;
    }
    
    /* Find the node */
    rc = dislmdb_find_node(env, node_id, &index);
    if (rc != 0) {
        return rc;
    }
    
    pthread_mutex_lock(&env->nodes_mutex);
    
    /* Get the old state */
    DISLMDB_NODE_STATE old_state = env->node_states[index];
    
    /* Update the state */
    env->node_states[index] = state;
    
    pthread_mutex_unlock(&env->nodes_mutex);
    
    /* Log the state change */
    dislmdb_log(env, DISLMDB_LOG_INFO, "NODE", "Node %s state changed from %d to %d", 
               node_id, old_state, state);
    
    /* Notify the callback if registered */
    pthread_mutex_lock(&env->status_mutex);
    if (env->status_callback) {
        env->status_callback(node_id, old_state, state, env->status_callback_data);
    }
    pthread_mutex_unlock(&env->status_mutex);
    
    return 0;
}

/**
 * Remove a node from the cluster
 */
int dislmdb_remove_node(DISLMDB_env *env, const char *node_id)
{
    uint32_t index;
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC || !node_id) {
        return EINVAL;
    }
    
    /* Find the node */
    rc = dislmdb_find_node(env, node_id, &index);
    if (rc != 0) {
        dislmdb_set_error(env, rc, "Node %s not found", node_id);
        return rc;
    }
    
    /* Disconnect from the node */
    rc = dislmdb_network_disconnect(env, node_id);
    if (rc != 0) {
        dislmdb_log(env, DISLMDB_LOG_WARNING, "NODE", 
                   "Failed to disconnect from node %s", node_id);
        /* Continue anyway to remove it from our list */
    }
    
    pthread_mutex_lock(&env->nodes_mutex);
    
    /* Remove the node by shifting all following nodes */
    for (uint32_t i = index; i < env->node_count - 1; i++) {
        memcpy(&env->nodes[i], &env->nodes[i + 1], sizeof(DISLMDB_node_addr));
        env->node_states[i] = env->node_states[i + 1];
    }
    
    env->node_count--;
    
    pthread_mutex_unlock(&env->nodes_mutex);
    
    dislmdb_log(env, DISLMDB_LOG_INFO, "NODE", "Removed node %s", node_id);
    
    return 0;
}

/**
 * Get the status of a node
 */
int dislmdb_get_node_state(DISLMDB_env *env, const char *node_id, 
                          DISLMDB_NODE_STATE *state)
{
    uint32_t index;
    int rc;
    
    if (!env || env->magic != DISLMDB_MAGIC || !node_id || !state) {
        return EINVAL;
    }
    
    /* Find the node */
    rc = dislmdb_find_node(env, node_id, &index);
    if (rc != 0) {
        return rc;
    }
    
    pthread_mutex_lock(&env->nodes_mutex);
    *state = env->node_states[index];
    pthread_mutex_unlock(&env->nodes_mutex);
    
    return 0;
}

/**
 * Get the current leader node ID
 */
int dislmdb_get_leader(DISLMDB_env *env, char *leader_id, size_t id_size)
{
    if (!env || env->magic != DISLMDB_MAGIC || !leader_id || id_size < 64) {
        return EINVAL;
    }
    
    /* Get the leader from the PBFT state */
    strncpy(leader_id, env->pbft_state.primary_id, id_size - 1);
    leader_id[id_size - 1] = '\0';
    
    return 0;
}

/**
 * Force sync with other nodes
 */
int dislmdb_force_sync(DISLMDB_env *env)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    /* This will be implemented as part of the synchronization mechanism */
    dislmdb_log(env, DISLMDB_LOG_INFO, "SYNC", "Forcing synchronization with other nodes");
    
    /* For now, just sync the local database */
    return dislmdb_env_sync(env, 1);
}

/**
 * Set a callback function for node status changes
 */
int dislmdb_set_status_callback(DISLMDB_env *env, 
                               dislmdb_status_callback callback,
                               void *user_data)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return EINVAL;
    }
    
    pthread_mutex_lock(&env->status_mutex);
    env->status_callback = callback;
    env->status_callback_data = user_data;
    pthread_mutex_unlock(&env->status_mutex);
    
    return 0;
}

/**
 * Add a new function for bytecode storage
 */
int dislmdb_store_bytecode(DISLMDB_env *env, 
                         const uint8_t *bytecode, 
                         size_t bytecode_size,
                         const char *bytecode_id,
                         unsigned int options)
{
    if (!env || !bytecode || !bytecode_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    
    /* Verify environment is initialized */
    if (!env->mdb_env) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    
    /* Use PBFT consensus if configured */
    if (env->config.consensus.mechanism == DISLMDB_CONSENSUS_PBFT) {
        return dislmdb_pbft_store_bytecode(env, bytecode, bytecode_size, bytecode_id, options);
    } else {
        /* For other consensus mechanisms or solo mode */
        dislmdb_log(env, DISLMDB_LOG_ERROR, "BYTECODE", 
                   "Bytecode storage requires Enhanced PBFT consensus");
        return DISLMDB_ERR_NOT_IMPLEMENTED;
    }
} 