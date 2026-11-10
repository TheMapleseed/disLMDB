/**
 * @file distributed_example.c
 * @brief Example demonstrating DisLMDB's distributed operation
 *
 * This example shows how to use DisLMDB in a multi-node configuration,
 * demonstrating node discovery, consensus, and distributed transactions.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 * 
 * This software is proprietary and confidential.
 * Unauthorized copying, transfer, or use of this file, in source or binary form,
 * is strictly prohibited except under the terms of a commercial license agreement
 * with The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dislmdb.h>
#include <dislmdb_errors.h>

/* Global flag for signal handling */
static volatile int running = 1;

/**
 * Signal handler for graceful shutdown
 */
void signal_handler(int signum) {
    printf("\nReceived signal %d, shutting down...\n", signum);
    running = 0;
}

/**
 * Callback function for node status changes
 */
void status_callback(const char *node_id, 
                   DISLMDB_NODE_STATE old_state,
                   DISLMDB_NODE_STATE new_state,
                   void *user_data) {
    (void)user_data;
    const char *states[] = {
        "UNKNOWN", "JOINING", "SYNCING", "NORMAL", "LEADER", 
        "FOLLOWER", "CANDIDATE", "LEAVING"
    };
    
    printf("Node %s changed state: %s -> %s\n", 
           node_id, 
           states[old_state], 
           states[new_state]);
}

int main(int argc, char *argv[]) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    MDB_dbi dbi;
    int rc;
    
    /* Parse command line arguments */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <db_path> <node_id> [port] [is_seed] [seed_node_addr]\n", argv[0]);
        return 1;
    }
    
    const char *db_path = argv[1];
    const char *node_id = argv[2];
    uint16_t port = (argc > 3) ? (uint16_t)atoi(argv[3]) : 9876;
    int is_seed = (argc > 4) ? atoi(argv[4]) : 0;
    const char *seed_node_addr = (argc > 5) ? argv[5] : NULL;
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Display version information */
    int major, minor, patch;
    const char *version = dislmdb_version(&major, &minor, &patch);
    printf("DisLMDB Version: %s (Major: %d, Minor: %d, Patch: %d)\n",
           version, major, minor, patch);
    
    /* Initialize configuration */
    DISLMDB_env_config config;
    rc = dislmdb_env_config_init(&config);
    if (rc != 0) {
        fprintf(stderr, "Error initializing configuration: %s\n",
                dislmdb_strerror(rc));
        return 1;
    }
    
    /* Set configuration parameters */
    config.path = db_path;
    config.lmdb_flags = 0;
    config.mode = 0644;
    config.mapsize = 10485760;  /* 10MB */
    config.maxreaders = 126;
    config.maxdbs = 10;
    
    /* Set node name */
    strncpy(config.node_name, node_id, sizeof(config.node_name) - 1);
    
    /* Set network configuration */
    config.network.local_port = port;
    config.network.is_seed_node = is_seed ? true : false;
    config.network.node_count = 0;
    config.network.nodes = NULL;
    
    /* Add seed node if provided */
    if (seed_node_addr && !is_seed) {
        config.network.seed_node_count = 1;
        strncpy(config.network.seed_nodes[0], seed_node_addr, 
                sizeof(config.network.seed_nodes[0]) - 1);
    } else {
        config.network.seed_node_count = 0;
    }
    
    /* Set consensus configuration for PBFT */
    config.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    config.consensus.timeout_ms = 5000;
    config.consensus.heartbeat_interval_ms = 1000;
    config.consensus.election_timeout_min_ms = 3000;
    config.consensus.election_timeout_max_ms = 6000;
    config.consensus.max_batch_size = 100;
    config.consensus.checkpoint_interval = 1000;
    config.consensus.fault_tolerance = 0;
    config.consensus.enable_liveness = true;
    config.consensus.persist_state = true;

    /* Create environment */
    rc = dislmdb_env_create(&env);
    if (rc != 0) {
        fprintf(stderr, "Error creating environment: %s\n",
                dislmdb_strerror(rc));
        return 1;
    }
    
    printf("Environment created successfully\n");
    
    /* Shared cluster key required for multi-node (fail-closed).
     * HMAC framing + AEAD payloads on BOTH (UDP signal / TCP data).
     * Override the demo key with DISLMDB_CLUSTER_KEY (64 hex chars).
     * Optional mTLS: set DISLMDB_MTLS=1 and provide cert paths via
     * DISLMDB_MTLS_CERT / DISLMDB_MTLS_KEY / DISLMDB_MTLS_CA. */
    if (seed_node_addr || is_seed) {
        uint8_t cluster_key[32];
        memset(cluster_key, 0x5A, sizeof(cluster_key));
        const char *key_hex = getenv("DISLMDB_CLUSTER_KEY");
        if (key_hex && strlen(key_hex) == 64) {
            int ok = 1;
            for (int i = 0; i < 32 && ok; i++) {
                unsigned int b = 0;
                if (sscanf(key_hex + (size_t)i * 2, "%2x", &b) != 1) {
                    ok = 0;
                } else {
                    cluster_key[i] = (uint8_t)b;
                }
            }
            if (!ok) {
                fprintf(stderr, "DISLMDB_CLUSTER_KEY must be 64 hex characters; using demo key\n");
                memset(cluster_key, 0x5A, sizeof(cluster_key));
            }
        }
        memcpy(config.network.cluster_key, cluster_key, 32);
        config.network.has_cluster_key = true;
        config.network.enable_message_auth = true;
        config.network.enable_payload_encryption = true;
        config.network.transport = DISLMDB_TRANSPORT_BOTH; /* UDP signal, TCP data */

        const char *mtls = getenv("DISLMDB_MTLS");
        if (mtls && mtls[0] == '1') {
            const char *cert = getenv("DISLMDB_MTLS_CERT");
            const char *key = getenv("DISLMDB_MTLS_KEY");
            const char *ca = getenv("DISLMDB_MTLS_CA");
            if (cert && key && ca) {
                config.network.enable_mtls = true;
                config.network.enable_tls = true;
                strncpy(config.network.tls_cert_path, cert,
                        sizeof(config.network.tls_cert_path) - 1);
                strncpy(config.network.tls_key_path, key,
                        sizeof(config.network.tls_key_path) - 1);
                strncpy(config.network.tls_ca_path, ca,
                        sizeof(config.network.tls_ca_path) - 1);
                printf("mTLS enabled (cert=%s)\n", cert);
            } else {
                fprintf(stderr,
                        "DISLMDB_MTLS=1 requires DISLMDB_MTLS_CERT/KEY/CA; continuing without mTLS\n");
            }
        }
    }

    /* Register status callback */
    rc = dislmdb_set_status_callback(env, status_callback, NULL);
    if (rc != 0) {
        fprintf(stderr, "Error setting status callback: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    /* Open environment */
    rc = dislmdb_env_open(env, &config);
    if (rc != 0) {
        fprintf(stderr, "Error opening environment: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Environment opened at %s (Node ID: %s, Port: %d, Seed: %s)\n", 
           db_path, node_id, port, is_seed ? "Yes" : "No");
    
    /* If not a seed node, wait for connection to seed node */
    if (!is_seed && seed_node_addr) {
        printf("Connecting to seed node %s...\n", seed_node_addr);
        
        /* Extract hostname and port from seed node address */
        char seed_hostname[256];
        uint16_t seed_port = 9876;
        
        if (sscanf(seed_node_addr, "%255[^:]:%hu", seed_hostname, &seed_port) < 1) {
            fprintf(stderr, "Invalid seed node address format\n");
            dislmdb_env_close(env);
            return 1;
        }
        
        /* Create a node address for the seed node */
        DISLMDB_node_addr seed_node;
        strncpy(seed_node.hostname, seed_hostname, sizeof(seed_node.hostname) - 1);
        seed_node.port = seed_port;
        sprintf(seed_node.node_id, "seed-%s", seed_hostname);  /* Placeholder ID */
        
        /* Add the seed node */
        rc = dislmdb_add_node(env, &seed_node);
        if (rc != 0) {
            fprintf(stderr, "Error adding seed node: %s\n",
                    dislmdb_strerror(rc));
            /* Continue anyway */
        }
        
        /* Wait for node discovery */
        printf("Waiting for node discovery...\n");
        sleep(3);
    }
    
    /* Begin distributed write (dislmdb_put — not raw mdb_put) */
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        fprintf(stderr, "Error beginning transaction: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Transaction started\n");
    
    rc = dislmdb_dbi_open(txn, "testdb", MDB_CREATE, &dbi);
    if (rc != 0) {
        fprintf(stderr, "Error opening database: %s\n",
                dislmdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Database opened\n");
    
    char key_buffer[64];
    snprintf(key_buffer, sizeof(key_buffer), "key-from-%s", node_id);
    
    MDB_val key, data;
    key.mv_size = strlen(key_buffer);
    key.mv_data = key_buffer;
    data.mv_size = strlen(node_id);
    data.mv_data = (void *)node_id;
    
    rc = dislmdb_put(txn, dbi, &key, &data, 0);
    if (rc != 0) {
        fprintf(stderr, "Error putting data: %s\n",
                dislmdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Data inserted: key='%s', value='%s'\n",
           (char *)key.mv_data, (char *)data.mv_data);
    
    rc = dislmdb_txn_commit(txn);
    if (rc != 0) {
        fprintf(stderr, "Error committing transaction: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Transaction committed via consensus\n");

    /* DISLMDB_SMOKE=1: exit after one consensus write (CI / make smoke-example). */
    const char *smoke = getenv("DISLMDB_SMOKE");
    if (smoke && smoke[0] == '1') {
        printf("Smoke mode: shutting down after commit\n");
        dislmdb_env_close(env);
        return 0;
    }

    printf("Node is running. Press Ctrl+C to exit.\n");
    
    while (running) {
        for (int i = 0; i < 10 && running; i++) {
            sleep(1);
        }
        
        if (!running) break;
        
        rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
        if (rc != 0) {
            fprintf(stderr, "Error beginning read transaction: %s\n",
                    dislmdb_strerror(rc));
            continue;
        }
        
        rc = dislmdb_dbi_open(txn, "testdb", 0, &dbi);
        if (rc != 0) {
            fprintf(stderr, "Error opening database for reading: %s\n",
                    dislmdb_strerror(rc));
            dislmdb_txn_abort(txn);
            continue;
        }
        
        MDB_txn *mdb_txn = dislmdb_get_lmdb_txn(txn);
        MDB_cursor *cursor;
        rc = mdb_cursor_open(mdb_txn, dbi, &cursor);
        if (rc != 0) {
            fprintf(stderr, "Error opening cursor: %s\n",
                    mdb_strerror(rc));
            dislmdb_txn_abort(txn);
            continue;
        }
        
        printf("\nDatabase contents:\n");
        printf("%-30s | %s\n", "Key", "Value");
        printf("------------------------------+------------------\n");
        
        while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
            printf("%-30.*s | %.*s\n",
                   (int)key.mv_size, (char *)key.mv_data,
                   (int)data.mv_size, (char *)data.mv_data);
        }
        
        if (rc != MDB_NOTFOUND) {
            fprintf(stderr, "Error reading database: %s\n",
                    mdb_strerror(rc));
        }
        
        mdb_cursor_close(cursor);
        dislmdb_txn_abort(txn);
        
        char leader_id[64];
        rc = dislmdb_get_leader(env, leader_id, sizeof(leader_id));
        if (rc != 0) {
            fprintf(stderr, "Error getting leader: %s\n",
                    dislmdb_strerror(rc));
        } else {
            printf("\nCurrent leader: %s\n", leader_id);
        }
        
        rc = dislmdb_force_sync(env);
        if (rc != 0) {
            fprintf(stderr, "Error forcing sync: %s\n",
                    dislmdb_strerror(rc));
        } else {
            printf("Force sync / state transfer requested\n");
        }
    }
    
    /* Sync and close environment */
    rc = dislmdb_env_sync(env, 1);
    if (rc != 0) {
        fprintf(stderr, "Error syncing environment: %s\n",
                dislmdb_strerror(rc));
    } else {
        printf("Environment synced to disk\n");
    }
    
    dislmdb_env_close(env);
    printf("Environment closed\n");
    
    return 0;
} 