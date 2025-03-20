/**
 * @file bytecode_example.c
 * @brief Example demonstrating bytecode storage with Enhanced PBFT consensus
 *
 * This example shows how to configure DisLMDB with the Enhanced PBFT consensus
 * mechanism and store bytecode data across the distributed database.
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
#include "dislmdb.h"

// Sample bytecode for demonstration
static const uint8_t SAMPLE_BYTECODE[] = {
    // Magic header
    0xCA, 0xFE, 0xBA, 0xBE,
    
    // Version
    0x00, 0x01,
    
    // Placeholder bytecode instructions
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};
#define BYTECODE_SIZE sizeof(SAMPLE_BYTECODE)

// Global variables for cleanup
static DISLMDB_env *env = NULL;
static volatile int running = 1;

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    printf("Received signal %d, shutting down...\n", signum);
    running = 0;
}

// Status callback for node state changes
void status_callback(const char *node_id, 
                     DISLMDB_NODE_STATE old_state,
                     DISLMDB_NODE_STATE new_state,
                     void *user_data) {
    printf("Node %s state changed: %d -> %d\n", node_id, old_state, new_state);
}

int main(int argc, char *argv[]) {
    int rc;
    const char *db_path = "./dislmdb-data";
    uint16_t port = 9876;
    bool is_seed = false;
    int opt;
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "p:d:s")) != -1) {
        switch (opt) {
            case 'p':
                port = (uint16_t)atoi(optarg);
                break;
            case 'd':
                db_path = optarg;
                break;
            case 's':
                is_seed = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-d db_path] [-s]\n", argv[0]);
                fprintf(stderr, "  -p port    Port number for network communication (default: 9876)\n");
                fprintf(stderr, "  -d db_path Path to database directory (default: ./dislmdb-data)\n");
                fprintf(stderr, "  -s         Set this node as a seed node\n");
                return 1;
        }
    }
    
    printf("Starting DisLMDB with Enhanced PBFT consensus\n");
    printf("Database path: %s\n", db_path);
    printf("Network port: %d\n", port);
    printf("Seed node: %s\n", is_seed ? "Yes" : "No");
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize environment configuration
    DISLMDB_env_config config;
    rc = dislmdb_env_config_init(&config);
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to initialize config: %s\n", dislmdb_strerror(rc));
        return 1;
    }
    
    // Set basic configuration
    config.path = db_path;
    config.lmdb_flags = 0;
    config.mode = 0664;
    config.mapsize = 10485760; // 10MB
    config.maxreaders = 126;
    config.maxdbs = 10;
    
    // Set network configuration
    config.network.local_port = port;
    config.network.is_seed_node = is_seed;
    
    // If not a seed node, configure a seed node to connect to
    if (!is_seed) {
        snprintf(config.network.seed_nodes[0], 256, "127.0.0.1:9876");
        config.network.seed_node_count = 1;
    }
    
    // Set consensus configuration to use Enhanced PBFT
    config.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    config.consensus.timeout_ms = 5000;       // 5 second timeout
    config.consensus.heartbeat_interval_ms = 1000;  // 1 second heartbeat
    config.consensus.election_timeout_min_ms = 5000;  // 5 second min election timeout
    config.consensus.election_timeout_max_ms = 10000; // 10 second max election timeout
    config.consensus.max_batch_size = 1;      // Tolerate 1 faulty node (needs 4 total nodes)
    config.consensus.checkpoint_interval = 100; // Checkpoint every 100 operations
    
    // Create the environment
    rc = dislmdb_env_create(&env);
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to create environment: %s\n", dislmdb_strerror(rc));
        return 1;
    }
    
    // Set status callback
    rc = dislmdb_set_status_callback(env, status_callback, NULL);
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to set status callback: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    // Open the environment
    rc = dislmdb_env_open(env, &config);
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to open environment: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("DisLMDB environment opened successfully\n");
    printf("Waiting for consensus...\n");
    
    // Give time for nodes to connect
    sleep(5);
    
    // Check if this node is the leader
    char leader_id[64];
    rc = dislmdb_get_leader(env, leader_id, sizeof(leader_id));
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to get leader: %s\n", dislmdb_strerror(rc));
        printf("No leader elected yet, will try to store bytecode anyway\n");
    } else {
        printf("Current leader: %s\n", leader_id);
    }
    
    // Store bytecode
    printf("Storing bytecode sample...\n");
    rc = dislmdb_store_bytecode(env, 
                              SAMPLE_BYTECODE, 
                              BYTECODE_SIZE,
                              "example_bytecode_v1",
                              0);
    
    if (rc != DISLMDB_SUCCESS) {
        fprintf(stderr, "Failed to store bytecode: %s\n", dislmdb_strerror(rc));
    } else {
        printf("Bytecode stored successfully!\n");
    }
    
    // Main loop - keep running until signaled to stop
    printf("Node running. Press Ctrl+C to exit.\n");
    while (running) {
        // Force a sync periodically
        rc = dislmdb_force_sync(env);
        if (rc != DISLMDB_SUCCESS) {
            fprintf(stderr, "Sync error: %s\n", dislmdb_strerror(rc));
        }
        
        sleep(5);
    }
    
    // Cleanup
    printf("Closing environment...\n");
    dislmdb_env_close(env);
    printf("Exited successfully\n");
    
    return 0;
} 