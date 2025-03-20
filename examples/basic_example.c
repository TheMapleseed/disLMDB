/**
 * @file basic_example.c
 * @brief Basic example demonstrating DisLMDB usage
 *
 * This example shows how to use DisLMDB in a single-node configuration,
 * including creating an environment, performing transactions, and
 * basic database operations.
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
#include <dislmdb.h>

int main(int argc, char *argv[]) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    MDB_dbi dbi;
    int rc;
    
    /* Parse command line arguments */
    const char *db_path = (argc > 1) ? argv[1] : "./testdb";
    
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
    
    /* Set network configuration for solo mode */
    config.network.local_port = 9876;
    config.network.is_seed_node = true;
    config.network.node_count = 0;
    config.network.nodes = NULL;
    
    /* Set consensus configuration for solo mode */
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    
    /* Create environment */
    rc = dislmdb_env_create(&env);
    if (rc != 0) {
        fprintf(stderr, "Error creating environment: %s\n",
                dislmdb_strerror(rc));
        return 1;
    }
    
    printf("Environment created successfully\n");
    
    /* Open environment */
    rc = dislmdb_env_open(env, &config);
    if (rc != 0) {
        fprintf(stderr, "Error opening environment: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Environment opened at %s\n", db_path);
    
    /* Begin transaction */
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        fprintf(stderr, "Error beginning transaction: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Transaction started\n");
    
    /* Get underlying LMDB transaction for database operations */
    MDB_txn *mdb_txn = dislmdb_get_lmdb_txn(txn);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "testdb", MDB_CREATE, &dbi);
    if (rc != 0) {
        fprintf(stderr, "Error opening database: %s\n",
                mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Database opened\n");
    
    /* Put data */
    MDB_val key, data;
    key.mv_size = 5;
    key.mv_data = "hello";
    data.mv_size = 5;
    data.mv_data = "world";
    
    rc = mdb_put(mdb_txn, dbi, &key, &data, 0);
    if (rc != 0) {
        fprintf(stderr, "Error putting data: %s\n",
                mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Data inserted: key='%s', value='%s'\n", 
           (char*)key.mv_data, (char*)data.mv_data);
    
    /* Commit transaction */
    rc = dislmdb_txn_commit(txn);
    if (rc != 0) {
        fprintf(stderr, "Error committing transaction: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Transaction committed\n");
    
    /* Start a read transaction to verify the data */
    rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        fprintf(stderr, "Error beginning read transaction: %s\n",
                dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "testdb", 0, &dbi);
    if (rc != 0) {
        fprintf(stderr, "Error opening database for reading: %s\n",
                mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    /* Get data */
    key.mv_size = 5;
    key.mv_data = "hello";
    
    rc = mdb_get(mdb_txn, dbi, &key, &data);
    if (rc != 0) {
        fprintf(stderr, "Error getting data: %s\n",
                mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    printf("Data retrieved: key='%s', value='%.*s'\n", 
           (char*)key.mv_data, (int)data.mv_size, (char*)data.mv_data);
    
    /* Abort read transaction (it's read-only anyway) */
    dislmdb_txn_abort(txn);
    
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