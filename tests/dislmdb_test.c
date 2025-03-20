/**
 * @file dislmdb_test.c
 * @brief Test program for DisLMDB
 *
 * This file contains basic tests for the DisLMDB library functionality.
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
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dislmdb.h>
#include <dislmdb_errors.h>

/** Test database path */
#define TEST_DB_PATH "./testdb"

/** Number of test entries */
#define NUM_TEST_ENTRIES 100

/** 
 * Test the version information function
 */
void test_version(void) {
    int major, minor, patch;
    const char *version = dislmdb_version(&major, &minor, &patch);
    
    printf("Version: %s (Major: %d, Minor: %d, Patch: %d)\n",
           version, major, minor, patch);
    
    assert(version != NULL);
    assert(major == DISLMDB_VERSION_MAJOR);
    assert(minor == DISLMDB_VERSION_MINOR);
    assert(patch == DISLMDB_VERSION_PATCH);
}

/**
 * Test environment creation and closing
 */
void test_env_create_close(void) {
    DISLMDB_env *env;
    int rc;
    
    printf("Testing environment creation and closing...\n");
    
    rc = dislmdb_env_create(&env);
    assert(rc == 0);
    assert(env != NULL);
    
    dislmdb_env_close(env);
    
    printf("PASSED\n");
}

/**
 * Test environment configuration
 */
void test_env_config(void) {
    DISLMDB_env_config config;
    int rc;
    
    printf("Testing environment configuration...\n");
    
    rc = dislmdb_env_config_init(&config);
    assert(rc == 0);
    
    assert(config.mapsize > 0);
    assert(config.maxreaders > 0);
    
    printf("PASSED\n");
}

/**
 * Test environment open and sync
 */
void test_env_open_sync(void) {
    DISLMDB_env *env;
    DISLMDB_env_config config;
    int rc;
    
    printf("Testing environment open and sync...\n");
    
    /* Create test directory if it doesn't exist */
    struct stat st = {0};
    if (stat(TEST_DB_PATH, &st) == -1) {
        mkdir(TEST_DB_PATH, 0700);
    }
    
    rc = dislmdb_env_create(&env);
    assert(rc == 0);
    
    rc = dislmdb_env_config_init(&config);
    assert(rc == 0);
    
    config.path = TEST_DB_PATH;
    config.mapsize = 10485760;  /* 10MB */
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    
    rc = dislmdb_env_open(env, &config);
    assert(rc == 0);
    
    rc = dislmdb_env_sync(env, 1);
    assert(rc == 0);
    
    dislmdb_env_close(env);
    
    printf("PASSED\n");
}

/**
 * Test transaction operations
 */
void test_transactions(void) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    DISLMDB_env_config config;
    MDB_dbi dbi;
    MDB_val key, data;
    MDB_txn *mdb_txn;
    int rc;
    
    printf("Testing transactions...\n");
    
    /* Setup environment */
    rc = dislmdb_env_create(&env);
    assert(rc == 0);
    
    rc = dislmdb_env_config_init(&config);
    assert(rc == 0);
    
    config.path = TEST_DB_PATH;
    config.mapsize = 10485760;  /* 10MB */
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    
    rc = dislmdb_env_open(env, &config);
    assert(rc == 0);
    
    /* Begin transaction */
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    assert(rc == 0);
    
    /* Get LMDB transaction */
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "testdb", MDB_CREATE, &dbi);
    assert(rc == 0);
    
    /* Write test */
    char key_buf[32];
    char data_buf[32];
    
    sprintf(key_buf, "test-key");
    sprintf(data_buf, "test-data");
    
    key.mv_size = strlen(key_buf);
    key.mv_data = key_buf;
    data.mv_size = strlen(data_buf);
    data.mv_data = data_buf;
    
    rc = mdb_put(mdb_txn, dbi, &key, &data, 0);
    assert(rc == 0);
    
    /* Commit transaction */
    rc = dislmdb_txn_commit(txn);
    assert(rc == 0);
    
    /* Begin read transaction */
    rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    assert(rc == 0);
    
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "testdb", 0, &dbi);
    assert(rc == 0);
    
    /* Read test */
    MDB_val read_data;
    rc = mdb_get(mdb_txn, dbi, &key, &read_data);
    assert(rc == 0);
    
    assert(read_data.mv_size == data.mv_size);
    assert(memcmp(read_data.mv_data, data.mv_data, data.mv_size) == 0);
    
    /* Abort transaction */
    dislmdb_txn_abort(txn);
    
    /* Close environment */
    dislmdb_env_close(env);
    
    printf("PASSED\n");
}

/**
 * Test database operations with multiple entries
 */
void test_multiple_entries(void) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    DISLMDB_env_config config;
    MDB_dbi dbi;
    MDB_val key, data;
    MDB_txn *mdb_txn;
    int rc;
    
    printf("Testing multiple entries...\n");
    
    /* Setup environment */
    rc = dislmdb_env_create(&env);
    assert(rc == 0);
    
    rc = dislmdb_env_config_init(&config);
    assert(rc == 0);
    
    config.path = TEST_DB_PATH;
    config.mapsize = 10485760;  /* 10MB */
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    
    rc = dislmdb_env_open(env, &config);
    assert(rc == 0);
    
    /* Begin transaction */
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    assert(rc == 0);
    
    /* Get LMDB transaction */
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "multidb", MDB_CREATE, &dbi);
    assert(rc == 0);
    
    /* Write multiple entries */
    char key_buf[32];
    char data_buf[32];
    
    for (int i = 0; i < NUM_TEST_ENTRIES; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(data_buf, "data-%d", i);
        
        key.mv_size = strlen(key_buf);
        key.mv_data = key_buf;
        data.mv_size = strlen(data_buf);
        data.mv_data = data_buf;
        
        rc = mdb_put(mdb_txn, dbi, &key, &data, 0);
        assert(rc == 0);
    }
    
    /* Commit transaction */
    rc = dislmdb_txn_commit(txn);
    assert(rc == 0);
    
    /* Begin read transaction */
    rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    assert(rc == 0);
    
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "multidb", 0, &dbi);
    assert(rc == 0);
    
    /* Read and verify entries */
    MDB_val read_data;
    
    for (int i = 0; i < NUM_TEST_ENTRIES; i++) {
        sprintf(key_buf, "key-%d", i);
        sprintf(data_buf, "data-%d", i);
        
        key.mv_size = strlen(key_buf);
        key.mv_data = key_buf;
        
        rc = mdb_get(mdb_txn, dbi, &key, &read_data);
        assert(rc == 0);
        
        assert(read_data.mv_size == strlen(data_buf));
        assert(memcmp(read_data.mv_data, data_buf, read_data.mv_size) == 0);
    }
    
    /* Abort transaction */
    dislmdb_txn_abort(txn);
    
    /* Close environment */
    dislmdb_env_close(env);
    
    printf("PASSED\n");
}

/**
 * Test cursor operations
 */
void test_cursors(void) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    DISLMDB_env_config config;
    MDB_dbi dbi;
    MDB_val key, data;
    MDB_txn *mdb_txn;
    MDB_cursor *cursor;
    int rc;
    
    printf("Testing cursors...\n");
    
    /* Setup environment */
    rc = dislmdb_env_create(&env);
    assert(rc == 0);
    
    rc = dislmdb_env_config_init(&config);
    assert(rc == 0);
    
    config.path = TEST_DB_PATH;
    config.mapsize = 10485760;  /* 10MB */
    config.consensus.mechanism = DISLMDB_CONSENSUS_SOLO;
    
    rc = dislmdb_env_open(env, &config);
    assert(rc == 0);
    
    /* Begin transaction */
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    assert(rc == 0);
    
    /* Get LMDB transaction */
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "cursordb", MDB_CREATE, &dbi);
    assert(rc == 0);
    
    /* Write multiple entries */
    char key_buf[32];
    char data_buf[32];
    
    for (int i = 0; i < 10; i++) {
        sprintf(key_buf, "ckey-%d", i);
        sprintf(data_buf, "cdata-%d", i);
        
        key.mv_size = strlen(key_buf);
        key.mv_data = key_buf;
        data.mv_size = strlen(data_buf);
        data.mv_data = data_buf;
        
        rc = mdb_put(mdb_txn, dbi, &key, &data, 0);
        assert(rc == 0);
    }
    
    /* Commit transaction */
    rc = dislmdb_txn_commit(txn);
    assert(rc == 0);
    
    /* Begin read transaction */
    rc = dislmdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    assert(rc == 0);
    
    mdb_txn = dislmdb_get_lmdb_txn(txn);
    assert(mdb_txn != NULL);
    
    /* Open database */
    rc = mdb_dbi_open(mdb_txn, "cursordb", 0, &dbi);
    assert(rc == 0);
    
    /* Create cursor */
    rc = mdb_cursor_open(mdb_txn, dbi, &cursor);
    assert(rc == 0);
    
    /* Iterate through all keys */
    int count = 0;
    while ((rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        char expected_key[32];
        char expected_data[32];
        
        sprintf(expected_key, "ckey-%d", count);
        sprintf(expected_data, "cdata-%d", count);
        
        assert(key.mv_size == strlen(expected_key));
        assert(memcmp(key.mv_data, expected_key, key.mv_size) == 0);
        
        assert(data.mv_size == strlen(expected_data));
        assert(memcmp(data.mv_data, expected_data, data.mv_size) == 0);
        
        count++;
    }
    
    assert(count == 10);
    assert(rc == MDB_NOTFOUND);
    
    /* Close cursor */
    mdb_cursor_close(cursor);
    
    /* Abort transaction */
    dislmdb_txn_abort(txn);
    
    /* Close environment */
    dislmdb_env_close(env);
    
    printf("PASSED\n");
}

/**
 * Test cleanup function to remove test directory
 */
void test_cleanup(void) {
    printf("Cleaning up test data...\n");
    
    /* Remove test database files - this is platform specific and may need adjustment */
    char cmd[256];
    sprintf(cmd, "rm -rf %s", TEST_DB_PATH);
    system(cmd);
    
    printf("Cleanup complete\n");
}

/**
 * Main test function
 */
int main(void) {
    printf("=== DisLMDB Test Suite ===\n\n");
    
    /* Run tests */
    test_version();
    test_env_create_close();
    test_env_config();
    test_env_open_sync();
    test_transactions();
    test_multiple_entries();
    test_cursors();
    
    /* Cleanup */
    test_cleanup();
    
    printf("\nAll tests PASSED!\n");
    return 0;
} 