# DisLMDB: Distributed Lightning Memory-Mapped Database

DisLMDB is a distributed version of the [Lightning Memory-Mapped Database (LMDB)](https://symas.com/lmdb/), designed to provide synchronized database operations across multiple nodes using a Byzantine Fault Tolerance consensus mechanism.

## Features

- **Distributed Database**: Synchronize operations across multiple nodes
- **ACID Compliance**: Retains all the ACID properties of the original LMDB
- **Byzantine Fault Tolerance**: Consensus protocol based on Practical Byzantine Fault Tolerance (PBFT)
- **Modern C Implementation**: Written in modern C (C23 standard)
- **Zero-Copy Design**: Inherits LMDB's zero-copy memory-mapped architecture for high performance
- **Node Discovery and Management**: Automatic discovery and management of nodes in the cluster
- **Leader Election**: Dynamic leader election for coordinating consensus
- **Efficient Synchronization**: Designed to efficiently replicate bytecode and ML model data between nodes

## Requirements

- C23 compatible compiler (GCC 13+ or Clang 16+)
- OpenSSL development libraries (libssl-dev)
- UUID development libraries (uuid-dev)
- POSIX-compliant operating system
- CMake 3.16 or higher (for building)

## Building

Makefile (recommended on macOS; no Homebrew required):

```bash
make          # builds libraries, examples, then runs unit + integration + e2e
make lib      # libraries only
make check    # re-run the full test suite
```

CMake:

```bash
mkdir build && cd build
cmake ..
cmake --build .   # builds and runs CTest via the build_and_test target
ctest --output-on-failure
```

### Tests

| Layer | Location | Role |
| --- | --- | --- |
| Unit | `tests/unit/` | Crypto, AEAD, TV-BLAKE3 |
| Integration | `tests/integration/`, `tests/dislmdb_test.c` | Ops, persist, membership, LMDB basics |
| E2E | `tests/e2e/` | Scenario scripts vs golden `expected/*.out` |

### Attribution

See [TRIBUTE_HOWARD_CHU.md](TRIBUTE_HOWARD_CHU.md) for a tribute to Howard Chu, inventor of LMDB, documenting the English Wikipedia article on Lightning Memory-Mapped Database.

## Usage

Here's a basic example of how to use DisLMDB:

```c
#include <dislmdb.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    DISLMDB_env *env;
    DISLMDB_txn *txn;
    MDB_dbi dbi;
    int rc;
    
    // Initialize configuration
    DISLMDB_env_config config;
    dislmdb_env_config_init(&config);
    
    // Set configuration parameters
    config.path = "./testdb";
    config.lmdb_flags = 0;
    config.mapsize = 10485760;  // 10MB
    config.network.local_port = 9876;
    
    // Create environment
    rc = dislmdb_env_create(&env);
    if (rc != 0) {
        fprintf(stderr, "Error creating environment: %s\n", dislmdb_strerror(rc));
        return 1;
    }
    
    // Open environment
    rc = dislmdb_env_open(env, &config);
    if (rc != 0) {
        fprintf(stderr, "Error opening environment: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    // Begin transaction
    rc = dislmdb_txn_begin(env, NULL, 0, &txn);
    if (rc != 0) {
        fprintf(stderr, "Error beginning transaction: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    // Get underlying LMDB transaction for database operations
    MDB_txn *mdb_txn = dislmdb_get_lmdb_txn(txn);
    
    // Open database
    rc = mdb_dbi_open(mdb_txn, "testdb", MDB_CREATE, &dbi);
    if (rc != 0) {
        fprintf(stderr, "Error opening database: %s\n", mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    // Put data
    MDB_val key, data;
    key.mv_size = 5;
    key.mv_data = "hello";
    data.mv_size = 5;
    data.mv_data = "world";
    
    rc = mdb_put(mdb_txn, dbi, &key, &data, 0);
    if (rc != 0) {
        fprintf(stderr, "Error putting data: %s\n", mdb_strerror(rc));
        dislmdb_txn_abort(txn);
        dislmdb_env_close(env);
        return 1;
    }
    
    // Commit transaction
    rc = dislmdb_txn_commit(txn);
    if (rc != 0) {
        fprintf(stderr, "Error committing transaction: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(env);
        return 1;
    }
    
    // Close environment
    dislmdb_env_close(env);
    
    return 0;
}
```

## Distributed Operation

To connect multiple nodes:

```c
// After environment creation, add nodes to the cluster
DISLMDB_node_addr node;
strncpy(node.hostname, "other-node.example.com", sizeof(node.hostname) - 1);
node.port = 9876;
strncpy(node.node_id, "node-id-string", sizeof(node.node_id) - 1);

rc = dislmdb_add_node(env, &node);
if (rc != 0) {
    fprintf(stderr, "Error adding node: %s\n", dislmdb_strerror(rc));
}
```

## Architecture

DisLMDB is designed with the following components:

1. **Core API Layer**: Extensions to LMDB for distributed operations
2. **Consensus Layer**: PBFT-based consensus mechanism
3. **Network Layer**: Communication between nodes
4. **Storage Layer**: Underlying LMDB storage

## Byzantine Fault Tolerance

DisLMDB implements the Practical Byzantine Fault Tolerance (PBFT) algorithm, which provides consensus with the following properties:

- Safety and liveness in an asynchronous environment
- Highly optimized for normal operation
- Tolerates f faulty nodes in a system with 3f+1 total nodes
- Designed for minimal overhead during normal operation

## License

DisLMDB is commercial proprietary software owned by The Mapleseed Inc. This software is provided under a commercial license agreement only and requires payment of license fees.

Use, distribution, or copying of this software without a valid license agreement is strictly prohibited.

Copyright 2025 David Harmon, The Mapleseed Inc. All rights reserved.

## Contributing

Contributions are governed by the terms of our Contributor License Agreement. Please contact us before submitting any contributions.

## Roadmap

- Implement additional consensus algorithms
- Add encryption for inter-node communication
- Add support for access control
- Improve documentation and examples
- Add benchmarks and performance optimization
- Create bindings for other programming languages 