cmake_minimum_required(VERSION 3.16)
project(DisLMDB VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(USING_CLANG TRUE)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(USING_GCC TRUE)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    set(USING_MSVC TRUE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-Werror)
endif()

if(USING_CLANG)
    # Scoped to DisLMDB targets only (not vendored LMDB)
    set(DISLMDB_EXTRA_WARNINGS
        -Wno-padded
        -Wno-reserved-id-macro
        -Wno-documentation-unknown-command
        -Wno-declaration-after-statement
        -Wno-pre-c11-compat
        -Wno-c++98-compat
        -Wno-c++98-compat-pedantic
        -Wno-unsafe-buffer-usage
        -Wno-disabled-macro-expansion
    )
elseif(USING_GCC)
    set(DISLMDB_EXTRA_WARNINGS
        -Wcast-qual
        -Wconversion
        -Wformat=2
        -Wundef
    )
endif()

option(ENABLE_SANITIZER "Enable sanitizers for debugging" OFF)
if(ENABLE_SANITIZER)
    if(USING_CLANG OR USING_GCC)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

option(DISLMDB_USE_OPENSSL "Use OpenSSL for hash/HMAC (non-Apple hosts)" OFF)
find_package(OpenSSL QUIET)
find_package(Threads REQUIRED)

# Portable mTLS 1.3 — vendored Mbed TLS (identical on every host)
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls)
if(NOT EXISTS ${MBEDTLS_DIR}/library/CMakeLists.txt AND NOT EXISTS ${MBEDTLS_DIR}/library/Makefile)
    message(FATAL_ERROR "Vendored Mbed TLS missing at ${MBEDTLS_DIR}")
endif()
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory(${MBEDTLS_DIR} ${CMAKE_BINARY_DIR}/mbedtls EXCLUDE_FROM_ALL)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism
    ${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-Raft-mechanism
    ${MBEDTLS_DIR}/include
)

set(LMDB_SOURCES src/mdb.c src/midl.c)
add_library(lmdb STATIC ${LMDB_SOURCES})
# Keep LMDB warnings quiet — third-party code
target_compile_options(lmdb PRIVATE -w)

set(ENHANCED_PBFT_SRCS
    Enhanced-PBFT-mechanism/epdft.c
    Enhanced-PBFT-mechanism/messaging.c
    Enhanced-PBFT-mechanism/security_manager.c
    Enhanced-PBFT-mechanism/blake3_ref.c
    Enhanced-PBFT-mechanism/time_variant_blake3.c
)

set(DISLMDB_SRCS
    src/dislmdb.c
    src/utils/dislmdb_utils.c
    src/utils/dislmdb_crypto.c
    src/utils/dislmdb_ops.c
    src/utils/dislmdb_persist.c
    src/utils/dislmdb_shard.c
    src/utils/dislmdb_topo.c
    src/network/dislmdb_network.c
    src/network/dislmdb_mtls.c
    src/network/dislmdb_quic.c
    src/network/dislmdb_quic_tls.c
    src/network/dislmdb_iouring.c
    src/consensus/dislmdb_consensus.c
    src/consensus/pbft_adapter.c
    src/consensus/raft_adapter.c
    src/consensus/raft_wal.c
    Enhanced-Raft-mechanism/raft.c
    ${ENHANCED_PBFT_SRCS}
)

add_library(dislmdb SHARED ${DISLMDB_SRCS})
target_compile_options(dislmdb PRIVATE ${DISLMDB_EXTRA_WARNINGS})

target_link_libraries(dislmdb PRIVATE mbedtls mbedx509 mbedcrypto)
message(STATUS "mTLS backend: vendored Mbed TLS 1.3 (portable)")

if(DISLMDB_USE_OPENSSL AND OPENSSL_FOUND)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_OPENSSL)
    target_include_directories(dislmdb PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(dislmdb PRIVATE OpenSSL::Crypto)
    message(STATUS "Hash/HMAC backend: OpenSSL")
elseif(APPLE)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_COMMONCRYPTO)
    target_link_libraries(dislmdb PRIVATE "-framework Security")
    message(STATUS "Hash/HMAC backend: CommonCrypto")
elseif(OPENSSL_FOUND)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_OPENSSL)
    target_include_directories(dislmdb PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(dislmdb PRIVATE OpenSSL::Crypto)
    message(STATUS "Hash/HMAC backend: OpenSSL (auto)")
else()
    message(FATAL_ERROR "No hash/HMAC backend. Install OpenSSL libcrypto or build on Apple.")
endif()

set_target_properties(dislmdb PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "include/dislmdb.h;include/dislmdb_consensus.h;include/dislmdb_network.h;include/dislmdb_errors.h;include/dislmdb_crypto.h"
)

target_link_libraries(dislmdb
    PRIVATE lmdb
    PRIVATE Threads::Threads
)

if(UNIX AND NOT APPLE)
    target_link_libraries(dislmdb PRIVATE uuid)
endif()

install(TARGETS dislmdb
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

add_executable(basic_example examples/basic_example.c)
target_link_libraries(basic_example dislmdb)

add_executable(distributed_example examples/distributed_example.c)
target_link_libraries(distributed_example dislmdb)

add_executable(bytecode_example examples/bytecode_example.c)
target_link_libraries(bytecode_example dislmdb)

enable_testing()

add_executable(dislmdb_test tests/dislmdb_test.c)
target_link_libraries(dislmdb_test dislmdb)
add_test(NAME dislmdb_basic_test COMMAND dislmdb_test WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_crypto tests/unit/test_crypto.c)
target_link_libraries(test_crypto dislmdb)
add_test(NAME unit_crypto COMMAND test_crypto)

add_executable(test_tvb3
    tests/unit/test_tvb3.c
    Enhanced-PBFT-mechanism/time_variant_blake3.c
    Enhanced-PBFT-mechanism/blake3_ref.c)
target_include_directories(test_tvb3 PRIVATE Enhanced-PBFT-mechanism)
add_test(NAME unit_tvb3 COMMAND test_tvb3)

add_executable(test_ops_persist tests/integration/test_ops_persist.c)
target_link_libraries(test_ops_persist dislmdb)
add_test(NAME integration_ops_persist COMMAND test_ops_persist WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_op_status tests/integration/test_op_status.c)
target_link_libraries(test_op_status dislmdb)
add_test(NAME integration_op_status COMMAND test_op_status WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_membership tests/integration/test_membership.c)
target_link_libraries(test_membership dislmdb)
add_test(NAME integration_membership COMMAND test_membership WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_shard_map tests/integration/test_shard_map.c)
target_link_libraries(test_shard_map dislmdb)
add_test(NAME integration_shard_map COMMAND test_shard_map WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_topo_modes tests/integration/test_topo_modes.c)
target_link_libraries(test_topo_modes dislmdb)
add_test(NAME integration_topo_modes COMMAND test_topo_modes WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_topo_forward tests/integration/test_topo_forward.c)
target_link_libraries(test_topo_forward dislmdb)
add_test(NAME integration_topo_forward COMMAND test_topo_forward WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_topo_plane tests/integration/test_topo_plane.c)
target_link_libraries(test_topo_plane dislmdb)
add_test(NAME integration_topo_plane COMMAND test_topo_plane WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_wal tests/integration/test_raft_wal.c)
target_link_libraries(test_raft_wal dislmdb)
add_test(NAME integration_raft_wal COMMAND test_raft_wal WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_wal_chaos tests/integration/test_raft_wal_chaos.c)
target_link_libraries(test_raft_wal_chaos dislmdb)
add_test(NAME integration_raft_wal_chaos COMMAND test_raft_wal_chaos WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_multinode tests/integration/test_multinode.c)
target_link_libraries(test_multinode dislmdb)
add_test(NAME integration_multinode COMMAND test_multinode WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_udp tests/integration/test_udp.c)
target_link_libraries(test_udp dislmdb)
add_test(NAME integration_udp COMMAND test_udp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_mixed tests/integration/test_mixed.c)
target_link_libraries(test_mixed dislmdb)
add_test(NAME integration_mixed COMMAND test_mixed WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_transport_adapt tests/unit/test_transport_adapt.c)
target_link_libraries(test_transport_adapt dislmdb)
add_test(NAME unit_transport_adapt COMMAND test_transport_adapt)

add_executable(test_quic_substrate tests/unit/test_quic_substrate.c)
target_link_libraries(test_quic_substrate dislmdb)
add_test(NAME unit_quic_substrate COMMAND test_quic_substrate)

add_executable(test_mtls_cluster tests/integration/test_mtls_cluster.c)
target_link_libraries(test_mtls_cluster dislmdb)
add_test(NAME integration_mtls_cluster COMMAND test_mtls_cluster WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_udp tests/integration/test_raft_udp.c)
target_link_libraries(test_raft_udp dislmdb)
add_test(NAME integration_raft_udp COMMAND test_raft_udp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_tcp tests/integration/test_raft_tcp.c)
target_link_libraries(test_raft_tcp dislmdb)
add_test(NAME integration_raft_tcp COMMAND test_raft_tcp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_both tests/integration/test_raft_both.c)
target_link_libraries(test_raft_both dislmdb)
add_test(NAME integration_raft_both COMMAND test_raft_both WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_mtls tests/integration/test_raft_mtls.c)
target_link_libraries(test_raft_mtls dislmdb)
add_test(NAME integration_raft_mtls COMMAND test_raft_mtls WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_mtls_tcp tests/integration/test_raft_mtls_tcp.c)
target_link_libraries(test_raft_mtls_tcp dislmdb)
add_test(NAME integration_raft_mtls_tcp COMMAND test_raft_mtls_tcp WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_fault tests/integration/test_raft_fault.c)
target_link_libraries(test_raft_fault dislmdb)
add_test(NAME integration_raft_fault COMMAND test_raft_fault WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_stage tests/integration/test_raft_stage.c)
target_link_libraries(test_raft_stage dislmdb)
add_test(NAME integration_raft_stage COMMAND test_raft_stage WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_membership_it tests/integration/test_raft_membership.c)
target_link_libraries(test_raft_membership_it dislmdb)
add_test(NAME integration_raft_membership COMMAND test_raft_membership_it WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft_leave tests/integration/test_raft_leave.c)
target_link_libraries(test_raft_leave dislmdb)
add_test(NAME integration_raft_leave COMMAND test_raft_leave WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_pbft_viewchange tests/integration/test_pbft_viewchange.c)
target_link_libraries(test_pbft_viewchange dislmdb)
add_test(NAME integration_pbft_viewchange COMMAND test_pbft_viewchange WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_fault_tolerance tests/integration/test_fault_tolerance.c)
target_link_libraries(test_fault_tolerance dislmdb)
add_test(NAME integration_fault_tolerance COMMAND test_fault_tolerance WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(test_raft tests/unit/test_raft.c Enhanced-Raft-mechanism/raft.c)
target_include_directories(test_raft PRIVATE Enhanced-Raft-mechanism)
target_link_libraries(test_raft PRIVATE Threads::Threads)
add_test(NAME unit_raft COMMAND test_raft)

add_executable(test_raft_membership tests/unit/test_raft_membership.c Enhanced-Raft-mechanism/raft.c)
target_include_directories(test_raft_membership PRIVATE Enhanced-Raft-mechanism)
target_link_libraries(test_raft_membership PRIVATE Threads::Threads)
add_test(NAME unit_raft_membership COMMAND test_raft_membership)

add_executable(test_mtls tests/unit/test_mtls.c src/network/dislmdb_mtls.c)
target_include_directories(test_mtls PRIVATE ${MBEDTLS_DIR}/include src/network)
target_link_libraries(test_mtls PRIVATE mbedtls mbedx509 mbedcrypto Threads::Threads)
add_test(NAME unit_mtls COMMAND test_mtls WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(e2e_runner tests/e2e/e2e_runner.c)
target_link_libraries(e2e_runner dislmdb)

add_test(
    NAME e2e_golden
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e/run_e2e.sh $<TARGET_FILE:e2e_runner>
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Run the full suite as part of the default build (`cmake --build` / `make`)
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS dislmdb_test test_crypto test_tvb3 test_raft test_raft_membership
            test_mtls test_transport_adapt test_quic_substrate
            test_ops_persist test_op_status test_membership test_shard_map test_topo_modes
            test_topo_forward test_topo_plane test_raft_wal test_raft_wal_chaos
            test_multinode test_udp test_mixed
            test_mtls_cluster test_raft_udp test_raft_tcp test_raft_both
            test_raft_mtls test_raft_mtls_tcp test_raft_fault test_raft_stage
            test_raft_membership_it test_raft_leave test_pbft_viewchange
            test_fault_tolerance e2e_runner
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running DisLMDB unit, integration, and e2e suites"
)
add_custom_target(build_and_test ALL DEPENDS check)

find_package(Doxygen)
if(DOXYGEN_FOUND AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set(DOXYGEN_CONFIG_FILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${DOXYGEN_CONFIG_FILE} @ONLY)
    add_custom_target(docs
        ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIG_FILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

message(STATUS "DisLMDB version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
