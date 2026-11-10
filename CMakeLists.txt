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

option(DISLMDB_USE_OPENSSL "Use OpenSSL instead of platform crypto" OFF)
find_package(OpenSSL QUIET)
find_package(Threads REQUIRED)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism
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
    src/network/dislmdb_network.c
    src/consensus/dislmdb_consensus.c
    src/consensus/pbft_adapter.c
    ${ENHANCED_PBFT_SRCS}
)

add_library(dislmdb SHARED ${DISLMDB_SRCS})
target_compile_options(dislmdb PRIVATE ${DISLMDB_EXTRA_WARNINGS})

if(DISLMDB_USE_OPENSSL AND OPENSSL_FOUND)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_OPENSSL)
    target_include_directories(dislmdb PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(dislmdb PRIVATE OpenSSL::Crypto)
    message(STATUS "Crypto backend: OpenSSL")
elseif(APPLE)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_COMMONCRYPTO)
    target_link_libraries(dislmdb PRIVATE "-framework Security")
    message(STATUS "Crypto backend: Apple CommonCrypto/Security")
elseif(OPENSSL_FOUND)
    target_compile_definitions(dislmdb PRIVATE DISLMDB_USE_OPENSSL)
    target_include_directories(dislmdb PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(dislmdb PRIVATE OpenSSL::Crypto)
    message(STATUS "Crypto backend: OpenSSL (auto)")
else()
    message(FATAL_ERROR "No crypto backend available. Install OpenSSL or build on Apple.")
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

add_executable(test_membership tests/integration/test_membership.c)
target_link_libraries(test_membership dislmdb)
add_test(NAME integration_membership COMMAND test_membership WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

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
    DEPENDS dislmdb_test test_crypto test_tvb3 test_ops_persist test_membership e2e_runner
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
