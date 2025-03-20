cmake_minimum_required(VERSION 3.16)
project(DisLMDB VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Detect compiler
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(USING_CLANG TRUE)
    message(STATUS "Detected Clang compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(USING_GCC TRUE)
    message(STATUS "Detected GCC compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    set(USING_MSVC TRUE)
    message(STATUS "Detected MSVC compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
else()
    message(WARNING "Unknown compiler: ${CMAKE_C_COMPILER_ID}")
endif()

# Add compile options
add_compile_options(-Wall -Wextra -Wpedantic)

# Error on warnings in Release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-Werror)
endif()

# Compiler-specific options
if(USING_CLANG)
    # Clang-specific warnings and optimizations
    add_compile_options(
        -Weverything
        -Wno-padded  # Silence padding warnings
        -Wno-reserved-id-macro  # Silence warnings about macros starting with underscore
        -Wno-documentation-unknown-command  # Silence unknown doxygen commands
    )
elseif(USING_GCC)
    # GCC-specific warnings
    add_compile_options(
        -Wcast-qual
        -Wconversion
        -Wdouble-promotion
        -Wformat=2
        -Wformat-truncation
        -Wundef
    )
endif()

# Sanitizer options (enabled with -DENABLE_SANITIZER=ON)
option(ENABLE_SANITIZER "Enable sanitizers for debugging" OFF)
if(ENABLE_SANITIZER)
    if(USING_CLANG OR USING_GCC)
        message(STATUS "Enabling sanitizers")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    else()
        message(WARNING "Sanitizers requested but not supported by current compiler")
    endif()
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism
    ${OPENSSL_INCLUDE_DIR}
)

# Define library sources
set(DISLMDB_SOURCES
    src/dislmdb.c
    src/utils/dislmdb_utils.c
    # Add these when implemented
    # src/consensus/dislmdb_consensus.c
    # src/consensus/dislmdb_pbft.c
    # src/network/dislmdb_network.c
    # src/storage/dislmdb_storage.c
)

# Define the original LMDB sources
set(LMDB_SOURCES
    src/mdb.c
    src/midl.c
)

# Create the LMDB static library
add_library(lmdb STATIC ${LMDB_SOURCES})

# Add Enhanced PBFT mechanism files
set(ENHANCED_PBFT_SRCS
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/epdft.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/epdft.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/messaging.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/messaging.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/security_manager.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/Enhanced-PBFT-mechanism/security_manager.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft_adapter.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/consensus/pbft_adapter.h"
)

# Add the adapter source files
set(DISLMDB_SRCS
    ${DISLMDB_SOURCES}
    ${ENHANCED_PBFT_SRCS}
)

# Create the DisLMDB library target
add_library(dislmdb SHARED ${DISLMDB_SRCS})

# Set library properties
set_target_properties(dislmdb PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "include/dislmdb.h;include/dislmdb_consensus.h;include/dislmdb_network.h;include/dislmdb_errors.h"
)

# Link dependencies
target_link_libraries(dislmdb
    PRIVATE lmdb
    PRIVATE ${OPENSSL_LIBRARIES}
    PRIVATE ${CMAKE_DL_LIBS}
    PRIVATE Threads::Threads
    PRIVATE uuid
    PRIVATE pthread
)

# Install rules
install(TARGETS dislmdb
    LIBRARY DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Example programs
add_executable(basic_example examples/basic_example.c)
target_link_libraries(basic_example dislmdb)

add_executable(distributed_example examples/distributed_example.c)
target_link_libraries(distributed_example dislmdb)

# Create directories for examples
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/examples)

# Testing
enable_testing()

# Create directories for tests
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Add test executable
add_executable(dislmdb_test tests/dislmdb_test.c)
target_link_libraries(dislmdb_test dislmdb)

# Register tests
add_test(NAME dislmdb_basic_test COMMAND dislmdb_test)

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    # Set Doxygen configuration
    set(DOXYGEN_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/docs)
    set(DOXYGEN_CONFIG_FILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    # Create Doxyfile
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${DOXYGEN_CONFIG_FILE} @ONLY)
    
    # Add custom target for documentation
    add_custom_target(docs
        ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIG_FILE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

# Show summary
message(STATUS "DisLMDB version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Compiler ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "C Compiler version: ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "OpenSSL found: ${OPENSSL_FOUND}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "Doxygen found: ${DOXYGEN_FOUND}")
message(STATUS "Sanitizers enabled: ${ENABLE_SANITIZER}") 