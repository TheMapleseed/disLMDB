/**
 * @file dislmdb_utils.c
 * @brief Utility functions for Distributed LMDB
 *
 * This file implements various utility functions used by the DisLMDB library.
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"

/**
 * Generate a unique ID
 *
 * @param id Output buffer for the ID (must be at least 37 bytes)
 * @return 0 on success, non-zero on error
 */
int dislmdb_generate_uuid(char *id)
{
    if (!id) {
        return EINVAL;
    }
    
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, id);
    return 0;
}

/**
 * Get the current time in milliseconds
 *
 * @return Current time in milliseconds since epoch
 */
uint64_t dislmdb_get_time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

/**
 * Get the current time as a string
 *
 * @param buf Output buffer for the time string
 * @param size Size of the output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_get_time_string(char *buf, size_t size)
{
    if (!buf || size < 20) {
        return EINVAL;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
    return 0;
}

/**
 * Calculate SHA-256 digest of data
 *
 * @param data Input data
 * @param size Size of input data
 * @param digest Output digest (must be at least 32 bytes)
 * @return 0 on success, non-zero on error
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
 * HMAC-SHA256 digest calculation
 *
 * @param key Key for HMAC
 * @param key_len Length of the key
 * @param data Input data
 * @param data_len Length of input data
 * @param digest Output digest (must be at least 32 bytes)
 * @return 0 on success, non-zero on error
 */
int dislmdb_hmac_sha256(const void *key, size_t key_len, 
                      const void *data, size_t data_len, 
                      uint8_t *digest)
{
    if (!key || !data || !digest) {
        return EINVAL;
    }
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) {
        return ENOMEM;
    }
    
    if (HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) != 1) {
        HMAC_CTX_free(ctx);
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }
    
    if (HMAC_Update(ctx, data, data_len) != 1) {
        HMAC_CTX_free(ctx);
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }
    
    unsigned int len = 32;
    if (HMAC_Final(ctx, digest, &len) != 1) {
        HMAC_CTX_free(ctx);
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }
    
    HMAC_CTX_free(ctx);
    return 0;
}

/**
 * Base64 encode data
 *
 * @param in Input data
 * @param len Length of input data
 * @param out Output buffer for encoded data
 * @param out_len Size of output buffer
 * @param out_written Bytes written to output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_base64_encode(const uint8_t *in, size_t len, 
                        char *out, size_t out_len, 
                        size_t *out_written)
{
    if (!in || !out || !out_written) {
        return EINVAL;
    }
    
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        return ENOMEM;
    }
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free_all(b64);
        return ENOMEM;
    }
    
    bio = BIO_push(b64, bio);
    
    if (BIO_write(bio, in, len) <= 0) {
        BIO_free_all(bio);
        return DISLMDB_ERR_NETWORK;
    }
    
    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        return DISLMDB_ERR_NETWORK;
    }
    
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    if (bufferPtr->length >= out_len) {
        BIO_free_all(bio);
        return ENOMEM;
    }
    
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';
    *out_written = bufferPtr->length;
    
    BIO_free_all(bio);
    return 0;
}

/**
 * Base64 decode data
 *
 * @param in Input data
 * @param len Length of input data
 * @param out Output buffer for decoded data
 * @param out_len Size of output buffer
 * @param out_written Bytes written to output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_base64_decode(const char *in, size_t len, 
                        uint8_t *out, size_t out_len, 
                        size_t *out_written)
{
    if (!in || !out || !out_written) {
        return EINVAL;
    }
    
    BIO *bio, *b64;
    
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        return ENOMEM;
    }
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(in, len);
    if (!bio) {
        BIO_free_all(b64);
        return ENOMEM;
    }
    
    bio = BIO_push(b64, bio);
    
    int decoded_size = BIO_read(bio, out, out_len);
    if (decoded_size <= 0) {
        BIO_free_all(bio);
        return DISLMDB_ERR_NETWORK;
    }
    
    *out_written = decoded_size;
    
    BIO_free_all(bio);
    return 0;
}

/**
 * Generate random bytes
 *
 * @param buf Output buffer for random bytes
 * @param len Number of random bytes to generate
 * @return 0 on success, non-zero on error
 */
int dislmdb_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return EINVAL;
    }
    
    if (RAND_bytes(buf, len) != 1) {
        return DISLMDB_ERR_NETWORK;
    }
    
    return 0;
}

/**
 * Get the hostname of the local machine
 *
 * @param hostname Output buffer for the hostname
 * @param size Size of the output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_get_hostname(char *hostname, size_t size)
{
    if (!hostname || size == 0) {
        return EINVAL;
    }
    
    if (gethostname(hostname, size) != 0) {
        return errno;
    }
    
    /* Ensure null termination */
    hostname[size - 1] = '\0';
    return 0;
}

/**
 * Get the local IP address
 *
 * @param ip_addr Output buffer for the IP address
 * @param size Size of the output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_get_local_ip(char *ip_addr, size_t size)
{
    if (!ip_addr || size < INET_ADDRSTRLEN) {
        return EINVAL;
    }
    
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    
    if (getifaddrs(&ifaddr) == -1) {
        return errno;
    }
    
    /* Find the first non-loopback IPv4 address */
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        
        family = ifa->ifa_addr->sa_family;
        
        if (family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            
            /* Skip loopback addresses */
            if ((ntohl(sa->sin_addr.s_addr) & 0xff000000) == 0x7f000000) {
                continue;
            }
            
            s = inet_ntop(AF_INET, &(sa->sin_addr), ip_addr, size);
            if (s == NULL) {
                freeifaddrs(ifaddr);
                return errno;
            }
            
            freeifaddrs(ifaddr);
            return 0;
        }
    }
    
    /* No suitable address found */
    freeifaddrs(ifaddr);
    return ENOENT;
}

/**
 * Check if a port is available
 *
 * @param port Port number to check
 * @return 1 if available, 0 if in use, -1 on error
 */
int dislmdb_check_port_available(uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    
    int on = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        close(sock);
        return -1;
    }
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;  /* Port is in use */
    }
    
    close(sock);
    return 1;  /* Port is available */
}

/**
 * Set a socket to non-blocking mode
 *
 * @param sock Socket file descriptor
 * @return 0 on success, non-zero on error
 */
int dislmdb_set_nonblocking(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return errno;
    }
    
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return errno;
    }
    
    return 0;
}

/**
 * Compare two operation IDs for equality
 *
 * @param id1 First operation ID
 * @param id2 Second operation ID
 * @return 1 if equal, 0 if not equal
 */
int dislmdb_op_id_equals(const DISLMDB_op_id *id1, const DISLMDB_op_id *id2)
{
    if (!id1 || !id2) {
        return 0;
    }
    
    return memcmp(id1->bytes, id2->bytes, DISLMDB_OP_ID_SIZE) == 0;
}

/**
 * Generate a unique operation ID
 *
 * @param id Output: The generated operation ID
 * @return 0 on success, non-zero on error
 */
int dislmdb_generate_op_id(DISLMDB_op_id *id)
{
    if (!id) {
        return EINVAL;
    }
    
    /* Use the first 16 bytes of a UUID */
    uuid_t uuid;
    uuid_generate(uuid);
    memcpy(id->bytes, uuid, DISLMDB_OP_ID_SIZE);
    
    return 0;
}

/**
 * Format an operation ID as a string
 *
 * @param id The operation ID
 * @param str Output buffer for the string representation
 * @param size Size of the output buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_op_id_to_string(const DISLMDB_op_id *id, char *str, size_t size)
{
    if (!id || !str || size < 33) {
        return EINVAL;
    }
    
    for (int i = 0; i < DISLMDB_OP_ID_SIZE; i++) {
        snprintf(str + (i * 2), 3, "%02x", id->bytes[i]);
    }
    
    return 0;
}

/**
 * Parse an operation ID from a string
 *
 * @param str String representation of the operation ID
 * @param id Output: The parsed operation ID
 * @return 0 on success, non-zero on error
 */
int dislmdb_string_to_op_id(const char *str, DISLMDB_op_id *id)
{
    if (!str || !id) {
        return EINVAL;
    }
    
    if (strlen(str) < 32) {
        return EINVAL;
    }
    
    for (int i = 0; i < DISLMDB_OP_ID_SIZE; i++) {
        char byte_str[3] = {str[i*2], str[i*2+1], '\0'};
        unsigned int byte;
        if (sscanf(byte_str, "%02x", &byte) != 1) {
            return EINVAL;
        }
        id->bytes[i] = (uint8_t)byte;
    }
    
    return 0;
}

/**
 * Calculate checksum of data
 *
 * @param data Input data
 * @param size Size of input data
 * @return Checksum value
 */
uint32_t dislmdb_calculate_checksum(const void *data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }
    
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t checksum = 0;
    
    for (size_t i = 0; i < size; i++) {
        checksum = ((checksum << 5) + checksum) + bytes[i]; /* Hash * 33 + byte */
    }
    
    return checksum;
}

/**
 * Get a string describing an error code
 *
 * @param err Error code
 * @return String description of the error
 */
const char *dislmdb_error_string(int err)
{
    /* Check if it's a DisLMDB-specific error */
    if (err >= DISLMDB_ERR_BASE) {
        switch (err) {
            case DISLMDB_NOOP:
                return "No operation performed";
            case DISLMDB_ERR_NETWORK:
                return "Network error";
            case DISLMDB_ERR_CONNECTION:
                return "Connection error";
            case DISLMDB_ERR_NODE_NOT_FOUND:
                return "Node not found";
            case DISLMDB_ERR_NODE_UNREACHABLE:
                return "Node unreachable";
            case DISLMDB_ERR_NO_LEADER:
                return "Leader not available";
            case DISLMDB_ERR_LEADER_CHANGE:
                return "Leader change in progress";
            case DISLMDB_ERR_CONSENSUS_FAILED:
                return "Consensus failed";
            case DISLMDB_ERR_CONSENSUS_TIMEOUT:
                return "Consensus timeout";
            case DISLMDB_ERR_OPERATION_REJECTED:
                return "Operation rejected by consensus";
            case DISLMDB_ERR_VERSION_MISMATCH:
                return "Protocol version mismatch";
            case DISLMDB_ERR_NODE_ID_MISMATCH:
                return "Node ID mismatch";
            case DISLMDB_ERR_AUTH_FAILED:
                return "Authentication failed";
            case DISLMDB_ERR_NOT_AUTHORIZED:
                return "Not authorized for operation";
            case DISLMDB_ERR_NETWORK_PARTITION:
                return "Network partition detected";
            case DISLMDB_ERR_SYNC_FAILED:
                return "Synchronization failed";
            case DISLMDB_ERR_DATA_CORRUPTION:
                return "Data corruption detected";
            case DISLMDB_ERR_CHECKPOINT_FAILED:
                return "Checkpoint failed";
            case DISLMDB_ERR_NODE_EXISTS:
                return "Node already exists";
            case DISLMDB_ERR_MAX_NODES:
                return "Maximum number of nodes reached";
            case DISLMDB_ERR_READ_ONLY:
                return "Read-only node";
            case DISLMDB_ERR_IN_PROGRESS:
                return "Operation in progress";
            case DISLMDB_ERR_INVALID_OPERATION:
                return "Invalid operation";
            case DISLMDB_ERR_OPERATION_EXISTS:
                return "Operation already exists";
            case DISLMDB_ERR_TXN_FAILED:
                return "Distributed transaction failed";
            case DISLMDB_ERR_CONFIG:
                return "Configuration error";
            case DISLMDB_ERR_NOT_IMPLEMENTED:
                return "Feature not implemented";
            case DISLMDB_ERR_OUT_OF_SEQUENCE:
                return "Out of sequence";
            case DISLMDB_ERR_VIEW_MISMATCH:
                return "View number mismatch";
            case DISLMDB_ERR_MESSAGE_VALIDATION:
                return "Message validation failed";
            case DISLMDB_ERR_SIGNATURE_VERIFICATION:
                return "Signature verification failed";
            case DISLMDB_ERR_NOT_INITIALIZED:
                return "Distributed environment not initialized";
            case DISLMDB_ERR_ALREADY_INITIALIZED:
                return "Distributed environment already initialized";
            case DISLMDB_ERR_BYZANTINE:
                return "Byzantine behavior detected";
            case DISLMDB_ERR_TOO_MANY_FAULTS:
                return "Too many faults detected";
            case DISLMDB_ERR_DIGEST_MISMATCH:
                return "Digest mismatch";
            case DISLMDB_ERR_STATE_TRANSFER_REQUIRED:
                return "State transfer required";
            case DISLMDB_ERR_BATCH_FAILED:
                return "Operation batching failed";
            case DISLMDB_ERR_UNREACHABLE_STATE:
                return "Unreachable consensus state";
            default:
                return "Unknown DisLMDB error";
        }
    }
    
    /* If not a DisLMDB error, use the system error string */
    return strerror(err);
}

/**
 * Parse a consensus operation from a byte buffer
 *
 * @param buffer The buffer containing the operation data
 * @param size Size of the buffer
 * @param operation Output: The parsed operation
 * @return 0 on success, non-zero on error
 */
int dislmdb_parse_operation(const uint8_t *buffer, size_t size, DISLMDB_operation *operation)
{
    if (!buffer || !operation || size < sizeof(DISLMDB_op_id) + sizeof(DISLMDB_OP_TYPE) + 
                                 sizeof(uint32_t) + sizeof(uint64_t) + 64 + sizeof(uint32_t) + 32) {
        return EINVAL;
    }
    
    size_t offset = 0;
    
    /* Parse operation ID */
    memcpy(&operation->id, buffer + offset, sizeof(DISLMDB_op_id));
    offset += sizeof(DISLMDB_op_id);
    
    /* Parse operation type */
    memcpy(&operation->type, buffer + offset, sizeof(DISLMDB_OP_TYPE));
    offset += sizeof(DISLMDB_OP_TYPE);
    
    /* Parse sequence number */
    memcpy(&operation->sequence, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    /* Parse timestamp */
    memcpy(&operation->timestamp, buffer + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    /* Parse node ID */
    memcpy(operation->node_id, buffer + offset, 64);
    offset += 64;
    
    /* Parse data size */
    memcpy(&operation->data_size, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    /* Validate data size */
    if (offset + operation->data_size + 32 > size) {
        return EINVAL;
    }
    
    /* Parse data */
    operation->data = (uint8_t *)malloc(operation->data_size);
    if (!operation->data) {
        return ENOMEM;
    }
    memcpy(operation->data, buffer + offset, operation->data_size);
    offset += operation->data_size;
    
    /* Parse digest */
    memcpy(operation->digest, buffer + offset, 32);
    
    /* Verify digest */
    uint8_t calculated_digest[32];
    dislmdb_sha256(operation->data, operation->data_size, calculated_digest);
    
    if (memcmp(calculated_digest, operation->digest, 32) != 0) {
        free(operation->data);
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }
    
    return 0;
}

/**
 * Serialize a consensus operation to a byte buffer
 *
 * @param operation The operation to serialize
 * @param buffer Output: Buffer to store the serialized operation
 * @param size Size of the buffer
 * @param bytes_written Output: Number of bytes written to the buffer
 * @return 0 on success, non-zero on error
 */
int dislmdb_serialize_operation(const DISLMDB_operation *operation, 
                               uint8_t *buffer, size_t size, 
                               size_t *bytes_written)
{
    if (!operation || !buffer || !bytes_written || !operation->data) {
        return EINVAL;
    }
    
    size_t required_size = sizeof(DISLMDB_op_id) + sizeof(DISLMDB_OP_TYPE) + 
                          sizeof(uint32_t) + sizeof(uint64_t) + 64 + 
                          sizeof(uint32_t) + operation->data_size + 32;
    
    if (size < required_size) {
        return ENOMEM;
    }
    
    size_t offset = 0;
    
    /* Serialize operation ID */
    memcpy(buffer + offset, &operation->id, sizeof(DISLMDB_op_id));
    offset += sizeof(DISLMDB_op_id);
    
    /* Serialize operation type */
    memcpy(buffer + offset, &operation->type, sizeof(DISLMDB_OP_TYPE));
    offset += sizeof(DISLMDB_OP_TYPE);
    
    /* Serialize sequence number */
    memcpy(buffer + offset, &operation->sequence, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    /* Serialize timestamp */
    memcpy(buffer + offset, &operation->timestamp, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    /* Serialize node ID */
    memcpy(buffer + offset, operation->node_id, 64);
    offset += 64;
    
    /* Serialize data size */
    memcpy(buffer + offset, &operation->data_size, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    /* Serialize data */
    memcpy(buffer + offset, operation->data, operation->data_size);
    offset += operation->data_size;
    
    /* Serialize digest */
    memcpy(buffer + offset, operation->digest, 32);
    offset += 32;
    
    *bytes_written = offset;
    return 0;
}

/**
 * Free resources associated with an operation
 *
 * @param operation The operation to free
 */
void dislmdb_free_operation(DISLMDB_operation *operation)
{
    if (operation && operation->data) {
        free(operation->data);
        operation->data = NULL;
        operation->data_size = 0;
    }
}

/**
 * Create a new operation
 *
 * @param op_type Operation type
 * @param data Operation data
 * @param data_size Size of operation data
 * @param node_id ID of the node creating the operation
 * @param sequence Sequence number (optional, can be 0)
 * @param operation Output: The created operation
 * @return 0 on success, non-zero on error
 */
int dislmdb_create_operation(DISLMDB_OP_TYPE op_type, 
                           const uint8_t *data, uint32_t data_size,
                           const char *node_id, uint32_t sequence,
                           DISLMDB_operation *operation)
{
    if (!data || data_size == 0 || !node_id || !operation) {
        return EINVAL;
    }
    
    /* Generate a unique operation ID */
    int rc = dislmdb_generate_op_id(&operation->id);
    if (rc != 0) {
        return rc;
    }
    
    /* Set operation properties */
    operation->type = op_type;
    operation->sequence = sequence;
    operation->timestamp = dislmdb_get_time_ms();
    strncpy(operation->node_id, node_id, 63);
    operation->node_id[63] = '\0';
    
    /* Allocate and copy data */
    operation->data = (uint8_t *)malloc(data_size);
    if (!operation->data) {
        return ENOMEM;
    }
    
    memcpy(operation->data, data, data_size);
    operation->data_size = data_size;
    
    /* Calculate data digest */
    dislmdb_sha256(data, data_size, operation->digest);
    
    return 0;
} 