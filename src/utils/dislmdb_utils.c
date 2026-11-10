/**
 * @file dislmdb_utils.c
 * @brief Utility functions for Distributed LMDB
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <uuid/uuid.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"

int dislmdb_generate_uuid(char *id)
{
    if (!id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, id);
    return DISLMDB_SUCCESS;
}

int dislmdb_get_time_string(char *buf, size_t size)
{
    if (!buf || size < 20) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    time_t now = time(NULL);
    struct tm tm_info;
#if defined(_WIN32)
    if (localtime_s(&tm_info, &now) != 0) {
        return errno;
    }
#else
    if (!localtime_r(&now, &tm_info)) {
        return errno ? errno : EIO;
    }
#endif
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_info);
    return DISLMDB_SUCCESS;
}

int dislmdb_hmac_sha256(const void *key, size_t key_len,
                        const void *data, size_t data_len,
                        uint8_t *digest)
{
    return dislmdb_crypto_hmac_sha256(key, key_len, data, data_len, digest);
}

int dislmdb_random_bytes(uint8_t *buf, size_t len)
{
    return dislmdb_crypto_random_bytes(buf, len);
}

int dislmdb_base64_encode(const uint8_t *in, size_t len,
                          char *out, size_t out_len,
                          size_t *out_written)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!in || !out || !out_written) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t needed = 4 * ((len + 2) / 3) + 1;
    if (out_len < needed) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        size_t remain = len - i;
        uint32_t a = in[i];
        uint32_t b = remain > 1 ? in[i + 1] : 0;
        uint32_t c = remain > 2 ? in[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = table[(triple >> 18) & 0x3F];
        out[j++] = table[(triple >> 12) & 0x3F];
        out[j++] = remain > 1 ? table[(triple >> 6) & 0x3F] : '=';
        out[j++] = remain > 2 ? table[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    *out_written = j;
    return DISLMDB_SUCCESS;
}

static int b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int dislmdb_base64_decode(const char *in, size_t len,
                          uint8_t *out, size_t out_len,
                          size_t *out_written)
{
    if (!in || !out || !out_written) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (len % 4 != 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 4) {
        int a = b64_decode_char(in[i]);
        int b = b64_decode_char(in[i + 1]);
        int c = in[i + 2] == '=' ? 0 : b64_decode_char(in[i + 2]);
        int d = in[i + 3] == '=' ? 0 : b64_decode_char(in[i + 3]);
        if (a < 0 || b < 0 || (in[i + 2] != '=' && c < 0) || (in[i + 3] != '=' && d < 0)) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        if (o >= out_len) return DISLMDB_ERR_BUFFER_OVERFLOW;
        out[o++] = (uint8_t)((a << 2) | (b >> 4));
        if (in[i + 2] != '=') {
            if (o >= out_len) return DISLMDB_ERR_BUFFER_OVERFLOW;
            out[o++] = (uint8_t)(((b & 0xF) << 4) | (c >> 2));
        }
        if (in[i + 3] != '=') {
            if (o >= out_len) return DISLMDB_ERR_BUFFER_OVERFLOW;
            out[o++] = (uint8_t)(((c & 0x3) << 6) | d);
        }
    }
    *out_written = o;
    return DISLMDB_SUCCESS;
}

int dislmdb_get_hostname(char *hostname, size_t size)
{
    if (!hostname || size == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (gethostname(hostname, size) != 0) {
        return errno;
    }
    hostname[size - 1] = '\0';
    return DISLMDB_SUCCESS;
}

int dislmdb_get_local_ip(char *ip_addr, size_t size)
{
    if (!ip_addr || size < INET_ADDRSTRLEN) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        return errno;
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        if ((ntohl(sa->sin_addr.s_addr) & 0xff000000u) == 0x7f000000u) {
            continue;
        }
        if (!inet_ntop(AF_INET, &sa->sin_addr, ip_addr, (socklen_t)size)) {
            freeifaddrs(ifaddr);
            return errno;
        }
        freeifaddrs(ifaddr);
        return DISLMDB_SUCCESS;
    }
    freeifaddrs(ifaddr);
    return ENOENT;
}

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
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

int dislmdb_set_nonblocking(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return errno;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return errno;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_op_id_equals(const DISLMDB_op_id *id1, const DISLMDB_op_id *id2)
{
    if (!id1 || !id2) {
        return 0;
    }
    return dislmdb_crypto_secure_eq(id1->bytes, id2->bytes, DISLMDB_OP_ID_SIZE) ? 1 : 0;
}

int dislmdb_generate_op_id(DISLMDB_op_id *id)
{
    if (!id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    return dislmdb_crypto_random_bytes(id->bytes, DISLMDB_OP_ID_SIZE) == 0
               ? DISLMDB_SUCCESS
               : DISLMDB_ERR_MEMORY_ERROR;
}

int dislmdb_op_id_to_string(const DISLMDB_op_id *id, char *str, size_t size)
{
    if (!id || !str || size < 33) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    for (int i = 0; i < DISLMDB_OP_ID_SIZE; i++) {
        snprintf(str + (i * 2), 3, "%02x", id->bytes[i]);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_string_to_op_id(const char *str, DISLMDB_op_id *id)
{
    if (!str || !id || strlen(str) < 32) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    for (int i = 0; i < DISLMDB_OP_ID_SIZE; i++) {
        char byte_str[3] = {str[i * 2], str[i * 2 + 1], '\0'};
        unsigned int byte = 0;
        if (sscanf(byte_str, "%02x", &byte) != 1) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        id->bytes[i] = (uint8_t)byte;
    }
    return DISLMDB_SUCCESS;
}

uint32_t dislmdb_calculate_checksum(const void *data, size_t size)
{
    uint8_t digest[DISLMDB_SHA256_DIGEST_LENGTH];
    if (!data || size == 0) {
        return 0;
    }
    if (dislmdb_crypto_sha256(data, size, digest) != 0) {
        return 0;
    }
    return dislmdb_read_u32(digest);
}

const char *dislmdb_error_string(int err)
{
    if (err == DISLMDB_SUCCESS) {
        return "Success";
    }
    if (err < DISLMDB_ERR_BASE) {
        return strerror(err);
    }
    switch (err) {
        case DISLMDB_NOOP: return "No operation performed";
        case DISLMDB_ERR_NETWORK: return "Network error";
        case DISLMDB_ERR_CONNECTION: return "Connection error";
        case DISLMDB_ERR_NODE_NOT_FOUND: return "Node not found";
        case DISLMDB_ERR_NODE_UNREACHABLE: return "Node unreachable";
        case DISLMDB_ERR_NO_LEADER: return "Leader not available";
        case DISLMDB_ERR_LEADER_CHANGE: return "Leader change in progress";
        case DISLMDB_ERR_CONSENSUS_FAILED: return "Consensus failed";
        case DISLMDB_ERR_CONSENSUS_TIMEOUT: return "Consensus timeout";
        case DISLMDB_ERR_OPERATION_REJECTED: return "Operation rejected by consensus";
        case DISLMDB_ERR_VERSION_MISMATCH: return "Protocol version mismatch";
        case DISLMDB_ERR_NODE_ID_MISMATCH: return "Node ID mismatch";
        case DISLMDB_ERR_AUTH_FAILED: return "Authentication failed";
        case DISLMDB_ERR_NOT_AUTHORIZED: return "Not authorized for operation";
        case DISLMDB_ERR_NETWORK_PARTITION: return "Network partition detected";
        case DISLMDB_ERR_SYNC_FAILED: return "Synchronization failed";
        case DISLMDB_ERR_DATA_CORRUPTION: return "Data corruption detected";
        case DISLMDB_ERR_CHECKPOINT_FAILED: return "Checkpoint failed";
        case DISLMDB_ERR_NODE_EXISTS: return "Node already exists";
        case DISLMDB_ERR_MAX_NODES: return "Maximum number of nodes reached";
        case DISLMDB_ERR_READ_ONLY: return "Read-only node";
        case DISLMDB_ERR_IN_PROGRESS: return "Operation in progress";
        case DISLMDB_ERR_INVALID_OPERATION: return "Invalid operation";
        case DISLMDB_ERR_OPERATION_EXISTS: return "Operation already exists";
        case DISLMDB_ERR_TXN_FAILED: return "Distributed transaction failed";
        case DISLMDB_ERR_CONFIG: return "Configuration error";
        case DISLMDB_ERR_NOT_IMPLEMENTED: return "Feature not implemented";
        case DISLMDB_ERR_OUT_OF_SEQUENCE: return "Out of sequence";
        case DISLMDB_ERR_VIEW_MISMATCH: return "View number mismatch";
        case DISLMDB_ERR_MESSAGE_VALIDATION: return "Message validation failed";
        case DISLMDB_ERR_SIGNATURE_VERIFICATION: return "Signature verification failed";
        case DISLMDB_ERR_NOT_INITIALIZED: return "Distributed environment not initialized";
        case DISLMDB_ERR_ALREADY_INITIALIZED: return "Distributed environment already initialized";
        case DISLMDB_ERR_BYZANTINE: return "Byzantine behavior detected";
        case DISLMDB_ERR_TOO_MANY_FAULTS: return "Too many faults detected";
        case DISLMDB_ERR_DIGEST_MISMATCH: return "Digest mismatch";
        case DISLMDB_ERR_STATE_TRANSFER_REQUIRED: return "State transfer required";
        case DISLMDB_ERR_BATCH_FAILED: return "Operation batching failed";
        case DISLMDB_ERR_UNREACHABLE_STATE: return "Unreachable consensus state";
        case DISLMDB_ERR_INVALID_PARAMETER: return "Invalid parameter";
        case DISLMDB_ERR_MEMORY_ERROR: return "Memory allocation error";
        case DISLMDB_ERR_THREAD_ERROR: return "Thread error";
        case DISLMDB_ERR_BUFFER_OVERFLOW: return "Buffer overflow";
        default: return "Unknown DisLMDB error";
    }
}

int dislmdb_parse_operation(const uint8_t *buffer, size_t size, DISLMDB_operation *operation)
{
    if (!buffer || !operation) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    const size_t min_size = DISLMDB_OP_ID_SIZE + 4 + 4 + 8 + 64 + 4 + 32;
    if (size < min_size) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    size_t offset = 0;
    memcpy(&operation->id, buffer + offset, DISLMDB_OP_ID_SIZE);
    offset += DISLMDB_OP_ID_SIZE;
    operation->type = (DISLMDB_OP_TYPE)dislmdb_read_u32(buffer + offset);
    offset += 4;
    operation->sequence = dislmdb_read_u32(buffer + offset);
    offset += 4;
    operation->timestamp = dislmdb_read_u64(buffer + offset);
    offset += 8;
    memcpy(operation->node_id, buffer + offset, 64);
    operation->node_id[63] = '\0';
    offset += 64;
    operation->data_size = dislmdb_read_u32(buffer + offset);
    offset += 4;

    if (offset + operation->data_size + 32 > size) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    if (operation->data_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    operation->data = malloc(operation->data_size ? operation->data_size : 1);
    if (!operation->data) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    if (operation->data_size > 0) {
        memcpy(operation->data, buffer + offset, operation->data_size);
    }
    offset += operation->data_size;
    memcpy(operation->digest, buffer + offset, 32);

    uint8_t calculated[32];
    if (dislmdb_crypto_sha256(operation->data, operation->data_size, calculated) != 0 ||
        !dislmdb_crypto_secure_eq(calculated, operation->digest, 32)) {
        free(operation->data);
        operation->data = NULL;
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_serialize_operation(const DISLMDB_operation *operation,
                                uint8_t *buffer, size_t size,
                                size_t *bytes_written)
{
    if (!operation || !buffer || !bytes_written || (!operation->data && operation->data_size)) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    size_t required = DISLMDB_OP_ID_SIZE + 4 + 4 + 8 + 64 + 4 + operation->data_size + 32;
    if (size < required) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    size_t offset = 0;
    memcpy(buffer + offset, &operation->id, DISLMDB_OP_ID_SIZE);
    offset += DISLMDB_OP_ID_SIZE;
    dislmdb_write_u32(buffer + offset, (uint32_t)operation->type);
    offset += 4;
    dislmdb_write_u32(buffer + offset, operation->sequence);
    offset += 4;
    dislmdb_write_u64(buffer + offset, operation->timestamp);
    offset += 8;
    memcpy(buffer + offset, operation->node_id, 64);
    offset += 64;
    dislmdb_write_u32(buffer + offset, operation->data_size);
    offset += 4;
    if (operation->data_size > 0) {
        memcpy(buffer + offset, operation->data, operation->data_size);
        offset += operation->data_size;
    }
    memcpy(buffer + offset, operation->digest, 32);
    offset += 32;
    *bytes_written = offset;
    return DISLMDB_SUCCESS;
}

void dislmdb_free_operation(DISLMDB_operation *operation)
{
    if (operation && operation->data) {
        free(operation->data);
        operation->data = NULL;
        operation->data_size = 0;
    }
}

int dislmdb_create_operation(DISLMDB_OP_TYPE op_type,
                             const uint8_t *data, uint32_t data_size,
                             const char *node_id, uint32_t sequence,
                             DISLMDB_operation *operation)
{
    if (!data || data_size == 0 || !node_id || !operation) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    int rc = dislmdb_generate_op_id(&operation->id);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    operation->type = op_type;
    operation->sequence = sequence;
    operation->timestamp = dislmdb_get_time_ms();
    strncpy(operation->node_id, node_id, sizeof(operation->node_id) - 1);
    operation->node_id[sizeof(operation->node_id) - 1] = '\0';
    operation->data = malloc(data_size);
    if (!operation->data) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    memcpy(operation->data, data, data_size);
    operation->data_size = data_size;
    return dislmdb_crypto_sha256(data, data_size, operation->digest);
}
