/**
 * @file dislmdb_network.c
 * @brief TCP network layer for DisLMDB with authenticated framed messages
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"

#define NET_MAX_CONNECTIONS DISLMDB_MAX_NODES
#define NET_HEADER_WIRE_SIZE 160
#define NET_HMAC_SIZE DISLMDB_HMAC_SHA256_LENGTH

typedef struct net_connection {
    bool in_use;
    int fd;
    DISLMDB_connection_info info;
} net_connection;

typedef struct network_context {
    DISLMDB_env *env;
    int listen_fd;
    pthread_t thread;
    bool running;
    pthread_mutex_t lock;
    net_connection connections[NET_MAX_CONNECTIONS];
    DISLMDB_network_stats stats;
    uint8_t auth_key[32];
    bool auth_enabled;
    bool encrypt_payloads;
    uint64_t start_ms;
} network_context;

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int pack_header(const DISLMDB_message_header *h, uint8_t out[NET_HEADER_WIRE_SIZE])
{
    memset(out, 0, NET_HEADER_WIRE_SIZE);
    size_t o = 0;
    dislmdb_write_u32(out + o, h->magic); o += 4;
    dislmdb_write_u32(out + o, h->version); o += 4;
    dislmdb_write_u32(out + o, (uint32_t)h->type); o += 4;
    dislmdb_write_u32(out + o, h->payload_size); o += 4;
    dislmdb_write_u64(out + o, h->timestamp); o += 8;
    memcpy(out + o, h->sender_id, 64); o += 64;
    memcpy(out + o, h->target_id, 64); o += 64;
    dislmdb_write_u32(out + o, h->flags); o += 4;
    dislmdb_write_u32(out + o, h->checksum); o += 4;
    (void)o;
    return 0;
}

static int unpack_header(const uint8_t in[NET_HEADER_WIRE_SIZE], DISLMDB_message_header *h)
{
    size_t o = 0;
    h->magic = dislmdb_read_u32(in + o); o += 4;
    h->version = dislmdb_read_u32(in + o); o += 4;
    h->type = (DISLMDB_MESSAGE_TYPE)dislmdb_read_u32(in + o); o += 4;
    h->payload_size = dislmdb_read_u32(in + o); o += 4;
    h->timestamp = dislmdb_read_u64(in + o); o += 8;
    memcpy(h->sender_id, in + o, 64); o += 64;
    memcpy(h->target_id, in + o, 64); o += 64;
    h->flags = dislmdb_read_u32(in + o); o += 4;
    h->checksum = dislmdb_read_u32(in + o); o += 4;
    (void)o;
    return 0;
}

static uint32_t payload_checksum(const uint8_t *payload, uint32_t size)
{
    uint8_t digest[DISLMDB_SHA256_DIGEST_LENGTH];
    if (dislmdb_crypto_sha256(payload ? payload : (const uint8_t *)"", size, digest) != 0) {
        return 0;
    }
    return dislmdb_read_u32(digest);
}

static int find_conn_by_id(network_context *ctx, const char *node_id)
{
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (ctx->connections[i].in_use &&
            strcmp(ctx->connections[i].info.node_id, node_id) == 0) {
            return i;
        }
    }
    return -1;
}

static int alloc_conn(network_context *ctx)
{
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (!ctx->connections[i].in_use) {
            memset(&ctx->connections[i], 0, sizeof(ctx->connections[i]));
            ctx->connections[i].in_use = true;
            ctx->connections[i].fd = -1;
            return i;
        }
    }
    return -1;
}

static void close_conn(network_context *ctx, int idx)
{
    if (idx < 0 || idx >= NET_MAX_CONNECTIONS || !ctx->connections[idx].in_use) {
        return;
    }
    if (ctx->connections[idx].fd >= 0) {
        close(ctx->connections[idx].fd);
    }
    ctx->connections[idx].in_use = false;
    ctx->connections[idx].fd = -1;
    if (ctx->stats.active_connections > 0) {
        ctx->stats.active_connections--;
    }
}

static int write_framed(network_context *ctx, int fd,
                        const DISLMDB_network_message *message)
{
    if (message->header.payload_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    const uint8_t *wire_payload = message->payload;
    uint32_t wire_size = message->header.payload_size;
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    if (ctx->encrypt_payloads && wire_size > 0 && wire_payload) {
        if (dislmdb_aead_seal(ctx->auth_key, wire_payload, wire_size, &sealed, &sealed_len) != 0) {
            return DISLMDB_ERR_AUTH_FAILED;
        }
        wire_payload = sealed;
        wire_size = (uint32_t)sealed_len;
    }

    DISLMDB_message_header hdr = message->header;
    hdr.magic = DISLMDB_MAGIC_NUMBER;
    hdr.version = DISLMDB_PROTOCOL_VERSION;
    hdr.payload_size = wire_size;
    hdr.checksum = payload_checksum(wire_payload, wire_size);
    if (hdr.timestamp == 0) {
        hdr.timestamp = dislmdb_get_time_ms();
    }
    if (ctx->encrypt_payloads) {
        hdr.flags |= 0x1u; /* encrypted */
    }

    uint8_t header_buf[NET_HEADER_WIRE_SIZE];
    pack_header(&hdr, header_buf);

    uint8_t hmac[NET_HMAC_SIZE];
    memset(hmac, 0, sizeof(hmac));
    if (ctx->auth_enabled) {
        size_t total = NET_HEADER_WIRE_SIZE + wire_size;
        uint8_t *tmp = malloc(total);
        if (!tmp) {
            free(sealed);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(tmp, header_buf, NET_HEADER_WIRE_SIZE);
        if (wire_size > 0 && wire_payload) {
            memcpy(tmp + NET_HEADER_WIRE_SIZE, wire_payload, wire_size);
        }
        int rc = dislmdb_crypto_hmac_sha256(ctx->auth_key, sizeof(ctx->auth_key),
                                            tmp, total, hmac);
        free(tmp);
        if (rc != 0) {
            free(sealed);
            return DISLMDB_ERR_AUTH_FAILED;
        }
    }

    if (send_all(fd, header_buf, NET_HEADER_WIRE_SIZE) != 0) {
        free(sealed);
        return DISLMDB_ERR_NETWORK;
    }
    if (wire_size > 0) {
        if (!wire_payload || send_all(fd, wire_payload, wire_size) != 0) {
            free(sealed);
            return DISLMDB_ERR_NETWORK;
        }
    }
    free(sealed);
    if (send_all(fd, hmac, NET_HMAC_SIZE) != 0) {
        return DISLMDB_ERR_NETWORK;
    }
    return DISLMDB_SUCCESS;
}

static int read_framed(network_context *ctx, int fd, DISLMDB_network_message *out)
{
    uint8_t header_buf[NET_HEADER_WIRE_SIZE];
    if (recv_all(fd, header_buf, NET_HEADER_WIRE_SIZE) != 0) {
        return DISLMDB_ERR_NETWORK;
    }

    DISLMDB_message_header hdr;
    unpack_header(header_buf, &hdr);

    if (hdr.magic != DISLMDB_MAGIC_NUMBER) {
        return DISLMDB_ERR_MESSAGE_VALIDATION;
    }
    if (hdr.version != DISLMDB_PROTOCOL_VERSION) {
        return DISLMDB_ERR_VERSION_MISMATCH;
    }
    if (hdr.payload_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    uint8_t *payload = NULL;
    if (hdr.payload_size > 0) {
        payload = malloc(hdr.payload_size);
        if (!payload) {
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        if (recv_all(fd, payload, hdr.payload_size) != 0) {
            free(payload);
            return DISLMDB_ERR_NETWORK;
        }
    }

    uint8_t hmac[NET_HMAC_SIZE];
    if (recv_all(fd, hmac, NET_HMAC_SIZE) != 0) {
        free(payload);
        return DISLMDB_ERR_NETWORK;
    }

    if (ctx->auth_enabled) {
        size_t total = NET_HEADER_WIRE_SIZE + hdr.payload_size;
        uint8_t *tmp = malloc(total);
        if (!tmp) {
            free(payload);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(tmp, header_buf, NET_HEADER_WIRE_SIZE);
        if (hdr.payload_size > 0) {
            memcpy(tmp + NET_HEADER_WIRE_SIZE, payload, hdr.payload_size);
        }
        uint8_t expected[NET_HMAC_SIZE];
        int rc = dislmdb_crypto_hmac_sha256(ctx->auth_key, sizeof(ctx->auth_key),
                                            tmp, total, expected);
        free(tmp);
        if (rc != 0 || !dislmdb_crypto_secure_eq(expected, hmac, NET_HMAC_SIZE)) {
            free(payload);
            return DISLMDB_ERR_SIGNATURE_VERIFICATION;
        }
    }

    uint32_t expect_ck = payload_checksum(payload, hdr.payload_size);
    if (expect_ck != hdr.checksum) {
        free(payload);
        return DISLMDB_ERR_DIGEST_MISMATCH;
    }

    if ((hdr.flags & 0x1u) != 0 && ctx->encrypt_payloads && payload && hdr.payload_size > 0) {
        uint8_t *plain = NULL;
        size_t plain_len = 0;
        if (dislmdb_aead_open(ctx->auth_key, payload, hdr.payload_size, &plain, &plain_len) != 0) {
            free(payload);
            return DISLMDB_ERR_AUTH_FAILED;
        }
        free(payload);
        payload = plain;
        hdr.payload_size = (uint32_t)plain_len;
    }

    out->header = hdr;
    out->payload = payload;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_set_auth_key(DISLMDB_env *env, const uint8_t key[32])
{
    if (!env || !env->network_context || !key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    memcpy(ctx->auth_key, key, 32);
    ctx->auth_enabled = true;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_set_encryption(DISLMDB_env *env, bool enable)
{
    if (!env || !env->network_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    ctx->encrypt_payloads = enable;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

static void dispatch_message(network_context *ctx, const DISLMDB_network_message *msg)
{
    DISLMDB_env *env = ctx->env;
    pthread_mutex_lock(&ctx->lock);
    ctx->stats.total_messages_received++;
    ctx->stats.total_bytes_received += NET_HEADER_WIRE_SIZE + msg->header.payload_size + NET_HMAC_SIZE;
    pthread_mutex_unlock(&ctx->lock);

    if (env->msg_callback) {
        env->msg_callback(msg, env->msg_callback_data);
    }
}

static void *network_thread(void *arg)
{
    network_context *ctx = arg;
    DISLMDB_env *env = ctx->env;

    while (ctx->running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = ctx->listen_fd;
        if (ctx->listen_fd >= 0) {
            FD_SET(ctx->listen_fd, &rfds);
        }

        pthread_mutex_lock(&ctx->lock);
        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            if (ctx->connections[i].in_use && ctx->connections[i].fd >= 0) {
                FD_SET(ctx->connections[i].fd, &rfds);
                if (ctx->connections[i].fd > maxfd) {
                    maxfd = ctx->connections[i].fd;
                }
            }
        }
        pthread_mutex_unlock(&ctx->lock);

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "select failed: %s", strerror(errno));
            break;
        }
        if (ready == 0) {
            continue;
        }

        if (ctx->listen_fd >= 0 && FD_ISSET(ctx->listen_fd, &rfds)) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int cfd = accept(ctx->listen_fd, (struct sockaddr *)&peer, &plen);
            if (cfd >= 0) {
                set_nonblocking(cfd);
                pthread_mutex_lock(&ctx->lock);
                int idx = alloc_conn(ctx);
                if (idx >= 0) {
                    ctx->connections[idx].fd = cfd;
                    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
                    ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
                    inet_ntop(AF_INET, &peer.sin_addr,
                              ctx->connections[idx].info.hostname,
                              sizeof(ctx->connections[idx].info.hostname));
                    ctx->connections[idx].info.port = ntohs(peer.sin_port);
                    ctx->stats.active_connections++;
                    ctx->stats.total_connections++;
                } else {
                    close(cfd);
                    ctx->stats.connection_failures++;
                }
                pthread_mutex_unlock(&ctx->lock);
            }
        }

        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            int fd = -1;
            pthread_mutex_lock(&ctx->lock);
            if (ctx->connections[i].in_use) {
                fd = ctx->connections[i].fd;
            }
            pthread_mutex_unlock(&ctx->lock);
            if (fd < 0 || !FD_ISSET(fd, &rfds)) {
                continue;
            }

            DISLMDB_network_message msg;
            memset(&msg, 0, sizeof(msg));
            int rc = read_framed(ctx, fd, &msg);
            if (rc != DISLMDB_SUCCESS) {
                pthread_mutex_lock(&ctx->lock);
                ctx->stats.total_errors++;
                close_conn(ctx, i);
                pthread_mutex_unlock(&ctx->lock);
                continue;
            }

            pthread_mutex_lock(&ctx->lock);
            if (ctx->connections[i].info.node_id[0] == '\0' && msg.header.sender_id[0] != '\0') {
                strncpy(ctx->connections[i].info.node_id, msg.header.sender_id,
                        sizeof(ctx->connections[i].info.node_id) - 1);
            }
            ctx->connections[i].info.last_activity_time = dislmdb_get_time_ms();
            ctx->connections[i].info.messages_received++;
            pthread_mutex_unlock(&ctx->lock);

            dispatch_message(ctx, &msg);
            free(msg.payload);
        }
    }

    return NULL;
}

int dislmdb_network_init(DISLMDB_env *env, const DISLMDB_network_config *config)
{
    if (!env || !config) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (env->network_context) {
        return DISLMDB_ERR_ALREADY_INITIALIZED;
    }

    network_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    ctx->env = env;
    ctx->listen_fd = -1;
    ctx->start_ms = dislmdb_get_time_ms();
    /*
     * Message auth requires an explicitly shared cluster key on every node.
     * Random per-process keys would make multi-node HMAC verification impossible.
     */
    if (config->enable_message_auth && !config->has_cluster_key) {
        free(ctx);
        return DISLMDB_ERR_AUTH_FAILED;
    }
    ctx->auth_enabled = config->enable_message_auth && config->has_cluster_key;
    ctx->encrypt_payloads = (config->enable_payload_encryption || config->enable_tls)
                            && config->has_cluster_key;
    if (ctx->auth_enabled || ctx->encrypt_payloads) {
        memcpy(ctx->auth_key, config->cluster_key, sizeof(ctx->auth_key));
    } else {
        memset(ctx->auth_key, 0, sizeof(ctx->auth_key));
    }
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx);
        return DISLMDB_ERR_THREAD_ERROR;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        return DISLMDB_ERR_NETWORK;
    }

    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(config->local_port ? config->local_port : DISLMDB_DEFAULT_PORT);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 32) < 0) {
        close(fd);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        return DISLMDB_ERR_NETWORK;
    }
    set_nonblocking(fd);
    ctx->listen_fd = fd;
    ctx->running = true;
    env->network_running = true;
    env->network_context = ctx;

    if (pthread_create(&ctx->thread, NULL, network_thread, ctx) != 0) {
        close(fd);
        env->network_context = NULL;
        env->network_running = false;
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        return DISLMDB_ERR_THREAD_ERROR;
    }

    /* Connect to configured seed nodes (host:port) */
    for (size_t i = 0; i < config->seed_node_count && i < 10; i++) {
        char host[256];
        char portstr[16];
        strncpy(host, config->seed_nodes[i], sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
        char *colon = strrchr(host, ':');
        uint16_t port = DISLMDB_DEFAULT_PORT;
        if (colon) {
            *colon = '\0';
            strncpy(portstr, colon + 1, sizeof(portstr) - 1);
            port = (uint16_t)atoi(portstr);
        }
        DISLMDB_node_addr na;
        memset(&na, 0, sizeof(na));
        strncpy(na.hostname, host, sizeof(na.hostname) - 1);
        na.port = port;
        snprintf(na.node_id, sizeof(na.node_id), "seed-%zu", i);
        (void)dislmdb_network_connect(env, &na, DISLMDB_DEFAULT_NETWORK_TIMEOUT_MS);
    }

    dislmdb_log(env, DISLMDB_LOG_INFO, "NET", "Network listening on port %u",
                (unsigned)(config->local_port ? config->local_port : DISLMDB_DEFAULT_PORT));
    return DISLMDB_SUCCESS;
}

int dislmdb_network_shutdown(DISLMDB_env *env)
{
    if (!env || !env->network_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    ctx->running = false;
    env->network_running = false;
    pthread_join(ctx->thread, NULL);

    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        close_conn(ctx, i);
    }
    if (ctx->listen_fd >= 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    pthread_mutex_unlock(&ctx->lock);

    volatile uint8_t *k = ctx->auth_key;
    for (size_t i = 0; i < sizeof(ctx->auth_key); i++) {
        k[i] = 0;
    }
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    env->network_context = NULL;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_send(DISLMDB_env *env,
                         const DISLMDB_network_message *message,
                         const char *node_id,
                         uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (!env || !env->network_context || !message || !node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    int fd = ctx->connections[idx].fd;
    pthread_mutex_unlock(&ctx->lock);

    DISLMDB_network_message msg = *message;
    if (msg.header.sender_id[0] == '\0') {
        strncpy(msg.header.sender_id, env->local_node_id, sizeof(msg.header.sender_id) - 1);
    }
    strncpy(msg.header.target_id, node_id, sizeof(msg.header.target_id) - 1);

    int rc = write_framed(ctx, fd, &msg);
    if (rc == DISLMDB_SUCCESS) {
        pthread_mutex_lock(&ctx->lock);
        ctx->stats.total_messages_sent++;
        ctx->stats.total_bytes_sent += NET_HEADER_WIRE_SIZE + msg.header.payload_size + NET_HMAC_SIZE;
        if (idx >= 0 && ctx->connections[idx].in_use) {
            ctx->connections[idx].info.messages_sent++;
            ctx->connections[idx].info.bytes_sent +=
                NET_HEADER_WIRE_SIZE + msg.header.payload_size + NET_HMAC_SIZE;
        }
        pthread_mutex_unlock(&ctx->lock);
    }
    return rc;
}

int dislmdb_network_broadcast(DISLMDB_env *env,
                              const DISLMDB_network_message *message,
                              uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (!env || !env->network_context || !message) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    int overall = DISLMDB_SUCCESS;

    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (!ctx->connections[i].in_use || ctx->connections[i].fd < 0) {
            continue;
        }
        int fd = ctx->connections[i].fd;
        char node_id[64];
        strncpy(node_id, ctx->connections[i].info.node_id, sizeof(node_id) - 1);
        node_id[sizeof(node_id) - 1] = '\0';
        pthread_mutex_unlock(&ctx->lock);

        DISLMDB_network_message msg = *message;
        if (msg.header.sender_id[0] == '\0') {
            strncpy(msg.header.sender_id, env->local_node_id, sizeof(msg.header.sender_id) - 1);
        }
        if (node_id[0] != '\0') {
            strncpy(msg.header.target_id, node_id, sizeof(msg.header.target_id) - 1);
        }
        int rc = write_framed(ctx, fd, &msg);
        if (rc != DISLMDB_SUCCESS) {
            overall = rc;
        } else {
            pthread_mutex_lock(&ctx->lock);
            ctx->stats.total_messages_sent++;
            pthread_mutex_unlock(&ctx->lock);
        }
        pthread_mutex_lock(&ctx->lock);
    }
    pthread_mutex_unlock(&ctx->lock);
    return overall;
}

int dislmdb_network_set_message_callback(DISLMDB_env *env,
                                         dislmdb_message_callback callback,
                                         void *user_data)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    env->msg_callback = callback;
    env->msg_callback_data = user_data;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_set_connection_callback(DISLMDB_env *env,
                                            dislmdb_connection_callback callback,
                                            void *user_data)
{
    if (!env) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    env->conn_callback = callback;
    env->conn_callback_data = user_data;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_get_connection_info(DISLMDB_env *env,
                                        const char *node_id,
                                        DISLMDB_connection_info *info)
{
    if (!env || !env->network_context || !node_id || !info) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    *info = ctx->connections[idx].info;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_get_stats(DISLMDB_env *env, DISLMDB_network_stats *stats)
{
    if (!env || !env->network_context || !stats) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    *stats = ctx->stats;
    stats->uptime_ms = dislmdb_get_time_ms() - ctx->start_ms;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_get_connected_nodes(DISLMDB_env *env,
                                        char node_ids[][64],
                                        size_t max_count,
                                        size_t *count)
{
    if (!env || !env->network_context || !node_ids || !count) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    size_t n = 0;
    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < NET_MAX_CONNECTIONS && n < max_count; i++) {
        if (ctx->connections[i].in_use && ctx->connections[i].info.node_id[0] != '\0') {
            strncpy(node_ids[n], ctx->connections[i].info.node_id, 63);
            node_ids[n][63] = '\0';
            n++;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    *count = n;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_connect(DISLMDB_env *env,
                            const DISLMDB_node_addr *node_addr,
                            uint32_t timeout_ms)
{
    (void)timeout_ms;
    if (!env || !env->network_context || !node_addr) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return DISLMDB_ERR_NETWORK;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node_addr->port);
    if (inet_pton(AF_INET, node_addr->hostname, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(node_addr->hostname);
        if (!he || he->h_addrtype != AF_INET) {
            close(fd);
            return DISLMDB_ERR_NODE_UNREACHABLE;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        ctx->stats.connection_failures++;
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_CONNECTION;
    }

    pthread_mutex_lock(&ctx->lock);
    int idx = alloc_conn(ctx);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        close(fd);
        return DISLMDB_ERR_MAX_NODES;
    }
    ctx->connections[idx].fd = fd;
    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
    ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
    strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
            sizeof(ctx->connections[idx].info.node_id) - 1);
    strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
            sizeof(ctx->connections[idx].info.hostname) - 1);
    ctx->connections[idx].info.port = node_addr->port;
    ctx->stats.active_connections++;
    ctx->stats.total_connections++;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_disconnect(DISLMDB_env *env, const char *node_id)
{
    if (!env || !env->network_context || !node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    close_conn(ctx, idx);
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_create_message(DISLMDB_network_message *message,
                                   DISLMDB_MESSAGE_TYPE type,
                                   const uint8_t *payload,
                                   uint32_t payload_size,
                                   const char *target_id)
{
    if (!message) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (payload_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    memset(message, 0, sizeof(*message));
    message->header.magic = DISLMDB_MAGIC_NUMBER;
    message->header.version = DISLMDB_PROTOCOL_VERSION;
    message->header.type = type;
    message->header.payload_size = payload_size;
    message->header.timestamp = dislmdb_get_time_ms();
    if (target_id) {
        strncpy(message->header.target_id, target_id, sizeof(message->header.target_id) - 1);
    }
    if (payload_size > 0) {
        if (!payload) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
        message->payload = malloc(payload_size);
        if (!message->payload) {
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(message->payload, payload, payload_size);
        message->header.checksum = payload_checksum(message->payload, payload_size);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_network_free_message(DISLMDB_network_message *message)
{
    if (!message) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    free(message->payload);
    message->payload = NULL;
    message->header.payload_size = 0;
    return DISLMDB_SUCCESS;
}

int dislmdb_network_send_consensus_message(DISLMDB_env *env,
                                           const DISLMDB_pbft_message *message,
                                           const char *node_id,
                                           uint32_t timeout_ms)
{
    if (!env || !message || !node_id) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_network_message nm;
    int rc = dislmdb_network_create_message(&nm, message->type,
                                            message->data, message->data_size, node_id);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, message->node_id, sizeof(nm.header.sender_id) - 1);
    rc = dislmdb_network_send(env, &nm, node_id, timeout_ms);
    dislmdb_network_free_message(&nm);
    return rc;
}

int dislmdb_network_broadcast_consensus_message(DISLMDB_env *env,
                                                const DISLMDB_pbft_message *message,
                                                uint32_t timeout_ms)
{
    if (!env || !message) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    DISLMDB_network_message nm;
    int rc = dislmdb_network_create_message(&nm, message->type,
                                            message->data, message->data_size, NULL);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    strncpy(nm.header.sender_id, message->node_id, sizeof(nm.header.sender_id) - 1);
    rc = dislmdb_network_broadcast(env, &nm, timeout_ms);
    dislmdb_network_free_message(&nm);
    return rc;
}
