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
#include "dislmdb_mtls.h"

#define NET_MAX_CONNECTIONS DISLMDB_MAX_NODES
#define NET_HEADER_WIRE_SIZE 160
#define NET_HMAC_SIZE DISLMDB_HMAC_SHA256_LENGTH

typedef struct net_connection {
    bool in_use;
    bool outbound;          /* true if we dialed; eligible for reconnect */
    int fd;
    uint16_t listen_port;   /* peer listen port (for reconnect / HELLO) */
    dislmdb_mtls_session *tls; /* non-NULL when enable_mtls wrapped this TCP fd */
    DISLMDB_connection_info info;
} net_connection;

typedef struct network_context {
    DISLMDB_env *env;
    int listen_fd;
    int udp_fd;                 /* datagram socket when transport includes UDP */
    DISLMDB_TRANSPORT transport;
    pthread_t thread;
    bool running;
    pthread_mutex_t lock;
    net_connection connections[NET_MAX_CONNECTIONS];
    DISLMDB_network_stats stats;
    uint8_t auth_key[32];
    bool auth_enabled;
    bool encrypt_payloads;
    bool mtls_enabled;
    dislmdb_mtls_ctx *mtls;
    uint64_t start_ms;
    uint64_t last_heartbeat_ms;
} network_context;

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void prepare_tcp_fd(int fd)
{
#if defined(SO_NOSIGPIPE)
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    (void)fd;
#endif
}

static int send_all_raw(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < len) {
#if defined(MSG_NOSIGNAL)
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
#else
        ssize_t n = send(fd, p + sent, len - sent, 0);
#endif
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Wait until writable rather than dropping the peer */
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(fd, &wfds);
                struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
                if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
                    return -1;
                }
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

static int recv_all_raw(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(fd, &rfds);
                struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
                if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
                    return -1;
                }
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

static dislmdb_mtls_session *tls_for_fd(network_context *ctx, int fd)
{
    if (!ctx || !ctx->mtls_enabled || fd < 0) {
        return NULL;
    }
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (ctx->connections[i].in_use && ctx->connections[i].fd == fd) {
            return ctx->connections[i].tls;
        }
    }
    return NULL;
}

static int send_all(network_context *ctx, int fd, const void *buf, size_t len)
{
    dislmdb_mtls_session *tls = tls_for_fd(ctx, fd);
    if (tls) {
        return dislmdb_mtls_send(tls, buf, len);
    }
    return send_all_raw(fd, buf, len);
}

static int recv_all(network_context *ctx, int fd, void *buf, size_t len)
{
    dislmdb_mtls_session *tls = tls_for_fd(ctx, fd);
    if (tls) {
        uint8_t *p = buf;
        size_t got = 0;
        while (got < len) {
            size_t n = 0;
            if (dislmdb_mtls_recv(tls, p + got, len - got, &n) != 0 || n == 0) {
                return -1;
            }
            got += n;
        }
        return 0;
    }
    return recv_all_raw(fd, buf, len);
}

static int mtls_wrap_client(network_context *ctx, int fd, const char *host,
                            dislmdb_mtls_session **out)
{
    if (!ctx->mtls_enabled || !ctx->mtls) {
        *out = NULL;
        return 0;
    }
    return dislmdb_mtls_client_handshake(ctx->mtls, fd, host, out);
}

static int mtls_wrap_server(network_context *ctx, int fd, dislmdb_mtls_session **out)
{
    if (!ctx->mtls_enabled || !ctx->mtls) {
        *out = NULL;
        return 0;
    }
    return dislmdb_mtls_server_handshake(ctx->mtls, fd, out);
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

bool dislmdb_network_is_signalling(DISLMDB_MESSAGE_TYPE type)
{
    switch (type) {
    case DISLMDB_MESSAGE_HEARTBEAT:
    case DISLMDB_MESSAGE_JOIN:
    case DISLMDB_MESSAGE_LEAVE:
    case DISLMDB_MESSAGE_ELECTION:
        return true;
    default:
        return false;
    }
}

static int write_framed(network_context *ctx, int fd,
                        const DISLMDB_network_message *message);

/** TCP stream fd for a slot, or -1 if the slot is UDP-only / closed. */
static int conn_tcp_fd(network_context *ctx, int idx)
{
    int fd = ctx->connections[idx].fd;
    if (fd >= 0 && fd != ctx->udp_fd) {
        return fd;
    }
    return -1;
}

static bool conn_can_udp(network_context *ctx, int idx)
{
    if (ctx->udp_fd < 0 || !ctx->connections[idx].in_use) {
        return false;
    }
    if (ctx->connections[idx].info.hostname[0] == '\0') {
        return false;
    }
    return ctx->connections[idx].listen_port != 0 ||
           ctx->connections[idx].info.port != 0;
}

/**
 * Choose wire fd for a peer slot under the current transport mode.
 * BOTH: signalling → UDP (fallback TCP); data → TCP (fallback UDP).
 */
static int pick_send_fd(network_context *ctx, int idx, DISLMDB_MESSAGE_TYPE type)
{
    if (idx < 0 || idx >= NET_MAX_CONNECTIONS || !ctx->connections[idx].in_use) {
        return -1;
    }
    int tcp = conn_tcp_fd(ctx, idx);
    int udp = conn_can_udp(ctx, idx) ? ctx->udp_fd : -1;
    int raw = ctx->connections[idx].fd;

    if (ctx->transport == DISLMDB_TRANSPORT_TCP) {
        return tcp;
    }
    if (ctx->transport == DISLMDB_TRANSPORT_UDP) {
        if (udp >= 0) {
            return udp;
        }
        return (raw == ctx->udp_fd) ? raw : -1;
    }

    /* DISLMDB_TRANSPORT_BOTH */
    if (dislmdb_network_is_signalling(type)) {
        if (udp >= 0) {
            return udp;
        }
        if (tcp >= 0) {
            return tcp;
        }
        return (raw == ctx->udp_fd) ? raw : -1;
    }
    if (tcp >= 0) {
        return tcp;
    }
    if (udp >= 0) {
        return udp;
    }
    return -1;
}

/** Alternate medium for BOTH-mode fallback after a failed primary send. */
static int pick_fallback_fd(network_context *ctx, int idx, int primary)
{
    if (ctx->transport != DISLMDB_TRANSPORT_BOTH || primary < 0) {
        return -1;
    }
    int tcp = conn_tcp_fd(ctx, idx);
    int udp = conn_can_udp(ctx, idx) ? ctx->udp_fd : -1;
    if (primary == ctx->udp_fd) {
        return tcp;
    }
    if (primary == tcp) {
        return udp;
    }
    return -1;
}

static int write_framed_adapt(network_context *ctx, int idx,
                              const DISLMDB_network_message *message,
                              int *used_fd_out)
{
    int primary = pick_send_fd(ctx, idx, message->header.type);
    if (used_fd_out) {
        *used_fd_out = primary;
    }
    if (primary < 0) {
        return DISLMDB_ERR_NETWORK;
    }
    int rc = write_framed(ctx, primary, message);
    if (rc == DISLMDB_SUCCESS) {
        return rc;
    }
    int alt = pick_fallback_fd(ctx, idx, primary);
    if (alt < 0 || alt == primary) {
        return rc;
    }
    if (used_fd_out) {
        *used_fd_out = alt;
    }
    return write_framed(ctx, alt, message);
}

static int alloc_conn(network_context *ctx)
{
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (!ctx->connections[i].in_use) {
            memset(&ctx->connections[i], 0, sizeof(ctx->connections[i]));
            ctx->connections[i].in_use = true;
            ctx->connections[i].outbound = false;
            ctx->connections[i].listen_port = 0;
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
    if (ctx->connections[idx].tls) {
        dislmdb_mtls_session_close(ctx->connections[idx].tls);
        ctx->connections[idx].tls = NULL;
        ctx->connections[idx].fd = -1;
    } else if (ctx->connections[idx].fd >= 0 &&
               ctx->connections[idx].fd != ctx->udp_fd) {
        close(ctx->connections[idx].fd);
        ctx->connections[idx].fd = -1;
    } else {
        ctx->connections[idx].fd = -1;
    }
    /* Keep outbound slots for heartbeat-driven reconnect */
    if (ctx->connections[idx].outbound &&
        ctx->connections[idx].info.hostname[0] != '\0' &&
        ctx->connections[idx].listen_port != 0) {
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
        if (ctx->stats.active_connections > 0) {
            ctx->stats.active_connections--;
        }
        return;
    }
    ctx->connections[idx].in_use = false;
    if (ctx->stats.active_connections > 0) {
        ctx->stats.active_connections--;
    }
}

static int try_reconnect(network_context *ctx, int idx)
{
    /* Caller may hold ctx->lock; do not block on mTLS handshake under the lock.
     * TCP connect is short; handshake runs after unlock in send_heartbeats. */
    net_connection *c = &ctx->connections[idx];
    if (!c->in_use || !c->outbound || c->fd >= 0) {
        return -1;
    }
    if (c->info.hostname[0] == '\0' || c->listen_port == 0) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    prepare_tcp_fd(fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(c->listen_port);
    if (inet_pton(AF_INET, c->info.hostname, &addr.sin_addr) != 1) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(c->info.hostname, NULL, &hints, &res) != 0 || !res) {
            close(fd);
            return -1;
        }
        memcpy(&addr.sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
               sizeof(addr.sin_addr));
        freeaddrinfo(res);
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        ctx->stats.connection_failures++;
        return -1;
    }
    /* Stash fd; mark connecting so we finish mTLS outside the lock */
    c->fd = fd;
    c->tls = NULL;
    c->info.state = DISLMDB_CONNECTION_CONNECTING;
    return 1; /* needs mtls finish */
}

/** Finish CONNECTING → CONNECTED. Must NOT be called with ctx->lock held when mTLS is on. */
static int finish_reconnect_mtls(network_context *ctx, int idx)
{
    int fd = -1;
    char host[256];
    bool need_mtls = false;

    pthread_mutex_lock(&ctx->lock);
    net_connection *c = &ctx->connections[idx];
    if (!c->in_use || c->fd < 0 || c->info.state != DISLMDB_CONNECTION_CONNECTING) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    if (!ctx->mtls_enabled) {
        c->info.state = DISLMDB_CONNECTION_CONNECTED;
        c->info.connect_time = dislmdb_get_time_ms();
        c->info.last_activity_time = c->info.connect_time;
        ctx->stats.active_connections++;
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }
    fd = c->fd;
    strncpy(host, c->info.hostname, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    c->fd = -1; /* lend to handshake */
    need_mtls = true;
    pthread_mutex_unlock(&ctx->lock);

    if (!need_mtls) {
        return 0;
    }
    dislmdb_mtls_session *tls = NULL;
    if (mtls_wrap_client(ctx, fd, host, &tls) != 0) {
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        if (ctx->connections[idx].in_use) {
            ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
            ctx->stats.connection_failures++;
        }
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    pthread_mutex_lock(&ctx->lock);
    if (!ctx->connections[idx].in_use) {
        pthread_mutex_unlock(&ctx->lock);
        dislmdb_mtls_session_close(tls);
        return -1;
    }
    ctx->connections[idx].fd = fd;
    ctx->connections[idx].tls = tls;
    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
    ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
    ctx->connections[idx].info.last_activity_time = ctx->connections[idx].info.connect_time;
    ctx->stats.active_connections++;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

static void send_heartbeats(network_context *ctx)
{
    DISLMDB_env *env = ctx->env;
    uint32_t interval = env->config.consensus.heartbeat_interval_ms;
    if (interval == 0) {
        interval = 1000;
    }
    uint64_t now = dislmdb_get_time_ms();
    pthread_mutex_lock(&ctx->lock);
    if (now - ctx->last_heartbeat_ms < interval) {
        pthread_mutex_unlock(&ctx->lock);
        return;
    }
    ctx->last_heartbeat_ms = now;

    int send_idx[NET_MAX_CONNECTIONS];
    char reconnect_labels[NET_MAX_CONNECTIONS][64];
    int pending_mtls[NET_MAX_CONNECTIONS];
    int n_send = 0;
    int n_hello = 0;
    int n_pending = 0;
    uint64_t stale_limit = (uint64_t)interval * 5u;

    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (!ctx->connections[i].in_use) {
            continue;
        }
        if (ctx->connections[i].fd < 0 && !conn_can_udp(ctx, i)) {
            if (ctx->connections[i].outbound) {
                int tr = try_reconnect(ctx, i);
                if (tr == 1 && n_pending < NET_MAX_CONNECTIONS) {
                    pending_mtls[n_pending++] = i;
                } else if (tr == 0) {
                    strncpy(reconnect_labels[n_hello], ctx->connections[i].info.node_id,
                            sizeof(reconnect_labels[n_hello]) - 1);
                    reconnect_labels[n_hello][sizeof(reconnect_labels[n_hello]) - 1] = '\0';
                    n_hello++;
                }
            }
            continue;
        }
        if (ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTING) {
            continue; /* finish_reconnect_mtls handles these */
        }
        if (ctx->connections[i].outbound &&
            ctx->connections[i].info.last_activity_time > 0 &&
            now - ctx->connections[i].info.last_activity_time > stale_limit) {
            close_conn(ctx, i);
            continue;
        }
        if (n_send < NET_MAX_CONNECTIONS) {
            send_idx[n_send++] = i;
        }
    }
    pthread_mutex_unlock(&ctx->lock);

    /* Complete mTLS outside the connection lock to avoid accept/handshake deadlock */
    for (int i = 0; i < n_pending; i++) {
        if (finish_reconnect_mtls(ctx, pending_mtls[i]) == 0) {
            pthread_mutex_lock(&ctx->lock);
            strncpy(reconnect_labels[n_hello],
                    ctx->connections[pending_mtls[i]].info.node_id,
                    sizeof(reconnect_labels[n_hello]) - 1);
            reconnect_labels[n_hello][sizeof(reconnect_labels[n_hello]) - 1] = '\0';
            n_hello++;
            pthread_mutex_unlock(&ctx->lock);
        }
    }

    if (n_send > 0) {
        DISLMDB_network_message hb;
        if (dislmdb_network_create_message(&hb, DISLMDB_MESSAGE_HEARTBEAT, NULL, 0, NULL)
            == DISLMDB_SUCCESS) {
            strncpy(hb.header.sender_id, env->local_node_id, sizeof(hb.header.sender_id) - 1);
            for (int i = 0; i < n_send; i++) {
                char tid[64];
                pthread_mutex_lock(&ctx->lock);
                strncpy(tid, ctx->connections[send_idx[i]].info.node_id, sizeof(tid) - 1);
                tid[sizeof(tid) - 1] = '\0';
                pthread_mutex_unlock(&ctx->lock);
                if (tid[0] != '\0') {
                    strncpy(hb.header.target_id, tid, sizeof(hb.header.target_id) - 1);
                } else {
                    hb.header.target_id[0] = '\0';
                }
                (void)write_framed_adapt(ctx, send_idx[i], &hb, NULL);
            }
            dislmdb_network_free_message(&hb);
        }
    }

    extern int dislmdb_pbft_send_hello(DISLMDB_env *e, const char *t);
    for (int i = 0; i < n_hello; i++) {
        (void)dislmdb_pbft_send_hello(env, reconnect_labels[i]);
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

    /* UDP path: assemble one datagram (WebTransport/QUIC-oriented substrate) */
    if (ctx->udp_fd >= 0 && fd == ctx->udp_fd) {
        size_t total = NET_HEADER_WIRE_SIZE + wire_size + NET_HMAC_SIZE;
        if (total > 65507) {
            free(sealed);
            return DISLMDB_ERR_BUFFER_OVERFLOW;
        }
        uint8_t *dgram = malloc(total);
        if (!dgram) {
            free(sealed);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        memcpy(dgram, header_buf, NET_HEADER_WIRE_SIZE);
        if (wire_size > 0 && wire_payload) {
            memcpy(dgram + NET_HEADER_WIRE_SIZE, wire_payload, wire_size);
        }
        memcpy(dgram + NET_HEADER_WIRE_SIZE + wire_size, hmac, NET_HMAC_SIZE);
        free(sealed);
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        bool found = false;
        pthread_mutex_lock(&ctx->lock);
        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            if (!ctx->connections[i].in_use ||
                ctx->connections[i].info.hostname[0] == '\0') {
                continue;
            }
            if (message->header.target_id[0] != '\0' &&
                strncmp(ctx->connections[i].info.node_id, message->header.target_id, 63) != 0) {
                continue;
            }
            to.sin_port = htons(ctx->connections[i].listen_port
                                    ? ctx->connections[i].listen_port
                                    : ctx->connections[i].info.port);
            if (inet_pton(AF_INET, ctx->connections[i].info.hostname, &to.sin_addr) == 1) {
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&ctx->lock);
        if (!found) {
            free(dgram);
            return DISLMDB_ERR_NODE_NOT_FOUND;
        }
        ssize_t sn = sendto(fd, dgram, total, 0, (struct sockaddr *)&to, sizeof(to));
        free(dgram);
        return sn == (ssize_t)total ? DISLMDB_SUCCESS : DISLMDB_ERR_NETWORK;
    }

    if (send_all(ctx, fd, header_buf, NET_HEADER_WIRE_SIZE) != 0) {
        free(sealed);
        return DISLMDB_ERR_NETWORK;
    }
    if (wire_size > 0) {
        if (!wire_payload || send_all(ctx, fd, wire_payload, wire_size) != 0) {
            free(sealed);
            return DISLMDB_ERR_NETWORK;
        }
    }
    free(sealed);
    if (send_all(ctx, fd, hmac, NET_HMAC_SIZE) != 0) {
        return DISLMDB_ERR_NETWORK;
    }
    return DISLMDB_SUCCESS;
}

static int read_framed(network_context *ctx, int fd, DISLMDB_network_message *out)
{
    uint8_t header_buf[NET_HEADER_WIRE_SIZE];
    if (recv_all(ctx, fd, header_buf, NET_HEADER_WIRE_SIZE) != 0) {
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
        if (recv_all(ctx, fd, payload, hdr.payload_size) != 0) {
            free(payload);
            return DISLMDB_ERR_NETWORK;
        }
    }

    uint8_t hmac[NET_HMAC_SIZE];
    if (recv_all(ctx, fd, hmac, NET_HMAC_SIZE) != 0) {
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
        int maxfd = -1;
        if (ctx->listen_fd >= 0) {
            FD_SET(ctx->listen_fd, &rfds);
            maxfd = ctx->listen_fd;
        }

        pthread_mutex_lock(&ctx->lock);
        if (ctx->udp_fd >= 0) {
            FD_SET(ctx->udp_fd, &rfds);
            if (ctx->udp_fd > maxfd) {
                maxfd = ctx->udp_fd;
            }
        }
        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            /* Shared UDP socket is polled once above; skip per-conn UDP fds */
            if (ctx->connections[i].in_use && ctx->connections[i].fd >= 0 &&
                ctx->connections[i].fd != ctx->udp_fd) {
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
            send_heartbeats(ctx);
            continue;
        }

        /* Opportunistic heartbeat even when traffic is present */
        send_heartbeats(ctx);

        if (ctx->udp_fd >= 0 && FD_ISSET(ctx->udp_fd, &rfds)) {
            uint8_t dgram[65536];
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            ssize_t n = recvfrom(ctx->udp_fd, dgram, sizeof(dgram), 0,
                                 (struct sockaddr *)&peer, &plen);
            if (n > (ssize_t)(NET_HEADER_WIRE_SIZE + NET_HMAC_SIZE)) {
                /* In-memory framed parse from datagram */
                DISLMDB_network_message msg;
                memset(&msg, 0, sizeof(msg));
                /* Temporarily treat as a contiguous frame via a pipe-free path:
                 * unpack header + payload + HMAC using the same layout as write_framed. */
                uint8_t hdr[NET_HEADER_WIRE_SIZE];
                memcpy(hdr, dgram, NET_HEADER_WIRE_SIZE);
                unpack_header(hdr, &msg.header);
                uint32_t psz = msg.header.payload_size;
                size_t need = NET_HEADER_WIRE_SIZE + psz + NET_HMAC_SIZE;
                if (psz <= DISLMDB_MAX_MESSAGE_SIZE && (size_t)n >= need) {
                    if (psz > 0) {
                        msg.payload = malloc(psz);
                        if (msg.payload) {
                            memcpy(msg.payload, dgram + NET_HEADER_WIRE_SIZE, psz);
                        }
                    }
                    bool auth_ok = true;
                    if (ctx->auth_enabled) {
                        uint8_t expect[NET_HMAC_SIZE];
                        memcpy(expect, dgram + NET_HEADER_WIRE_SIZE + psz, NET_HMAC_SIZE);
                        uint8_t mac[NET_HMAC_SIZE];
                        if (dislmdb_crypto_hmac_sha256(ctx->auth_key, 32, dgram,
                                                       NET_HEADER_WIRE_SIZE + psz, mac) != 0 ||
                            !dislmdb_crypto_secure_eq(mac, expect, NET_HMAC_SIZE)) {
                            auth_ok = false;
                        }
                    }
                    if (auth_ok) {
                        char host[64];
                        uint16_t sport = ntohs(peer.sin_port);
                        inet_ntop(AF_INET, &peer.sin_addr, host, sizeof(host));
                        pthread_mutex_lock(&ctx->lock);
                        int idx = -1;
                        /* Merge onto an existing peer (TCP or UDP) — avoid dual slots. */
                        if (msg.header.sender_id[0] != '\0') {
                            idx = find_conn_by_id(ctx, msg.header.sender_id);
                        }
                        if (idx < 0) {
                            for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
                                if (!ctx->connections[i].in_use) {
                                    continue;
                                }
                                if (strcmp(ctx->connections[i].info.hostname, host) != 0) {
                                    continue;
                                }
                                uint16_t lp = ctx->connections[i].listen_port
                                                  ? ctx->connections[i].listen_port
                                                  : ctx->connections[i].info.port;
                                if (lp == sport || ctx->connections[i].info.port == sport) {
                                    idx = i;
                                    break;
                                }
                                /* BOTH: hostname match is enough once TCP exists */
                                if (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
                                    conn_tcp_fd(ctx, i) >= 0) {
                                    idx = i;
                                    break;
                                }
                            }
                        }
                        if (idx < 0) {
                            idx = alloc_conn(ctx);
                            if (idx >= 0) {
                                ctx->connections[idx].fd = ctx->udp_fd;
                                ctx->connections[idx].outbound = false;
                                ctx->connections[idx].listen_port = sport;
                                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
                                strncpy(ctx->connections[idx].info.hostname, host,
                                        sizeof(ctx->connections[idx].info.hostname) - 1);
                                ctx->connections[idx].info.port = sport;
                                ctx->stats.active_connections++;
                                ctx->stats.total_connections++;
                            }
                        } else {
                            /* Refresh listen port from datagram source when known */
                            if (sport != 0 && ctx->connections[idx].listen_port == 0) {
                                ctx->connections[idx].listen_port = sport;
                            }
                            if (ctx->connections[idx].info.hostname[0] == '\0') {
                                strncpy(ctx->connections[idx].info.hostname, host,
                                        sizeof(ctx->connections[idx].info.hostname) - 1);
                            }
                        }
                        if (idx >= 0 && msg.header.sender_id[0] != '\0') {
                            char *cid = ctx->connections[idx].info.node_id;
                            if (cid[0] == '\0' || strncmp(cid, "seed-", 5) == 0) {
                                strncpy(cid, msg.header.sender_id, 63);
                            }
                            ctx->connections[idx].info.last_activity_time = dislmdb_get_time_ms();
                            ctx->connections[idx].info.messages_received++;
                        }
                        pthread_mutex_unlock(&ctx->lock);
                        if (msg.header.type != DISLMDB_MESSAGE_HEARTBEAT) {
                            dispatch_message(ctx, &msg);
                        }
                    }
                    free(msg.payload);
                }
            }
        }

        if (ctx->listen_fd >= 0 && FD_ISSET(ctx->listen_fd, &rfds)) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int cfd = accept(ctx->listen_fd, (struct sockaddr *)&peer, &plen);
            if (cfd >= 0) {
                prepare_tcp_fd(cfd);
                /* Keep accepted sockets blocking: select gates readiness,
                 * but frames may arrive in multiple segments. */
                dislmdb_mtls_session *tls = NULL;
                if (mtls_wrap_server(ctx, cfd, &tls) != 0) {
                    close(cfd);
                    pthread_mutex_lock(&ctx->lock);
                    ctx->stats.connection_failures++;
                    pthread_mutex_unlock(&ctx->lock);
                } else {
                    char hostbuf[64];
                    inet_ntop(AF_INET, &peer.sin_addr, hostbuf, sizeof(hostbuf));
                    pthread_mutex_lock(&ctx->lock);
                    /* Prefer upgrading an existing UDP-only slot for this host. */
                    int idx = -1;
                    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
                        if (!ctx->connections[i].in_use) {
                            continue;
                        }
                        if (strcmp(ctx->connections[i].info.hostname, hostbuf) != 0) {
                            continue;
                        }
                        if (ctx->connections[i].fd == ctx->udp_fd ||
                            ctx->connections[i].fd < 0) {
                            idx = i;
                            break;
                        }
                    }
                    if (idx < 0) {
                        idx = alloc_conn(ctx);
                        if (idx >= 0) {
                            ctx->stats.active_connections++;
                            ctx->stats.total_connections++;
                        }
                    }
                    if (idx >= 0) {
                        ctx->connections[idx].fd = cfd;
                        ctx->connections[idx].tls = tls;
                        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
                        ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
                        strncpy(ctx->connections[idx].info.hostname, hostbuf,
                                sizeof(ctx->connections[idx].info.hostname) - 1);
                        /* Ephemeral TCP source port — keep listen_port if already known */
                        ctx->connections[idx].info.port = ntohs(peer.sin_port);
                    } else {
                        if (tls) {
                            dislmdb_mtls_session_close(tls);
                        } else {
                            close(cfd);
                        }
                        ctx->stats.connection_failures++;
                    }
                    pthread_mutex_unlock(&ctx->lock);
                }
            }
        }

        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            int fd = -1;
            pthread_mutex_lock(&ctx->lock);
            if (ctx->connections[i].in_use) {
                fd = ctx->connections[i].fd;
            }
            pthread_mutex_unlock(&ctx->lock);
            /* Shared UDP socket is drained above — never stream-read it. */
            if (fd < 0 || fd == ctx->udp_fd || !FD_ISSET(fd, &rfds)) {
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
            if (msg.header.sender_id[0] != '\0') {
                char *cid = ctx->connections[i].info.node_id;
                if (cid[0] == '\0' || strncmp(cid, "seed-", 5) == 0) {
                    strncpy(cid, msg.header.sender_id, sizeof(ctx->connections[i].info.node_id) - 1);
                    cid[sizeof(ctx->connections[i].info.node_id) - 1] = '\0';
                }
            }
            ctx->connections[i].info.last_activity_time = dislmdb_get_time_ms();
            ctx->connections[i].info.messages_received++;
            pthread_mutex_unlock(&ctx->lock);

            /* Heartbeats only refresh activity; no consensus dispatch */
            if (msg.header.type != DISLMDB_MESSAGE_HEARTBEAT) {
                dispatch_message(ctx, &msg);
            }
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
    ctx->udp_fd = -1;
    ctx->transport = config->transport;
    ctx->start_ms = dislmdb_get_time_ms();
    /*
     * Auth/encryption activate once a cluster key is installed. Preferring
     * enable_message_auth without a key is allowed for solo bring-up; multi-node
     * open is rejected earlier in dislmdb_env_open when no key is configured.
     */
    ctx->auth_enabled = config->enable_message_auth && config->has_cluster_key;
    ctx->encrypt_payloads = (config->enable_payload_encryption || config->enable_tls)
                            && config->has_cluster_key;
    if (ctx->auth_enabled || ctx->encrypt_payloads) {
        memcpy(ctx->auth_key, config->cluster_key, sizeof(ctx->auth_key));
    } else {
        memset(ctx->auth_key, 0, sizeof(ctx->auth_key));
    }

    ctx->mtls_enabled = false;
    ctx->mtls = NULL;
    if (config->enable_mtls) {
        if (!dislmdb_mtls_available() ||
            config->tls_cert_path[0] == '\0' ||
            config->tls_key_path[0] == '\0') {
            free(ctx);
            return DISLMDB_ERR_CONFIG;
        }
        dislmdb_mtls_config mc = {
            .cert_path = config->tls_cert_path,
            .key_path = config->tls_key_path,
            .ca_path = config->tls_ca_path[0] ? config->tls_ca_path : config->tls_cert_path,
            .require_client_cert = true,
        };
        ctx->mtls = dislmdb_mtls_create(&mc);
        if (!ctx->mtls) {
            free(ctx);
            return DISLMDB_ERR_AUTH_FAILED;
        }
        ctx->mtls_enabled = true;
    }

    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        if (ctx->mtls) {
            dislmdb_mtls_destroy(ctx->mtls);
        }
        free(ctx);
        return DISLMDB_ERR_THREAD_ERROR;
    }

    uint16_t port = config->local_port ? config->local_port : DISLMDB_DEFAULT_PORT;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    bool want_tcp = (ctx->transport == DISLMDB_TRANSPORT_TCP ||
                     ctx->transport == DISLMDB_TRANSPORT_BOTH);
    bool want_udp = (ctx->transport == DISLMDB_TRANSPORT_UDP ||
                     ctx->transport == DISLMDB_TRANSPORT_BOTH);

    if (want_tcp) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            pthread_mutex_destroy(&ctx->lock);
            if (ctx->mtls) {
                dislmdb_mtls_destroy(ctx->mtls);
            }
            free(ctx);
            return DISLMDB_ERR_NETWORK;
        }
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 32) < 0) {
            close(fd);
            pthread_mutex_destroy(&ctx->lock);
            if (ctx->mtls) {
                dislmdb_mtls_destroy(ctx->mtls);
            }
            free(ctx);
            return DISLMDB_ERR_NETWORK;
        }
        set_nonblocking(fd);
        ctx->listen_fd = fd;
    }

    if (want_udp) {
        int ufd = socket(AF_INET, SOCK_DGRAM, 0);
        if (ufd < 0) {
            if (ctx->listen_fd >= 0) {
                close(ctx->listen_fd);
            }
            pthread_mutex_destroy(&ctx->lock);
            if (ctx->mtls) {
                dislmdb_mtls_destroy(ctx->mtls);
            }
            free(ctx);
            return DISLMDB_ERR_NETWORK;
        }
        int on = 1;
        setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        /* UDP may share the same port as TCP on most stacks */
        if (bind(ufd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(ufd);
            if (ctx->listen_fd >= 0) {
                close(ctx->listen_fd);
            }
            pthread_mutex_destroy(&ctx->lock);
            if (ctx->mtls) {
                dislmdb_mtls_destroy(ctx->mtls);
            }
            free(ctx);
            return DISLMDB_ERR_NETWORK;
        }
        set_nonblocking(ufd);
        ctx->udp_fd = ufd;
    }

    if (ctx->listen_fd < 0 && ctx->udp_fd < 0) {
        pthread_mutex_destroy(&ctx->lock);
        if (ctx->mtls) {
            dislmdb_mtls_destroy(ctx->mtls);
        }
        free(ctx);
        return DISLMDB_ERR_CONFIG;
    }

    ctx->running = true;
    env->network_running = true;
    env->network_context = ctx;

    if (pthread_create(&ctx->thread, NULL, network_thread, ctx) != 0) {
        if (ctx->listen_fd >= 0) {
            close(ctx->listen_fd);
        }
        if (ctx->udp_fd >= 0) {
            close(ctx->udp_fd);
        }
        env->network_context = NULL;
        env->network_running = false;
        pthread_mutex_destroy(&ctx->lock);
        if (ctx->mtls) {
            dislmdb_mtls_destroy(ctx->mtls);
        }
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

    dislmdb_log(env, DISLMDB_LOG_INFO, "NET",
                "Network listening on port %u transport=%d mtls=%s",
                (unsigned)(config->local_port ? config->local_port : DISLMDB_DEFAULT_PORT),
                (int)ctx->transport, ctx->mtls_enabled ? "on" : "off");
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
    if (ctx->udp_fd >= 0) {
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
    }
    pthread_mutex_unlock(&ctx->lock);

    volatile uint8_t *k = ctx->auth_key;
    for (size_t i = 0; i < sizeof(ctx->auth_key); i++) {
        k[i] = 0;
    }
    if (ctx->mtls) {
        dislmdb_mtls_destroy(ctx->mtls);
        ctx->mtls = NULL;
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
    pthread_mutex_unlock(&ctx->lock);

    DISLMDB_network_message msg = *message;
    if (msg.header.sender_id[0] == '\0') {
        strncpy(msg.header.sender_id, env->local_node_id, sizeof(msg.header.sender_id) - 1);
    }
    strncpy(msg.header.target_id, node_id, sizeof(msg.header.target_id) - 1);

    int used_fd = -1;
    int rc = write_framed_adapt(ctx, idx, &msg, &used_fd);
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
    } else {
        /* Only tear down a failed TCP stream — UDP misses must not drop the peer. */
        pthread_mutex_lock(&ctx->lock);
        if (idx >= 0 && ctx->connections[idx].in_use &&
            used_fd >= 0 && used_fd != ctx->udp_fd &&
            ctx->connections[idx].fd == used_fd) {
            close_conn(ctx, idx);
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

    int idxs[NET_MAX_CONNECTIONS];
    char ids[NET_MAX_CONNECTIONS][64];
    int n = 0;
    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
        if (!ctx->connections[i].in_use) {
            continue;
        }
        if (ctx->connections[i].fd < 0 && !conn_can_udp(ctx, i)) {
            continue;
        }
        idxs[n] = i;
        strncpy(ids[n], ctx->connections[i].info.node_id, sizeof(ids[n]) - 1);
        ids[n][sizeof(ids[n]) - 1] = '\0';
        n++;
    }
    pthread_mutex_unlock(&ctx->lock);

    for (int i = 0; i < n; i++) {
        DISLMDB_network_message msg = *message;
        if (msg.header.sender_id[0] == '\0') {
            strncpy(msg.header.sender_id, env->local_node_id, sizeof(msg.header.sender_id) - 1);
        }
        if (ids[i][0] != '\0') {
            strncpy(msg.header.target_id, ids[i], sizeof(msg.header.target_id) - 1);
        }
        int used_fd = -1;
        int rc = write_framed_adapt(ctx, idxs[i], &msg, &used_fd);
        pthread_mutex_lock(&ctx->lock);
        if (rc != DISLMDB_SUCCESS) {
            overall = rc;
            if (used_fd >= 0 && used_fd != ctx->udp_fd &&
                idxs[i] >= 0 && idxs[i] < NET_MAX_CONNECTIONS &&
                ctx->connections[idxs[i]].in_use &&
                ctx->connections[idxs[i]].fd == used_fd) {
                close_conn(ctx, idxs[i]);
            }
        } else {
            ctx->stats.total_messages_sent++;
        }
        pthread_mutex_unlock(&ctx->lock);
    }
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
    /*
     * Dial policy:
     *   UDP  → shared datagram socket only
     *   TCP  → stream dial
     *   BOTH → dial TCP for reliable data; UDP listen already up for signalling
     */
    bool udp = (ctx->transport == DISLMDB_TRANSPORT_UDP);

    /* Already connected / pending to this peer? */
    pthread_mutex_lock(&ctx->lock);
    int existing = find_conn_by_id(ctx, node_addr->node_id);
    if (existing >= 0 && ctx->connections[existing].fd >= 0 &&
        ctx->connections[existing].info.state == DISLMDB_CONNECTION_CONNECTED) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_SUCCESS;
    }
    pthread_mutex_unlock(&ctx->lock);

    int fd = -1;
    if (udp) {
        if (ctx->udp_fd < 0) {
            return DISLMDB_ERR_NETWORK;
        }
        fd = ctx->udp_fd; /* shared datagram socket */
    } else {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return DISLMDB_ERR_NETWORK;
        }
        prepare_tcp_fd(fd);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(node_addr->port);
        if (inet_pton(AF_INET, node_addr->hostname, &addr.sin_addr) != 1) {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(node_addr->hostname, NULL, &hints, &res) != 0 || !res) {
                close(fd);
                return DISLMDB_ERR_NODE_UNREACHABLE;
            }
            memcpy(&addr.sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
                   sizeof(addr.sin_addr));
            freeaddrinfo(res);
        }
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            /* Keep an outbound slot so the network thread can reconnect later */
            pthread_mutex_lock(&ctx->lock);
            ctx->stats.connection_failures++;
            int idx = find_conn_by_id(ctx, node_addr->node_id);
            if (idx < 0) {
                idx = alloc_conn(ctx);
            }
            if (idx >= 0) {
                ctx->connections[idx].in_use = true;
                ctx->connections[idx].outbound = true;
                ctx->connections[idx].fd = -1;
                ctx->connections[idx].tls = NULL;
                ctx->connections[idx].listen_port = node_addr->port;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
                strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
                        sizeof(ctx->connections[idx].info.node_id) - 1);
                strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
                        sizeof(ctx->connections[idx].info.hostname) - 1);
                ctx->connections[idx].info.port = node_addr->port;
            }
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_SUCCESS; /* deferred reconnect */
        }
    }

    dislmdb_mtls_session *tls = NULL;
    if (!udp) {
        if (mtls_wrap_client(ctx, fd, node_addr->hostname, &tls) != 0) {
            close(fd);
            pthread_mutex_lock(&ctx->lock);
            ctx->stats.connection_failures++;
            int idx = find_conn_by_id(ctx, node_addr->node_id);
            if (idx < 0) {
                idx = alloc_conn(ctx);
            }
            if (idx >= 0) {
                ctx->connections[idx].in_use = true;
                ctx->connections[idx].outbound = true;
                ctx->connections[idx].fd = -1;
                ctx->connections[idx].tls = NULL;
                ctx->connections[idx].listen_port = node_addr->port;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
                strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
                        sizeof(ctx->connections[idx].info.node_id) - 1);
                strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
                        sizeof(ctx->connections[idx].info.hostname) - 1);
                ctx->connections[idx].info.port = node_addr->port;
            }
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_SUCCESS; /* deferred reconnect */
        }
    }

    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_addr->node_id);
    if (idx < 0) {
        idx = alloc_conn(ctx);
    }
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        if (tls) {
            dislmdb_mtls_session_close(tls);
        } else if (!udp) {
            close(fd);
        }
        return DISLMDB_ERR_MAX_NODES;
    }
    ctx->connections[idx].fd = fd;
    ctx->connections[idx].tls = tls;
    ctx->connections[idx].outbound = true;
    ctx->connections[idx].listen_port = node_addr->port;
    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
    ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
    ctx->connections[idx].info.last_activity_time = ctx->connections[idx].info.connect_time;
    strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
            sizeof(ctx->connections[idx].info.node_id) - 1);
    strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
            sizeof(ctx->connections[idx].info.hostname) - 1);
    ctx->connections[idx].info.port = node_addr->port;
    ctx->stats.active_connections++;
    ctx->stats.total_connections++;
    char peer_label[64];
    strncpy(peer_label, node_addr->node_id, sizeof(peer_label) - 1);
    peer_label[sizeof(peer_label) - 1] = '\0';
    pthread_mutex_unlock(&ctx->lock);

    extern int dislmdb_pbft_send_hello(DISLMDB_env *env, const char *target_node_id);
    (void)dislmdb_pbft_send_hello(env, peer_label);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_bind_peer_id(DISLMDB_env *env,
                                 const char *old_or_empty,
                                 const char *real_node_id,
                                 uint16_t listen_port)
{
    if (!env || !env->network_context || !real_node_id || real_node_id[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = -1;
    if (old_or_empty && old_or_empty[0] != '\0') {
        idx = find_conn_by_id(ctx, old_or_empty);
    }
    if (idx < 0) {
        /* Match any seed-* or empty-id live connection */
        for (int i = 0; i < NET_MAX_CONNECTIONS; i++) {
            if (!ctx->connections[i].in_use) {
                continue;
            }
            const char *cid = ctx->connections[i].info.node_id;
            if (cid[0] == '\0' || strncmp(cid, "seed-", 5) == 0) {
                idx = i;
                break;
            }
            if (strncmp(cid, real_node_id, 63) == 0) {
                idx = i;
                break;
            }
        }
    }
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    strncpy(ctx->connections[idx].info.node_id, real_node_id,
            sizeof(ctx->connections[idx].info.node_id) - 1);
    ctx->connections[idx].info.node_id[sizeof(ctx->connections[idx].info.node_id) - 1] = '\0';
    if (listen_port != 0) {
        ctx->connections[idx].listen_port = listen_port;
        ctx->connections[idx].info.port = listen_port;
    }
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
