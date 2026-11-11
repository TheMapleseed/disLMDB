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
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#include <sys/event.h>
#define DISLMDB_NET_HAS_KQUEUE 1
#endif

#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"
#include "dislmdb_mtls.h"
#include "dislmdb_quic.h"
#include "dislmdb_iouring.h"

#define NET_CONN_INITIAL DISLMDB_MAX_NODES /* growable; not a hard cluster cap */
#define NET_HEADER_WIRE_SIZE 160
#define NET_HMAC_SIZE DISLMDB_HMAC_SHA256_LENGTH
/** Per-peer outbound queue — survives TCP CONNECTING / brief UDP misses. */
#define NET_OUTBOX_CAP 32
/** Kernel socket buffer for TCP and UDP (send + recv). */
#define NET_SOCK_BUF_BYTES (256 * 1024)

typedef struct net_outbox_slot {
    bool in_use;
    DISLMDB_network_message msg; /* owns payload copy */
} net_outbox_slot;

typedef struct net_connection {
    bool in_use;
    bool outbound;          /* true if we dialed; eligible for reconnect */
    int fd;
    uint16_t listen_port;   /* peer listen port (for reconnect / HELLO) */
    dislmdb_mtls_session *tls; /* non-NULL when enable_mtls wrapped this TCP fd */
    pthread_mutex_t io_lock;   /* serialize framed TCP/TLS read vs write */
    bool io_lock_ready;
    uint64_t peer_dgram_cid; /* bound DQGM session id from peer */
    bool peer_cid_bound;     /* true once first DQGM cid observed */
    uint64_t peer_last_pkt;  /* highest accepted DQGM pkt_num (v2+) */
    bool peer_pkt_seen;      /* true once a v2+ pkt_num was accepted */
    uint64_t local_acked_pkt; /* highest cumulative ACK from peer (our pkts) */
    bool hello_reengage;     /* revived from CLOSED — HELLO should reply once */
    uint64_t last_tcp_attempt_ms; /* rate-limit BOTH TCP dials while UDP lives */
    char peer_region[64];    /* optional; nearest-dial affinity */
    char peer_locality[64];
    bool peer_voting;        /* from HELLO; default true */
    uint32_t rtt_ewma_ms;     /* 0 = unsampled */
    uint64_t last_tx_ms;     /* for RTT sample on next RX */
    bool hs_inflight;        /* mTLS handshake queued/running on worker */
    net_outbox_slot outbox[NET_OUTBOX_CAP];
    uint32_t outbox_head;    /* next to drain */
    uint32_t outbox_count;
    DISLMDB_connection_info info;
} net_connection;

/** BOTH: avoid handshake thrash that stalls the net thread (starves UDP Raft). */
#define NET_BOTH_TCP_RETRY_MS 2000u
#define NET_HS_QUEUE_MAX 64u
#define NET_HS_WORKERS_DEFAULT 2u
#define NET_HS_WORKERS_MAX 8u
#define NET_QUIC_SESSIONS_MAX 16u

typedef struct net_quic_session {
    bool active;
    dislmdb_quic_conn conn;
    struct sockaddr_in peer;
} net_quic_session;

typedef struct net_quic_pending {
    bool active;
    bool have_sh;
    dislmdb_quic_conn conn;
    uint8_t xpriv[32];
    uint8_t ch[512];
    size_t ch_len;
    uint8_t sh[512];
    size_t sh_len;
    uint8_t client_initial[512]; /* our outbound Initial for retransmit */
    size_t client_initial_len;
    uint8_t server_initial[2048];
    size_t server_initial_len;
    uint8_t server_hs[8192]; /* stashed if HS arrives before Initial */
    size_t server_hs_len;
    struct sockaddr_in peer;
} net_quic_pending;

typedef enum {
    NET_HS_CLIENT = 1,
    NET_HS_SERVER = 2
} net_hs_kind;

typedef struct net_hs_job {
    net_hs_kind kind;
    int conn_idx;                 /* client: existing CONNECTING slot; server: -1 */
    int fd;
    char host[256];
    uint16_t peer_port;           /* server: ephemeral source port */
    struct net_hs_job *next;
} net_hs_job;

typedef struct network_context {
    DISLMDB_env *env;
    int listen_fd;
    int udp_fd;                 /* datagram socket when transport includes UDP */
    int wake_r;                 /* self-pipe read — wakes poll/kqueue on shutdown */
    int wake_w;                 /* self-pipe write */
    int kq;                     /* BSD/Darwin kqueue; -1 → poll/io_uring */
    dislmdb_iouring *uring;     /* Linux io_uring; NULL → poll/kqueue */
    DISLMDB_TRANSPORT transport;
    pthread_t thread;
    bool running;
    pthread_mutex_t lock;
    net_connection *connections; /* heap; grows past NET_CONN_INITIAL */
    int conn_cap;
    DISLMDB_network_stats stats;
    uint8_t auth_key[32];
    bool auth_enabled;
    bool encrypt_payloads;
    uint8_t region_key[32];
    bool has_region_key;
    uint8_t cross_region_key[32];
    bool has_cross_region_key;
    uint32_t rtt_budget_ms;
    bool mtls_enabled;
    dislmdb_mtls_ctx *mtls;
    uint64_t dgram_cid;           /* DQGM session id (QUIC/WT substrate) */
    uint64_t dgram_pkt_num;       /* outbound DQGM packet number (v2) */
    uint64_t start_ms;
    uint64_t last_heartbeat_ms;
    /* Phase G: mTLS handshake worker pool */
    pthread_mutex_t hs_mu;
    pthread_cond_t hs_cv;
    pthread_t *hs_threads;
    uint32_t hs_nworkers;
    bool hs_running;
    bool hs_mu_ready;
    net_hs_job *hs_head;
    net_hs_job *hs_tail;
    uint32_t hs_depth;
    /* QUIC substrate sessions (Initial → 1-RTT). */
    net_quic_session quic_sessions[NET_QUIC_SESSIONS_MAX];
    net_quic_pending quic_pending[NET_QUIC_SESSIONS_MAX];
    dislmdb_quic_tls_identity *quic_identity; /* leaf+key for CertificateVerify */
    bool quic_pki_strict; /* true when PEM CA configured — chain verify required */
} network_context;

static int quic_session_store(network_context *ctx, const dislmdb_quic_conn *conn,
                              const struct sockaddr_in *peer)
{
    if (!ctx || !conn || !peer || !conn->has_app_keys || conn->scid_len == 0) {
        return -1;
    }
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (ctx->quic_sessions[i].active &&
            ctx->quic_sessions[i].conn.scid_len == conn->scid_len &&
            memcmp(ctx->quic_sessions[i].conn.scid, conn->scid, conn->scid_len) ==
                0) {
            ctx->quic_sessions[i].conn = *conn;
            ctx->quic_sessions[i].peer = *peer;
            return 0;
        }
    }
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (!ctx->quic_sessions[i].active) {
            ctx->quic_sessions[i].active = true;
            ctx->quic_sessions[i].conn = *conn;
            ctx->quic_sessions[i].peer = *peer;
            return 0;
        }
    }
    /* Evict slot 0 when full (substrate). */
    ctx->quic_sessions[0].active = true;
    ctx->quic_sessions[0].conn = *conn;
    ctx->quic_sessions[0].peer = *peer;
    return 0;
}

static net_quic_session *quic_session_find(network_context *ctx,
                                           const uint8_t *dcid, size_t dcid_len)
{
    if (!ctx || !dcid || dcid_len == 0) {
        return NULL;
    }
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (ctx->quic_sessions[i].active &&
            ctx->quic_sessions[i].conn.scid_len == dcid_len &&
            memcmp(ctx->quic_sessions[i].conn.scid, dcid, dcid_len) == 0) {
            return &ctx->quic_sessions[i];
        }
    }
    return NULL;
}

static net_quic_pending *quic_pending_find_peer(network_context *ctx,
                                                const struct sockaddr_in *peer)
{
    if (!ctx || !peer) {
        return NULL;
    }
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (ctx->quic_pending[i].active &&
            ctx->quic_pending[i].peer.sin_addr.s_addr == peer->sin_addr.s_addr &&
            ctx->quic_pending[i].peer.sin_port == peer->sin_port) {
            return &ctx->quic_pending[i];
        }
    }
    return NULL;
}

static int quic_pending_store(network_context *ctx, const net_quic_pending *p)
{
    if (!ctx || !p) {
        return -1;
    }
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (!ctx->quic_pending[i].active) {
            ctx->quic_pending[i] = *p;
            ctx->quic_pending[i].active = true;
            return 0;
        }
    }
    ctx->quic_pending[0] = *p;
    ctx->quic_pending[0].active = true;
    return 0;
}

/**
 * Finish client HS when Initial(SH) + Handshake are both present.
 * Caller holds ctx->lock. On success fills cfin/hello for post-unlock I/O.
 */
static bool quic_pending_try_complete(network_context *ctx, net_quic_pending *pend,
                                      uint8_t *cfin, size_t cfin_cap,
                                      size_t *cfin_len, char *hello_id,
                                      size_t hello_cap, struct sockaddr_in *peer_out)
{
    if (!ctx || !pend || !pend->active || !pend->have_sh ||
        pend->server_hs_len == 0 || !cfin || !cfin_len || !hello_id || !peer_out) {
        return false;
    }
    *cfin_len = 0;
    hello_id[0] = '\0';
    const dislmdb_quic_tls_identity *trust =
        ctx->quic_pki_strict ? ctx->quic_identity : NULL;
    if (dislmdb_quic_client_complete_handshake(
            &pend->conn, pend->ch, pend->ch_len, pend->xpriv, pend->server_initial,
            pend->server_initial_len, pend->server_hs, pend->server_hs_len, trust,
            cfin, cfin_cap, cfin_len) != 0) {
        return false;
    }
    *peer_out = pend->peer;
    (void)quic_session_store(ctx, &pend->conn, &pend->peer);
    for (int ci = 0; ci < ctx->conn_cap; ci++) {
        if (!ctx->connections[ci].in_use) {
            continue;
        }
        uint16_t lp = ctx->connections[ci].listen_port
                          ? ctx->connections[ci].listen_port
                          : ctx->connections[ci].info.port;
        if (lp == ntohs(pend->peer.sin_port)) {
            strncpy(hello_id, ctx->connections[ci].info.node_id, hello_cap - 1);
            hello_id[hello_cap - 1] = '\0';
            break;
        }
    }
    pend->active = false;
    pend->server_hs_len = 0;
    dislmdb_quic_conn_reset(&pend->conn);
    return true;
}

static int find_conn_by_id(network_context *ctx, const char *node_id);

/** Higher = closer. Unknown peer topo ranks as neutral (1). */
static int topo_affinity_rank(const network_context *ctx, const net_connection *c)
{
    if (!ctx || !c || !ctx->env) {
        return 1;
    }
    const char *lr = ctx->env->config.region;
    const char *ll = ctx->env->config.locality;
    if (lr[0] == '\0') {
        return 1;
    }
    if (c->peer_region[0] == '\0') {
        return 1;
    }
    if (strncmp(c->peer_region, lr, sizeof(c->peer_region)) != 0) {
        return 0; /* cross-region — dial later / softer */
    }
    if (ll[0] != '\0' && c->peer_locality[0] != '\0' &&
        strncmp(c->peer_locality, ll, sizeof(c->peer_locality)) == 0) {
        return 3;
    }
    return 2; /* same region */
}

static void conn_set_topo(net_connection *c, const DISLMDB_node_addr *na)
{
    if (!c || !na) {
        return;
    }
    strncpy(c->peer_region, na->region, sizeof(c->peer_region) - 1);
    c->peer_region[sizeof(c->peer_region) - 1] = '\0';
    strncpy(c->peer_locality, na->locality, sizeof(c->peer_locality) - 1);
    c->peer_locality[sizeof(c->peer_locality) - 1] = '\0';
    strncpy(c->info.region, na->region, sizeof(c->info.region) - 1);
    c->info.region[sizeof(c->info.region) - 1] = '\0';
    strncpy(c->info.locality, na->locality, sizeof(c->info.locality) - 1);
    c->info.locality[sizeof(c->info.locality) - 1] = '\0';
}

static void conn_note_tx(net_connection *c)
{
    if (!c) {
        return;
    }
    c->last_tx_ms = dislmdb_get_time_ms();
}

static void conn_note_rx(net_connection *c)
{
    if (!c || c->last_tx_ms == 0) {
        return;
    }
    uint64_t now = dislmdb_get_time_ms();
    if (now < c->last_tx_ms) {
        return;
    }
    uint32_t sample = (uint32_t)(now - c->last_tx_ms);
    if (sample == 0) {
        sample = 1;
    }
    if (c->rtt_ewma_ms == 0) {
        c->rtt_ewma_ms = sample;
    } else {
        c->rtt_ewma_ms = (c->rtt_ewma_ms * 7u + sample) / 8u;
    }
    c->info.rtt_ewma_ms = c->rtt_ewma_ms;
    c->last_tx_ms = 0;
}

/** Cross-region when both sides advertise a region and they differ. */
static bool conn_is_cross_region(const network_context *ctx, const net_connection *c)
{
    return ctx && c && topo_affinity_rank(ctx, c) == 0;
}

/**
 * Select HMAC/AEAD key for a peer. Fail closed for cross-region without
 * cross_region_key when a regional plane is configured.
 */
static int plane_key_for_conn(const network_context *ctx, const net_connection *c,
                              uint8_t out[32])
{
    if (!ctx || !out) {
        return -1;
    }
    if (c && conn_is_cross_region(ctx, c)) {
        if (ctx->has_cross_region_key) {
            memcpy(out, ctx->cross_region_key, 32);
            return 0;
        }
        /* Cross-region peer but no cross key — refuse (wrong plane). */
        if (ctx->has_region_key) {
            return -1;
        }
    } else if (ctx->has_region_key) {
        memcpy(out, ctx->region_key, 32);
        return 0;
    }
    memcpy(out, ctx->auth_key, 32);
    return 0;
}

static int find_conn_idx_for_target(network_context *ctx, const char *target_id)
{
    if (!ctx || !target_id || target_id[0] == '\0') {
        return -1;
    }
    return find_conn_by_id(ctx, target_id);
}

static void free_network_context(network_context *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->kq >= 0) {
        close(ctx->kq);
        ctx->kq = -1;
    }
    if (ctx->uring) {
        dislmdb_iouring_destroy(ctx->uring);
        ctx->uring = NULL;
    }
    free(ctx->connections);
    ctx->connections = NULL;
    ctx->conn_cap = 0;
    for (uint32_t i = 0; i < NET_QUIC_SESSIONS_MAX; i++) {
        if (ctx->quic_sessions[i].active) {
            dislmdb_quic_conn_reset(&ctx->quic_sessions[i].conn);
            ctx->quic_sessions[i].active = false;
        }
        if (ctx->quic_pending[i].active) {
            dislmdb_quic_conn_reset(&ctx->quic_pending[i].conn);
            ctx->quic_pending[i].active = false;
        }
    }
    dislmdb_quic_tls_identity_destroy(ctx->quic_identity);
    ctx->quic_identity = NULL;
    free(ctx);
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Bound peer I/O so a half-open/dead TCP peer cannot stall the net thread. */
#define NET_IO_TIMEOUT_MS 200

static void prepare_sock_buffers(int fd)
{
    int buf = NET_SOCK_BUF_BYTES;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
}

static void prepare_tcp_fd(int fd)
{
#if defined(SO_NOSIGPIPE)
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    prepare_sock_buffers(fd);
    struct timeval tv;
    tv.tv_sec = NET_IO_TIMEOUT_MS / 1000;
    tv.tv_usec = (NET_IO_TIMEOUT_MS % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                /* Short wait then fail — do not burn seconds on a dead peer */
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                if (poll(&pfd, 1, NET_IO_TIMEOUT_MS) <= 0) {
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
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT) {
                struct pollfd pfd = {.fd = fd, .events = POLLIN};
                if (poll(&pfd, 1, NET_IO_TIMEOUT_MS) <= 0) {
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
    for (int i = 0; i < ctx->conn_cap; i++) {
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
    int best = -1;
    int fallback = -1;
    uint64_t best_score = 0;
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (!ctx->connections[i].in_use ||
            strcmp(ctx->connections[i].info.node_id, node_id) != 0) {
            continue;
        }
        if (fallback < 0) {
            fallback = i;
        }
        if (ctx->connections[i].fd < 0 ||
            ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTED) {
            continue;
        }
        /*
         * Rank by proven traffic, not outbound bit — a silent dialed socket
         * must not beat a busy accepted stream for the same peer.
         * Prefer listen_port-bearing slots so BOTH signalling can use UDP.
         */
        uint64_t score = ctx->connections[i].info.last_activity_time;
        score += (uint64_t)ctx->connections[i].info.messages_sent * 10000ull;
        score += (uint64_t)ctx->connections[i].info.messages_received * 100ull;
        if (ctx->connections[i].listen_port != 0) {
            score += 500000ull;
        }
        score += (uint64_t)topo_affinity_rank(ctx, &ctx->connections[i]) * 250000ull;
        if (ctx->connections[i].outbound) {
            score += 1ull; /* weak tie-break only */
        }
        if (best < 0 || score >= best_score) {
            best = i;
            best_score = score;
        }
    }
    return best >= 0 ? best : fallback;
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
    if (idx < 0 || idx >= ctx->conn_cap || !ctx->connections[idx].in_use) {
        return -1;
    }
    int tcp = conn_tcp_fd(ctx, idx);
    /* Never write on a half-open dial — fall through to UDP under BOTH. */
    if (tcp >= 0 &&
        ctx->connections[idx].info.state != DISLMDB_CONNECTION_CONNECTED) {
        tcp = -1;
    }
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
    bool lock_io = (primary != ctx->udp_fd && ctx->connections[idx].io_lock_ready);
    if (lock_io) {
        pthread_mutex_lock(&ctx->connections[idx].io_lock);
    }
    int rc = write_framed(ctx, primary, message);
    if (rc == DISLMDB_SUCCESS) {
        if (lock_io) {
            pthread_mutex_unlock(&ctx->connections[idx].io_lock);
        }
        return rc;
    }
    int alt = pick_fallback_fd(ctx, idx, primary);
    if (alt < 0 || alt == primary) {
        if (lock_io) {
            pthread_mutex_unlock(&ctx->connections[idx].io_lock);
        }
        return rc;
    }
    if (used_fd_out) {
        *used_fd_out = alt;
    }
    /* Fallback may switch TCP↔UDP; only hold io lock for TCP */
    if (lock_io && alt == ctx->udp_fd) {
        pthread_mutex_unlock(&ctx->connections[idx].io_lock);
        lock_io = false;
    }
    rc = write_framed(ctx, alt, message);
    if (lock_io) {
        pthread_mutex_unlock(&ctx->connections[idx].io_lock);
    }
    return rc;
}

static void ensure_io_lock(net_connection *c)
{
    if (!c->io_lock_ready) {
        if (pthread_mutex_init(&c->io_lock, NULL) == 0) {
            c->io_lock_ready = true;
        }
    }
}

static void outbox_clear(net_connection *c)
{
    for (uint32_t i = 0; i < NET_OUTBOX_CAP; i++) {
        if (c->outbox[i].in_use) {
            dislmdb_network_free_message(&c->outbox[i].msg);
            c->outbox[i].in_use = false;
        }
    }
    c->outbox_head = 0;
    c->outbox_count = 0;
}

/** Deep-copy message into the peer outbox. Caller holds ctx->lock. */
static int outbox_enqueue_locked(network_context *ctx, int idx,
                                 const DISLMDB_network_message *message)
{
    if (idx < 0 || idx >= ctx->conn_cap || !ctx->connections[idx].in_use ||
        !message) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    net_connection *c = &ctx->connections[idx];
    if (c->outbox_count >= NET_OUTBOX_CAP) {
        /* Drop oldest to make room — prefer fresher consensus/replication. */
        uint32_t drop = c->outbox_head;
        if (c->outbox[drop].in_use) {
            dislmdb_network_free_message(&c->outbox[drop].msg);
            c->outbox[drop].in_use = false;
        }
        c->outbox_head = (c->outbox_head + 1u) % NET_OUTBOX_CAP;
        c->outbox_count--;
        ctx->stats.outbox_dropped++;
        ctx->stats.total_errors++;
    }
    uint32_t slot = (c->outbox_head + c->outbox_count) % NET_OUTBOX_CAP;
    DISLMDB_network_message copy;
    int rc = dislmdb_network_create_message(&copy, message->header.type,
                                            message->payload,
                                            message->header.payload_size,
                                            message->header.target_id[0]
                                                ? message->header.target_id
                                                : NULL);
    if (rc != DISLMDB_SUCCESS) {
        return rc;
    }
    copy.header = message->header;
    copy.header.payload_size = message->header.payload_size;
    /* create_message may clear sender; restore after */
    strncpy(copy.header.sender_id, message->header.sender_id,
            sizeof(copy.header.sender_id) - 1);
    strncpy(copy.header.target_id, message->header.target_id,
            sizeof(copy.header.target_id) - 1);
    c->outbox[slot].msg = copy;
    c->outbox[slot].in_use = true;
    c->outbox_count++;
    ctx->stats.outbox_enqueued++;
    return DISLMDB_SUCCESS;
}

/**
 * Drain buffered frames for one peer.
 * Must NOT be called with ctx->lock held (write_framed_adapt may lock).
 * @param max_frames 0 = unlimited; otherwise stop after this many successful
 *        sends so the net thread can return to RX (fairness / no RX starve).
 * @return true if the peer may still have outbox frames after returning.
 */
static bool outbox_drain(network_context *ctx, int idx, uint32_t max_frames);

/**
 * Fair multi-peer drain on the net thread: round-robin one frame per peer
 * per pass (no worker-join). Caps total frames so poll/RX stays responsive.
 * Prior async join-parallelism starved RX and flaked FORWARD RPC.
 */
static void outbox_drain_many(network_context *ctx, const int *idxs, int n)
{
    if (!ctx || !idxs || n <= 0) {
        return;
    }
    const uint32_t kMaxTotal = 64;
    uint32_t sent = 0;
    bool progress;
    do {
        progress = false;
        for (int i = 0; i < n && sent < kMaxTotal; i++) {
            if (outbox_drain(ctx, idxs[i], 1)) {
                progress = true;
            }
            sent++;
        }
    } while (progress && sent < kMaxTotal);
}

static bool outbox_drain(network_context *ctx, int idx, uint32_t max_frames)
{
    uint32_t frames = 0;
    bool more = false;
    for (;;) {
        if (max_frames > 0 && frames >= max_frames) {
            pthread_mutex_lock(&ctx->lock);
            more = (idx >= 0 && idx < ctx->conn_cap && ctx->connections[idx].in_use &&
                    ctx->connections[idx].outbox_count > 0);
            pthread_mutex_unlock(&ctx->lock);
            return more;
        }
        DISLMDB_network_message msg;
        pthread_mutex_lock(&ctx->lock);
        if (idx < 0 || idx >= ctx->conn_cap || !ctx->connections[idx].in_use ||
            ctx->connections[idx].outbox_count == 0) {
            pthread_mutex_unlock(&ctx->lock);
            return false;
        }
        net_connection *c = &ctx->connections[idx];
        uint32_t head = c->outbox_head;
        if (!c->outbox[head].in_use) {
            c->outbox_head = (head + 1u) % NET_OUTBOX_CAP;
            if (c->outbox_count > 0) {
                c->outbox_count--;
            }
            pthread_mutex_unlock(&ctx->lock);
            continue;
        }
        msg = c->outbox[head].msg;
        c->outbox[head].in_use = false;
        memset(&c->outbox[head].msg, 0, sizeof(c->outbox[head].msg));
        c->outbox_head = (head + 1u) % NET_OUTBOX_CAP;
        c->outbox_count--;
        pthread_mutex_unlock(&ctx->lock);
        int used_fd = -1;
        int rc = write_framed_adapt(ctx, idx, &msg, &used_fd);
        if (rc != DISLMDB_SUCCESS) {
            /* Policy rejects: drop (do not spin the outbox forever). */
            if (rc == DISLMDB_ERR_NODE_UNREACHABLE ||
                rc == DISLMDB_ERR_NOT_AUTHORIZED ||
                rc == DISLMDB_ERR_AUTH_FAILED) {
                pthread_mutex_lock(&ctx->lock);
                ctx->stats.outbox_dropped++;
                pthread_mutex_unlock(&ctx->lock);
                dislmdb_network_free_message(&msg);
                frames++;
                continue;
            }
            /* Put it back at the front and stop — path still not ready. */
            pthread_mutex_lock(&ctx->lock);
            if (ctx->connections[idx].in_use) {
                net_connection *c2 = &ctx->connections[idx];
                if (c2->outbox_count < NET_OUTBOX_CAP) {
                    uint32_t new_head =
                        (c2->outbox_head + NET_OUTBOX_CAP - 1u) % NET_OUTBOX_CAP;
                    c2->outbox[new_head].msg = msg;
                    c2->outbox[new_head].in_use = true;
                    c2->outbox_head = new_head;
                    c2->outbox_count++;
                    msg.payload = NULL; /* ownership moved back */
                    more = true;
                } else {
                    ctx->stats.outbox_dropped++;
                }
            }
            pthread_mutex_unlock(&ctx->lock);
            dislmdb_network_free_message(&msg);
            return more;
        }
        pthread_mutex_lock(&ctx->lock);
        ctx->stats.outbox_drained++;
        ctx->stats.total_messages_sent++;
        ctx->stats.total_bytes_sent +=
            NET_HEADER_WIRE_SIZE + msg.header.payload_size + NET_HMAC_SIZE;
        if (ctx->connections[idx].in_use) {
            ctx->connections[idx].info.messages_sent++;
            ctx->connections[idx].info.last_activity_time = dislmdb_get_time_ms();
        }
        pthread_mutex_unlock(&ctx->lock);
        dislmdb_network_free_message(&msg);
        frames++;
    }
}

static int grow_connections(network_context *ctx)
{
    int ncap = ctx->conn_cap > 0 ? ctx->conn_cap * 2 : NET_CONN_INITIAL;
    if (ncap < NET_CONN_INITIAL) {
        ncap = NET_CONN_INITIAL;
    }
    net_connection *n =
        realloc(ctx->connections, (size_t)ncap * sizeof(net_connection));
    if (!n) {
        return -1;
    }
    for (int i = ctx->conn_cap; i < ncap; i++) {
        memset(&n[i], 0, sizeof(n[i]));
        n[i].fd = -1;
    }
    ctx->connections = n;
    ctx->conn_cap = ncap;
    return 0;
}

static int alloc_conn(network_context *ctx)
{
    if (!ctx->connections || ctx->conn_cap <= 0) {
        if (grow_connections(ctx) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (!ctx->connections[i].in_use) {
            bool had_lock = ctx->connections[i].io_lock_ready;
            pthread_mutex_t saved = ctx->connections[i].io_lock;
            outbox_clear(&ctx->connections[i]);
            memset(&ctx->connections[i], 0, sizeof(ctx->connections[i]));
            if (had_lock) {
                ctx->connections[i].io_lock = saved;
                ctx->connections[i].io_lock_ready = true;
            } else {
                ensure_io_lock(&ctx->connections[i]);
            }
            ctx->connections[i].in_use = true;
            ctx->connections[i].outbound = false;
            ctx->connections[i].listen_port = 0;
            ctx->connections[i].fd = -1;
            ctx->connections[i].peer_voting = true;
            ctx->connections[i].info.peer_voting = true;
            return i;
        }
    }
    int old = ctx->conn_cap;
    if (grow_connections(ctx) != 0) {
        return -1;
    }
    int i = old;
    ensure_io_lock(&ctx->connections[i]);
    ctx->connections[i].in_use = true;
    ctx->connections[i].outbound = false;
    ctx->connections[i].listen_port = 0;
    ctx->connections[i].fd = -1;
    ctx->connections[i].peer_voting = true;
    ctx->connections[i].info.peer_voting = true;
    return i;
}

/** Authoritative count — avoids drift when CONNECTING slots close or peers dedupe. */
static uint32_t recount_active_connections_locked(const network_context *ctx)
{
    uint32_t n = 0;
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (ctx->connections[i].in_use &&
            ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTED) {
            n++;
        }
    }
    return n;
}

/**
 * Drop TCP/TLS on a slot. Under BOTH, fall back to the shared UDP fd so
 * Raft/election signalling keeps a CONNECTED path (outbox can drain).
 * Returns true if the slot remained usable (UDP placeholder or kept).
 */
static bool demote_tcp_to_udp_locked(network_context *ctx, int idx)
{
    if (idx < 0 || idx >= ctx->conn_cap || !ctx->connections[idx].in_use) {
        return false;
    }
    if (ctx->connections[idx].tls) {
        dislmdb_mtls_session_close(ctx->connections[idx].tls);
        ctx->connections[idx].tls = NULL;
    } else if (ctx->connections[idx].fd >= 0 &&
               ctx->connections[idx].fd != ctx->udp_fd) {
        close(ctx->connections[idx].fd);
    }
    if (ctx->transport == DISLMDB_TRANSPORT_BOTH && ctx->udp_fd >= 0 &&
        ctx->connections[idx].listen_port != 0 &&
        ctx->connections[idx].info.hostname[0] != '\0') {
        ctx->connections[idx].fd = ctx->udp_fd;
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
        ctx->connections[idx].info.last_activity_time = dislmdb_get_time_ms();
        ctx->stats.active_connections = recount_active_connections_locked(ctx);
        return true;
    }
    ctx->connections[idx].fd = -1;
    return false;
}

static void close_conn(network_context *ctx, int idx)
{
    if (idx < 0 || idx >= ctx->conn_cap || !ctx->connections[idx].in_use) {
        return;
    }
    ctx->connections[idx].hs_inflight = false;
    bool was_connected =
        (ctx->connections[idx].info.state == DISLMDB_CONNECTION_CONNECTED);
    if (demote_tcp_to_udp_locked(ctx, idx)) {
        /* BOTH: UDP signalling stays up; TCP will re-dial on a backoff. */
        return;
    }
    /* Keep outbound slots for heartbeat-driven reconnect (outbox survives). */
    if (ctx->connections[idx].outbound &&
        ctx->connections[idx].info.hostname[0] != '\0' &&
        ctx->connections[idx].listen_port != 0) {
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
        if (was_connected && ctx->stats.active_connections > 0) {
            ctx->stats.active_connections--;
        } else {
            ctx->stats.active_connections = recount_active_connections_locked(ctx);
        }
        return;
    }
    outbox_clear(&ctx->connections[idx]);
    ctx->connections[idx].in_use = false;
    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
    if (was_connected && ctx->stats.active_connections > 0) {
        ctx->stats.active_connections--;
    } else {
        ctx->stats.active_connections = recount_active_connections_locked(ctx);
    }
}

/** Another live TCP slot already reaches this peer (by id and/or host:port). */
static int find_other_live_peer(network_context *ctx, int self_idx,
                               const char *node_id, const char *hostname,
                               uint16_t port)
{
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (i == self_idx || !ctx->connections[i].in_use) {
            continue;
        }
        if (ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTED &&
            ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTING) {
            continue;
        }
        /* UDP-only placeholders must not suppress a TCP dial under BOTH. */
        if (conn_tcp_fd(ctx, i) < 0) {
            continue;
        }
        if (node_id && node_id[0] != '\0' &&
            ctx->connections[i].info.node_id[0] != '\0' &&
            strncmp(ctx->connections[i].info.node_id, node_id, 63) == 0) {
            return i;
        }
        if (hostname && hostname[0] != '\0' && port != 0 &&
            strcmp(ctx->connections[i].info.hostname, hostname) == 0) {
            uint16_t op = ctx->connections[i].listen_port
                              ? ctx->connections[i].listen_port
                              : ctx->connections[i].info.port;
            if (op == port) {
                return i;
            }
        }
    }
    return -1;
}

static int try_reconnect(network_context *ctx, int idx)
{
    /* Caller may hold ctx->lock — use nonblocking connect so a dead peer
     * cannot stall the network thread / serialize broadcasts. */
    net_connection *c = &ctx->connections[idx];
    if (!c->in_use || !c->outbound) {
        return -1;
    }
    /* BOTH may already hold the shared udp_fd for signalling — still dial TCP. */
    bool udp_placeholder =
        (ctx->transport == DISLMDB_TRANSPORT_BOTH && ctx->udp_fd >= 0 &&
         c->fd == ctx->udp_fd);
    if (c->fd >= 0 && !udp_placeholder) {
        return -1;
    }
    if (c->info.hostname[0] == '\0' || c->listen_port == 0) {
        return -1;
    }
    /* Do not dial a second TCP/mTLS path when inbound (or another slot) is live.
     * Duplicate sockets split Raft votes / PBFT broadcasts onto a silent peer. */
    if (find_other_live_peer(ctx, idx, c->info.node_id, c->info.hostname,
                             c->listen_port) >= 0) {
        return -1;
    }
    /*
     * BOTH + live UDP: rate-limit TCP/mTLS dials. Handshakes run on the net
     * thread and otherwise starve datagram Raft for up to several seconds.
     */
    if (udp_placeholder) {
        uint64_t now = dislmdb_get_time_ms();
        /* Cross-region peers wait longer so same-region TCP dials win the net thread. */
        uint64_t retry_ms = NET_BOTH_TCP_RETRY_MS;
        if (topo_affinity_rank(ctx, c) == 0) {
            retry_ms *= 3u;
        }
        if (c->last_tcp_attempt_ms != 0 &&
            now - c->last_tcp_attempt_ms < retry_ms) {
            return -1;
        }
        c->last_tcp_attempt_ms = now;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    prepare_tcp_fd(fd);
    (void)set_nonblocking(fd);
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
    int cr = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (cr != 0 && errno != EINPROGRESS && errno != EALREADY) {
        close(fd);
        ctx->stats.connection_failures++;
        return -1;
    }
    /* Stash fd; finish (poll + optional mTLS) outside the lock */
    c->fd = fd;
    c->tls = NULL;
    c->info.state = DISLMDB_CONNECTION_CONNECTING;
    return 1; /* needs finish_reconnect_mtls */
}

/**
 * Poll nonblocking connect without stalling the net thread.
 * Returns 0 if established, 1 if still in progress, -1 on failure.
 */
static int poll_connect_ready(int fd)
{
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    int sel = poll(&pfd, 1, 0);
    if (sel < 0) {
        return -1;
    }
    if (sel == 0) {
        return 1; /* still connecting — retry next heartbeat */
    }
    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
        return -1;
    }
    return 0;
}

/** True if @p fd appears in @p pfds with a readable revent. */
static bool poll_readable(const struct pollfd *pfds, int np, int fd)
{
    if (!pfds || fd < 0) {
        return false;
    }
    for (int i = 0; i < np; i++) {
        if (pfds[i].fd == fd &&
            (pfds[i].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
            return true;
        }
    }
    return false;
}

static void conn_fail_connecting(network_context *ctx, int idx)
{
    if (!ctx->connections[idx].in_use) {
        return;
    }
    ctx->connections[idx].hs_inflight = false;
    ctx->connections[idx].tls = NULL;
    if (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
        ctx->connections[idx].listen_port != 0 && ctx->udp_fd >= 0) {
        ctx->connections[idx].fd = ctx->udp_fd;
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
    } else {
        ctx->connections[idx].fd = -1;
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
    }
    ctx->stats.connection_failures++;
}

static int attach_client_tls(network_context *ctx, int idx, int fd,
                             dislmdb_mtls_session *tls)
{
    pthread_mutex_lock(&ctx->lock);
    if (!ctx->connections[idx].in_use) {
        pthread_mutex_unlock(&ctx->lock);
        if (tls) {
            dislmdb_mtls_session_close(tls);
        } else {
            close(fd);
        }
        return -1;
    }
    int other = find_other_live_peer(ctx, idx, ctx->connections[idx].info.node_id,
                                     ctx->connections[idx].info.hostname,
                                     ctx->connections[idx].listen_port);
    if (other >= 0) {
        ctx->connections[idx].hs_inflight = false;
        pthread_mutex_unlock(&ctx->lock);
        if (tls) {
            dislmdb_mtls_session_close(tls);
        }
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        if (ctx->connections[idx].in_use) {
            ctx->connections[idx].tls = NULL;
            if (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
                ctx->connections[idx].listen_port != 0 && ctx->udp_fd >= 0) {
                ctx->connections[idx].fd = ctx->udp_fd;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
            } else {
                ctx->connections[idx].fd = -1;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
            }
        }
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }
    ensure_io_lock(&ctx->connections[idx]);
    ctx->connections[idx].fd = fd;
    ctx->connections[idx].tls = tls;
    ctx->connections[idx].hs_inflight = false;
    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
    ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
    ctx->connections[idx].info.last_activity_time = ctx->connections[idx].info.connect_time;
    ctx->stats.active_connections++;
    bool drain = (ctx->connections[idx].outbox_count > 0);
    pthread_mutex_unlock(&ctx->lock);
    if (drain) {
        outbox_drain(ctx, idx, 0);
    }
    return 0;
}

static int attach_server_tls(network_context *ctx, int fd, dislmdb_mtls_session *tls,
                             const char *hostbuf, uint16_t peer_port)
{
    pthread_mutex_lock(&ctx->lock);
    int idx = -1;
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (!ctx->connections[i].in_use) {
            continue;
        }
        if (strcmp(ctx->connections[i].info.hostname, hostbuf) != 0) {
            continue;
        }
        if (ctx->connections[i].fd == ctx->udp_fd || ctx->connections[i].fd < 0) {
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
        ensure_io_lock(&ctx->connections[idx]);
        ctx->connections[idx].fd = fd;
        ctx->connections[idx].tls = tls;
        ctx->connections[idx].hs_inflight = false;
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
        ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
        strncpy(ctx->connections[idx].info.hostname, hostbuf,
                sizeof(ctx->connections[idx].info.hostname) - 1);
        ctx->connections[idx].info.port = peer_port;
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }
    ctx->stats.connection_failures++;
    pthread_mutex_unlock(&ctx->lock);
    if (tls) {
        dislmdb_mtls_session_close(tls);
    } else {
        close(fd);
    }
    return -1;
}

static void hs_run_client(network_context *ctx, net_hs_job *job)
{
    dislmdb_mtls_session *tls = NULL;
    if (mtls_wrap_client(ctx, job->fd, job->host, &tls) != 0) {
        close(job->fd);
        pthread_mutex_lock(&ctx->lock);
        if (job->conn_idx >= 0 && job->conn_idx < ctx->conn_cap) {
            conn_fail_connecting(ctx, job->conn_idx);
        }
        pthread_mutex_unlock(&ctx->lock);
        return;
    }
    (void)attach_client_tls(ctx, job->conn_idx, job->fd, tls);
}

static void hs_run_server(network_context *ctx, net_hs_job *job)
{
    dislmdb_mtls_session *tls = NULL;
    if (mtls_wrap_server(ctx, job->fd, &tls) != 0) {
        close(job->fd);
        pthread_mutex_lock(&ctx->lock);
        ctx->stats.connection_failures++;
        pthread_mutex_unlock(&ctx->lock);
        return;
    }
    (void)attach_server_tls(ctx, job->fd, tls, job->host, job->peer_port);
}

static void *hs_worker_main(void *arg)
{
    network_context *ctx = arg;
    for (;;) {
        pthread_mutex_lock(&ctx->hs_mu);
        while (ctx->hs_running && !ctx->hs_head) {
            pthread_cond_wait(&ctx->hs_cv, &ctx->hs_mu);
        }
        if (!ctx->hs_running && !ctx->hs_head) {
            pthread_mutex_unlock(&ctx->hs_mu);
            break;
        }
        net_hs_job *job = ctx->hs_head;
        ctx->hs_head = job->next;
        if (!ctx->hs_head) {
            ctx->hs_tail = NULL;
        }
        ctx->hs_depth--;
        pthread_mutex_unlock(&ctx->hs_mu);

        if (job->kind == NET_HS_CLIENT) {
            hs_run_client(ctx, job);
        } else if (job->kind == NET_HS_SERVER) {
            hs_run_server(ctx, job);
        }
        free(job);
    }
    return NULL;
}

static int hs_enqueue(network_context *ctx, net_hs_job *job)
{
    if (!ctx->hs_mu_ready || !ctx->hs_running) {
        return -1;
    }
    pthread_mutex_lock(&ctx->hs_mu);
    if (!ctx->hs_running || ctx->hs_depth >= NET_HS_QUEUE_MAX) {
        pthread_mutex_unlock(&ctx->hs_mu);
        return -1;
    }
    if (ctx->hs_tail) {
        ctx->hs_tail->next = job;
    } else {
        ctx->hs_head = job;
    }
    ctx->hs_tail = job;
    ctx->hs_depth++;
    pthread_cond_signal(&ctx->hs_cv);
    pthread_mutex_unlock(&ctx->hs_mu);
    return 0;
}

static int hs_pool_start(network_context *ctx, uint32_t nworkers)
{
    if (nworkers == 0) {
        nworkers = NET_HS_WORKERS_DEFAULT;
    }
    if (nworkers > NET_HS_WORKERS_MAX) {
        nworkers = NET_HS_WORKERS_MAX;
    }
    if (pthread_mutex_init(&ctx->hs_mu, NULL) != 0 ||
        pthread_cond_init(&ctx->hs_cv, NULL) != 0) {
        return -1;
    }
    ctx->hs_mu_ready = true;
    ctx->hs_threads = calloc(nworkers, sizeof(pthread_t));
    if (!ctx->hs_threads) {
        pthread_mutex_destroy(&ctx->hs_mu);
        pthread_cond_destroy(&ctx->hs_cv);
        ctx->hs_mu_ready = false;
        return -1;
    }
    ctx->hs_nworkers = nworkers;
    ctx->hs_running = true;
    for (uint32_t i = 0; i < nworkers; i++) {
        if (pthread_create(&ctx->hs_threads[i], NULL, hs_worker_main, ctx) != 0) {
            ctx->hs_running = false;
            pthread_cond_broadcast(&ctx->hs_cv);
            for (uint32_t j = 0; j < i; j++) {
                pthread_join(ctx->hs_threads[j], NULL);
            }
            free(ctx->hs_threads);
            ctx->hs_threads = NULL;
            pthread_mutex_destroy(&ctx->hs_mu);
            pthread_cond_destroy(&ctx->hs_cv);
            ctx->hs_mu_ready = false;
            return -1;
        }
    }
    return 0;
}

static void hs_pool_stop(network_context *ctx)
{
    if (!ctx->hs_mu_ready) {
        return;
    }
    pthread_mutex_lock(&ctx->hs_mu);
    ctx->hs_running = false;
    pthread_cond_broadcast(&ctx->hs_cv);
    pthread_mutex_unlock(&ctx->hs_mu);
    for (uint32_t i = 0; i < ctx->hs_nworkers; i++) {
        pthread_join(ctx->hs_threads[i], NULL);
    }
    free(ctx->hs_threads);
    ctx->hs_threads = NULL;
    ctx->hs_nworkers = 0;
    while (ctx->hs_head) {
        net_hs_job *job = ctx->hs_head;
        ctx->hs_head = job->next;
        if (job->fd >= 0) {
            close(job->fd);
        }
        if (job->kind == NET_HS_CLIENT && job->conn_idx >= 0) {
            pthread_mutex_lock(&ctx->lock);
            if (job->conn_idx < ctx->conn_cap) {
                conn_fail_connecting(ctx, job->conn_idx);
            }
            pthread_mutex_unlock(&ctx->lock);
        }
        free(job);
    }
    ctx->hs_tail = NULL;
    ctx->hs_depth = 0;
    pthread_mutex_destroy(&ctx->hs_mu);
    pthread_cond_destroy(&ctx->hs_cv);
    ctx->hs_mu_ready = false;
}

/**
 * Finish CONNECTING → CONNECTED.
 * TCP poll stays on the net thread; blocking mTLS is queued to the HS pool
 * (inline fallback if the queue is full / pool down).
 */
static int finish_reconnect_mtls(network_context *ctx, int idx)
{
    int fd = -1;
    char host[256];

    pthread_mutex_lock(&ctx->lock);
    net_connection *c = &ctx->connections[idx];
    if (!c->in_use || c->info.state != DISLMDB_CONNECTION_CONNECTING) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    if (c->hs_inflight) {
        pthread_mutex_unlock(&ctx->lock);
        return -1; /* worker still finishing TLS */
    }
    if (c->fd < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    fd = c->fd;
    strncpy(host, c->info.hostname, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    bool need_mtls = ctx->mtls_enabled;
    pthread_mutex_unlock(&ctx->lock);

    int pr = poll_connect_ready(fd);
    if (pr == 1) {
        return -1; /* leave CONNECTING; try again next heartbeat */
    }
    if (pr != 0) {
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        if (ctx->connections[idx].in_use) {
            conn_fail_connecting(ctx, idx);
        }
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    if (!need_mtls) {
        pthread_mutex_lock(&ctx->lock);
        if (!ctx->connections[idx].in_use ||
            ctx->connections[idx].info.state != DISLMDB_CONNECTION_CONNECTING ||
            ctx->connections[idx].fd != fd) {
            pthread_mutex_unlock(&ctx->lock);
            close(fd);
            return -1;
        }
        if (find_other_live_peer(ctx, idx, ctx->connections[idx].info.node_id,
                                 ctx->connections[idx].info.hostname,
                                 ctx->connections[idx].listen_port) >= 0) {
            if (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
                ctx->connections[idx].listen_port != 0 && ctx->udp_fd >= 0) {
                ctx->connections[idx].fd = ctx->udp_fd;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
            } else {
                ctx->connections[idx].fd = -1;
                ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
            }
            pthread_mutex_unlock(&ctx->lock);
            close(fd);
            return 0;
        }
        ensure_io_lock(&ctx->connections[idx]);
        ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
        ctx->connections[idx].info.connect_time = dislmdb_get_time_ms();
        ctx->connections[idx].info.last_activity_time =
            ctx->connections[idx].info.connect_time;
        ctx->stats.active_connections++;
        pthread_mutex_unlock(&ctx->lock);
        return 0;
    }

    pthread_mutex_lock(&ctx->lock);
    if (!ctx->connections[idx].in_use ||
        ctx->connections[idx].info.state != DISLMDB_CONNECTION_CONNECTING ||
        ctx->connections[idx].fd != fd || ctx->connections[idx].hs_inflight) {
        pthread_mutex_unlock(&ctx->lock);
        close(fd);
        return -1;
    }
    ctx->connections[idx].fd = -1; /* lend to handshake */
    ctx->connections[idx].hs_inflight = true;
    pthread_mutex_unlock(&ctx->lock);

    net_hs_job *job = calloc(1, sizeof(*job));
    if (job) {
        job->kind = NET_HS_CLIENT;
        job->conn_idx = idx;
        job->fd = fd;
        strncpy(job->host, host, sizeof(job->host) - 1);
        if (hs_enqueue(ctx, job) == 0) {
            return -1; /* async — CONNECTED when worker finishes */
        }
        free(job);
    }
    /* Queue full / pool down — inline fallback so dials still complete. */
    dislmdb_mtls_session *tls = NULL;
    if (mtls_wrap_client(ctx, fd, host, &tls) != 0) {
        close(fd);
        pthread_mutex_lock(&ctx->lock);
        if (ctx->connections[idx].in_use) {
            conn_fail_connecting(ctx, idx);
        }
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    return attach_client_tls(ctx, idx, fd, tls);
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

    int send_idx[ctx->conn_cap];
    char reconnect_labels[ctx->conn_cap][64];
    int pending_mtls[ctx->conn_cap];
    int n_send = 0;
    int n_hello = 0;
    int n_pending = 0;
    uint64_t stale_limit = (uint64_t)interval * 5u;

    for (int i = 0; i < ctx->conn_cap; i++) {
        if (!ctx->connections[i].in_use) {
            continue;
        }
        /*
         * Reconnect / UDP revive when the slot has no live stream fd:
         *   UDP-only  → connectionless revive (fd = shared udp_fd) + HELLO
         *   TCP/BOTH  → dial TCP (BOTH must not stick on udp_fd or data
         *               never gets a stream and try_reconnect is skipped)
         */
        if (ctx->connections[i].outbound &&
            (ctx->connections[i].fd < 0 ||
             (ctx->transport == DISLMDB_TRANSPORT_UDP &&
              ctx->connections[i].info.state == DISLMDB_CONNECTION_CLOSED &&
              conn_can_udp(ctx, i)) ||
             (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
              ctx->connections[i].fd == ctx->udp_fd &&
              conn_tcp_fd(ctx, i) < 0 && conn_can_udp(ctx, i)))) {
            if (ctx->transport == DISLMDB_TRANSPORT_UDP && conn_can_udp(ctx, i)) {
                if (ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTED ||
                    ctx->connections[i].fd < 0) {
                    ctx->connections[i].info.state = DISLMDB_CONNECTION_CONNECTED;
                    ctx->connections[i].hello_reengage = true;
                    ctx->connections[i].fd = ctx->udp_fd;
                    ctx->stats.active_connections =
                        recount_active_connections_locked(ctx);
                    if (n_hello < ctx->conn_cap &&
                        ctx->connections[i].info.node_id[0] != '\0') {
                        strncpy(reconnect_labels[n_hello],
                                ctx->connections[i].info.node_id,
                                sizeof(reconnect_labels[n_hello]) - 1);
                        reconnect_labels[n_hello]
                            [sizeof(reconnect_labels[n_hello]) - 1] = '\0';
                        n_hello++;
                        ctx->connections[i].hello_reengage = false;
                    }
                }
                if (n_send < ctx->conn_cap) {
                    send_idx[n_send++] = i;
                }
                continue;
            }
            /* BOTH UDP placeholder or fd<0: keep signalling, optionally dial TCP. */
            if (ctx->transport == DISLMDB_TRANSPORT_BOTH && conn_can_udp(ctx, i) &&
                (ctx->connections[i].fd < 0 ||
                 ctx->connections[i].fd == ctx->udp_fd)) {
                if (ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTED) {
                    ctx->connections[i].info.state = DISLMDB_CONNECTION_CONNECTED;
                    ctx->connections[i].fd = ctx->udp_fd;
                    ctx->connections[i].hello_reengage = true;
                    ctx->stats.active_connections =
                        recount_active_connections_locked(ctx);
                }
                if (n_send < ctx->conn_cap) {
                    send_idx[n_send++] = i;
                }
            }
            if (ctx->connections[i].fd < 0 ||
                (ctx->transport == DISLMDB_TRANSPORT_BOTH &&
                 ctx->connections[i].fd == ctx->udp_fd)) {
                int tr = try_reconnect(ctx, i);
                if (tr == 1 && n_pending < ctx->conn_cap) {
                    pending_mtls[n_pending++] = i;
                } else if (tr == 0) {
                    strncpy(reconnect_labels[n_hello], ctx->connections[i].info.node_id,
                            sizeof(reconnect_labels[n_hello]) - 1);
                    reconnect_labels[n_hello][sizeof(reconnect_labels[n_hello]) - 1] =
                        '\0';
                    n_hello++;
                }
            }
            continue;
        }
        if (ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTING) {
            continue; /* finish_reconnect_mtls handles these */
        }
        /* Stale-close TCP streams only — BOTH demotes to UDP (see close_conn). */
        if (ctx->connections[i].outbound &&
            ctx->transport != DISLMDB_TRANSPORT_UDP &&
            conn_tcp_fd(ctx, i) >= 0 &&
            ctx->connections[i].info.last_activity_time > 0 &&
            now - ctx->connections[i].info.last_activity_time > stale_limit) {
            close_conn(ctx, i);
            continue;
        }
        if (n_send < ctx->conn_cap) {
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
                if (write_framed_adapt(ctx, send_idx[i], &hb, NULL) == DISLMDB_SUCCESS) {
                    pthread_mutex_lock(&ctx->lock);
                    if (ctx->connections[send_idx[i]].in_use) {
                        ctx->connections[send_idx[i]].info.last_activity_time =
                            dislmdb_get_time_ms();
                    }
                    pthread_mutex_unlock(&ctx->lock);
                }
            }
            dislmdb_network_free_message(&hb);
        }
    }

    extern int dislmdb_pbft_send_hello(DISLMDB_env *e, const char *t);
    for (int i = 0; i < n_hello; i++) {
        (void)dislmdb_pbft_send_hello(env, reconnect_labels[i]);
    }

    /* Drain per-peer outboxes now that reconnect / heartbeats ran. */
    int drain_idx[ctx->conn_cap];
    int n_drain = 0;
    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (ctx->connections[i].in_use && ctx->connections[i].outbox_count > 0 &&
            n_drain < ctx->conn_cap) {
            drain_idx[n_drain++] = i;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    outbox_drain_many(ctx, drain_idx, n_drain);
}

static int write_framed(network_context *ctx, int fd,
                        const DISLMDB_network_message *message)
{
    if (message->header.payload_size > DISLMDB_MAX_MESSAGE_SIZE) {
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }

    uint8_t plane_key[32];
    memcpy(plane_key, ctx->auth_key, 32);
    int cidx = -1;
    pthread_mutex_lock(&ctx->lock);
    cidx = find_conn_idx_for_target(ctx, message->header.target_id);
    if (cidx < 0 && message->header.target_id[0] == '\0') {
        /* broadcast: default plane */
    } else if (cidx >= 0) {
        if (plane_key_for_conn(ctx, &ctx->connections[cidx], plane_key) != 0) {
            ctx->stats.plane_auth_fail++;
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_ERR_NOT_AUTHORIZED;
        }
        if (ctx->rtt_budget_ms > 0 && ctx->connections[cidx].rtt_ewma_ms > 0 &&
            ctx->connections[cidx].rtt_ewma_ms > ctx->rtt_budget_ms) {
            ctx->stats.rtt_rejects++;
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_ERR_NODE_UNREACHABLE;
        }
        conn_note_tx(&ctx->connections[cidx]);
    }
    pthread_mutex_unlock(&ctx->lock);

    const uint8_t *wire_payload = message->payload;
    uint32_t wire_size = message->header.payload_size;
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    if (ctx->encrypt_payloads && wire_size > 0 && wire_payload) {
        if (dislmdb_aead_seal(plane_key, wire_payload, wire_size, &sealed, &sealed_len) != 0) {
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
        int rc = dislmdb_crypto_hmac_sha256(plane_key, sizeof(plane_key),
                                            tmp, total, hmac);
        free(tmp);
        if (rc != 0) {
            free(sealed);
            return DISLMDB_ERR_AUTH_FAILED;
        }
    }

    /* UDP path: DQGM v3 session envelope + framed message (QUIC/WT substrate). */
    if (ctx->udp_fd >= 0 && fd == ctx->udp_fd) {
        size_t body = NET_HEADER_WIRE_SIZE + wire_size + NET_HMAC_SIZE;
        size_t total = DISLMDB_DGRAM_ENVELOPE_V3_SIZE + body;
        if (total > 65507) {
            free(sealed);
            return DISLMDB_ERR_BUFFER_OVERFLOW;
        }
        uint8_t *dgram = malloc(total);
        if (!dgram) {
            free(sealed);
            return DISLMDB_ERR_MEMORY_ERROR;
        }
        uint64_t pkt;
        uint64_t ack = 0;
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        bool found = false;
        pthread_mutex_lock(&ctx->lock);
        if (ctx->dgram_pkt_num == 0) {
            ctx->dgram_pkt_num = 1;
        }
        pkt = ctx->dgram_pkt_num++;
        for (int i = 0; i < ctx->conn_cap; i++) {
            if (!ctx->connections[i].in_use ||
                ctx->connections[i].info.hostname[0] == '\0') {
                continue;
            }
            if (message->header.target_id[0] != '\0' &&
                strncmp(ctx->connections[i].info.node_id, message->header.target_id, 63) != 0) {
                continue;
            }
            /* Cumulative ACK: highest contiguous pkt accepted from this peer */
            if (ctx->connections[i].peer_pkt_seen) {
                ack = ctx->connections[i].peer_last_pkt;
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
        dislmdb_write_u32(dgram, DISLMDB_DQGM_MAGIC);
        dgram[4] = DISLMDB_DQGM_VERSION; /* v3: pkt_num + cumulative ack */
        /* First packet of a session advertises CID reset so peers can rebind. */
        dgram[5] = (pkt == 1ull) ? (uint8_t)DISLMDB_DQGM_FLAG_CID_RESET : 0u;
        /* stream_id: 0 = signalling, 1 = bulk/data (WebTransport-oriented) */
        uint16_t stream = dislmdb_network_is_signalling(message->header.type) ? 0u : 1u;
        dislmdb_write_u16(dgram + 6, stream);
        dislmdb_write_u64(dgram + 8, ctx->dgram_cid);
        dislmdb_write_u64(dgram + 16, pkt);
        dislmdb_write_u64(dgram + 24, ack);
        memcpy(dgram + DISLMDB_DGRAM_ENVELOPE_V3_SIZE, header_buf, NET_HEADER_WIRE_SIZE);
        if (wire_size > 0 && wire_payload) {
            memcpy(dgram + DISLMDB_DGRAM_ENVELOPE_V3_SIZE + NET_HEADER_WIRE_SIZE,
                   wire_payload, wire_size);
        }
        memcpy(dgram + DISLMDB_DGRAM_ENVELOPE_V3_SIZE + NET_HEADER_WIRE_SIZE + wire_size,
               hmac, NET_HMAC_SIZE);
        free(sealed);
        if (!found) {
            free(dgram);
            return DISLMDB_ERR_NODE_NOT_FOUND;
        }

        /* Prefer 1-RTT wrap when a QUIC session exists for this peer. */
        if (ctx->transport == DISLMDB_TRANSPORT_QUIC ||
            ctx->transport == DISLMDB_TRANSPORT_BOTH) {
            pthread_mutex_lock(&ctx->lock);
            net_quic_session *qs = NULL;
            for (uint32_t qi = 0; qi < NET_QUIC_SESSIONS_MAX; qi++) {
                if (!ctx->quic_sessions[qi].active ||
                    !ctx->quic_sessions[qi].conn.has_app_keys) {
                    continue;
                }
                if (ctx->quic_sessions[qi].peer.sin_addr.s_addr ==
                        to.sin_addr.s_addr &&
                    ctx->quic_sessions[qi].peer.sin_port == to.sin_port) {
                    qs = &ctx->quic_sessions[qi];
                    break;
                }
            }
            if (qs) {
                uint8_t qpkt[4096];
                size_t qpkt_len = 0;
                uint64_t qpn = qs->conn.next_pn_out++;
                bool from_client = !qs->conn.is_server;
                int qrc = dislmdb_quic_build_one_rtt_packet(
                    &qs->conn, from_client, qpn & 0xffu, dgram, total, qpkt,
                    sizeof(qpkt), &qpkt_len);
                pthread_mutex_unlock(&ctx->lock);
                free(dgram);
                if (qrc != 0) {
                    return DISLMDB_ERR_NETWORK;
                }
                ssize_t sn =
                    sendto(fd, qpkt, qpkt_len, 0, (struct sockaddr *)&to,
                           sizeof(to));
                return sn == (ssize_t)qpkt_len ? DISLMDB_SUCCESS
                                               : DISLMDB_ERR_NETWORK;
            }
            pthread_mutex_unlock(&ctx->lock);
            if (ctx->transport == DISLMDB_TRANSPORT_QUIC) {
                free(dgram);
                return DISLMDB_ERR_NODE_UNREACHABLE;
            }
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

    uint8_t used_key[32];
    memcpy(used_key, ctx->auth_key, 32);
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
        bool ok = false;
        const uint8_t *candidates[3];
        int nc = 0;
        candidates[nc++] = ctx->auth_key;
        if (ctx->has_region_key) {
            candidates[nc++] = ctx->region_key;
        }
        if (ctx->has_cross_region_key) {
            candidates[nc++] = ctx->cross_region_key;
        }
        for (int ki = 0; ki < nc && !ok; ki++) {
            uint8_t expected[NET_HMAC_SIZE];
            if (dislmdb_crypto_hmac_sha256(candidates[ki], 32, tmp, total, expected) == 0 &&
                dislmdb_crypto_secure_eq(expected, hmac, NET_HMAC_SIZE)) {
                memcpy(used_key, candidates[ki], 32);
                ok = true;
            }
        }
        free(tmp);
        if (!ok) {
            ctx->stats.plane_auth_fail++;
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
        if (dislmdb_aead_open(used_key, payload, hdr.payload_size, &plain, &plain_len) != 0) {
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

int dislmdb_network_set_plane_keys(DISLMDB_env *env,
                                   const uint8_t *region_key, bool has_region,
                                   const uint8_t *cross_key, bool has_cross)
{
    if (!env || !env->network_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (has_region && !region_key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (has_cross && !cross_key) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    ctx->has_region_key = has_region;
    ctx->has_cross_region_key = has_cross;
    if (has_region) {
        memcpy(ctx->region_key, region_key, 32);
    }
    if (has_cross) {
        memcpy(ctx->cross_region_key, cross_key, 32);
    }
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

bool dislmdb_network_rtt_within_budget(DISLMDB_env *env, const char *node_id)
{
    if (!env || !env->network_context || !node_id) {
        return true;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    uint32_t budget = ctx->rtt_budget_ms;
    int idx = find_conn_by_id(ctx, node_id);
    uint32_t ewma = (idx >= 0) ? ctx->connections[idx].rtt_ewma_ms : 0;
    pthread_mutex_unlock(&ctx->lock);
    if (budget == 0 || ewma == 0) {
        return true;
    }
    return ewma <= budget;
}

int dislmdb_network_set_rtt_ewma(DISLMDB_env *env, const char *node_id, uint32_t ms)
{
    if (!env || !env->network_context || !node_id || node_id[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    ctx->connections[idx].rtt_ewma_ms = ms;
    ctx->connections[idx].info.rtt_ewma_ms = ms;
    pthread_mutex_unlock(&ctx->lock);
    return DISLMDB_SUCCESS;
}

int dislmdb_network_set_peer_topo(DISLMDB_env *env,
                                  const char *node_id,
                                  const char *region,
                                  const char *locality,
                                  bool peer_voting)
{
    if (!env || !env->network_context || !node_id || node_id[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    if (idx < 0) {
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    net_connection *c = &ctx->connections[idx];
    if (region) {
        strncpy(c->peer_region, region, sizeof(c->peer_region) - 1);
        c->peer_region[sizeof(c->peer_region) - 1] = '\0';
        strncpy(c->info.region, region, sizeof(c->info.region) - 1);
        c->info.region[sizeof(c->info.region) - 1] = '\0';
    }
    if (locality) {
        strncpy(c->peer_locality, locality, sizeof(c->peer_locality) - 1);
        c->peer_locality[sizeof(c->peer_locality) - 1] = '\0';
        strncpy(c->info.locality, locality, sizeof(c->info.locality) - 1);
        c->info.locality[sizeof(c->info.locality) - 1] = '\0';
    }
    c->peer_voting = peer_voting;
    c->info.peer_voting = peer_voting;
    pthread_mutex_unlock(&ctx->lock);

    /* Mirror onto env node table when present. */
    pthread_mutex_lock(&env->nodes_mutex);
    for (uint32_t i = 0; i < env->node_count; i++) {
        if (strncmp(env->nodes[i].node_id, node_id, 63) == 0) {
            if (region && region[0] != '\0') {
                strncpy(env->nodes[i].region, region, sizeof(env->nodes[i].region) - 1);
            }
            if (locality && locality[0] != '\0') {
                strncpy(env->nodes[i].locality, locality,
                        sizeof(env->nodes[i].locality) - 1);
            }
            break;
        }
    }
    pthread_mutex_unlock(&env->nodes_mutex);
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
    if (msg->header.sender_id[0] != '\0') {
        int si = find_conn_by_id(ctx, msg->header.sender_id);
        if (si >= 0) {
            conn_note_rx(&ctx->connections[si]);
        }
    }
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
        /*
         * Wait backend: Darwin/BSD kqueue (EV_ONESHOT, rebuild each tick) or
         * portable poll(). Both scale past FD_SETSIZE; rebuild keeps growable
         * conn tables correct without sticky registration state.
         */
        pthread_mutex_lock(&ctx->lock);
        int nslot = 3 + ctx->conn_cap;
        int conn_cap_snap = ctx->conn_cap;
        pthread_mutex_unlock(&ctx->lock);
        struct pollfd *pfds = calloc((size_t)nslot, sizeof(*pfds));
        if (!pfds) {
            dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "pollfd alloc failed");
            break;
        }
        int np = 0;
        if (ctx->listen_fd >= 0) {
            pfds[np].fd = ctx->listen_fd;
            pfds[np].events = POLLIN;
            np++;
        }
        if (ctx->wake_r >= 0) {
            pfds[np].fd = ctx->wake_r;
            pfds[np].events = POLLIN;
            np++;
        }
        pthread_mutex_lock(&ctx->lock);
        if (ctx->udp_fd >= 0) {
            pfds[np].fd = ctx->udp_fd;
            pfds[np].events = POLLIN;
            np++;
        }
        for (int i = 0; i < conn_cap_snap && i < ctx->conn_cap && np < nslot; i++) {
            /* Shared UDP socket is polled once above; skip per-conn UDP fds */
            if (ctx->connections[i].in_use && ctx->connections[i].fd >= 0 &&
                ctx->connections[i].fd != ctx->udp_fd) {
                pfds[np].fd = ctx->connections[i].fd;
                pfds[np].events = POLLIN;
                np++;
            }
        }
        pthread_mutex_unlock(&ctx->lock);

        /* Short timeout so shutdown cannot sit in the wait for a full second */
        int ready = 0;
#if defined(__linux__)
        if (ctx->uring && np > 0) {
            int *fdlist = calloc((size_t)np, sizeof(int));
            int *ready_fds = calloc((size_t)np, sizeof(int));
            if (!fdlist || !ready_fds) {
                free(fdlist);
                free(ready_fds);
                free(pfds);
                dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "io_uring fdlist alloc failed");
                break;
            }
            for (int i = 0; i < np; i++) {
                fdlist[i] = pfds[i].fd;
            }
            int nready = 0;
            ready = dislmdb_iouring_wait_readable(ctx->uring, fdlist, np, ready_fds,
                                                  np, &nready, 250);
            if (ready < 0) {
                free(fdlist);
                free(ready_fds);
                free(pfds);
                if (errno == EINTR) {
                    continue;
                }
                dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "io_uring wait failed: %s",
                            strerror(errno));
                break;
            }
            for (int i = 0; i < nready; i++) {
                int efd = ready_fds[i];
                for (int j = 0; j < np; j++) {
                    if (pfds[j].fd == efd) {
                        pfds[j].revents = POLLIN;
                        break;
                    }
                }
            }
            free(fdlist);
            free(ready_fds);
        } else
#endif
#if defined(DISLMDB_NET_HAS_KQUEUE)
        if (ctx->kq >= 0 && np > 0) {
            struct kevent *ch = calloc((size_t)np, sizeof(*ch));
            struct kevent *ev = calloc((size_t)np, sizeof(*ev));
            if (!ch || !ev) {
                free(ch);
                free(ev);
                free(pfds);
                dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "kevent alloc failed");
                break;
            }
            for (int i = 0; i < np; i++) {
                EV_SET(&ch[i], (uintptr_t)pfds[i].fd, EVFILT_READ,
                       EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0, NULL);
            }
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 250L * 1000L * 1000L};
            ready = kevent(ctx->kq, ch, np, ev, np, &ts);
            if (ready > 0) {
                for (int i = 0; i < ready; i++) {
                    int efd = (int)ev[i].ident;
                    short rev = POLLIN;
                    if (ev[i].flags & EV_ERROR) {
                        rev = (short)(rev | POLLERR);
                    }
                    if (ev[i].flags & EV_EOF) {
                        rev = (short)(rev | POLLHUP);
                    }
                    for (int j = 0; j < np; j++) {
                        if (pfds[j].fd == efd) {
                            pfds[j].revents = rev;
                            break;
                        }
                    }
                }
            }
            free(ch);
            free(ev);
            if (ready < 0) {
                free(pfds);
                if (errno == EINTR) {
                    continue;
                }
                dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "kevent failed: %s",
                            strerror(errno));
                break;
            }
        } else
#endif
        {
            ready = poll(pfds, (nfds_t)np, 250);
            if (ready < 0) {
                free(pfds);
                if (errno == EINTR) {
                    continue;
                }
                dislmdb_log(env, DISLMDB_LOG_ERROR, "NET", "poll failed: %s",
                            strerror(errno));
                break;
            }
        }
        if (!ctx->running) {
            free(pfds);
            break;
        }
        if (ctx->wake_r >= 0 && poll_readable(pfds, np, ctx->wake_r)) {
            uint8_t drain[64];
            while (read(ctx->wake_r, drain, sizeof(drain)) > 0) {
            }
            if (!ctx->running) {
                free(pfds);
                break;
            }
        }

        /*
         * Drain ready sockets BEFORE heartbeats / mTLS reconnect. Handshakes
         * block the net thread; processing UDP first keeps Raft elections
         * and AppendEntries flowing under BOTH+mTLS.
         */
        if (ready > 0 && ctx->udp_fd >= 0 && poll_readable(pfds, np, ctx->udp_fd)) {
            uint8_t dgram[65536];
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            ssize_t n = recvfrom(ctx->udp_fd, dgram, sizeof(dgram), 0,
                                 (struct sockaddr *)&peer, &plen);
            bool skip_framed = false;
            uint8_t quic_dqgm[2048];
            size_t quic_dqgm_len = 0;
            bool have_quic_dqgm = false;
            if (n > 0) {
                /*
                 * QUIC long-header (not DQGM): Version Negotiation for foreign
                 * versions; DISLMDB_QUIC_VERSION Initial → substrate handshake
                 * reply (SH Initial + EE/Cert/CV/Fin Handshake). 1-RTT CRYPTO
                 * may carry a DQGM envelope for the framed path below.
                 */
                dislmdb_quic_dgram_kind qk =
                    dislmdb_quic_classify(dgram, (size_t)n);
                if (qk == DISLMDB_QUIC_DGRAM_QUIC_LONG ||
                    qk == DISLMDB_QUIC_DGRAM_VERSION_NEG ||
                    qk == DISLMDB_QUIC_DGRAM_QUIC_SHORT) {
                    if (qk == DISLMDB_QUIC_DGRAM_QUIC_LONG) {
                        dislmdb_quic_long_header qh;
                        if (dislmdb_quic_parse_long_header(dgram, (size_t)n,
                                                           &qh) == 0) {
                            if (qh.version != DISLMDB_QUIC_VERSION &&
                                qh.version != DISLMDB_QUIC_VERSION_NEGOTIATION) {
                                uint8_t vn[256];
                                size_t vn_len = 0;
                                if (dislmdb_quic_encode_version_negotiation(
                                        &qh, vn, sizeof(vn), &vn_len) == 0 &&
                                    vn_len > 0) {
                                    (void)sendto(ctx->udp_fd, vn, vn_len, 0,
                                                 (struct sockaddr *)&peer, plen);
                                    pthread_mutex_lock(&ctx->lock);
                                    ctx->stats.total_messages_sent++;
                                    pthread_mutex_unlock(&ctx->lock);
                                }
                            } else if (qh.version == DISLMDB_QUIC_VERSION &&
                                       qh.type == DISLMDB_QUIC_LONG_INITIAL) {
                                /* Simultaneous dial: peer Initial may be their
                                 * ClientHello, not our ServerHello — only treat
                                 * as SH when open succeeds; else server-handle
                                 * and/or retransmit our lost Initial. */
                                bool took_as_client_sh = false;
                                uint8_t early_cfin[512];
                                size_t early_cfin_len = 0;
                                char early_hello[64] = {0};
                                struct sockaddr_in early_peer;
                                bool early_done = false;
                                uint8_t retx[512];
                                size_t retx_len = 0;
                                memset(&early_peer, 0, sizeof(early_peer));
                                pthread_mutex_lock(&ctx->lock);
                                net_quic_pending *pend =
                                    quic_pending_find_peer(ctx, &peer);
                                if (pend && !pend->have_sh &&
                                    (size_t)n <= sizeof(pend->server_initial)) {
                                    uint64_t spn = 0;
                                    uint8_t try_sh[sizeof(pend->sh)];
                                    size_t try_sh_len = 0;
                                    if (dislmdb_quic_open_initial_packet(
                                            &pend->conn, false, dgram, (size_t)n,
                                            &spn, try_sh, sizeof(try_sh),
                                            &try_sh_len) == 0 &&
                                        try_sh_len > 0) {
                                        memcpy(pend->server_initial, dgram,
                                               (size_t)n);
                                        pend->server_initial_len = (size_t)n;
                                        memcpy(pend->sh, try_sh, try_sh_len);
                                        pend->sh_len = try_sh_len;
                                        pend->have_sh = true;
                                        took_as_client_sh = true;
                                        early_done = quic_pending_try_complete(
                                            ctx, pend, early_cfin,
                                            sizeof(early_cfin), &early_cfin_len,
                                            early_hello, sizeof(early_hello),
                                            &early_peer);
                                    } else if (pend->client_initial_len > 0 &&
                                               pend->client_initial_len <=
                                                   sizeof(retx)) {
                                        /* Peer CH or lost SH — re-poke dial. */
                                        memcpy(retx, pend->client_initial,
                                               pend->client_initial_len);
                                        retx_len = pend->client_initial_len;
                                    }
                                }
                                pthread_mutex_unlock(&ctx->lock);
                                if (early_done) {
                                    if (early_cfin_len > 0) {
                                        (void)sendto(ctx->udp_fd, early_cfin,
                                                     early_cfin_len, 0,
                                                     (struct sockaddr *)&early_peer,
                                                     sizeof(early_peer));
                                    }
                                    if (early_hello[0] != '\0') {
                                        extern int dislmdb_pbft_send_hello(
                                            DISLMDB_env *e, const char *t);
                                        (void)dislmdb_pbft_send_hello(ctx->env,
                                                                      early_hello);
                                    }
                                }
                                if (retx_len > 0) {
                                    (void)sendto(ctx->udp_fd, retx, retx_len, 0,
                                                 (struct sockaddr *)&peer, plen);
                                }
                                if (!took_as_client_sh) {
                                    /*
                                     * Simultaneous open: higher listen port
                                     * takes server role; lower stays client and
                                     * waits for SH. No outbound pending → we
                                     * are the passive peer (always server).
                                     */
                                    uint16_t our_port =
                                        ctx->env
                                            ? ctx->env->config.network.local_port
                                            : 0;
                                    uint16_t peer_port = ntohs(peer.sin_port);
                                    bool have_outbound = false;
                                    pthread_mutex_lock(&ctx->lock);
                                    have_outbound =
                                        quic_pending_find_peer(ctx, &peer) !=
                                        NULL;
                                    pthread_mutex_unlock(&ctx->lock);
                                    bool we_should_server =
                                        !have_outbound ||
                                        (our_port > peer_port);
                                    if (we_should_server) {
                                    uint8_t ini[2048], hsp[8192];
                                    size_t ini_len = 0, hsp_len = 0;
                                    dislmdb_quic_conn qconn;
                                    memset(&qconn, 0, sizeof(qconn));
                                    if (dislmdb_quic_server_handle_initial(
                                            dgram, (size_t)n, ini, sizeof(ini),
                                            &ini_len, hsp, sizeof(hsp), &hsp_len,
                                            &qconn, ctx->quic_identity) == 0) {
                                        if (ini_len > 0) {
                                            (void)sendto(ctx->udp_fd, ini, ini_len,
                                                         0,
                                                         (struct sockaddr *)&peer,
                                                         plen);
                                        }
                                        if (hsp_len > 0) {
                                            (void)sendto(ctx->udp_fd, hsp, hsp_len,
                                                         0,
                                                         (struct sockaddr *)&peer,
                                                         plen);
                                        }
                                        pthread_mutex_lock(&ctx->lock);
                                        net_quic_pending *drop =
                                            quic_pending_find_peer(ctx, &peer);
                                        if (drop) {
                                            drop->active = false;
                                            dislmdb_quic_conn_reset(&drop->conn);
                                        }
                                        (void)quic_session_store(ctx, &qconn,
                                                                 &peer);
                                        ctx->stats.total_messages_sent +=
                                            (ini_len > 0 ? 1u : 0u) +
                                            (hsp_len > 0 ? 1u : 0u);
                                        pthread_mutex_unlock(&ctx->lock);
                                    }
                                    } /* we_should_server */
                                }
                            } else if (qh.version == DISLMDB_QUIC_VERSION &&
                                       qh.type == DISLMDB_QUIC_LONG_HANDSHAKE) {
                                uint8_t cfin[512];
                                size_t cfin_len = 0;
                                char hello_id[64] = {0};
                                struct sockaddr_in hs_peer;
                                bool hs_done = false;
                                memset(&hs_peer, 0, sizeof(hs_peer));
                                pthread_mutex_lock(&ctx->lock);
                                net_quic_pending *pend =
                                    quic_pending_find_peer(ctx, &peer);
                                if (pend && (size_t)n <= sizeof(pend->server_hs)) {
                                    memcpy(pend->server_hs, dgram, (size_t)n);
                                    pend->server_hs_len = (size_t)n;
                                    hs_done = quic_pending_try_complete(
                                        ctx, pend, cfin, sizeof(cfin), &cfin_len,
                                        hello_id, sizeof(hello_id), &hs_peer);
                                }
                                pthread_mutex_unlock(&ctx->lock);
                                if (hs_done) {
                                    if (cfin_len > 0) {
                                        (void)sendto(ctx->udp_fd, cfin, cfin_len, 0,
                                                     (struct sockaddr *)&hs_peer,
                                                     sizeof(hs_peer));
                                    }
                                    if (hello_id[0] != '\0') {
                                        extern int dislmdb_pbft_send_hello(
                                            DISLMDB_env *e, const char *t);
                                        (void)dislmdb_pbft_send_hello(ctx->env,
                                                                      hello_id);
                                    }
                                }
                            }
                        }
                    } else if (qk == DISLMDB_QUIC_DGRAM_QUIC_SHORT &&
                               (size_t)n >= 1 + 8) {
                        /* Try 8-byte DCID first (our server CIDs are 8 bytes). */
                        size_t try_lens[] = {8, 4, 16, 20};
                        net_quic_session *qs = NULL;
                        pthread_mutex_lock(&ctx->lock);
                        for (size_t ti = 0;
                             ti < sizeof(try_lens) / sizeof(try_lens[0]); ti++) {
                            if ((size_t)n < 1 + try_lens[ti] + 1 + 16) {
                                continue;
                            }
                            qs = quic_session_find(ctx, dgram + 1, try_lens[ti]);
                            if (qs) {
                                break;
                            }
                        }
                        if (qs) {
                            uint64_t qpn = 0;
                            uint8_t plain[2048];
                            size_t plain_len = 0;
                            bool from_client = qs->conn.is_server;
                            if (dislmdb_quic_open_one_rtt_packet(
                                    &qs->conn, from_client, dgram, (size_t)n, &qpn,
                                    plain, sizeof(plain), &plain_len) == 0 &&
                                plain_len > 0 && plain_len <= sizeof(quic_dqgm)) {
                                qs->peer = peer;
                                ctx->stats.total_messages_received++;
                                memcpy(quic_dqgm, plain, plain_len);
                                quic_dqgm_len = plain_len;
                                have_quic_dqgm = true;
                            }
                        }
                        pthread_mutex_unlock(&ctx->lock);
                    }
                    if (!have_quic_dqgm) {
                        skip_framed = true;
                    }
                }
            }
            if (have_quic_dqgm ||
                (!skip_framed &&
                 n > (ssize_t)(NET_HEADER_WIRE_SIZE + NET_HMAC_SIZE))) {
                /* Strip DQGM session envelope (v1/v2/v3 — ack on v3). */
                const uint8_t *dgram_body =
                    have_quic_dqgm ? quic_dqgm : dgram;
                size_t dgram_body_len =
                    have_quic_dqgm ? quic_dqgm_len : (size_t)n;
                const uint8_t *frame = dgram_body;
                size_t frame_len = dgram_body_len;
                bool has_dqgm = false;
                bool has_pkt = false;
                bool has_ack = false;
                uint8_t dqgm_flags = 0;
                uint64_t dqgm_cid = 0;
                uint64_t dqgm_pkt = 0;
                uint64_t dqgm_ack = 0;
                if (frame_len >= DISLMDB_DGRAM_ENVELOPE_V1_SIZE &&
                    dislmdb_read_u32(dgram_body) == DISLMDB_DQGM_MAGIC) {
                    uint8_t ver = dgram_body[4];
                    dqgm_flags = dgram_body[5];
                    if (ver == 3 && frame_len >= DISLMDB_DGRAM_ENVELOPE_V3_SIZE) {
                        has_dqgm = true;
                        has_pkt = true;
                        has_ack = true;
                        dqgm_cid = dislmdb_read_u64(dgram_body + 8);
                        dqgm_pkt = dislmdb_read_u64(dgram_body + 16);
                        dqgm_ack = dislmdb_read_u64(dgram_body + 24);
                        frame = dgram_body + DISLMDB_DGRAM_ENVELOPE_V3_SIZE;
                        frame_len -= DISLMDB_DGRAM_ENVELOPE_V3_SIZE;
                    } else if (ver == 2 &&
                               frame_len >= DISLMDB_DGRAM_ENVELOPE_V2_SIZE) {
                        has_dqgm = true;
                        has_pkt = true;
                        dqgm_cid = dislmdb_read_u64(dgram_body + 8);
                        dqgm_pkt = dislmdb_read_u64(dgram_body + 16);
                        frame = dgram_body + DISLMDB_DGRAM_ENVELOPE_V2_SIZE;
                        frame_len -= DISLMDB_DGRAM_ENVELOPE_V2_SIZE;
                    } else if (ver == 1) {
                        has_dqgm = true;
                        dqgm_cid = dislmdb_read_u64(dgram_body + 8);
                        frame = dgram_body + DISLMDB_DGRAM_ENVELOPE_V1_SIZE;
                        frame_len -= DISLMDB_DGRAM_ENVELOPE_V1_SIZE;
                    }
                }
                if (frame_len > (size_t)(NET_HEADER_WIRE_SIZE + NET_HMAC_SIZE)) {
                /* In-memory framed parse from datagram */
                DISLMDB_network_message msg;
                memset(&msg, 0, sizeof(msg));
                uint8_t hdr[NET_HEADER_WIRE_SIZE];
                memcpy(hdr, frame, NET_HEADER_WIRE_SIZE);
                unpack_header(hdr, &msg.header);
                uint32_t psz = msg.header.payload_size;
                size_t need = NET_HEADER_WIRE_SIZE + psz + NET_HMAC_SIZE;
                if (psz <= DISLMDB_MAX_MESSAGE_SIZE && frame_len >= need) {
                    if (psz > 0) {
                        msg.payload = malloc(psz);
                        if (msg.payload) {
                            memcpy(msg.payload, frame + NET_HEADER_WIRE_SIZE, psz);
                        }
                    }
                    bool auth_ok = true;
                    uint8_t used_key[32];
                    memcpy(used_key, ctx->auth_key, 32);
                    if (ctx->auth_enabled) {
                        uint8_t expect[NET_HMAC_SIZE];
                        memcpy(expect, frame + NET_HEADER_WIRE_SIZE + psz, NET_HMAC_SIZE);
                        const uint8_t *cands[3];
                        int nc = 0;
                        cands[nc++] = ctx->auth_key;
                        if (ctx->has_region_key) {
                            cands[nc++] = ctx->region_key;
                        }
                        if (ctx->has_cross_region_key) {
                            cands[nc++] = ctx->cross_region_key;
                        }
                        auth_ok = false;
                        for (int ki = 0; ki < nc; ki++) {
                            uint8_t mac[NET_HMAC_SIZE];
                            if (dislmdb_crypto_hmac_sha256(cands[ki], 32, frame,
                                                           NET_HEADER_WIRE_SIZE + psz,
                                                           mac) == 0 &&
                                dislmdb_crypto_secure_eq(mac, expect, NET_HMAC_SIZE)) {
                                memcpy(used_key, cands[ki], 32);
                                auth_ok = true;
                                break;
                            }
                        }
                        if (!auth_ok) {
                            ctx->stats.plane_auth_fail++;
                        }
                    }
                    if (auth_ok && (msg.header.flags & 0x1u) != 0 &&
                        ctx->encrypt_payloads && msg.payload && psz > 0) {
                        uint8_t *plain = NULL;
                        size_t plain_len = 0;
                        if (dislmdb_aead_open(used_key, msg.payload, psz,
                                              &plain, &plain_len) != 0) {
                            auth_ok = false;
                        } else {
                            free(msg.payload);
                            msg.payload = plain;
                            msg.header.payload_size = (uint32_t)plain_len;
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
                            for (int i = 0; i < ctx->conn_cap; i++) {
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
                            if (sport != 0) {
                                ctx->connections[idx].info.port = sport;
                            }
                            if (ctx->connections[idx].info.hostname[0] == '\0') {
                                strncpy(ctx->connections[idx].info.hostname, host,
                                        sizeof(ctx->connections[idx].info.hostname) - 1);
                            }
                            /*
                             * Peer restart / stale-close: datagram proves the
                             * peer is reachable. Revive CLOSED slots so
                             * broadcast includes them. Pure UDP may bind the
                             * shared datagram fd; BOTH/TCP keep fd unset so
                             * heartbeat can dial a stream.
                             */
                            if (ctx->connections[idx].info.state !=
                                    DISLMDB_CONNECTION_CONNECTED &&
                                ctx->connections[idx].info.state !=
                                    DISLMDB_CONNECTION_CONNECTING) {
                                ctx->connections[idx].info.state =
                                    DISLMDB_CONNECTION_CONNECTED;
                                ctx->connections[idx].hello_reengage = true;
                                if (ctx->transport == DISLMDB_TRANSPORT_UDP &&
                                    ctx->udp_fd >= 0 &&
                                    (ctx->connections[idx].fd < 0 ||
                                     ctx->connections[idx].fd == ctx->udp_fd)) {
                                    ctx->connections[idx].fd = ctx->udp_fd;
                                }
                                ctx->stats.active_connections =
                                    recount_active_connections_locked(ctx);
                            }
                        }
                        bool cid_ok = true;
                        if (idx >= 0 && has_dqgm) {
                            bool session_reset =
                                (dqgm_flags & DISLMDB_DQGM_FLAG_CID_RESET) != 0 ||
                                (has_pkt && dqgm_pkt == 1ull);
                            if (!ctx->connections[idx].peer_cid_bound) {
                                ctx->connections[idx].peer_dgram_cid = dqgm_cid;
                                ctx->connections[idx].peer_cid_bound = true;
                            } else if (ctx->connections[idx].peer_dgram_cid != dqgm_cid) {
                                if (session_reset) {
                                    ctx->connections[idx].peer_dgram_cid = dqgm_cid;
                                    ctx->connections[idx].peer_last_pkt = 0;
                                    ctx->connections[idx].peer_pkt_seen = false;
                                    ctx->stats.dqgm_session_rebind++;
                                } else {
                                    cid_ok = false;
                                    ctx->stats.dqgm_cid_mismatch++;
                                    ctx->stats.total_errors++;
                                }
                            } else if (session_reset) {
                                /* Same CID but sender restarted pkt space */
                                ctx->connections[idx].peer_last_pkt = 0;
                                ctx->connections[idx].peer_pkt_seen = false;
                                ctx->stats.dqgm_session_rebind++;
                            }
                            if (cid_ok && has_pkt) {
                                if (ctx->connections[idx].peer_pkt_seen &&
                                    dqgm_pkt <= ctx->connections[idx].peer_last_pkt) {
                                    cid_ok = false;
                                    ctx->stats.dqgm_replay_drop++;
                                    ctx->stats.total_errors++;
                                } else {
                                    ctx->connections[idx].peer_last_pkt = dqgm_pkt;
                                    ctx->connections[idx].peer_pkt_seen = true;
                                }
                            }
                            if (cid_ok && has_ack) {
                                ctx->stats.dqgm_ack_rx++;
                                if (dqgm_ack > ctx->connections[idx].local_acked_pkt) {
                                    ctx->connections[idx].local_acked_pkt = dqgm_ack;
                                    ctx->stats.dqgm_ack_advance++;
                                }
                            }
                            if (cid_ok) {
                                ctx->stats.dqgm_packets_rx++;
                            }
                        }
                        if (idx >= 0 && msg.header.sender_id[0] != '\0') {
                            char *nid = ctx->connections[idx].info.node_id;
                            if (nid[0] == '\0' || strncmp(nid, "seed-", 5) == 0) {
                                strncpy(nid, msg.header.sender_id, 63);
                            }
                            ctx->connections[idx].info.last_activity_time = dislmdb_get_time_ms();
                            ctx->connections[idx].info.messages_received++;
                        }
                        pthread_mutex_unlock(&ctx->lock);
                        if (cid_ok && msg.header.type != DISLMDB_MESSAGE_HEARTBEAT) {
                            dispatch_message(ctx, &msg);
                        }
                    }
                    free(msg.payload);
                }
                } /* frame_len large enough */
            }
        }

        if (ready > 0 && ctx->listen_fd >= 0 && poll_readable(pfds, np, ctx->listen_fd)) {
            struct sockaddr_in peer;
            socklen_t plen = sizeof(peer);
            int cfd = accept(ctx->listen_fd, (struct sockaddr *)&peer, &plen);
            if (cfd >= 0) {
                prepare_tcp_fd(cfd);
                (void)set_nonblocking(cfd);
                char hostbuf[64];
                inet_ntop(AF_INET, &peer.sin_addr, hostbuf, sizeof(hostbuf));
                uint16_t peer_port = ntohs(peer.sin_port);
                if (ctx->mtls_enabled) {
                    net_hs_job *job = calloc(1, sizeof(*job));
                    bool queued = false;
                    if (job) {
                        job->kind = NET_HS_SERVER;
                        job->conn_idx = -1;
                        job->fd = cfd;
                        job->peer_port = peer_port;
                        strncpy(job->host, hostbuf, sizeof(job->host) - 1);
                        if (hs_enqueue(ctx, job) == 0) {
                            queued = true;
                        } else {
                            free(job);
                        }
                    }
                    if (!queued) {
                        /* Inline fallback when HS queue is saturated. */
                        dislmdb_mtls_session *tls = NULL;
                        if (mtls_wrap_server(ctx, cfd, &tls) != 0) {
                            close(cfd);
                            pthread_mutex_lock(&ctx->lock);
                            ctx->stats.connection_failures++;
                            pthread_mutex_unlock(&ctx->lock);
                        } else {
                            (void)attach_server_tls(ctx, cfd, tls, hostbuf, peer_port);
                        }
                    }
                } else {
                    (void)attach_server_tls(ctx, cfd, NULL, hostbuf, peer_port);
                }
            }
        }

        for (int i = 0; i < ctx->conn_cap; i++) {
            int fd = -1;
            dislmdb_mtls_session *tls = NULL;
            bool have_io = false;
            pthread_mutex_lock(&ctx->lock);
            if (ctx->connections[i].in_use) {
                fd = ctx->connections[i].fd;
                tls = ctx->connections[i].tls;
                have_io = ctx->connections[i].io_lock_ready;
            }
            pthread_mutex_unlock(&ctx->lock);
            /* Shared UDP socket is drained above — never stream-read it. */
            if (fd < 0 || fd == ctx->udp_fd) {
                continue;
            }
            /* TLS may have app data buffered after TCP is drained — poll alone misses it. */
            bool sock_ready = poll_readable(pfds, np, fd);
            bool tls_ready = tls && dislmdb_mtls_pending(tls);
            if (!sock_ready && !tls_ready) {
                continue;
            }

            DISLMDB_network_message msg;
            memset(&msg, 0, sizeof(msg));
            if (have_io) {
                pthread_mutex_lock(&ctx->connections[i].io_lock);
            }
            int rc = read_framed(ctx, fd, &msg);
            if (have_io) {
                pthread_mutex_unlock(&ctx->connections[i].io_lock);
            }
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

            /* Drain remaining TLS app-data without waiting for poll */
            while (ctx->mtls_enabled) {
                pthread_mutex_lock(&ctx->lock);
                if (!ctx->connections[i].in_use) {
                    pthread_mutex_unlock(&ctx->lock);
                    break;
                }
                tls = ctx->connections[i].tls;
                fd = ctx->connections[i].fd;
                have_io = ctx->connections[i].io_lock_ready;
                pthread_mutex_unlock(&ctx->lock);
                if (fd < 0 || !tls || !dislmdb_mtls_pending(tls)) {
                    break;
                }
                memset(&msg, 0, sizeof(msg));
                if (have_io) {
                    pthread_mutex_lock(&ctx->connections[i].io_lock);
                }
                rc = read_framed(ctx, fd, &msg);
                if (have_io) {
                    pthread_mutex_unlock(&ctx->connections[i].io_lock);
                }
                if (rc != DISLMDB_SUCCESS) {
                    break;
                }
                pthread_mutex_lock(&ctx->lock);
                if (msg.header.sender_id[0] != '\0') {
                    char *cid = ctx->connections[i].info.node_id;
                    if (cid[0] == '\0' || strncmp(cid, "seed-", 5) == 0) {
                        strncpy(cid, msg.header.sender_id,
                                sizeof(ctx->connections[i].info.node_id) - 1);
                    }
                }
                ctx->connections[i].info.last_activity_time = dislmdb_get_time_ms();
                ctx->connections[i].info.messages_received++;
                pthread_mutex_unlock(&ctx->lock);
                if (msg.header.type != DISLMDB_MESSAGE_HEARTBEAT) {
                    dispatch_message(ctx, &msg);
                }
                free(msg.payload);
            }
        }

        /* After I/O so mTLS reconnect cannot starve datagram Raft. */
        send_heartbeats(ctx);
        free(pfds);
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
    ctx->wake_r = -1;
    ctx->wake_w = -1;
    ctx->kq = -1;
    ctx->uring = NULL;
#if defined(__linux__)
    if (dislmdb_iouring_available()) {
        ctx->uring = dislmdb_iouring_create(64);
    }
#endif
#if defined(DISLMDB_NET_HAS_KQUEUE)
    if (!ctx->uring) {
        ctx->kq = kqueue();
        if (ctx->kq < 0) {
            ctx->kq = -1;
        }
    }
#endif
    ctx->transport = config->transport;
    ctx->connections = calloc(NET_CONN_INITIAL, sizeof(net_connection));
    if (!ctx->connections) {
        free_network_context(ctx);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    ctx->conn_cap = NET_CONN_INITIAL;
    for (int i = 0; i < ctx->conn_cap; i++) {
        ctx->connections[i].fd = -1;
    }
    ctx->start_ms = dislmdb_get_time_ms();
    {
        uint8_t dig[32];
        char seed[96];
        snprintf(seed, sizeof(seed), "%s:%u",
                 env->local_node_id,
                 (unsigned)(config->local_port ? config->local_port : DISLMDB_DEFAULT_PORT));
        if (dislmdb_crypto_sha256(seed, strnlen(seed, sizeof(seed)), dig) == 0) {
            ctx->dgram_cid = dislmdb_read_u64(dig);
        } else {
            ctx->dgram_cid = ctx->start_ms ^ (uint64_t)getpid();
        }
        ctx->dgram_pkt_num = 1;
    }
    {
        int wake[2] = {-1, -1};
        if (pipe(wake) == 0) {
            (void)set_nonblocking(wake[0]);
            (void)set_nonblocking(wake[1]);
            ctx->wake_r = wake[0];
            ctx->wake_w = wake[1];
        }
    }
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
    /* Regional planes: prefer env region_key as intra-plane when set. */
    ctx->has_region_key = false;
    ctx->has_cross_region_key = false;
    ctx->rtt_budget_ms = 0;
    if (ctx->env) {
        ctx->rtt_budget_ms = ctx->env->config.rtt_budget_ms;
        if (ctx->env->config.has_region_key) {
            memcpy(ctx->region_key, ctx->env->config.region_key, 32);
            ctx->has_region_key = true;
            /* Intra-region plane becomes the default auth key when no explicit
             * cluster key was preferred — already copied above when has_cluster_key. */
            if (!config->has_cluster_key) {
                memcpy(ctx->auth_key, ctx->region_key, 32);
                ctx->auth_enabled = true;
            }
        }
        if (ctx->env->config.has_cross_region_key) {
            memcpy(ctx->cross_region_key, ctx->env->config.cross_region_key, 32);
            ctx->has_cross_region_key = true;
        }
    }

    ctx->mtls_enabled = false;
    ctx->mtls = NULL;
    if (config->enable_mtls) {
        if (!dislmdb_mtls_available() ||
            config->tls_cert_path[0] == '\0' ||
            config->tls_key_path[0] == '\0') {
            free_network_context(ctx);
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
            free_network_context(ctx);
            return DISLMDB_ERR_AUTH_FAILED;
        }
        ctx->mtls_enabled = true;
    }

    ctx->quic_identity = NULL;
    ctx->quic_pki_strict = false;
    if (config->tls_cert_path[0] != '\0' && config->tls_key_path[0] != '\0') {
        const char *ca = config->tls_ca_path[0] ? config->tls_ca_path
                                                : config->tls_cert_path;
        ctx->quic_identity = dislmdb_quic_tls_identity_load(
            config->tls_cert_path, config->tls_key_path, ca);
        ctx->quic_pki_strict = (ctx->quic_identity != NULL);
    }
    if (!ctx->quic_identity &&
        (ctx->transport == DISLMDB_TRANSPORT_QUIC ||
         ctx->transport == DISLMDB_TRANSPORT_BOTH ||
         ctx->transport == DISLMDB_TRANSPORT_UDP)) {
        /* Ephemeral self-signed when PEM not configured (peer TOFU). */
        ctx->quic_identity =
            dislmdb_quic_tls_identity_self_signed("dislmdb-quic");
    }

    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        if (ctx->mtls) {
            dislmdb_mtls_destroy(ctx->mtls);
        }
        free_network_context(ctx);
        return DISLMDB_ERR_THREAD_ERROR;
    }

    /* Handshake workers: always start (no-op queue when mTLS off; ready if enabled). */
    if (hs_pool_start(ctx, config->handshake_workers) != 0) {
        pthread_mutex_destroy(&ctx->lock);
        if (ctx->mtls) {
            dislmdb_mtls_destroy(ctx->mtls);
        }
        free_network_context(ctx);
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
                     ctx->transport == DISLMDB_TRANSPORT_BOTH ||
                     ctx->transport == DISLMDB_TRANSPORT_QUIC);

#define NET_INIT_FAIL(code)                                                       \
    do {                                                                          \
        if (ctx->listen_fd >= 0) {                                                \
            close(ctx->listen_fd);                                                \
            ctx->listen_fd = -1;                                                  \
        }                                                                         \
        if (ctx->udp_fd >= 0) {                                                   \
            close(ctx->udp_fd);                                                   \
            ctx->udp_fd = -1;                                                     \
        }                                                                         \
        if (ctx->wake_r >= 0) {                                                   \
            close(ctx->wake_r);                                                   \
            ctx->wake_r = -1;                                                     \
        }                                                                         \
        if (ctx->wake_w >= 0) {                                                   \
            close(ctx->wake_w);                                                   \
            ctx->wake_w = -1;                                                     \
        }                                                                         \
        hs_pool_stop(ctx);                                                        \
        pthread_mutex_destroy(&ctx->lock);                                        \
        if (ctx->mtls) {                                                          \
            dislmdb_mtls_destroy(ctx->mtls);                                      \
            ctx->mtls = NULL;                                                     \
        }                                                                         \
        free_network_context(ctx);                                                \
        return (code);                                                            \
    } while (0)

    if (want_tcp) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            NET_INIT_FAIL(DISLMDB_ERR_NETWORK);
        }
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(fd, 32) < 0) {
            close(fd);
            NET_INIT_FAIL(DISLMDB_ERR_NETWORK);
        }
        set_nonblocking(fd);
        ctx->listen_fd = fd;
    }

    if (want_udp) {
        int ufd = socket(AF_INET, SOCK_DGRAM, 0);
        if (ufd < 0) {
            NET_INIT_FAIL(DISLMDB_ERR_NETWORK);
        }
        int on = 1;
        setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        prepare_sock_buffers(ufd);
        /* UDP may share the same port as TCP on most stacks */
        if (bind(ufd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(ufd);
            NET_INIT_FAIL(DISLMDB_ERR_NETWORK);
        }
        set_nonblocking(ufd);
        ctx->udp_fd = ufd;
    }

    if (ctx->listen_fd < 0 && ctx->udp_fd < 0) {
        NET_INIT_FAIL(DISLMDB_ERR_CONFIG);
    }

    ctx->running = true;
    env->network_running = true;
    env->network_context = ctx;

    if (pthread_create(&ctx->thread, NULL, network_thread, ctx) != 0) {
        env->network_context = NULL;
        env->network_running = false;
        NET_INIT_FAIL(DISLMDB_ERR_THREAD_ERROR);
    }
#undef NET_INIT_FAIL

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
    /* Kick poll so join does not wait for the poll timeout */
    if (ctx->wake_w >= 0) {
        uint8_t b = 1;
        (void)write(ctx->wake_w, &b, 1);
    }
    pthread_join(ctx->thread, NULL);
    /* Drain handshake workers after the net thread can no longer enqueue. */
    hs_pool_stop(ctx);

    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < ctx->conn_cap; i++) {
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
    if (ctx->wake_r >= 0) {
        close(ctx->wake_r);
        ctx->wake_r = -1;
    }
    if (ctx->wake_w >= 0) {
        close(ctx->wake_w);
        ctx->wake_w = -1;
    }
    if (ctx->kq >= 0) {
        close(ctx->kq);
        ctx->kq = -1;
    }
    if (ctx->uring) {
        dislmdb_iouring_destroy(ctx->uring);
        ctx->uring = NULL;
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
    free_network_context(ctx);
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
            ctx->connections[idx].info.last_activity_time = dislmdb_get_time_ms();
        }
        pthread_mutex_unlock(&ctx->lock);
        outbox_drain(ctx, idx, 0);
        return rc;
    }
    /* Policy rejects must not be buffered — surface immediately. */
    if (rc == DISLMDB_ERR_NODE_UNREACHABLE || rc == DISLMDB_ERR_NOT_AUTHORIZED ||
        rc == DISLMDB_ERR_AUTH_FAILED) {
        return rc;
    }
    /* Buffer for later drain (TCP CONNECTING / transient UDP miss). */
    pthread_mutex_lock(&ctx->lock);
    int eq = outbox_enqueue_locked(ctx, idx, &msg);
    if (eq == DISLMDB_SUCCESS) {
        /* Keep a broken TCP stream for reconnect, but do not drop the peer. */
        if (used_fd >= 0 && used_fd != ctx->udp_fd &&
            ctx->connections[idx].in_use &&
            ctx->connections[idx].fd == used_fd) {
            close_conn(ctx, idx);
        }
        pthread_mutex_unlock(&ctx->lock);
        return DISLMDB_SUCCESS;
    }
    if (idx >= 0 && ctx->connections[idx].in_use &&
        used_fd >= 0 && used_fd != ctx->udp_fd &&
        ctx->connections[idx].fd == used_fd) {
        close_conn(ctx, idx);
    }
    pthread_mutex_unlock(&ctx->lock);
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

    int idxs[ctx->conn_cap];
    char ids[ctx->conn_cap][64];
    int n = 0;
    pthread_mutex_lock(&ctx->lock);
    /* Collect unique peer ids then resolve each via find_conn_by_id scoring */
    char seen[ctx->conn_cap][64];
    int nseen = 0;
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (!ctx->connections[i].in_use) {
            continue;
        }
        const char *nid = ctx->connections[i].info.node_id;
        if (nid[0] == '\0') {
            /* Anonymous live slot — include once by index */
            if (ctx->connections[i].info.state == DISLMDB_CONNECTION_CLOSED ||
                ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTING ||
                ctx->connections[i].info.state == DISLMDB_CONNECTION_DISCONNECTING) {
                continue;
            }
            if (ctx->connections[i].fd < 0 && !conn_can_udp(ctx, i)) {
                continue;
            }
            idxs[n] = i;
            ids[n][0] = '\0';
            n++;
            continue;
        }
        bool dup = false;
        for (int j = 0; j < nseen; j++) {
            if (strcmp(seen[j], nid) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) {
            continue;
        }
        strncpy(seen[nseen], nid, sizeof(seen[nseen]) - 1);
        seen[nseen][sizeof(seen[nseen]) - 1] = '\0';
        nseen++;
    }
    for (int s = 0; s < nseen; s++) {
        int idx = find_conn_by_id(ctx, seen[s]);
        if (idx < 0) {
            continue;
        }
        /* CONNECTING/CLOSED outbound still get outbox entries for later drain. */
        if (ctx->connections[idx].info.state == DISLMDB_CONNECTION_DISCONNECTING) {
            continue;
        }
        bool wire_ready =
            (ctx->connections[idx].info.state == DISLMDB_CONNECTION_CONNECTED) &&
            (ctx->connections[idx].fd >= 0 || conn_can_udp(ctx, idx));
        bool can_buffer =
            ctx->connections[idx].outbound ||
            ctx->connections[idx].info.state == DISLMDB_CONNECTION_CONNECTED ||
            conn_can_udp(ctx, idx);
        if (!wire_ready && !can_buffer) {
            continue;
        }
        idxs[n] = idx;
        strncpy(ids[n], seen[s], sizeof(ids[n]) - 1);
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
        bool defer = false;
        pthread_mutex_lock(&ctx->lock);
        if (idxs[i] >= 0 && idxs[i] < ctx->conn_cap &&
            ctx->connections[idxs[i]].in_use &&
            ctx->connections[idxs[i]].info.state != DISLMDB_CONNECTION_CONNECTED) {
            defer = true;
        }
        pthread_mutex_unlock(&ctx->lock);
        if (defer) {
            pthread_mutex_lock(&ctx->lock);
            if (outbox_enqueue_locked(ctx, idxs[i], &msg) != DISLMDB_SUCCESS) {
                overall = DISLMDB_ERR_NETWORK;
            }
            pthread_mutex_unlock(&ctx->lock);
            continue;
        }
        int used_fd = -1;
        int rc = write_framed_adapt(ctx, idxs[i], &msg, &used_fd);
        pthread_mutex_lock(&ctx->lock);
        if (rc != DISLMDB_SUCCESS) {
            if (outbox_enqueue_locked(ctx, idxs[i], &msg) == DISLMDB_SUCCESS) {
                if (used_fd >= 0 && used_fd != ctx->udp_fd &&
                    idxs[i] >= 0 && idxs[i] < ctx->conn_cap &&
                    ctx->connections[idxs[i]].in_use &&
                    ctx->connections[idxs[i]].fd == used_fd) {
                    close_conn(ctx, idxs[i]);
                }
            } else {
                overall = rc;
                if (used_fd >= 0 && used_fd != ctx->udp_fd &&
                    idxs[i] >= 0 && idxs[i] < ctx->conn_cap &&
                    ctx->connections[idxs[i]].in_use &&
                    ctx->connections[idxs[i]].fd == used_fd) {
                    close_conn(ctx, idxs[i]);
                }
            }
        } else {
            ctx->stats.total_messages_sent++;
            if (idxs[i] >= 0 && idxs[i] < ctx->conn_cap &&
                ctx->connections[idxs[i]].in_use) {
                ctx->connections[idxs[i]].info.messages_sent++;
                ctx->connections[idxs[i]].info.last_activity_time = dislmdb_get_time_ms();
            }
        }
        pthread_mutex_unlock(&ctx->lock);
        if (rc == DISLMDB_SUCCESS) {
            outbox_drain(ctx, idxs[i], 0);
        }
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
    /* Heal any counter drift from dial dedupe / CONNECTING closes. */
    ctx->stats.active_connections = recount_active_connections_locked(ctx);
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
    for (int i = 0; i < ctx->conn_cap && n < max_count; i++) {
        if (ctx->connections[i].in_use &&
            ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTED &&
            ctx->connections[i].info.node_id[0] != '\0') {
            strncpy(node_ids[n], ctx->connections[i].info.node_id, 63);
            node_ids[n][63] = '\0';
            n++;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    *count = n;
    return DISLMDB_SUCCESS;
}

uint32_t dislmdb_network_connected_peer_count(DISLMDB_env *env)
{
    if (!env || !env->network_context) {
        return 0;
    }
    network_context *ctx = env->network_context;
    uint32_t n = 0;
    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (ctx->connections[i].in_use &&
            ctx->connections[i].info.state == DISLMDB_CONNECTION_CONNECTED &&
            ctx->connections[i].info.node_id[0] != '\0' &&
            strncmp(ctx->connections[i].info.node_id, env->local_node_id, 63) != 0) {
            n++;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return n;
}

int dislmdb_network_wait_connected(DISLMDB_env *env,
                                   uint32_t min_peers,
                                   uint32_t timeout_ms)
{
    if (!env || !env->network_context) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (min_peers == 0) {
        return DISLMDB_SUCCESS;
    }
    uint64_t start = dislmdb_get_time_ms();
    for (;;) {
        if (dislmdb_network_connected_peer_count(env) >= min_peers) {
            return DISLMDB_SUCCESS;
        }
        if (dislmdb_get_time_ms() - start >= timeout_ms) {
            return DISLMDB_ERR_NODE_UNREACHABLE;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 25 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
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
    bool udp = (ctx->transport == DISLMDB_TRANSPORT_UDP ||
                ctx->transport == DISLMDB_TRANSPORT_QUIC);

    /* Already connected / pending to this peer? */
    pthread_mutex_lock(&ctx->lock);
    int existing = find_conn_by_id(ctx, node_addr->node_id);
    if (existing >= 0 &&
        ctx->connections[existing].info.state == DISLMDB_CONNECTION_CONNECTED) {
        bool have_tcp = conn_tcp_fd(ctx, existing) >= 0;
        /*
         * BOTH needs a real TCP stream for the data lane. A UDP-only
         * CONNECTED slot (fd == udp_fd) must not suppress the TCP dial.
         */
        if (udp || have_tcp ||
            (ctx->transport == DISLMDB_TRANSPORT_TCP &&
             ctx->connections[existing].fd >= 0)) {
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_SUCCESS;
        }
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
                ctx->connections[idx].tls = NULL;
                ctx->connections[idx].listen_port = node_addr->port;
                conn_set_topo(&ctx->connections[idx], node_addr);
                strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
                        sizeof(ctx->connections[idx].info.node_id) - 1);
                strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
                        sizeof(ctx->connections[idx].info.hostname) - 1);
                ctx->connections[idx].info.port = node_addr->port;
                /* BOTH: keep UDP signalling CONNECTED so Raft never waits on TCP. */
                if (ctx->transport == DISLMDB_TRANSPORT_BOTH && ctx->udp_fd >= 0 &&
                    node_addr->port != 0) {
                    ctx->connections[idx].fd = ctx->udp_fd;
                    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
                    ctx->connections[idx].info.last_activity_time =
                        dislmdb_get_time_ms();
                    ctx->stats.active_connections =
                        recount_active_connections_locked(ctx);
                } else {
                    ctx->connections[idx].fd = -1;
                    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
                }
            }
            pthread_mutex_unlock(&ctx->lock);
            return DISLMDB_SUCCESS; /* deferred reconnect */
        }
        (void)set_nonblocking(fd);
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
                ctx->connections[idx].tls = NULL;
                ctx->connections[idx].listen_port = node_addr->port;
                conn_set_topo(&ctx->connections[idx], node_addr);
                strncpy(ctx->connections[idx].info.node_id, node_addr->node_id,
                        sizeof(ctx->connections[idx].info.node_id) - 1);
                strncpy(ctx->connections[idx].info.hostname, node_addr->hostname,
                        sizeof(ctx->connections[idx].info.hostname) - 1);
                ctx->connections[idx].info.port = node_addr->port;
                if (ctx->transport == DISLMDB_TRANSPORT_BOTH && ctx->udp_fd >= 0 &&
                    node_addr->port != 0) {
                    ctx->connections[idx].fd = ctx->udp_fd;
                    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CONNECTED;
                    ctx->connections[idx].info.last_activity_time =
                        dislmdb_get_time_ms();
                    ctx->stats.active_connections =
                        recount_active_connections_locked(ctx);
                } else {
                    ctx->connections[idx].fd = -1;
                    ctx->connections[idx].info.state = DISLMDB_CONNECTION_CLOSED;
                }
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
    ensure_io_lock(&ctx->connections[idx]);
    ctx->connections[idx].fd = fd;
    ctx->connections[idx].tls = tls;
    ctx->connections[idx].outbound = true;
    ctx->connections[idx].listen_port = node_addr->port;
    conn_set_topo(&ctx->connections[idx], node_addr);
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

    if (ctx->transport == DISLMDB_TRANSPORT_QUIC && ctx->udp_fd >= 0 &&
        node_addr->port != 0) {
        net_quic_pending pend;
        memset(&pend, 0, sizeof(pend));
        uint8_t dcid[8], scid[8], ipkt[512];
        size_t ipkt_len = 0;
        int csr = dislmdb_quic_client_start(&pend.conn, dcid, scid, pend.xpriv,
                                           pend.ch, sizeof(pend.ch), &pend.ch_len,
                                           ipkt, sizeof(ipkt), &ipkt_len);
        if (csr == 0) {
            struct sockaddr_in to;
            memset(&to, 0, sizeof(to));
            to.sin_family = AF_INET;
            to.sin_port = htons(node_addr->port);
            if (inet_pton(AF_INET, node_addr->hostname, &to.sin_addr) == 1) {
                pend.peer = to;
                pend.active = true;
                if (ipkt_len <= sizeof(pend.client_initial)) {
                    memcpy(pend.client_initial, ipkt, ipkt_len);
                    pend.client_initial_len = ipkt_len;
                }
                pthread_mutex_lock(&ctx->lock);
                (void)quic_pending_store(ctx, &pend);
                pthread_mutex_unlock(&ctx->lock);
                (void)sendto(ctx->udp_fd, ipkt, ipkt_len, 0,
                             (struct sockaddr *)&to, sizeof(to));
            } else {
                dislmdb_quic_conn_reset(&pend.conn);
            }
        }
    }

    extern int dislmdb_pbft_send_hello(DISLMDB_env *env, const char *target_node_id);
    /* QUIC: HELLO waits until 1-RTT session exists (see Handshake RX path). */
    if (ctx->transport != DISLMDB_TRANSPORT_QUIC) {
        (void)dislmdb_pbft_send_hello(env, peer_label);
    }
    return DISLMDB_SUCCESS;
}

bool dislmdb_network_take_hello_reengage(DISLMDB_env *env, const char *node_id)
{
    if (!env || !env->network_context || !node_id || node_id[0] == '\0') {
        return false;
    }
    network_context *ctx = env->network_context;
    pthread_mutex_lock(&ctx->lock);
    int idx = find_conn_by_id(ctx, node_id);
    bool need = false;
    if (idx >= 0 && ctx->connections[idx].hello_reengage) {
        need = true;
        ctx->connections[idx].hello_reengage = false;
    }
    pthread_mutex_unlock(&ctx->lock);
    return need;
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
        for (int i = 0; i < ctx->conn_cap; i++) {
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
    /* Drop silent duplicate dials to the same peer id. Never close a
     * CONNECTED slot that has already exchanged traffic. */
    for (int i = 0; i < ctx->conn_cap; i++) {
        if (i == idx || !ctx->connections[i].in_use) {
            continue;
        }
        if (strncmp(ctx->connections[i].info.node_id, real_node_id, 63) != 0) {
            continue;
        }
        bool silent = (ctx->connections[i].fd < 0) ||
                      (ctx->connections[i].info.state != DISLMDB_CONNECTION_CONNECTED) ||
                      (ctx->connections[i].info.messages_received == 0 &&
                       ctx->connections[i].info.messages_sent == 0);
        if (silent && ctx->connections[idx].fd >= 0) {
            close_conn(ctx, i);
        }
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
