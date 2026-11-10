/**
 * @file dislmdb_mtls.c
 * @brief Portable mutual TLS 1.3 via vendored Mbed TLS (all platforms)
 */
#include "dislmdb_mtls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"

struct dislmdb_mtls_ctx {
    dislmdb_mtls_config cfg;
    char *cert_path;
    char *key_path;
    char *ca_path;
    mbedtls_x509_crt own_cert;
    mbedtls_pk_context own_key;
    mbedtls_x509_crt ca_cert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    pthread_mutex_t rng_lock; /* ctr_drbg is not thread-safe */
    bool ready;
};

struct dislmdb_mtls_session {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context net;
    int owns_fd;
};

bool dislmdb_mtls_available(void)
{
    return true;
}

#define MTLS_IO_TIMEOUT_MS 2000
#define MTLS_HANDSHAKE_DEADLINE_MS 8000

/** Avoid SIGPIPE; bound I/O so handshake/send cannot stall forever. */
static void mtls_prepare_fd(int fd)
{
#if defined(SO_NOSIGPIPE)
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    struct timeval tv;
    tv.tv_sec = MTLS_IO_TIMEOUT_MS / 1000;
    tv.tv_usec = (MTLS_IO_TIMEOUT_MS % 1000) * 1000;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static uint64_t mtls_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static int mtls_wait_fd(int fd, int want_write, uint64_t deadline_ms)
{
    uint64_t now = mtls_now_ms();
    if (now >= deadline_ms) {
        return -1;
    }
    uint64_t left = deadline_ms - now;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv = {
        .tv_sec = (time_t)(left / 1000ull),
        .tv_usec = (suseconds_t)((left % 1000ull) * 1000ull)};
    int rc = want_write ? select(fd + 1, NULL, &fds, NULL, &tv)
                        : select(fd + 1, &fds, NULL, NULL, &tv);
    return rc > 0 ? 0 : -1;
}

static int mtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    mbedtls_net_context *net = (mbedtls_net_context *)ctx;
    if (!net || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
#if defined(MSG_NOSIGNAL)
    int ret = (int)send(net->fd, buf, len, MSG_NOSIGNAL);
#else
    int ret = (int)write(net->fd, buf, len);
#endif
    if (ret < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ETIMEDOUT) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

static int mtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    mbedtls_net_context *net = (mbedtls_net_context *)ctx;
    if (!net || net->fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }
    int ret = (int)recv(net->fd, buf, len, 0);
    if (ret < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ETIMEDOUT) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        if (errno == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        }
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (ret == 0) {
        return MBEDTLS_ERR_NET_CONN_RESET;
    }
    return ret;
}

static char *dup_path(const char *p)
{
    if (!p) {
        return NULL;
    }
    size_t n = strlen(p) + 1;
    char *d = malloc(n);
    if (!d) {
        return NULL;
    }
    memcpy(d, p, n);
    return d;
}

static int rng_seed(dislmdb_mtls_ctx *c)
{
    const char pers[] = "dislmdb-mtls-1.3";
    return mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func, &c->entropy,
                                 (const unsigned char *)pers, sizeof(pers) - 1);
}

/** Thread-safe RNG wrapper for concurrent handshakes / record protection */
static int mtls_rng(void *p_rng, unsigned char *output, size_t output_len)
{
    dislmdb_mtls_ctx *c = p_rng;
    pthread_mutex_lock(&c->rng_lock);
    int rc = mbedtls_ctr_drbg_random(&c->ctr_drbg, output, output_len);
    pthread_mutex_unlock(&c->rng_lock);
    return rc;
}

dislmdb_mtls_ctx *dislmdb_mtls_create(const dislmdb_mtls_config *cfg)
{
    if (!cfg || !cfg->cert_path || !cfg->key_path) {
        return NULL;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return NULL;
    }

    dislmdb_mtls_ctx *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }

    mbedtls_x509_crt_init(&c->own_cert);
    mbedtls_pk_init(&c->own_key);
    mbedtls_x509_crt_init(&c->ca_cert);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->ctr_drbg);
    if (pthread_mutex_init(&c->rng_lock, NULL) != 0) {
        free(c);
        return NULL;
    }

    c->cert_path = dup_path(cfg->cert_path);
    c->key_path = dup_path(cfg->key_path);
    c->ca_path = dup_path(cfg->ca_path);
    c->cfg.cert_path = c->cert_path;
    c->cfg.key_path = c->key_path;
    c->cfg.ca_path = c->ca_path;
    c->cfg.require_client_cert = cfg->require_client_cert;

    if (!c->cert_path || !c->key_path) {
        dislmdb_mtls_destroy(c);
        return NULL;
    }

    if (rng_seed(c) != 0) {
        dislmdb_mtls_destroy(c);
        return NULL;
    }

    if (mbedtls_x509_crt_parse_file(&c->own_cert, c->cert_path) != 0) {
        dislmdb_mtls_destroy(c);
        return NULL;
    }
    if (mbedtls_pk_parse_keyfile(&c->own_key, c->key_path, NULL, mtls_rng, c) != 0) {
        dislmdb_mtls_destroy(c);
        return NULL;
    }
    if (c->ca_path) {
        if (mbedtls_x509_crt_parse_file(&c->ca_cert, c->ca_path) != 0) {
            dislmdb_mtls_destroy(c);
            return NULL;
        }
    }

    c->ready = true;
    return c;
}

void dislmdb_mtls_destroy(dislmdb_mtls_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    mbedtls_x509_crt_free(&ctx->own_cert);
    mbedtls_pk_free(&ctx->own_key);
    mbedtls_x509_crt_free(&ctx->ca_cert);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    pthread_mutex_destroy(&ctx->rng_lock);
    free(ctx->cert_path);
    free(ctx->key_path);
    free(ctx->ca_path);
    free(ctx);
}

static int conf_tls13(dislmdb_mtls_ctx *ctx, mbedtls_ssl_config *conf, int endpoint)
{
    int ret = mbedtls_ssl_config_defaults(conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        return ret;
    }

    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_rng(conf, mtls_rng, ctx);

    /* Mutual certificate authentication — fail closed without peer cert */
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    if (ctx->ca_path) {
        mbedtls_ssl_conf_ca_chain(conf, &ctx->ca_cert, NULL);
    } else {
        mbedtls_ssl_conf_ca_chain(conf, &ctx->own_cert, NULL);
    }

    ret = mbedtls_ssl_conf_own_cert(conf, &ctx->own_cert, &ctx->own_key);
    if (ret != 0) {
        return ret;
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_conf_tls13_key_exchange_modes(
        conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
#endif
    (void)ctx;
    return 0;
}

static int handshake_on_fd(dislmdb_mtls_ctx *ctx, int tcp_fd, int endpoint,
                           const char *peer_hostname, dislmdb_mtls_session **session)
{
    if (!ctx || !ctx->ready || tcp_fd < 0 || !session) {
        return -1;
    }

    dislmdb_mtls_session *s = calloc(1, sizeof(*s));
    if (!s) {
        return -1;
    }

    mbedtls_net_init(&s->net);
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mtls_prepare_fd(tcp_fd);
    s->net.fd = tcp_fd;
    s->owns_fd = 1;

    if (conf_tls13(ctx, &s->conf, endpoint) != 0) {
        s->owns_fd = 0;
        dislmdb_mtls_session_close(s);
        return -1;
    }

    if (mbedtls_ssl_setup(&s->ssl, &s->conf) != 0) {
        s->owns_fd = 0;
        dislmdb_mtls_session_close(s);
        return -1;
    }

    if (endpoint == MBEDTLS_SSL_IS_CLIENT && peer_hostname && peer_hostname[0]) {
        /* Cluster peers often dial by IP; chain+mTLS auth is authoritative.
         * Only bind SNI/hostname check for DNS names. */
        struct in_addr a4;
        struct in6_addr a6;
        bool is_ip = (inet_pton(AF_INET, peer_hostname, &a4) == 1) ||
                     (inet_pton(AF_INET6, peer_hostname, &a6) == 1);
        if (!is_ip) {
            (void)mbedtls_ssl_set_hostname(&s->ssl, peer_hostname);
        }
    }

    mbedtls_ssl_set_bio(&s->ssl, &s->net, mtls_net_send, mtls_net_recv, NULL);

    uint64_t deadline = mtls_now_ms() + MTLS_HANDSHAKE_DEADLINE_MS;
    int ret;
    while ((ret = mbedtls_ssl_handshake(&s->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            if (mtls_wait_fd(tcp_fd, 0, deadline) != 0) {
                s->owns_fd = 0;
                dislmdb_mtls_session_close(s);
                return -1;
            }
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (mtls_wait_fd(tcp_fd, 1, deadline) != 0) {
                s->owns_fd = 0;
                dislmdb_mtls_session_close(s);
                return -1;
            }
            continue;
        }
        s->owns_fd = 0;
        dislmdb_mtls_session_close(s);
        return -1;
    }

    if (mbedtls_ssl_get_verify_result(&s->ssl) != 0) {
        s->owns_fd = 0;
        dislmdb_mtls_session_close(s);
        return -1;
    }

    *session = s;
    return 0;
}

int dislmdb_mtls_client_handshake(dislmdb_mtls_ctx *ctx, int tcp_fd,
                                  const char *peer_hostname,
                                  dislmdb_mtls_session **session)
{
    return handshake_on_fd(ctx, tcp_fd, MBEDTLS_SSL_IS_CLIENT, peer_hostname, session);
}

int dislmdb_mtls_server_handshake(dislmdb_mtls_ctx *ctx, int tcp_fd,
                                  dislmdb_mtls_session **session)
{
    return handshake_on_fd(ctx, tcp_fd, MBEDTLS_SSL_IS_SERVER, NULL, session);
}

int dislmdb_mtls_send(dislmdb_mtls_session *s, const void *buf, size_t len)
{
    if (!s || !buf || len == 0) {
        return -1;
    }
    uint64_t deadline = mtls_now_ms() + MTLS_IO_TIMEOUT_MS;
    size_t off = 0;
    while (off < len) {
        int n = mbedtls_ssl_write(&s->ssl, (const unsigned char *)buf + off, len - off);
        if (n == MBEDTLS_ERR_SSL_WANT_READ) {
            if (mtls_wait_fd(s->net.fd, 0, deadline) != 0) {
                return -1;
            }
            continue;
        }
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (mtls_wait_fd(s->net.fd, 1, deadline) != 0) {
                return -1;
            }
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        off += (size_t)n;
        deadline = mtls_now_ms() + MTLS_IO_TIMEOUT_MS;
    }
    return 0;
}

int dislmdb_mtls_recv(dislmdb_mtls_session *s, void *buf, size_t len, size_t *got)
{
    if (!s || !buf || !got || len == 0) {
        return -1;
    }
    uint64_t deadline = mtls_now_ms() + MTLS_IO_TIMEOUT_MS;
    for (;;) {
        int n = mbedtls_ssl_read(&s->ssl, (unsigned char *)buf, len);
        if (n == MBEDTLS_ERR_SSL_WANT_READ) {
            if (mtls_wait_fd(s->net.fd, 0, deadline) != 0) {
                return -1;
            }
            continue;
        }
        if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (mtls_wait_fd(s->net.fd, 1, deadline) != 0) {
                return -1;
            }
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        *got = (size_t)n;
        return 0;
    }
}

bool dislmdb_mtls_pending(const dislmdb_mtls_session *s)
{
    if (!s) {
        return false;
    }
    return mbedtls_ssl_check_pending(&s->ssl) != 0 ||
           mbedtls_ssl_get_bytes_avail(&s->ssl) > 0;
}

void dislmdb_mtls_session_close(dislmdb_mtls_session *s)
{
    if (!s) {
        return;
    }
    /* Best-effort notify; peer may already be gone — must not raise SIGPIPE */
    (void)mbedtls_ssl_close_notify(&s->ssl);
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ssl_config_free(&s->conf);
    if (s->owns_fd) {
        mbedtls_net_free(&s->net);
    } else {
        /* Caller retains the TCP fd on failed handshakes */
        s->net.fd = -1;
    }
    free(s);
}

int dislmdb_mtls_connect_host(dislmdb_mtls_ctx *ctx, const char *host, uint16_t port,
                              dislmdb_mtls_session **session)
{
    if (!ctx || !host || !session) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    int rc = dislmdb_mtls_client_handshake(ctx, fd, host, session);
    if (rc != 0) {
        close(fd);
    }
    return rc;
}
