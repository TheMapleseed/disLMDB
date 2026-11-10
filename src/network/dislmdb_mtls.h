/**
 * @file dislmdb_mtls.h
 * @brief Portable mutual TLS 1.3 for DisLMDB cluster TCP paths
 *
 * Single backend: vendored Mbed TLS (TLS 1.3 only, mutual certificate auth).
 * Same code path on every POSIX host — no platform-localized TLS stacks.
 */
#ifndef DISLMDB_MTLS_H
#define DISLMDB_MTLS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dislmdb_mtls_config {
    const char *cert_path;
    const char *key_path;
    const char *ca_path;
    bool require_client_cert; /* server-side mTLS */
} dislmdb_mtls_config;

typedef struct dislmdb_mtls_ctx dislmdb_mtls_ctx;
typedef struct dislmdb_mtls_session dislmdb_mtls_session;

/** @brief Create an mTLS context (TLS 1.3 only). Returns NULL on failure. */
dislmdb_mtls_ctx *dislmdb_mtls_create(const dislmdb_mtls_config *cfg);

void dislmdb_mtls_destroy(dislmdb_mtls_ctx *ctx);

/**
 * @brief Wrap an already-connected TCP socket as an mTLS client.
 * @return 0 on success; socket ownership transfers into *session.
 */
int dislmdb_mtls_client_handshake(dislmdb_mtls_ctx *ctx, int tcp_fd,
                                  const char *peer_hostname,
                                  dislmdb_mtls_session **session);

int dislmdb_mtls_server_handshake(dislmdb_mtls_ctx *ctx, int tcp_fd,
                                  dislmdb_mtls_session **session);

/** @brief Dial host:port over TCP, then perform TLS 1.3 mTLS client handshake */
int dislmdb_mtls_connect_host(dislmdb_mtls_ctx *ctx, const char *host, uint16_t port,
                              dislmdb_mtls_session **session);

int dislmdb_mtls_send(dislmdb_mtls_session *s, const void *buf, size_t len);
int dislmdb_mtls_recv(dislmdb_mtls_session *s, void *buf, size_t len, size_t *got);
void dislmdb_mtls_session_close(dislmdb_mtls_session *s);

/** @brief True if this build provides real TLS 1.3 mTLS */
bool dislmdb_mtls_available(void);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_MTLS_H */
