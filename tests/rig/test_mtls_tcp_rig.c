/**
 * @file test_mtls_tcp_rig.c
 * @brief Sandbox-safe: real TCP loopback + mTLS 1.3 framed exchange (no LMDB)
 *
 * Proves cluster-style mutual TLS over a listening socket without mmap.
 */
#include "../harness/test_harness.h"
#include "../../src/network/dislmdb_mtls.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    dislmdb_mtls_ctx *mtls;
    int listen_fd;
    int result;
    dislmdb_mtls_session *sess;
    char rx[128];
    size_t rx_len;
} server_arg_t;

static int gen_certs(const char *dir)
{
    char cmd[512];
    mkdir(dir, 0700);
    snprintf(cmd, sizeof(cmd),
             "openssl req -x509 -newkey rsa:2048 -nodes "
             "-keyout '%s/key.pem' -out '%s/cert.pem' -days 1 "
             "-subj '/CN=dislmdb-rig' >/dev/null 2>&1",
             dir, dir);
    return system(cmd);
}

static void *server_thread(void *arg)
{
    server_arg_t *a = arg;
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int cfd = accept(a->listen_fd, (struct sockaddr *)&peer, &plen);
    if (cfd < 0) {
        a->result = -1;
        return NULL;
    }
    if (dislmdb_mtls_server_handshake(a->mtls, cfd, &a->sess) != 0) {
        close(cfd);
        a->result = -2;
        return NULL;
    }
    size_t got = 0;
    if (dislmdb_mtls_recv(a->sess, a->rx, sizeof(a->rx), &got) != 0) {
        a->result = -3;
        return NULL;
    }
    a->rx_len = got;
    /* Echo back */
    if (dislmdb_mtls_send(a->sess, a->rx, got) != 0) {
        a->result = -4;
        return NULL;
    }
    a->result = 0;
    return NULL;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "rig/mtls_tcp");

    EXPECT_TRUE(&ctx, "mtls_available", dislmdb_mtls_available());
    EXPECT_EQ_INT(&ctx, "gen_certs", gen_certs("./rig_mtls_certs"), 0);

    dislmdb_mtls_config cfg = {
        .cert_path = "./rig_mtls_certs/cert.pem",
        .key_path = "./rig_mtls_certs/key.pem",
        .ca_path = "./rig_mtls_certs/cert.pem",
        .require_client_cert = true,
    };
    dislmdb_mtls_ctx *mtls = dislmdb_mtls_create(&cfg);
    EXPECT_TRUE(&ctx, "ctx_create", mtls != NULL);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_TRUE(&ctx, "listen_socket", lfd >= 0);
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ephemeral — avoids port fights */
    EXPECT_EQ_INT(&ctx, "bind", bind(lfd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    EXPECT_EQ_INT(&ctx, "listen", listen(lfd, 1), 0);
    socklen_t alen = sizeof(addr);
    EXPECT_EQ_INT(&ctx, "getsockname", getsockname(lfd, (struct sockaddr *)&addr, &alen), 0);
    uint16_t port = ntohs(addr.sin_port);

    server_arg_t sarg = {.mtls = mtls, .listen_fd = lfd, .result = -9, .sess = NULL};
    pthread_t th;
    EXPECT_EQ_INT(&ctx, "pthread", pthread_create(&th, NULL, server_thread, &sarg), 0);

    dislmdb_mtls_session *cs = NULL;
    int crc = dislmdb_mtls_connect_host(mtls, "127.0.0.1", port, &cs);
    EXPECT_EQ_INT(&ctx, "client_connect", crc, 0);
    EXPECT_TRUE(&ctx, "client_sess", cs != NULL);

    const char msg[] = "framed-mtls-payload";
    EXPECT_EQ_INT(&ctx, "client_send", dislmdb_mtls_send(cs, msg, sizeof(msg)), 0);

    char echo[128];
    size_t got = 0;
    EXPECT_EQ_INT(&ctx, "client_recv", dislmdb_mtls_recv(cs, echo, sizeof(echo), &got), 0);
    EXPECT_TRUE(&ctx, "echo_match",
                got == sizeof(msg) && memcmp(echo, msg, sizeof(msg)) == 0);

    pthread_join(th, NULL);
    EXPECT_EQ_INT(&ctx, "server_ok", sarg.result, 0);
    EXPECT_TRUE(&ctx, "server_saw",
                sarg.rx_len == sizeof(msg) && memcmp(sarg.rx, msg, sizeof(msg)) == 0);

    dislmdb_mtls_session_close(cs);
    dislmdb_mtls_session_close(sarg.sess);
    close(lfd);
    dislmdb_mtls_destroy(mtls);
    system("rm -rf ./rig_mtls_certs");
    return test_end(&ctx);
}
