/**
 * @file test_mtls.c
 * @brief Unit: portable mTLS 1.3 — create, fail-closed, loopback handshake
 */
#include "../harness/test_harness.h"
#include "../../src/network/dislmdb_mtls.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
    dislmdb_mtls_ctx *mtls;
    int client_fd;
    int result;
    dislmdb_mtls_session *sess;
} client_arg_t;

static void *client_thread(void *arg)
{
    client_arg_t *a = arg;
    a->result = dislmdb_mtls_client_handshake(a->mtls, a->client_fd, "localhost", &a->sess);
    return NULL;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/mtls");

    EXPECT_TRUE(&ctx, "mtls_available", dislmdb_mtls_available());

    mkdir("./it_mtls_certs", 0700);
    int gen = system(
        "openssl req -x509 -newkey rsa:2048 -nodes "
        "-keyout ./it_mtls_certs/key.pem -out ./it_mtls_certs/cert.pem "
        "-days 1 -subj '/CN=localhost' >/dev/null 2>&1");
    EXPECT_EQ_INT(&ctx, "gen_certs", gen, 0);

    dislmdb_mtls_config cfg = {
        .cert_path = "./it_mtls_certs/cert.pem",
        .key_path = "./it_mtls_certs/key.pem",
        .ca_path = "./it_mtls_certs/cert.pem",
        .require_client_cert = true,
    };
    dislmdb_mtls_ctx *mtls = dislmdb_mtls_create(&cfg);
    EXPECT_TRUE(&ctx, "ctx_create", mtls != NULL);

    /* Negative: connect to nothing should fail closed */
    dislmdb_mtls_session *sess = NULL;
    int crc = dislmdb_mtls_connect_host(mtls, "127.0.0.1", 1, &sess);
    EXPECT_TRUE(&ctx, "connect_fail_closed", crc != 0 && sess == NULL);

    /* Positive: loopback mTLS 1.3 handshake + echo */
    int sv[2] = {-1, -1};
    EXPECT_EQ_INT(&ctx, "socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    client_arg_t carg = {.mtls = mtls, .client_fd = sv[0], .result = -1, .sess = NULL};
    pthread_t th;
    EXPECT_EQ_INT(&ctx, "pthread_create", pthread_create(&th, NULL, client_thread, &carg), 0);

    dislmdb_mtls_session *ssess = NULL;
    int src = dislmdb_mtls_server_handshake(mtls, sv[1], &ssess);
    EXPECT_EQ_INT(&ctx, "server_handshake", src, 0);
    EXPECT_TRUE(&ctx, "server_session", ssess != NULL);

    pthread_join(th, NULL);
    EXPECT_EQ_INT(&ctx, "client_handshake", carg.result, 0);
    EXPECT_TRUE(&ctx, "client_session", carg.sess != NULL);

    if (ssess && carg.sess) {
        const char msg[] = "dislmdb-mtls-ok";
        EXPECT_EQ_INT(&ctx, "client_send",
                      dislmdb_mtls_send(carg.sess, msg, sizeof(msg)), 0);
        char buf[64];
        size_t got = 0;
        EXPECT_EQ_INT(&ctx, "server_recv",
                      dislmdb_mtls_recv(ssess, buf, sizeof(buf), &got), 0);
        EXPECT_TRUE(&ctx, "echo_len", got == sizeof(msg));
        EXPECT_TRUE(&ctx, "echo_payload", memcmp(buf, msg, sizeof(msg)) == 0);
    }

    dislmdb_mtls_session_close(carg.sess);
    dislmdb_mtls_session_close(ssess);
    dislmdb_mtls_destroy(mtls);
    system("rm -rf ./it_mtls_certs");
    return test_end(&ctx);
}
