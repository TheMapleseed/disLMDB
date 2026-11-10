/**
 * @file node_agent.c
 * @brief Long-running DisLMDB node + test-only admin control plane for Orb/Docker
 *
 * Admin protocol (TCP, one line request → one line response):
 *   PING
 *   STATUS
 *   PUT <key> <value>
 *   GET <key>
 *   JOIN <host> <port> <node_id>
 *   SYNC
 *   QUIT
 */
#include "dislmdb.h"
#include "dislmdb_errors.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;
static DISLMDB_env *g_env;
static char g_node_id[64];

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static int put_kv(const char *key, const char *val)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(g_env, NULL, 0, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, "kv", MDB_CREATE, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
    MDB_val v = {.mv_size = strlen(val), .mv_data = (void *)val};
    rc = dislmdb_put(txn, dbi, &k, &v, 0);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    return dislmdb_txn_commit(txn);
}

static int get_kv(const char *key, char *out, size_t out_len)
{
    DISLMDB_txn *txn = NULL;
    int rc = dislmdb_txn_begin(g_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) {
        return rc;
    }
    MDB_dbi dbi;
    rc = dislmdb_dbi_open(txn, "kv", 0, &dbi);
    if (rc != 0) {
        dislmdb_txn_abort(txn);
        return rc;
    }
    MDB_val k = {.mv_size = strlen(key), .mv_data = (void *)key};
    MDB_val v;
    rc = mdb_get(dislmdb_get_lmdb_txn(txn), dbi, &k, &v);
    if (rc == 0 && out && out_len > 0) {
        size_t n = v.mv_size < out_len - 1 ? v.mv_size : out_len - 1;
        memcpy(out, v.mv_data, n);
        out[n] = '\0';
    }
    dislmdb_txn_abort(txn);
    return rc;
}

static void reply(int fd, const char *line)
{
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s\n", line);
    if (n > 0) {
        (void)write(fd, buf, (size_t)n);
    }
}

static void handle_line(int fd, char *line)
{
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    if (len == 0) {
        return;
    }

    if (strcmp(line, "PING") == 0) {
        reply(fd, "OK PONG");
        return;
    }
    if (strcmp(line, "QUIT") == 0) {
        reply(fd, "OK BYE");
        g_running = 0;
        return;
    }
    if (strcmp(line, "SYNC") == 0) {
        int rc = dislmdb_force_sync(g_env);
        if (rc == 0) {
            reply(fd, "OK");
        } else {
            char err[128];
            snprintf(err, sizeof(err), "ERR %s", dislmdb_strerror(rc));
            reply(fd, err);
        }
        return;
    }
    if (strcmp(line, "STATUS") == 0) {
        DISLMDB_metrics m;
        memset(&m, 0, sizeof(m));
        (void)dislmdb_get_metrics(g_env, &m);
        char buf[256];
        snprintf(buf, sizeof(buf), "OK id=%s replicas=%u", g_node_id,
                 (unsigned)m.replica_count);
        reply(fd, buf);
        return;
    }

    char cmd[32], a[256], b[256], c[128];
    int n = sscanf(line, "%31s %255s %255s %127s", cmd, a, b, c);
    if (strcmp(cmd, "PUT") == 0 && n >= 3) {
        int rc = put_kv(a, b);
        if (rc == 0) {
            reply(fd, "OK");
        } else {
            char err[160];
            snprintf(err, sizeof(err), "ERR %s", dislmdb_strerror(rc));
            reply(fd, err);
        }
        return;
    }
    if (strcmp(cmd, "GET") == 0 && n >= 2) {
        char val[512];
        int rc = get_kv(a, val, sizeof(val));
        if (rc == 0) {
            char out[600];
            snprintf(out, sizeof(out), "OK %s", val);
            reply(fd, out);
        } else if (rc == MDB_NOTFOUND) {
            reply(fd, "ERR NOTFOUND");
        } else {
            char err[160];
            snprintf(err, sizeof(err), "ERR %s", dislmdb_strerror(rc));
            reply(fd, err);
        }
        return;
    }
    if (strcmp(cmd, "JOIN") == 0 && n >= 4) {
        DISLMDB_node_addr peer;
        memset(&peer, 0, sizeof(peer));
        strncpy(peer.hostname, a, sizeof(peer.hostname) - 1);
        peer.port = (uint16_t)atoi(b);
        strncpy(peer.node_id, c, sizeof(peer.node_id) - 1);
        int rc = dislmdb_add_node(g_env, &peer);
        if (rc == DISLMDB_SUCCESS || rc == DISLMDB_ERR_NODE_EXISTS) {
            reply(fd, "OK");
        } else {
            char err[160];
            snprintf(err, sizeof(err), "ERR %s", dislmdb_strerror(rc));
            reply(fd, err);
        }
        return;
    }

    reply(fd, "ERR UNKNOWN");
}

static void *admin_thread(void *arg)
{
    int listen_fd = *(int *)arg;
    while (g_running) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(listen_fd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (!g_running) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            usleep(20 * 1000);
            continue;
        }
        char buf[1024];
        ssize_t n = read(cfd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            handle_line(cfd, buf);
        }
        close(cfd);
    }
    return NULL;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s --id ID --data DIR --peer-port N --admin-port N "
            "[--seed] [--join host:port] [--fault N] [--transport tcp|udp|both]\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *data_dir = "/data";
    uint16_t peer_port = 9876;
    uint16_t admin_port = 19876;
    int is_seed = 0;
    const char *join = NULL;
    uint32_t fault = 0;
    DISLMDB_TRANSPORT transport = DISLMDB_TRANSPORT_BOTH;

    g_node_id[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            strncpy(g_node_id, argv[++i], sizeof(g_node_id) - 1);
        } else if (strcmp(argv[i], "--data") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(argv[i], "--peer-port") == 0 && i + 1 < argc) {
            peer_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--admin-port") == 0 && i + 1 < argc) {
            admin_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seed") == 0) {
            is_seed = 1;
        } else if (strcmp(argv[i], "--join") == 0 && i + 1 < argc) {
            join = argv[++i];
        } else if (strcmp(argv[i], "--fault") == 0 && i + 1 < argc) {
            fault = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            if (strcmp(t, "tcp") == 0) {
                transport = DISLMDB_TRANSPORT_TCP;
            } else if (strcmp(t, "udp") == 0) {
                transport = DISLMDB_TRANSPORT_UDP;
            } else if (strcmp(t, "both") == 0) {
                transport = DISLMDB_TRANSPORT_BOTH;
            } else {
                usage(argv[0]);
                return 2;
            }
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (g_node_id[0] == '\0') {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    DISLMDB_env_config cfg;
    dislmdb_env_config_init(&cfg);
    cfg.path = data_dir;
    cfg.mapsize = 32 * 1024 * 1024;
    cfg.maxdbs = 16;
    strncpy(cfg.node_name, g_node_id, sizeof(cfg.node_name) - 1);
    cfg.network.local_port = peer_port;
    cfg.network.transport = transport;
    cfg.network.is_seed_node = is_seed ? true : false;
    memset(cfg.network.cluster_key, 0x5A, 32);
    cfg.network.has_cluster_key = true;
    cfg.network.enable_message_auth = true;
    cfg.network.enable_payload_encryption = false;
    cfg.consensus.mechanism = DISLMDB_CONSENSUS_PBFT;
    cfg.consensus.fault_tolerance = fault;
    cfg.consensus.timeout_ms = 5000;
    cfg.consensus.heartbeat_interval_ms = 400;
    cfg.consensus.persist_state = true;

    if (join) {
        cfg.network.seed_node_count = 1;
        strncpy(cfg.network.seed_nodes[0], join, sizeof(cfg.network.seed_nodes[0]) - 1);
    }

    int rc = dislmdb_env_create(&g_env);
    if (rc != 0) {
        fprintf(stderr, "env_create: %s\n", dislmdb_strerror(rc));
        return 1;
    }
    rc = dislmdb_env_open(g_env, &cfg);
    if (rc != 0) {
        fprintf(stderr, "env_open: %s\n", dislmdb_strerror(rc));
        dislmdb_env_close(g_env);
        return 1;
    }

    if (join) {
        char host[256];
        uint16_t port = 9876;
        if (sscanf(join, "%255[^:]:%hu", host, &port) >= 1) {
            DISLMDB_node_addr seed;
            memset(&seed, 0, sizeof(seed));
            strncpy(seed.hostname, host, sizeof(seed.hostname) - 1);
            seed.port = port;
            snprintf(seed.node_id, sizeof(seed.node_id), "seed-%s", host);
            (void)dislmdb_add_node(g_env, &seed);
        }
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        dislmdb_env_close(g_env);
        return 1;
    }
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(admin_port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(lfd, 8) != 0) {
        perror("bind/listen");
        close(lfd);
        dislmdb_env_close(g_env);
        return 1;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, admin_thread, &lfd) != 0) {
        perror("pthread_create");
        close(lfd);
        dislmdb_env_close(g_env);
        return 1;
    }

    fprintf(stderr, "node_agent id=%s peer=%u admin=%u seed=%d ready\n",
            g_node_id, (unsigned)peer_port, (unsigned)admin_port, is_seed);

    while (g_running) {
        sleep(1);
    }

    close(lfd);
    pthread_join(th, NULL);
    dislmdb_env_close(g_env);
    return 0;
}
