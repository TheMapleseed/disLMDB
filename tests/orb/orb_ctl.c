/**
 * @file orb_ctl.c
 * @brief Client for node_agent admin protocol (OrbStack / Docker harness)
 *
 * Usage: orb_ctl <host:admin_port> <CMD> [args...]
 * Example: orb_ctl 127.0.0.1:19876 PUT alpha omega
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int parse_host_port(const char *spec, char *host, size_t host_len, uint16_t *port)
{
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec) {
        return -1;
    }
    size_t hlen = (size_t)(colon - spec);
    if (hlen >= host_len) {
        return -1;
    }
    memcpy(host, spec, hlen);
    host[hlen] = '\0';
    *port = (uint16_t)atoi(colon + 1);
    return *port ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host:admin_port> <CMD> [args...]\n", argv[0]);
        return 2;
    }

    char host[256];
    uint16_t port = 0;
    if (parse_host_port(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "bad host:port\n");
        return 2;
    }

    char req[900];
    size_t off = 0;
    for (int i = 2; i < argc; i++) {
        int n = snprintf(req + off, sizeof(req) - off, "%s%s",
                         i == 2 ? "" : " ", argv[i]);
        if (n < 0 || (size_t)n >= sizeof(req) - off) {
            fprintf(stderr, "request too long\n");
            return 2;
        }
        off += (size_t)n;
    }
    if (off + 2 >= sizeof(req)) {
        return 2;
    }
    req[off++] = '\n';
    req[off] = '\0';

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "resolve: %s\n", gai_strerror(gai));
        return 1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));
        return 1;
    }

    if (write(fd, req, strlen(req)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    char resp[1024];
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "no response\n");
        return 1;
    }
    resp[n] = '\0';
    fputs(resp, stdout);
    if (strncmp(resp, "OK", 2) == 0) {
        return 0;
    }
    return 1;
}
