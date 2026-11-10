/**
 * @file test_raft_bus_rig.c
 * @brief Sandbox-safe: 3-node Raft over an in-memory bus (no LMDB / no UDP)
 *
 * Covers election, propose, apply, and surviving one "dead" peer (f=1 style).
 */
#include "../harness/test_harness.h"
#include "../../Enhanced-Raft-mechanism/raft.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define N 3

typedef struct BusMsg {
    RaftMessage msg;
    struct BusMsg *next;
} BusMsg;

typedef struct {
    RaftNode *nodes[N];
    char ids[N][RAFT_NODE_ID_LEN];
    bool alive[N];
    pthread_mutex_t lock;
    BusMsg *head;
    BusMsg *tail;
    pthread_t dispatcher;
    bool running;
    int applied[N];
} Bus;

static Bus g_bus;

static int idx_of(const char *id)
{
    for (int i = 0; i < N; i++) {
        if (strncmp(g_bus.ids[i], id, RAFT_NODE_ID_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

static void enqueue(const RaftMessage *msg)
{
    BusMsg *m = calloc(1, sizeof(*m));
    if (!m) {
        return;
    }
    m->msg = *msg;
    /* Deep-copy log entries if present */
    if (msg->entry_count > 0 && msg->entries) {
        m->msg.entries = calloc(msg->entry_count, sizeof(RaftLogEntry));
        if (!m->msg.entries) {
            free(m);
            return;
        }
        for (size_t i = 0; i < msg->entry_count; i++) {
            m->msg.entries[i] = msg->entries[i];
            if (msg->entries[i].data && msg->entries[i].data_len) {
                m->msg.entries[i].data = malloc(msg->entries[i].data_len);
                if (m->msg.entries[i].data) {
                    memcpy(m->msg.entries[i].data, msg->entries[i].data,
                           msg->entries[i].data_len);
                }
            }
        }
    }
    pthread_mutex_lock(&g_bus.lock);
    if (!g_bus.tail) {
        g_bus.head = g_bus.tail = m;
    } else {
        g_bus.tail->next = m;
        g_bus.tail = m;
    }
    pthread_mutex_unlock(&g_bus.lock);
}

static void on_out(const RaftMessage *msg, void *ud)
{
    (void)ud;
    enqueue(msg);
}

static void on_apply(uint64_t index, const uint8_t *data, size_t len, void *ud)
{
    (void)index;
    (void)data;
    (void)len;
    int *slot = ud;
    (*slot)++;
}

static void *dispatch_thread(void *arg)
{
    (void)arg;
    while (g_bus.running) {
        BusMsg *m = NULL;
        pthread_mutex_lock(&g_bus.lock);
        if (g_bus.head) {
            m = g_bus.head;
            g_bus.head = m->next;
            if (!g_bus.head) {
                g_bus.tail = NULL;
            }
        }
        pthread_mutex_unlock(&g_bus.lock);
        if (!m) {
            usleep(5 * 1000);
            continue;
        }
        if (m->msg.to[0] != '\0') {
            int ti = idx_of(m->msg.to);
            if (ti >= 0 && g_bus.alive[ti] && g_bus.nodes[ti]) {
                (void)raft_handle_message(g_bus.nodes[ti], &m->msg);
            }
        } else {
            for (int i = 0; i < N; i++) {
                if (!g_bus.alive[i] || !g_bus.nodes[i]) {
                    continue;
                }
                if (strncmp(g_bus.ids[i], m->msg.from, RAFT_NODE_ID_LEN) == 0) {
                    continue;
                }
                (void)raft_handle_message(g_bus.nodes[i], &m->msg);
            }
        }
        raft_message_clear(&m->msg);
        free(m);
    }
    return NULL;
}

static int wait_leader(char *out, int ms)
{
    int w = 0;
    while (w < ms) {
        for (int i = 0; i < N; i++) {
            if (!g_bus.alive[i]) {
                continue;
            }
            char lid[RAFT_NODE_ID_LEN];
            raft_leader_id(g_bus.nodes[i], lid);
            if (lid[0] != '\0') {
                strncpy(out, lid, RAFT_NODE_ID_LEN - 1);
                return 0;
            }
        }
        usleep(20 * 1000);
        w += 20;
    }
    return -1;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "rig/raft_bus");

    memset(&g_bus, 0, sizeof(g_bus));
    pthread_mutex_init(&g_bus.lock, NULL);
    strncpy(g_bus.ids[0], "bus-a", RAFT_NODE_ID_LEN - 1);
    strncpy(g_bus.ids[1], "bus-b", RAFT_NODE_ID_LEN - 1);
    strncpy(g_bus.ids[2], "bus-c", RAFT_NODE_ID_LEN - 1);
    for (int i = 0; i < N; i++) {
        g_bus.alive[i] = true;
    }

    g_bus.running = true;
    EXPECT_EQ_INT(&ctx, "dispatcher",
                  pthread_create(&g_bus.dispatcher, NULL, dispatch_thread, NULL), 0);

    for (int i = 0; i < N; i++) {
        RaftConfig cfg = raft_config_default();
        strncpy(cfg.node_id, g_bus.ids[i], RAFT_NODE_ID_LEN - 1);
        cfg.peer_count = 0;
        for (int j = 0; j < N; j++) {
            if (j == i) {
                continue;
            }
            strncpy(cfg.peer_ids[cfg.peer_count], g_bus.ids[j], RAFT_NODE_ID_LEN - 1);
            cfg.peer_count++;
        }
        cfg.election_timeout_min_ms = 80;
        cfg.election_timeout_max_ms = 160;
        cfg.heartbeat_ms = 40;
        g_bus.nodes[i] = raft_create(&cfg, on_out, on_apply, &g_bus.applied[i]);
        EXPECT_TRUE(&ctx, i == 0 ? "create_a" : (i == 1 ? "create_b" : "create_c"),
                    g_bus.nodes[i] != NULL);
        raft_start(g_bus.nodes[i]);
    }

    char leader[RAFT_NODE_ID_LEN] = {0};
    EXPECT_EQ_INT(&ctx, "elect", wait_leader(leader, 5000), 0);
    EXPECT_TRUE(&ctx, "leader_named", leader[0] != '\0');

    int li = idx_of(leader);
    EXPECT_TRUE(&ctx, "leader_idx", li >= 0);
    const char *payload = "bus-commit-1";
    RaftError err = raft_propose(g_bus.nodes[li], (const uint8_t *)payload,
                                 strlen(payload), 3000);
    EXPECT_EQ_INT(&ctx, "propose_all_up", (int)err, (int)RAFT_OK);

    /* Kill non-leader (majority of 2/3 still holds) */
    int victim = (li + 1) % N;
    g_bus.alive[victim] = false;
    usleep(250 * 1000);

    const char *payload2 = "bus-commit-2";
    /* Find current leader among alive; retry propose across brief election races. */
    char leader2[RAFT_NODE_ID_LEN] = {0};
    EXPECT_EQ_INT(&ctx, "reelect_or_keep", wait_leader(leader2, 5000), 0);
    int li2 = idx_of(leader2);
    EXPECT_TRUE(&ctx, "leader2_alive", li2 >= 0 && g_bus.alive[li2]);
    err = RAFT_ERR_TIMEOUT;
    for (int attempt = 0; attempt < 5 && err != RAFT_OK; attempt++) {
        memset(leader2, 0, sizeof(leader2));
        if (wait_leader(leader2, 2000) != 0) {
            continue;
        }
        li2 = idx_of(leader2);
        if (li2 < 0 || !g_bus.alive[li2]) {
            continue;
        }
        err = raft_propose(g_bus.nodes[li2], (const uint8_t *)payload2,
                           strlen(payload2), 4000);
        if (err == RAFT_ERR_NOT_LEADER) {
            usleep(100 * 1000);
        }
    }
    EXPECT_EQ_INT(&ctx, "propose_after_kill", (int)err, (int)RAFT_OK);

    int applied_alive = 0;
    for (int i = 0; i < N; i++) {
        if (g_bus.alive[i]) {
            applied_alive += g_bus.applied[i];
        }
    }
    EXPECT_TRUE(&ctx, "applied_progress", applied_alive >= 2);

    g_bus.running = false;
    pthread_join(g_bus.dispatcher, NULL);
    for (int i = 0; i < N; i++) {
        if (g_bus.nodes[i]) {
            raft_stop(g_bus.nodes[i]);
            raft_destroy(g_bus.nodes[i]);
        }
    }
    pthread_mutex_destroy(&g_bus.lock);
    return test_end(&ctx);
}
