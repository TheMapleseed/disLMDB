/**
 * @file test_raft_membership.c
 * @brief Unit: Raft joint-consensus membership (solo → 2 peers via in-proc bus)
 */
#include "../harness/test_harness.h"
#include "../../Enhanced-Raft-mechanism/raft.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define N 2

typedef struct BusMsg {
    RaftMessage msg;
    struct BusMsg *next;
} BusMsg;

typedef struct {
    RaftNode *nodes[N];
    char ids[N][RAFT_NODE_ID_LEN];
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
            if (ti >= 0 && g_bus.nodes[ti]) {
                (void)raft_handle_message(g_bus.nodes[ti], &m->msg);
            }
        }
        raft_message_clear(&m->msg);
        free(m);
    }
    return NULL;
}

int main(void)
{
    test_ctx_t ctx;
    test_begin(&ctx, "unit/raft_membership");

    memset(&g_bus, 0, sizeof(g_bus));
    pthread_mutex_init(&g_bus.lock, NULL);
    strncpy(g_bus.ids[0], "m-a", RAFT_NODE_ID_LEN - 1);
    strncpy(g_bus.ids[1], "m-b", RAFT_NODE_ID_LEN - 1);

    g_bus.running = true;
    EXPECT_EQ_INT(&ctx, "dispatcher",
                  pthread_create(&g_bus.dispatcher, NULL, dispatch_thread, NULL), 0);

    /* A starts solo; B starts knowing A (will receive AppendEntries after join). */
    RaftConfig cfg_a = raft_config_default();
    strncpy(cfg_a.node_id, g_bus.ids[0], RAFT_NODE_ID_LEN - 1);
    cfg_a.peer_count = 0;
    cfg_a.election_timeout_min_ms = 60;
    cfg_a.election_timeout_max_ms = 120;
    cfg_a.heartbeat_ms = 30;
    g_bus.nodes[0] = raft_create(&cfg_a, on_out, on_apply, &g_bus.applied[0]);
    EXPECT_TRUE(&ctx, "create_a", g_bus.nodes[0] != NULL);
    raft_start(g_bus.nodes[0]);

    for (int i = 0; i < 50 && !raft_is_leader(g_bus.nodes[0]); i++) {
        usleep(20 * 1000);
    }
    EXPECT_TRUE(&ctx, "a_leader", raft_is_leader(g_bus.nodes[0]));
    EXPECT_EQ_INT(&ctx, "peers_solo", (int)raft_peer_count(g_bus.nodes[0]), 0);

    RaftConfig cfg_b = raft_config_default();
    strncpy(cfg_b.node_id, g_bus.ids[1], RAFT_NODE_ID_LEN - 1);
    cfg_b.peer_count = 1;
    strncpy(cfg_b.peer_ids[0], g_bus.ids[0], RAFT_NODE_ID_LEN - 1);
    cfg_b.election_timeout_min_ms = 200;
    cfg_b.election_timeout_max_ms = 400;
    cfg_b.heartbeat_ms = 30;
    g_bus.nodes[1] = raft_create(&cfg_b, on_out, on_apply, &g_bus.applied[1]);
    EXPECT_TRUE(&ctx, "create_b", g_bus.nodes[1] != NULL);
    raft_start(g_bus.nodes[1]);

    char peers[1][RAFT_NODE_ID_LEN];
    memset(peers, 0, sizeof(peers));
    strncpy(peers[0], g_bus.ids[1], RAFT_NODE_ID_LEN - 1);

    RaftError err = raft_propose_membership(g_bus.nodes[0], peers, 1, 4000);
    EXPECT_EQ_INT(&ctx, "joint_ok", (int)err, (int)RAFT_OK);
    EXPECT_TRUE(&ctx, "not_joint", !raft_in_joint_consensus(g_bus.nodes[0]));
    EXPECT_EQ_INT(&ctx, "peers_a", (int)raft_peer_count(g_bus.nodes[0]), 1);
    EXPECT_EQ_INT(&ctx, "peers_b", (int)raft_peer_count(g_bus.nodes[1]), 1);

    const char *payload = "after-join";
    err = raft_propose(g_bus.nodes[0], (const uint8_t *)payload, strlen(payload), 3000);
    EXPECT_EQ_INT(&ctx, "propose_2node", (int)err, (int)RAFT_OK);

    for (int i = 0; i < 50 && g_bus.applied[1] < 1; i++) {
        usleep(20 * 1000);
    }
    EXPECT_TRUE(&ctx, "b_applied", g_bus.applied[1] >= 1);

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
