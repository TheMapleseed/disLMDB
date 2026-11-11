/**
 * @file cluster_rig.c
 * @brief In-memory multi-node Raft cluster for sandbox-safe testing
 */
#include "cluster_rig.h"

#include "../../Enhanced-Raft-mechanism/raft.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char key[RIG_KEY_LEN];
    char val[RIG_VAL_LEN];
    bool used;
} RigKvSlot;

typedef struct BusMsg {
    RaftMessage msg;
    struct BusMsg *next;
} BusMsg;

typedef struct RigNodeCtx {
    struct RigCluster *cluster;
    uint32_t index;
} RigNodeCtx;

struct RigCluster {
    RigConfig cfg;
    char ids[RIG_MAX_NODES][RIG_ID_LEN];
    RaftNode *nodes[RIG_MAX_NODES];
    RigNodeCtx ctx[RIG_MAX_NODES];
    bool in_use[RIG_MAX_NODES];
    bool alive[RIG_MAX_NODES];
    RigKvSlot kv[RIG_MAX_NODES][RIG_KV_SLOTS];
    pthread_mutex_t lock;
    BusMsg *head;
    BusMsg *tail;
    BusMsg *sig_head;
    BusMsg *sig_tail;
    uint64_t signal_msgs;
    uint64_t data_msgs;
    uint64_t dropped_msgs;
    uint32_t drop_pct;
    uint32_t rng;
    uint32_t spawn_seq;
    pthread_t dispatcher;
    bool running;
    bool dispatcher_started;
};

static bool raft_msg_is_signal(RaftMsgType t)
{
    return t == RAFT_MSG_REQUEST_VOTE || t == RAFT_MSG_REQUEST_VOTE_REPLY;
}

static uint32_t rig_rand(RigCluster *c)
{
    /* xorshift32 — deterministic adversity without libc rand locking */
    uint32_t x = c->rng ? c->rng : 0xA5A5u;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    c->rng = x ? x : 0xA5A5u;
    return c->rng;
}

static int idx_of(RigCluster *c, const char *id)
{
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (!c->in_use[i]) {
            continue;
        }
        if (strncmp(c->ids[i], id, RIG_ID_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int find_free_slot(const RigCluster *c)
{
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (!c->in_use[i]) {
            return (int)i;
        }
    }
    return -1;
}

static void kv_set(RigCluster *c, uint32_t ni, const char *key, const char *val)
{
    RigKvSlot *slots = c->kv[ni];
    for (int i = 0; i < RIG_KV_SLOTS; i++) {
        if (slots[i].used && strncmp(slots[i].key, key, RIG_KEY_LEN) == 0) {
            strncpy(slots[i].val, val, RIG_VAL_LEN - 1);
            slots[i].val[RIG_VAL_LEN - 1] = '\0';
            return;
        }
    }
    for (int i = 0; i < RIG_KV_SLOTS; i++) {
        if (!slots[i].used) {
            slots[i].used = true;
            strncpy(slots[i].key, key, RIG_KEY_LEN - 1);
            strncpy(slots[i].val, val, RIG_VAL_LEN - 1);
            return;
        }
    }
}

static int kv_get(const RigCluster *c, uint32_t ni, const char *key,
                  char *out, size_t out_len)
{
    const RigKvSlot *slots = c->kv[ni];
    for (int i = 0; i < RIG_KV_SLOTS; i++) {
        if (slots[i].used && strncmp(slots[i].key, key, RIG_KEY_LEN) == 0) {
            strncpy(out, slots[i].val, out_len - 1);
            out[out_len - 1] = '\0';
            return 0;
        }
    }
    return -1;
}

static int encode_put(const char *key, const char *val, uint8_t **out, size_t *out_len)
{
    size_t k = strlen(key), v = strlen(val);
    size_t n = 4 + k + 1 + v + 1;
    uint8_t *buf = malloc(n);
    if (!buf) {
        return -1;
    }
    memcpy(buf, "PUT\0", 4);
    memcpy(buf + 4, key, k + 1);
    memcpy(buf + 4 + k + 1, val, v + 1);
    *out = buf;
    *out_len = n;
    return 0;
}

static void apply_put_blob(RigCluster *c, uint32_t ni, const uint8_t *data, size_t len)
{
    if (!data || len < 6 || memcmp(data, "PUT\0", 4) != 0) {
        return;
    }
    const char *key = (const char *)(data + 4);
    size_t klen = strnlen(key, RIG_KEY_LEN);
    if (4 + klen + 1 >= len) {
        return;
    }
    const char *val = (const char *)(data + 4 + klen + 1);
    kv_set(c, ni, key, val);
}

static void enqueue_on(BusMsg **head, BusMsg **tail, BusMsg *m)
{
    if (!*tail) {
        *head = *tail = m;
    } else {
        (*tail)->next = m;
        *tail = m;
    }
}

static void enqueue_copy(RigCluster *c, const RaftMessage *msg)
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
                } else {
                    m->msg.entries[i].data_len = 0;
                }
            }
        }
    }
    pthread_mutex_lock(&c->lock);
    if (c->cfg.transport == RIG_TRANSPORT_MIXED && raft_msg_is_signal(msg->type)) {
        enqueue_on(&c->sig_head, &c->sig_tail, m);
        c->signal_msgs++;
    } else {
        enqueue_on(&c->head, &c->tail, m);
        c->data_msgs++;
    }
    pthread_mutex_unlock(&c->lock);
}

static void on_out(const RaftMessage *msg, void *ud)
{
    RigNodeCtx *ctx = ud;
    if (!ctx || !ctx->cluster) {
        return;
    }
    enqueue_copy(ctx->cluster, msg);
}

static void on_apply(uint64_t index, const uint8_t *data, size_t len, void *ud)
{
    (void)index;
    RigNodeCtx *ctx = ud;
    if (!ctx || !ctx->cluster || ctx->index >= RIG_MAX_NODES) {
        return;
    }
    apply_put_blob(ctx->cluster, ctx->index, data, len);
}

static void deliver_bus_msg(RigCluster *c, BusMsg *m)
{
    int from_i = idx_of(c, m->msg.from);
    if (from_i >= 0 && (!c->in_use[from_i] || !c->alive[from_i])) {
        raft_message_clear(&m->msg);
        free(m);
        return;
    }

    pthread_mutex_lock(&c->lock);
    uint32_t drop = c->drop_pct;
    bool should_drop = false;
    if (drop > 0) {
        should_drop = (rig_rand(c) % 100u) < drop;
        if (should_drop) {
            c->dropped_msgs++;
        }
    }
    pthread_mutex_unlock(&c->lock);
    if (should_drop) {
        raft_message_clear(&m->msg);
        free(m);
        return;
    }

    if (m->msg.to[0] != '\0') {
        int ti = idx_of(c, m->msg.to);
        if (ti >= 0 && c->in_use[ti] && c->alive[ti] && c->nodes[ti]) {
            (void)raft_handle_message(c->nodes[ti], &m->msg);
        }
    } else {
        for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
            if (!c->in_use[i] || !c->alive[i] || !c->nodes[i]) {
                continue;
            }
            if (strncmp(c->ids[i], m->msg.from, RIG_ID_LEN) == 0) {
                continue;
            }
            (void)raft_handle_message(c->nodes[i], &m->msg);
        }
    }
    raft_message_clear(&m->msg);
    free(m);
}

static void *dispatch_thread(void *arg)
{
    RigCluster *c = arg;
    while (c->running) {
        BusMsg *m = NULL;
        pthread_mutex_lock(&c->lock);
        if (c->sig_head) {
            m = c->sig_head;
            c->sig_head = m->next;
            if (!c->sig_head) {
                c->sig_tail = NULL;
            }
        } else if (c->head) {
            m = c->head;
            c->head = m->next;
            if (!c->head) {
                c->tail = NULL;
            }
        }
        pthread_mutex_unlock(&c->lock);
        if (!m) {
            usleep(2 * 1000);
            continue;
        }
        deliver_bus_msg(c, m);
    }
    return NULL;
}

static RaftNode *make_node(RigCluster *c, uint32_t index)
{
    RaftConfig rc = raft_config_default();
    strncpy(rc.node_id, c->ids[index], RAFT_NODE_ID_LEN - 1);
    rc.peer_count = 0;
    for (uint32_t j = 0; j < RIG_MAX_NODES; j++) {
        if (j == index || !c->in_use[j]) {
            continue;
        }
        strncpy(rc.peer_ids[rc.peer_count], c->ids[j], RAFT_NODE_ID_LEN - 1);
        rc.peer_count++;
    }
    rc.election_timeout_min_ms = c->cfg.election_timeout_min_ms;
    rc.election_timeout_max_ms = c->cfg.election_timeout_max_ms;
    rc.heartbeat_ms = c->cfg.heartbeat_ms;
    c->ctx[index].cluster = c;
    c->ctx[index].index = index;
    return raft_create(&rc, on_out, on_apply, &c->ctx[index]);
}

RigConfig rig_config_default(void)
{
    RigConfig c;
    memset(&c, 0, sizeof(c));
    c.node_count = 3;
    c.transport = RIG_TRANSPORT_BUS;
    c.election_timeout_min_ms = 80;
    c.election_timeout_max_ms = 160;
    c.heartbeat_ms = 40;
    c.id_prefix = "rig";
    c.drop_pct = 0;
    return c;
}

RigCluster *rig_cluster_create(const RigConfig *cfg)
{
    if (!cfg || cfg->node_count < 2 || cfg->node_count > RIG_MAX_NODES) {
        return NULL;
    }
    RigCluster *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->cfg = *cfg;
    c->drop_pct = cfg->drop_pct > 100 ? 100 : cfg->drop_pct;
    c->rng = 0xC0FFEEu ^ (cfg->node_count * 2654435761u);
    pthread_mutex_init(&c->lock, NULL);

    const char *pfx = cfg->id_prefix ? cfg->id_prefix : "rig";
    for (uint32_t i = 0; i < cfg->node_count; i++) {
        snprintf(c->ids[i], RIG_ID_LEN, "%s-%u", pfx, i);
        c->in_use[i] = true;
        c->alive[i] = true;
    }

    for (uint32_t i = 0; i < cfg->node_count; i++) {
        c->nodes[i] = make_node(c, i);
        if (!c->nodes[i]) {
            rig_cluster_destroy(c);
            return NULL;
        }
    }

    c->running = true;
    if (pthread_create(&c->dispatcher, NULL, dispatch_thread, c) != 0) {
        c->running = false;
        for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
            if (c->nodes[i]) {
                raft_destroy(c->nodes[i]);
                c->nodes[i] = NULL;
            }
        }
        pthread_mutex_destroy(&c->lock);
        free(c);
        return NULL;
    }
    c->dispatcher_started = true;

    for (uint32_t i = 0; i < cfg->node_count; i++) {
        raft_start(c->nodes[i]);
    }
    return c;
}

void rig_cluster_destroy(RigCluster *c)
{
    if (!c) {
        return;
    }
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (c->nodes[i]) {
            raft_stop(c->nodes[i]);
        }
    }
    c->running = false;
    if (c->dispatcher_started) {
        pthread_join(c->dispatcher, NULL);
        c->dispatcher_started = false;
    }
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (c->nodes[i]) {
            raft_destroy(c->nodes[i]);
            c->nodes[i] = NULL;
        }
        c->in_use[i] = false;
        c->alive[i] = false;
    }
    while (c->head) {
        BusMsg *m = c->head;
        c->head = m->next;
        raft_message_clear(&m->msg);
        free(m);
    }
    while (c->sig_head) {
        BusMsg *m = c->sig_head;
        c->sig_head = m->next;
        raft_message_clear(&m->msg);
        free(m);
    }
    pthread_mutex_destroy(&c->lock);
    free(c);
}

uint64_t rig_signal_msgs(const RigCluster *c)
{
    return c ? c->signal_msgs : 0;
}

uint64_t rig_data_msgs(const RigCluster *c)
{
    return c ? c->data_msgs : 0;
}

void rig_set_drop_pct(RigCluster *c, uint32_t pct)
{
    if (!c) {
        return;
    }
    pthread_mutex_lock(&c->lock);
    c->drop_pct = pct > 100 ? 100 : pct;
    pthread_mutex_unlock(&c->lock);
}

uint64_t rig_dropped_msgs(const RigCluster *c)
{
    return c ? c->dropped_msgs : 0;
}

void rig_kill(RigCluster *c, uint32_t index)
{
    if (!c || index >= RIG_MAX_NODES || !c->in_use[index]) {
        return;
    }
    c->alive[index] = false;
}

void rig_revive(RigCluster *c, uint32_t index)
{
    if (!c || index >= RIG_MAX_NODES || !c->in_use[index]) {
        return;
    }
    c->alive[index] = true;
}

bool rig_alive(const RigCluster *c, uint32_t index)
{
    return c && index < RIG_MAX_NODES && c->in_use[index] && c->alive[index];
}

bool rig_in_use(const RigCluster *c, uint32_t index)
{
    return c && index < RIG_MAX_NODES && c->in_use[index];
}

int rig_spawn(RigCluster *c, const char *node_id)
{
    if (!c) {
        return -1;
    }
    pthread_mutex_lock(&c->lock);
    int slot = find_free_slot(c);
    if (slot < 0) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    char idbuf[RIG_ID_LEN];
    if (node_id && node_id[0] != '\0') {
        strncpy(idbuf, node_id, RIG_ID_LEN - 1);
        idbuf[RIG_ID_LEN - 1] = '\0';
    } else {
        const char *pfx = c->cfg.id_prefix ? c->cfg.id_prefix : "rig";
        snprintf(idbuf, sizeof(idbuf), "%s-s%u", pfx, c->spawn_seq++);
    }
    if (idx_of(c, idbuf) >= 0) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    strncpy(c->ids[slot], idbuf, RIG_ID_LEN - 1);
    c->ids[slot][RIG_ID_LEN - 1] = '\0';
    c->in_use[slot] = true;
    c->alive[slot] = true;
    memset(c->kv[slot], 0, sizeof(c->kv[slot]));
    pthread_mutex_unlock(&c->lock);

    RaftNode *n = make_node(c, (uint32_t)slot);
    if (!n) {
        pthread_mutex_lock(&c->lock);
        c->in_use[slot] = false;
        c->alive[slot] = false;
        c->ids[slot][0] = '\0';
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    c->nodes[slot] = n;

    /* Wire existing peers ↔ newcomer */
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if ((int)i == slot || !c->in_use[i] || !c->nodes[i]) {
            continue;
        }
        (void)raft_add_peer(c->nodes[i], c->ids[slot]);
        (void)raft_add_peer(c->nodes[slot], c->ids[i]);
    }
    raft_start(c->nodes[slot]);
    return slot;
}

int rig_despawn(RigCluster *c, uint32_t index)
{
    if (!c || index >= RIG_MAX_NODES || !c->in_use[index] || !c->nodes[index]) {
        return -1;
    }
    /* Keep a quorum foothold — refuse to drop below 2 active slots. */
    if (rig_active_count(c) <= 2) {
        return -1;
    }
    char leaving[RIG_ID_LEN];
    strncpy(leaving, c->ids[index], RIG_ID_LEN - 1);
    leaving[RIG_ID_LEN - 1] = '\0';

    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (i == index || !c->in_use[i] || !c->nodes[i]) {
            continue;
        }
        (void)raft_remove_peer(c->nodes[i], leaving);
    }

    raft_stop(c->nodes[index]);
    raft_destroy(c->nodes[index]);
    c->nodes[index] = NULL;
    c->alive[index] = false;
    c->in_use[index] = false;
    c->ids[index][0] = '\0';
    memset(c->kv[index], 0, sizeof(c->kv[index]));
    return 0;
}

int rig_wait_leader(RigCluster *c, char *out_id, size_t out_len, int timeout_ms)
{
    if (!c || !out_id || out_len < 2) {
        return -1;
    }
    int w = 0;
    while (w < timeout_ms) {
        for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
            if (!c->in_use[i] || !c->alive[i] || !c->nodes[i]) {
                continue;
            }
            char lid[RAFT_NODE_ID_LEN];
            raft_leader_id(c->nodes[i], lid);
            if (lid[0] != '\0') {
                strncpy(out_id, lid, out_len - 1);
                out_id[out_len - 1] = '\0';
                return 0;
            }
        }
        usleep(10 * 1000);
        w += 10;
    }
    return -1;
}

int rig_put(RigCluster *c, const char *key, const char *value, int timeout_ms)
{
    if (!c || !key || !value) {
        return -1;
    }
    char leader[RIG_ID_LEN];
    if (rig_wait_leader(c, leader, sizeof(leader), timeout_ms) != 0) {
        return -1;
    }
    int li = idx_of(c, leader);
    if (li < 0 || !c->alive[li]) {
        return -1;
    }
    uint8_t *blob = NULL;
    size_t blen = 0;
    if (encode_put(key, value, &blob, &blen) != 0) {
        return -1;
    }
    RaftError err = raft_propose(c->nodes[li], blob, blen, (uint32_t)timeout_ms);
    free(blob);
    return err == RAFT_OK ? 0 : -1;
}

int rig_get(const RigCluster *c, uint32_t node_index, const char *key,
            char *out, size_t out_len)
{
    if (!c || node_index >= RIG_MAX_NODES || !c->in_use[node_index] || !key ||
        !out) {
        return -1;
    }
    return kv_get(c, node_index, key, out, out_len);
}

int rig_wait_get(RigCluster *c, uint32_t node_index, const char *key,
                 const char *expect, int timeout_ms)
{
    int w = 0;
    char buf[RIG_VAL_LEN];
    while (w < timeout_ms) {
        if (rig_get(c, node_index, key, buf, sizeof(buf)) == 0 &&
            strcmp(buf, expect) == 0) {
            return 0;
        }
        usleep(10 * 1000);
        w += 10;
    }
    return -1;
}

int rig_wait_get_all_alive(RigCluster *c, const char *key, const char *expect,
                           int timeout_ms)
{
    if (!c || !key || !expect) {
        return -1;
    }
    int w = 0;
    while (w < timeout_ms) {
        bool all = true;
        uint32_t seen = 0;
        for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
            if (!c->in_use[i] || !c->alive[i]) {
                continue;
            }
            seen++;
            char buf[RIG_VAL_LEN];
            if (rig_get(c, i, key, buf, sizeof(buf)) != 0 ||
                strcmp(buf, expect) != 0) {
                all = false;
                break;
            }
        }
        if (all && seen > 0) {
            return 0;
        }
        usleep(10 * 1000);
        w += 10;
    }
    return -1;
}

uint32_t rig_node_count(const RigCluster *c)
{
    return c ? c->cfg.node_count : 0;
}

uint32_t rig_active_count(const RigCluster *c)
{
    if (!c) {
        return 0;
    }
    uint32_t n = 0;
    for (uint32_t i = 0; i < RIG_MAX_NODES; i++) {
        if (c->in_use[i]) {
            n++;
        }
    }
    return n;
}

const char *rig_node_id(const RigCluster *c, uint32_t index)
{
    if (!c || index >= RIG_MAX_NODES || !c->in_use[index]) {
        return "";
    }
    return c->ids[index];
}
