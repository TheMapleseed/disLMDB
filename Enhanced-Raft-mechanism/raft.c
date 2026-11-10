/**
 * @file raft.c
 * @brief Raft consensus core — leader election and log replication
 */
#include "raft.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

struct RaftNode {
    RaftConfig cfg;
    RaftRole role;
    uint64_t current_term;
    char voted_for[RAFT_NODE_ID_LEN];
    char leader_id[RAFT_NODE_ID_LEN];
    RaftLogEntry log[RAFT_MAX_LOG];
    size_t log_count; /* number of entries; index = position+1 */
    uint64_t commit_index;
    uint64_t last_applied;
    uint64_t next_index[RAFT_MAX_PEERS];
    uint64_t match_index[RAFT_MAX_PEERS];
    uint32_t votes;
    raft_outbound_fn outbound;
    raft_apply_fn apply;
    void *user_data;
    pthread_mutex_t lock;
    pthread_cond_t commit_cv;
    pthread_t tick_thread;
    bool running;
    uint64_t election_deadline_ms;
    uint64_t last_heartbeat_ms;
    bool propose_inflight;
    uint64_t propose_index;
};

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint32_t rand_range(uint32_t lo, uint32_t hi)
{
    if (hi <= lo) {
        return lo;
    }
    return lo + (uint32_t)(rand() % (int)(hi - lo + 1));
}

RaftConfig raft_config_default(void)
{
    RaftConfig c;
    memset(&c, 0, sizeof(c));
    c.election_timeout_min_ms = 300;
    c.election_timeout_max_ms = 600;
    c.heartbeat_ms = 100;
    return c;
}

static void reset_election_deadline(RaftNode *n)
{
    uint32_t to = rand_range(n->cfg.election_timeout_min_ms,
                             n->cfg.election_timeout_max_ms);
    n->election_deadline_ms = now_ms() + to;
}

static uint64_t last_log_index(const RaftNode *n)
{
    return n->log_count;
}

static uint64_t last_log_term(const RaftNode *n)
{
    if (n->log_count == 0) {
        return 0;
    }
    return n->log[n->log_count - 1].term;
}

static int peer_index(const RaftNode *n, const char *id)
{
    for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
        if (strncmp(n->cfg.peer_ids[i], id, RAFT_NODE_ID_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void send_msg(RaftNode *n, RaftMessage *msg)
{
    strncpy(msg->from, n->cfg.node_id, RAFT_NODE_ID_LEN - 1);
    if (n->outbound) {
        n->outbound(msg, n->user_data);
    }
}

static void become_follower(RaftNode *n, uint64_t term)
{
    n->role = RAFT_FOLLOWER;
    n->current_term = term;
    n->voted_for[0] = '\0';
    n->leader_id[0] = '\0';
    n->votes = 0;
    reset_election_deadline(n);
}

static void apply_committed(RaftNode *n)
{
    while (n->last_applied < n->commit_index) {
        n->last_applied++;
        size_t li = (size_t)n->last_applied - 1;
        if (li < n->log_count && n->apply) {
            n->apply(n->log[li].index, n->log[li].data, n->log[li].data_len, n->user_data);
        }
        if (n->propose_inflight && n->propose_index == n->last_applied) {
            n->propose_inflight = false;
            pthread_cond_broadcast(&n->commit_cv);
        }
    }
}

static void advance_commit(RaftNode *n)
{
    if (n->role != RAFT_LEADER) {
        return;
    }
    for (uint64_t N = n->log_count; N > n->commit_index; N--) {
        if (n->log[N - 1].term != n->current_term) {
            continue;
        }
        uint32_t replicas = 1; /* self */
        for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
            if (n->match_index[i] >= N) {
                replicas++;
            }
        }
        uint32_t majority = (n->cfg.peer_count + 1) / 2 + 1;
        if (replicas >= majority) {
            n->commit_index = N;
            apply_committed(n);
            break;
        }
    }
}

static void broadcast_append(RaftNode *n, bool heartbeat_only)
{
    for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
        RaftMessage msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = RAFT_MSG_APPEND_ENTRIES;
        msg.term = n->current_term;
        strncpy(msg.to, n->cfg.peer_ids[i], RAFT_NODE_ID_LEN - 1);
        uint64_t next = n->next_index[i];
        msg.prev_log_index = next > 0 ? next - 1 : 0;
        msg.prev_log_term = 0;
        if (msg.prev_log_index > 0 && msg.prev_log_index <= n->log_count) {
            msg.prev_log_term = n->log[msg.prev_log_index - 1].term;
        }
        msg.leader_commit = n->commit_index;
        if (!heartbeat_only && next <= n->log_count) {
            size_t count = n->log_count - (size_t)(next - 1);
            if (count > 16) {
                count = 16;
            }
            msg.entries = calloc(count, sizeof(RaftLogEntry));
            if (msg.entries) {
                msg.entry_count = count;
                for (size_t e = 0; e < count; e++) {
                    size_t li = (size_t)(next - 1) + e;
                    msg.entries[e].term = n->log[li].term;
                    msg.entries[e].index = n->log[li].index;
                    msg.entries[e].data_len = n->log[li].data_len;
                    if (n->log[li].data_len && n->log[li].data) {
                        msg.entries[e].data = malloc(n->log[li].data_len);
                        if (msg.entries[e].data) {
                            memcpy(msg.entries[e].data, n->log[li].data, n->log[li].data_len);
                        }
                    }
                }
            }
        }
        send_msg(n, &msg);
        raft_message_clear(&msg);
    }
    n->last_heartbeat_ms = now_ms();
}

static void start_election(RaftNode *n)
{
    n->role = RAFT_CANDIDATE;
    n->current_term++;
    strncpy(n->voted_for, n->cfg.node_id, RAFT_NODE_ID_LEN - 1);
    n->votes = 1;
    n->leader_id[0] = '\0';
    reset_election_deadline(n);

    uint32_t majority = (n->cfg.peer_count + 1) / 2 + 1;
    if (n->votes >= majority) {
        /* Solo / single voter wins immediately */
        n->role = RAFT_LEADER;
        strncpy(n->leader_id, n->cfg.node_id, RAFT_NODE_ID_LEN - 1);
        for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
            n->next_index[i] = last_log_index(n) + 1;
            n->match_index[i] = 0;
        }
        broadcast_append(n, true);
        return;
    }

    for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
        RaftMessage msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = RAFT_MSG_REQUEST_VOTE;
        msg.term = n->current_term;
        strncpy(msg.to, n->cfg.peer_ids[i], RAFT_NODE_ID_LEN - 1);
        msg.last_log_index = last_log_index(n);
        msg.last_log_term = last_log_term(n);
        send_msg(n, &msg);
    }
}

static void *tick_thread(void *arg)
{
    RaftNode *n = arg;
    while (n->running) {
        pthread_mutex_lock(&n->lock);
        uint64_t now = now_ms();
        if (n->role == RAFT_LEADER) {
            if (now - n->last_heartbeat_ms >= n->cfg.heartbeat_ms) {
                broadcast_append(n, true);
            }
        } else if (now >= n->election_deadline_ms) {
            start_election(n);
        }
        pthread_mutex_unlock(&n->lock);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

RaftNode *raft_create(const RaftConfig *cfg,
                      raft_outbound_fn outbound,
                      raft_apply_fn apply,
                      void *user_data)
{
    if (!cfg || cfg->node_id[0] == '\0') {
        return NULL;
    }
    RaftNode *n = calloc(1, sizeof(*n));
    if (!n) {
        return NULL;
    }
    n->cfg = *cfg;
    n->role = RAFT_FOLLOWER;
    n->outbound = outbound;
    n->apply = apply;
    n->user_data = user_data;
    pthread_mutex_init(&n->lock, NULL);
    pthread_cond_init(&n->commit_cv, NULL);
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    reset_election_deadline(n);
    return n;
}

void raft_destroy(RaftNode *node)
{
    if (!node) {
        return;
    }
    raft_stop(node);
    for (size_t i = 0; i < node->log_count; i++) {
        free(node->log[i].data);
    }
    pthread_mutex_destroy(&node->lock);
    pthread_cond_destroy(&node->commit_cv);
    free(node);
}

void raft_start(RaftNode *node)
{
    if (!node || node->running) {
        return;
    }
    node->running = true;
    reset_election_deadline(node);
    pthread_create(&node->tick_thread, NULL, tick_thread, node);
}

void raft_stop(RaftNode *node)
{
    if (!node || !node->running) {
        return;
    }
    node->running = false;
    pthread_join(node->tick_thread, NULL);
}

RaftError raft_propose(RaftNode *node, const uint8_t *data, size_t len, uint32_t timeout_ms)
{
    if (!node || (!data && len > 0)) {
        return RAFT_ERR_INVALID;
    }
    pthread_mutex_lock(&node->lock);
    if (node->role != RAFT_LEADER) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_NOT_LEADER;
    }
    if (node->log_count >= RAFT_MAX_LOG) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_FULL;
    }
    size_t idx = node->log_count;
    node->log[idx].term = node->current_term;
    node->log[idx].index = idx + 1;
    node->log[idx].data_len = len;
    node->log[idx].data = NULL;
    if (len > 0) {
        node->log[idx].data = malloc(len);
        if (!node->log[idx].data) {
            pthread_mutex_unlock(&node->lock);
            return RAFT_ERR_MEMORY;
        }
        memcpy(node->log[idx].data, data, len);
    }
    node->log_count++;
    node->propose_inflight = true;
    node->propose_index = node->log[idx].index;

    /* Solo cluster: commit immediately */
    if (node->cfg.peer_count == 0) {
        node->commit_index = node->log[idx].index;
        apply_committed(node);
        pthread_mutex_unlock(&node->lock);
        return RAFT_OK;
    }

    broadcast_append(node, false);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += (time_t)(timeout_ms / 1000u);
    deadline.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    while (node->propose_inflight && node->last_applied < node->propose_index) {
        int wr = pthread_cond_timedwait(&node->commit_cv, &node->lock, &deadline);
        if (wr == ETIMEDOUT) {
            node->propose_inflight = false;
            pthread_mutex_unlock(&node->lock);
            return RAFT_ERR_TIMEOUT;
        }
    }
    pthread_mutex_unlock(&node->lock);
    return RAFT_OK;
}

static void handle_request_vote(RaftNode *n, const RaftMessage *msg)
{
    RaftMessage reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = RAFT_MSG_REQUEST_VOTE_REPLY;
    reply.term = n->current_term;
    strncpy(reply.to, msg->from, RAFT_NODE_ID_LEN - 1);

    if (msg->term < n->current_term) {
        reply.vote_granted = false;
        send_msg(n, &reply);
        return;
    }
    if (msg->term > n->current_term) {
        become_follower(n, msg->term);
        reply.term = n->current_term;
    }
    bool up_to_date =
        (msg->last_log_term > last_log_term(n)) ||
        (msg->last_log_term == last_log_term(n) && msg->last_log_index >= last_log_index(n));
    if ((n->voted_for[0] == '\0' || strncmp(n->voted_for, msg->from, RAFT_NODE_ID_LEN) == 0) &&
        up_to_date) {
        strncpy(n->voted_for, msg->from, RAFT_NODE_ID_LEN - 1);
        reply.vote_granted = true;
        reset_election_deadline(n);
    } else {
        reply.vote_granted = false;
    }
    send_msg(n, &reply);
}

static void handle_request_vote_reply(RaftNode *n, const RaftMessage *msg)
{
    if (n->role != RAFT_CANDIDATE || msg->term != n->current_term) {
        if (msg->term > n->current_term) {
            become_follower(n, msg->term);
        }
        return;
    }
    if (msg->vote_granted) {
        n->votes++;
        uint32_t majority = (n->cfg.peer_count + 1) / 2 + 1;
        if (n->votes >= majority) {
            n->role = RAFT_LEADER;
            strncpy(n->leader_id, n->cfg.node_id, RAFT_NODE_ID_LEN - 1);
            for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
                n->next_index[i] = last_log_index(n) + 1;
                n->match_index[i] = 0;
            }
            broadcast_append(n, true);
        }
    }
}

static void handle_append_entries(RaftNode *n, const RaftMessage *msg)
{
    RaftMessage reply;
    memset(&reply, 0, sizeof(reply));
    reply.type = RAFT_MSG_APPEND_ENTRIES_REPLY;
    reply.term = n->current_term;
    strncpy(reply.to, msg->from, RAFT_NODE_ID_LEN - 1);

    if (msg->term < n->current_term) {
        reply.success = false;
        send_msg(n, &reply);
        return;
    }
    if (msg->term >= n->current_term) {
        become_follower(n, msg->term);
        strncpy(n->leader_id, msg->from, RAFT_NODE_ID_LEN - 1);
        reply.term = n->current_term;
    }
    reset_election_deadline(n);

    if (msg->prev_log_index > 0) {
        if (msg->prev_log_index > n->log_count ||
            n->log[msg->prev_log_index - 1].term != msg->prev_log_term) {
            reply.success = false;
            send_msg(n, &reply);
            return;
        }
    }

    /* Append / conflict resolution */
    for (size_t i = 0; i < msg->entry_count; i++) {
        uint64_t index = msg->prev_log_index + 1 + i;
        if (index <= n->log_count) {
            if (n->log[index - 1].term != msg->entries[i].term) {
                for (size_t j = (size_t)index - 1; j < n->log_count; j++) {
                    free(n->log[j].data);
                    memset(&n->log[j], 0, sizeof(n->log[j]));
                }
                n->log_count = (size_t)index - 1;
            } else {
                continue;
            }
        }
        if (n->log_count >= RAFT_MAX_LOG) {
            break;
        }
        size_t li = n->log_count;
        n->log[li].term = msg->entries[i].term;
        n->log[li].index = index;
        n->log[li].data_len = msg->entries[i].data_len;
        n->log[li].data = NULL;
        if (msg->entries[i].data_len && msg->entries[i].data) {
            n->log[li].data = malloc(msg->entries[i].data_len);
            if (n->log[li].data) {
                memcpy(n->log[li].data, msg->entries[i].data, msg->entries[i].data_len);
            }
        }
        n->log_count++;
    }

    if (msg->leader_commit > n->commit_index) {
        uint64_t last = last_log_index(n);
        n->commit_index = msg->leader_commit < last ? msg->leader_commit : last;
        apply_committed(n);
    }
    reply.success = true;
    reply.match_index = last_log_index(n);
    send_msg(n, &reply);
}

static void handle_append_entries_reply(RaftNode *n, const RaftMessage *msg)
{
    if (msg->term > n->current_term) {
        become_follower(n, msg->term);
        return;
    }
    if (n->role != RAFT_LEADER || msg->term != n->current_term) {
        return;
    }
    int pi = peer_index(n, msg->from);
    if (pi < 0) {
        return;
    }
    if (msg->success) {
        n->match_index[pi] = msg->match_index;
        n->next_index[pi] = msg->match_index + 1;
        advance_commit(n);
    } else if (n->next_index[pi] > 1) {
        n->next_index[pi]--;
        broadcast_append(n, false);
    }
}

RaftError raft_handle_message(RaftNode *node, const RaftMessage *msg)
{
    if (!node || !msg) {
        return RAFT_ERR_INVALID;
    }
    pthread_mutex_lock(&node->lock);
    switch (msg->type) {
        case RAFT_MSG_REQUEST_VOTE:
            handle_request_vote(node, msg);
            break;
        case RAFT_MSG_REQUEST_VOTE_REPLY:
            handle_request_vote_reply(node, msg);
            break;
        case RAFT_MSG_APPEND_ENTRIES:
            handle_append_entries(node, msg);
            break;
        case RAFT_MSG_APPEND_ENTRIES_REPLY:
            handle_append_entries_reply(node, msg);
            break;
        default:
            break;
    }
    pthread_mutex_unlock(&node->lock);
    return RAFT_OK;
}

RaftRole raft_role(const RaftNode *node)
{
    return node ? node->role : RAFT_FOLLOWER;
}

uint64_t raft_term(const RaftNode *node)
{
    return node ? node->current_term : 0;
}

uint64_t raft_commit_index(const RaftNode *node)
{
    return node ? node->commit_index : 0;
}

uint64_t raft_last_applied(const RaftNode *node)
{
    return node ? node->last_applied : 0;
}

bool raft_is_leader(const RaftNode *node)
{
    return node && node->role == RAFT_LEADER;
}

void raft_leader_id(const RaftNode *node, char out[RAFT_NODE_ID_LEN])
{
    if (!out) {
        return;
    }
    out[0] = '\0';
    if (!node) {
        return;
    }
    strncpy(out, node->leader_id, RAFT_NODE_ID_LEN - 1);
}

void raft_message_clear(RaftMessage *msg)
{
    if (!msg) {
        return;
    }
    if (msg->entries) {
        for (size_t i = 0; i < msg->entry_count; i++) {
            free(msg->entries[i].data);
        }
        free(msg->entries);
    }
    msg->entries = NULL;
    msg->entry_count = 0;
}

static void write_u64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[7 - i] = (uint8_t)((v >> (i * 8)) & 0xff);
    }
}

static uint64_t read_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

int raft_message_serialize(const RaftMessage *msg, uint8_t **out, size_t *out_len)
{
    if (!msg || !out || !out_len) {
        return -1;
    }
    size_t need = 1 + 8 + 64 + 64 + 8 + 8 + 8 + 8 + 8 + 1 + 1 + 8 + 4;
    for (size_t i = 0; i < msg->entry_count; i++) {
        need += 8 + 8 + 4 + msg->entries[i].data_len;
    }
    uint8_t *buf = calloc(1, need);
    if (!buf) {
        return -1;
    }
    size_t o = 0;
    buf[o++] = (uint8_t)msg->type;
    write_u64(buf + o, msg->term); o += 8;
    memcpy(buf + o, msg->from, 64); o += 64;
    memcpy(buf + o, msg->to, 64); o += 64;
    write_u64(buf + o, msg->last_log_index); o += 8;
    write_u64(buf + o, msg->last_log_term); o += 8;
    write_u64(buf + o, msg->prev_log_index); o += 8;
    write_u64(buf + o, msg->prev_log_term); o += 8;
    write_u64(buf + o, msg->leader_commit); o += 8;
    buf[o++] = msg->success ? 1 : 0;
    buf[o++] = msg->vote_granted ? 1 : 0;
    write_u64(buf + o, msg->match_index); o += 8;
    uint32_t ec = (uint32_t)msg->entry_count;
    buf[o++] = (uint8_t)((ec >> 24) & 0xff);
    buf[o++] = (uint8_t)((ec >> 16) & 0xff);
    buf[o++] = (uint8_t)((ec >> 8) & 0xff);
    buf[o++] = (uint8_t)(ec & 0xff);
    for (size_t i = 0; i < msg->entry_count; i++) {
        write_u64(buf + o, msg->entries[i].term); o += 8;
        write_u64(buf + o, msg->entries[i].index); o += 8;
        uint32_t dl = (uint32_t)msg->entries[i].data_len;
        buf[o++] = (uint8_t)((dl >> 24) & 0xff);
        buf[o++] = (uint8_t)((dl >> 16) & 0xff);
        buf[o++] = (uint8_t)((dl >> 8) & 0xff);
        buf[o++] = (uint8_t)(dl & 0xff);
        if (dl && msg->entries[i].data) {
            memcpy(buf + o, msg->entries[i].data, dl);
            o += dl;
        }
    }
    *out = buf;
    *out_len = o;
    return 0;
}

int raft_message_deserialize(const uint8_t *buf, size_t len, RaftMessage *out)
{
    if (!buf || !out || len < 1 + 8 + 64 + 64 + 8 * 5 + 2 + 8 + 4) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    size_t o = 0;
    out->type = (RaftMsgType)buf[o++];
    out->term = read_u64(buf + o); o += 8;
    memcpy(out->from, buf + o, 64); o += 64;
    memcpy(out->to, buf + o, 64); o += 64;
    out->last_log_index = read_u64(buf + o); o += 8;
    out->last_log_term = read_u64(buf + o); o += 8;
    out->prev_log_index = read_u64(buf + o); o += 8;
    out->prev_log_term = read_u64(buf + o); o += 8;
    out->leader_commit = read_u64(buf + o); o += 8;
    out->success = buf[o++] != 0;
    out->vote_granted = buf[o++] != 0;
    out->match_index = read_u64(buf + o); o += 8;
    if (o + 4 > len) {
        return -1;
    }
    uint32_t ec = ((uint32_t)buf[o] << 24) | ((uint32_t)buf[o + 1] << 16) |
                  ((uint32_t)buf[o + 2] << 8) | (uint32_t)buf[o + 3];
    o += 4;
    if (ec > 64) {
        return -1;
    }
    if (ec > 0) {
        out->entries = calloc(ec, sizeof(RaftLogEntry));
        if (!out->entries) {
            return -1;
        }
        out->entry_count = ec;
        for (uint32_t i = 0; i < ec; i++) {
            if (o + 8 + 8 + 4 > len) {
                raft_message_clear(out);
                return -1;
            }
            out->entries[i].term = read_u64(buf + o); o += 8;
            out->entries[i].index = read_u64(buf + o); o += 8;
            uint32_t dl = ((uint32_t)buf[o] << 24) | ((uint32_t)buf[o + 1] << 16) |
                          ((uint32_t)buf[o + 2] << 8) | (uint32_t)buf[o + 3];
            o += 4;
            out->entries[i].data_len = dl;
            if (dl > 0) {
                if (o + dl > len) {
                    raft_message_clear(out);
                    return -1;
                }
                out->entries[i].data = malloc(dl);
                if (!out->entries[i].data) {
                    raft_message_clear(out);
                    return -1;
                }
                memcpy(out->entries[i].data, buf + o, dl);
                o += dl;
            }
        }
    }
    return 0;
}
