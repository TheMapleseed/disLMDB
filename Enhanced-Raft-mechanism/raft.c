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

#define RAFT_CFG_MAGIC 0x52434647u /* 'RCFG' */
#define RAFT_CFG_PHASE_JOINT 1u
#define RAFT_CFG_PHASE_NEW 2u

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
    uint32_t votes;      /* Cold (or sole) config vote tally while candidate */
    uint32_t votes_new;  /* Cnew vote tally while in joint consensus */
    /* Joint consensus: Cold (old_*) and Cnew (new_*); cfg.peers = Cold ∪ Cnew */
    bool in_joint;
    char old_peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t old_peer_count;
    char new_peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t new_peer_count;
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

static uint64_t last_log_index(const RaftNode *n);
static int peer_index(const RaftNode *n, const char *id);

static void write_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static uint32_t read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static bool is_membership_entry(const uint8_t *data, size_t len)
{
    return data && len >= 9 && read_u32(data) == RAFT_CFG_MAGIC;
}

static int encode_membership(uint8_t phase,
                             const char peers[][RAFT_NODE_ID_LEN],
                             uint32_t peer_count,
                             uint8_t **out,
                             size_t *out_len)
{
    if (!out || !out_len || peer_count > RAFT_MAX_PEERS) {
        return -1;
    }
    if (peer_count > 0 && !peers) {
        return -1;
    }
    size_t need = 4 + 1 + 4 + (size_t)peer_count * RAFT_NODE_ID_LEN;
    uint8_t *buf = calloc(1, need);
    if (!buf) {
        return -1;
    }
    size_t o = 0;
    write_u32(buf + o, RAFT_CFG_MAGIC); o += 4;
    buf[o++] = phase;
    write_u32(buf + o, peer_count); o += 4;
    for (uint32_t i = 0; i < peer_count; i++) {
        memcpy(buf + o, peers[i], RAFT_NODE_ID_LEN);
        o += RAFT_NODE_ID_LEN;
    }
    *out = buf;
    *out_len = o;
    return 0;
}

static int decode_membership(const uint8_t *data, size_t len,
                             uint8_t *phase_out,
                             char peers[][RAFT_NODE_ID_LEN],
                             uint32_t *peer_count_out)
{
    if (!is_membership_entry(data, len) || !phase_out || !peer_count_out) {
        return -1;
    }
    size_t o = 4;
    uint8_t phase = data[o++];
    if (phase != RAFT_CFG_PHASE_JOINT && phase != RAFT_CFG_PHASE_NEW) {
        return -1;
    }
    if (o + 4 > len) {
        return -1;
    }
    uint32_t pc = read_u32(data + o); o += 4;
    if (pc > RAFT_MAX_PEERS || o + (size_t)pc * RAFT_NODE_ID_LEN > len) {
        return -1;
    }
    if (peers) {
        for (uint32_t i = 0; i < pc; i++) {
            memcpy(peers[i], data + o, RAFT_NODE_ID_LEN);
            peers[i][RAFT_NODE_ID_LEN - 1] = '\0';
            o += RAFT_NODE_ID_LEN;
        }
    }
    *phase_out = phase;
    *peer_count_out = pc;
    return 0;
}

static void install_peer_set(RaftNode *n,
                             const char peers[][RAFT_NODE_ID_LEN],
                             uint32_t count)
{
    uint64_t old_next[RAFT_MAX_PEERS];
    uint64_t old_match[RAFT_MAX_PEERS];
    char old_ids[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t old_count = n->cfg.peer_count;
    memcpy(old_ids, n->cfg.peer_ids, sizeof(old_ids));
    memcpy(old_next, n->next_index, sizeof(old_next));
    memcpy(old_match, n->match_index, sizeof(old_match));

    memset(n->cfg.peer_ids, 0, sizeof(n->cfg.peer_ids));
    memset(n->next_index, 0, sizeof(n->next_index));
    memset(n->match_index, 0, sizeof(n->match_index));
    n->cfg.peer_count = 0;
    for (uint32_t i = 0; i < count && n->cfg.peer_count < RAFT_MAX_PEERS; i++) {
        if (peers[i][0] == '\0') {
            continue;
        }
        if (strncmp(peers[i], n->cfg.node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        uint32_t dst = n->cfg.peer_count;
        strncpy(n->cfg.peer_ids[dst], peers[i], RAFT_NODE_ID_LEN - 1);
        n->cfg.peer_ids[dst][RAFT_NODE_ID_LEN - 1] = '\0';
        n->next_index[dst] = last_log_index(n) + 1;
        n->match_index[dst] = 0;
        for (uint32_t j = 0; j < old_count; j++) {
            if (strncmp(old_ids[j], peers[i], RAFT_NODE_ID_LEN) == 0) {
                n->next_index[dst] = old_next[j];
                n->match_index[dst] = old_match[j];
                break;
            }
        }
        n->cfg.peer_count++;
    }
}

static void union_peers(const char a[][RAFT_NODE_ID_LEN], uint32_t ac,
                        const char b[][RAFT_NODE_ID_LEN], uint32_t bc,
                        char out[][RAFT_NODE_ID_LEN], uint32_t *out_count)
{
    *out_count = 0;
    for (uint32_t i = 0; i < ac && *out_count < RAFT_MAX_PEERS; i++) {
        strncpy(out[*out_count], a[i], RAFT_NODE_ID_LEN - 1);
        out[*out_count][RAFT_NODE_ID_LEN - 1] = '\0';
        (*out_count)++;
    }
    for (uint32_t i = 0; i < bc && *out_count < RAFT_MAX_PEERS; i++) {
        bool found = false;
        for (uint32_t j = 0; j < *out_count; j++) {
            if (strncmp(out[j], b[i], RAFT_NODE_ID_LEN) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            strncpy(out[*out_count], b[i], RAFT_NODE_ID_LEN - 1);
            out[*out_count][RAFT_NODE_ID_LEN - 1] = '\0';
            (*out_count)++;
        }
    }
}

/** Strip self from a voter list into peer-set form (others only). */
static uint32_t peers_excluding_self(const RaftNode *n,
                                     const char voters[][RAFT_NODE_ID_LEN],
                                     uint32_t vc,
                                     char out[][RAFT_NODE_ID_LEN])
{
    uint32_t oc = 0;
    for (uint32_t i = 0; i < vc && oc < RAFT_MAX_PEERS; i++) {
        if (voters[i][0] == '\0') {
            continue;
        }
        if (strncmp(voters[i], n->cfg.node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        strncpy(out[oc], voters[i], RAFT_NODE_ID_LEN - 1);
        out[oc][RAFT_NODE_ID_LEN - 1] = '\0';
        oc++;
    }
    return oc;
}

static void activate_membership_locked(RaftNode *n, const uint8_t *data, size_t len)
{
    uint8_t phase = 0;
    char voters[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t vc = 0;
    memset(voters, 0, sizeof(voters));
    if (decode_membership(data, len, &phase, voters, &vc) != 0) {
        return;
    }
    char peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    memset(peers, 0, sizeof(peers));
    uint32_t pc = peers_excluding_self(n, voters, vc, peers);

    if (phase == RAFT_CFG_PHASE_JOINT) {
        n->old_peer_count = n->cfg.peer_count;
        memcpy(n->old_peers, n->cfg.peer_ids, sizeof(n->old_peers));
        n->new_peer_count = pc;
        memcpy(n->new_peers, peers, sizeof(n->new_peers));
        char uni[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
        uint32_t uc = 0;
        union_peers(n->old_peers, n->old_peer_count, n->new_peers, n->new_peer_count,
                    uni, &uc);
        install_peer_set(n, uni, uc);
        n->in_joint = true;
    } else {
        install_peer_set(n, peers, pc);
        n->new_peer_count = n->cfg.peer_count;
        memcpy(n->new_peers, n->cfg.peer_ids, sizeof(n->new_peers));
        n->old_peer_count = 0;
        memset(n->old_peers, 0, sizeof(n->old_peers));
        n->in_joint = false;
    }
}

/** Quorum in one peer set (self always counts). */
static bool set_has_majority(const RaftNode *n, uint64_t index,
                             const char peers[][RAFT_NODE_ID_LEN],
                             uint32_t peer_count)
{
    uint32_t replicas = 1; /* self */
    for (uint32_t i = 0; i < peer_count; i++) {
        int pi = peer_index(n, peers[i]);
        if (pi >= 0 && n->match_index[pi] >= index) {
            replicas++;
        }
    }
    uint32_t majority = (peer_count + 1) / 2 + 1;
    return replicas >= majority;
}

static bool entry_committed_by_quorum(const RaftNode *n, uint64_t index)
{
    if (n->in_joint) {
        return set_has_majority(n, index, n->old_peers, n->old_peer_count) &&
               set_has_majority(n, index, n->new_peers, n->new_peer_count);
    }
    uint32_t replicas = 1;
    for (uint32_t i = 0; i < n->cfg.peer_count; i++) {
        if (n->match_index[i] >= index) {
            replicas++;
        }
    }
    uint32_t majority = (n->cfg.peer_count + 1) / 2 + 1;
    return replicas >= majority;
}

static bool peer_in_set(const char peers[][RAFT_NODE_ID_LEN], uint32_t count,
                        const char *id)
{
    for (uint32_t i = 0; i < count; i++) {
        if (strncmp(peers[i], id, RAFT_NODE_ID_LEN) == 0) {
            return true;
        }
    }
    return false;
}

static bool election_won(const RaftNode *n)
{
    if (n->in_joint) {
        uint32_t mo = (n->old_peer_count + 1) / 2 + 1;
        uint32_t mn = (n->new_peer_count + 1) / 2 + 1;
        return n->votes >= mo && n->votes_new >= mn;
    }
    return n->votes >= (n->cfg.peer_count + 1) / 2 + 1;
}

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

/**
 * Emit one Raft message. Caller must hold n->lock.
 * The lock is dropped across the outbound callback so TCP/mTLS I/O cannot
 * deadlock against the network thread (which takes io_lock then raft_handle).
 */
static void send_msg(RaftNode *n, RaftMessage *msg)
{
    strncpy(msg->from, n->cfg.node_id, RAFT_NODE_ID_LEN - 1);
    if (!n->outbound) {
        return;
    }
    raft_outbound_fn out = n->outbound;
    void *ud = n->user_data;
    pthread_mutex_unlock(&n->lock);
    out(msg, ud);
    pthread_mutex_lock(&n->lock);
}

static void become_follower(RaftNode *n, uint64_t term)
{
    n->role = RAFT_FOLLOWER;
    n->current_term = term;
    n->voted_for[0] = '\0';
    n->leader_id[0] = '\0';
    n->votes = 0;
    n->votes_new = 0;
    reset_election_deadline(n);
}

static void apply_committed(RaftNode *n)
{
    while (n->last_applied < n->commit_index) {
        n->last_applied++;
        size_t li = (size_t)n->last_applied - 1;
        if (li < n->log_count && n->apply) {
            const uint8_t *d = n->log[li].data;
            size_t dl = n->log[li].data_len;
            /* Membership entries reconfigure the voter set on append; skip app apply. */
            if (!is_membership_entry(d, dl)) {
                n->apply(n->log[li].index, d, dl, n->user_data);
            }
        }
        if (n->propose_inflight && n->propose_index == n->last_applied) {
            n->propose_inflight = false;
            pthread_cond_broadcast(&n->commit_cv);
        }
    }
}

static void broadcast_append(RaftNode *n, bool heartbeat_only);

static void advance_commit(RaftNode *n)
{
    if (n->role != RAFT_LEADER) {
        return;
    }
    for (uint64_t N = n->log_count; N > n->commit_index; N--) {
        if (n->log[N - 1].term != n->current_term) {
            continue;
        }
        if (entry_committed_by_quorum(n, N)) {
            n->commit_index = N;
            apply_committed(n);
            /*
             * Push the new leader_commit immediately. Followers only apply
             * up to the commit index carried on AppendEntries; waiting for
             * the next heartbeat window leaves a visible lag (and flakes
             * under BOTH/mTLS when heartbeats contend with TCP upgrade).
             */
            broadcast_append(n, true);
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
    /* Self-vote counts in every voter set that includes this node (always). */
    n->votes = 1;
    n->votes_new = n->in_joint ? 1 : 0;
    n->leader_id[0] = '\0';
    reset_election_deadline(n);

    if (election_won(n)) {
        /* Solo / already-quorum wins immediately */
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

RaftError raft_add_peer(RaftNode *node, const char *peer_id)
{
    if (!node || !peer_id || peer_id[0] == '\0') {
        return RAFT_ERR_INVALID;
    }
    if (strncmp(peer_id, node->cfg.node_id, RAFT_NODE_ID_LEN) == 0) {
        return RAFT_OK;
    }
    pthread_mutex_lock(&node->lock);
    if (peer_index(node, peer_id) >= 0) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_OK;
    }
    if (node->cfg.peer_count >= RAFT_MAX_PEERS) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_FULL;
    }
    uint32_t i = node->cfg.peer_count;
    strncpy(node->cfg.peer_ids[i], peer_id, RAFT_NODE_ID_LEN - 1);
    node->cfg.peer_ids[i][RAFT_NODE_ID_LEN - 1] = '\0';
    node->next_index[i] = last_log_index(node) + 1;
    node->match_index[i] = 0;
    node->cfg.peer_count++;
    pthread_mutex_unlock(&node->lock);
    return RAFT_OK;
}

RaftError raft_remove_peer(RaftNode *node, const char *peer_id)
{
    if (!node || !peer_id || peer_id[0] == '\0') {
        return RAFT_ERR_INVALID;
    }
    pthread_mutex_lock(&node->lock);
    int pi = peer_index(node, peer_id);
    if (pi < 0) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_OK;
    }
    for (uint32_t i = (uint32_t)pi; i + 1 < node->cfg.peer_count; i++) {
        memcpy(node->cfg.peer_ids[i], node->cfg.peer_ids[i + 1], RAFT_NODE_ID_LEN);
        node->next_index[i] = node->next_index[i + 1];
        node->match_index[i] = node->match_index[i + 1];
    }
    uint32_t last = node->cfg.peer_count - 1;
    memset(node->cfg.peer_ids[last], 0, RAFT_NODE_ID_LEN);
    node->next_index[last] = 0;
    node->match_index[last] = 0;
    node->cfg.peer_count--;
    pthread_mutex_unlock(&node->lock);
    return RAFT_OK;
}

/** Caller holds node->lock. Appends entry, activates membership if needed, waits. */
static RaftError append_and_wait_locked(RaftNode *node,
                                        uint8_t *owned_data,
                                        size_t len,
                                        uint32_t timeout_ms)
{
    if (node->log_count >= RAFT_MAX_LOG) {
        free(owned_data);
        return RAFT_ERR_FULL;
    }
    size_t idx = node->log_count;
    node->log[idx].term = node->current_term;
    node->log[idx].index = idx + 1;
    node->log[idx].data_len = len;
    node->log[idx].data = owned_data;
    node->log_count++;
    if (is_membership_entry(owned_data, len)) {
        activate_membership_locked(node, owned_data, len);
    }
    node->propose_inflight = true;
    node->propose_index = node->log[idx].index;

    /*
     * Local-only commit when no other voters must ack: plain solo, or a joint
     * step whose Cold and Cnew are both empty (should not happen in practice).
     */
    if ((!node->in_joint && node->cfg.peer_count == 0) ||
        (node->in_joint && node->old_peer_count == 0 && node->new_peer_count == 0)) {
        node->commit_index = node->log[idx].index;
        apply_committed(node);
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
            return RAFT_ERR_TIMEOUT;
        }
    }
    return RAFT_OK;
}

static bool peer_sets_equal(const char a[][RAFT_NODE_ID_LEN], uint32_t ac,
                            const char b[][RAFT_NODE_ID_LEN], uint32_t bc)
{
    if (ac != bc) {
        return false;
    }
    for (uint32_t i = 0; i < ac; i++) {
        if (!peer_in_set(b, bc, a[i])) {
            return false;
        }
    }
    return true;
}

RaftError raft_propose_membership(RaftNode *node,
                                  const char peer_ids[][RAFT_NODE_ID_LEN],
                                  uint32_t peer_count,
                                  uint32_t timeout_ms)
{
    if (!node || (peer_count > 0 && !peer_ids) || peer_count > RAFT_MAX_PEERS) {
        return RAFT_ERR_INVALID;
    }
    /*
     * Membership entries carry the full voter set (including the proposing
     * leader). Each node installs peers = voters \ {self}, so followers do
     * not end up with an empty peer list.
     */
    char voters[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t vc = 0;
    memset(voters, 0, sizeof(voters));
    strncpy(voters[vc], node->cfg.node_id, RAFT_NODE_ID_LEN - 1);
    voters[vc][RAFT_NODE_ID_LEN - 1] = '\0';
    vc++;
    for (uint32_t i = 0; i < peer_count && vc < RAFT_MAX_PEERS; i++) {
        if (peer_ids[i][0] == '\0') {
            continue;
        }
        if (peer_in_set(voters, vc, peer_ids[i])) {
            continue;
        }
        strncpy(voters[vc], peer_ids[i], RAFT_NODE_ID_LEN - 1);
        voters[vc][RAFT_NODE_ID_LEN - 1] = '\0';
        vc++;
    }

    /* Peer view (excluding self) for equality / joint Cold comparison. */
    char target_peers[RAFT_MAX_PEERS][RAFT_NODE_ID_LEN];
    uint32_t tc = 0;
    memset(target_peers, 0, sizeof(target_peers));
    for (uint32_t i = 0; i < vc; i++) {
        if (strncmp(voters[i], node->cfg.node_id, RAFT_NODE_ID_LEN) == 0) {
            continue;
        }
        strncpy(target_peers[tc], voters[i], RAFT_NODE_ID_LEN - 1);
        target_peers[tc][RAFT_NODE_ID_LEN - 1] = '\0';
        tc++;
    }

    pthread_mutex_lock(&node->lock);
    if (node->role != RAFT_LEADER) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_NOT_LEADER;
    }
    if (node->in_joint) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_STATE;
    }
    if (peer_sets_equal(node->cfg.peer_ids, node->cfg.peer_count, target_peers, tc)) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_OK;
    }

    uint8_t *joint = NULL;
    size_t joint_len = 0;
    if (encode_membership(RAFT_CFG_PHASE_JOINT, voters, vc, &joint, &joint_len) != 0) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_MEMORY;
    }
    RaftError err = append_and_wait_locked(node, joint, joint_len, timeout_ms);
    if (err != RAFT_OK) {
        pthread_mutex_unlock(&node->lock);
        return err;
    }
    if (node->role != RAFT_LEADER) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_NOT_LEADER;
    }

    uint8_t *neu = NULL;
    size_t neu_len = 0;
    if (encode_membership(RAFT_CFG_PHASE_NEW, voters, vc, &neu, &neu_len) != 0) {
        pthread_mutex_unlock(&node->lock);
        return RAFT_ERR_MEMORY;
    }
    err = append_and_wait_locked(node, neu, neu_len, timeout_ms);
    pthread_mutex_unlock(&node->lock);
    return err;
}

RaftError raft_step_down(RaftNode *node)
{
    if (!node) {
        return RAFT_ERR_INVALID;
    }
    pthread_mutex_lock(&node->lock);
    become_follower(node, node->current_term);
    /* Expire the election timer so the tick thread starts a new election ASAP. */
    node->election_deadline_ms = now_ms();
    pthread_mutex_unlock(&node->lock);
    return RAFT_OK;
}

RaftError raft_propose(RaftNode *node, const uint8_t *data, size_t len, uint32_t timeout_ms)
{
    if (!node || (!data && len > 0)) {
        return RAFT_ERR_INVALID;
    }
    uint8_t *copy = NULL;
    if (len > 0) {
        copy = malloc(len);
        if (!copy) {
            return RAFT_ERR_MEMORY;
        }
        memcpy(copy, data, len);
    }
    pthread_mutex_lock(&node->lock);
    if (node->role != RAFT_LEADER) {
        pthread_mutex_unlock(&node->lock);
        free(copy);
        return RAFT_ERR_NOT_LEADER;
    }
    RaftError err = append_and_wait_locked(node, copy, len, timeout_ms);
    pthread_mutex_unlock(&node->lock);
    return err;
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
        if (n->in_joint) {
            if (peer_in_set(n->old_peers, n->old_peer_count, msg->from)) {
                n->votes++;
            }
            if (peer_in_set(n->new_peers, n->new_peer_count, msg->from)) {
                n->votes_new++;
            }
        } else {
            n->votes++;
        }
        if (election_won(n)) {
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
        /* Membership takes effect as soon as it is appended (Raft §4.1). */
        if (is_membership_entry(n->log[li].data, n->log[li].data_len)) {
            activate_membership_locked(n, n->log[li].data, n->log[li].data_len);
        }
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

uint32_t raft_peer_count(const RaftNode *node)
{
    return node ? node->cfg.peer_count : 0;
}

bool raft_in_joint_consensus(const RaftNode *node)
{
    return node && node->in_joint;
}

uint32_t raft_copy_peers(const RaftNode *node,
                         char out[][RAFT_NODE_ID_LEN],
                         uint32_t max_out)
{
    if (!node || !out || max_out == 0) {
        return 0;
    }
    uint32_t n = node->cfg.peer_count < max_out ? node->cfg.peer_count : max_out;
    for (uint32_t i = 0; i < n; i++) {
        memcpy(out[i], node->cfg.peer_ids[i], RAFT_NODE_ID_LEN);
    }
    return n;
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
