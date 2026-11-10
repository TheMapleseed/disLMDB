/**
 * @file epdft.c
 * @brief Enhanced PBFT core — port of TheMapleseed/Enhanced-PBFT-mechanism (Rust)
 */

#include "epdft.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dislmdb_crypto.h"

typedef struct Slot {
    bool in_use;
    uint64_t sequence;
    uint8_t digest[SECURITY_DIGEST_LEN];
    uint8_t *data;
    size_t data_len;
    uint64_t prepare_bits;
    uint64_t commit_bits;
    bool sent_prepare;
    bool sent_commit;
    bool executed;
} Slot;

typedef struct VcEntry {
    bool used;
    uint64_t new_view;
    uint64_t support_bits;
    uint64_t stable_max;
} VcEntry;

typedef enum {
    LIVE_INACTIVE = 0,
    LIVE_WAIT_PRE_PREPARE,
    LIVE_WAIT_PREPARE,
    LIVE_WAIT_COMMIT
} LivenessPhase;

typedef struct CoreImpl {
    Slot slots[EPDFT_MAX_SLOTS];
    VcEntry vc[16];
    /* Retained committed payloads for state transfer (ring) */
    struct {
        bool used;
        uint64_t sequence;
        uint8_t *data;
        size_t len;
    } history[256];
    size_t history_head;
    LivenessPhase live_phase;
    uint64_t live_deadline_ms;
    pthread_t live_thread;
    bool live_running;
} CoreImpl;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* defined below */
void consensus_core_stop_liveness(ConsensusCore *core);

static void history_push(CoreImpl *impl, uint64_t seq, const uint8_t *data, size_t len)
{
    size_t idx = impl->history_head % 256;
    free(impl->history[idx].data);
    impl->history[idx].data = NULL;
    impl->history[idx].used = true;
    impl->history[idx].sequence = seq;
    impl->history[idx].len = len;
    if (len > 0 && data) {
        impl->history[idx].data = malloc(len);
        if (impl->history[idx].data) {
            memcpy(impl->history[idx].data, data, len);
        } else {
            impl->history[idx].len = 0;
        }
    }
    impl->history_head++;
}

static void arm_liveness(ConsensusCore *core, LivenessPhase phase, uint32_t ms)
{
    CoreImpl *impl = core->impl;
    if (!core->config.timeouts.enabled || !impl) {
        return;
    }
    impl->live_phase = phase;
    impl->live_deadline_ms = now_ms() + ms;
}

ConsensusConfig consensus_config_default(void)
{
    ConsensusConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.fault_tolerance = 0;
    cfg.min_nodes = 1;
    cfg.replica_count = 0;
    cfg.max_message_size = 16u * 1024u * 1024u;
    cfg.verify_signatures = false;
    cfg.timeouts.enabled = false;
    cfg.timeouts.wait_pre_prepare_ms = 5000;
    cfg.timeouts.prepare_certificate_ms = 3000;
    cfg.timeouts.commit_certificate_ms = 3000;
    cfg.timeouts.view_change_resend_ms = 5000;
    cfg.timeouts.prepare_timeout = (struct timespec){.tv_sec = 5, .tv_nsec = 0};
    cfg.timeouts.commit_timeout = (struct timespec){.tv_sec = 5, .tv_nsec = 0};
    cfg.timeouts.view_change_timeout = (struct timespec){.tv_sec = 10, .tv_nsec = 0};
    return cfg;
}

uint32_t consensus_config_quorum(const ConsensusConfig *cfg)
{
    if (!cfg) {
        return 1;
    }
    return 2u * cfg->fault_tolerance + 1u;
}

int consensus_config_validate(const ConsensusConfig *cfg)
{
    if (!cfg || cfg->replica_count == 0) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    if (cfg->replica_count > EPDFT_MAX_REPLICAS) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    uint32_t need = 3u * cfg->fault_tolerance + 1u;
    if (cfg->replica_count < need) {
        return CONSENSUS_ERROR_INSUFFICIENT_REPLICAS;
    }
    return CONSENSUS_OK;
}

NodeId *node_id_create(const char *id)
{
    if (!id || id[0] == '\0') {
        return NULL;
    }
    NodeId *n = calloc(1, sizeof(*n));
    if (!n) {
        return NULL;
    }
    strncpy(n->id, id, sizeof(n->id) - 1);
    return n;
}

void node_id_destroy(NodeId *node_id)
{
    free(node_id);
}

static int replica_index(const ConsensusConfig *cfg, const char *id)
{
    for (uint32_t i = 0; i < cfg->replica_count; i++) {
        if (strncmp(cfg->replica_ids[i], id, EPDFT_NODE_ID_LEN) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void primary_id_for_view(const ConsensusConfig *cfg, uint64_t view,
                                char out[EPDFT_NODE_ID_LEN])
{
    uint32_t n = cfg->replica_count ? cfg->replica_count : 1;
    uint32_t idx = (uint32_t)(view % n);
    strncpy(out, cfg->replica_ids[idx], EPDFT_NODE_ID_LEN - 1);
    out[EPDFT_NODE_ID_LEN - 1] = '\0';
}

static void refresh_primary(ConsensusCore *core)
{
    char primary[EPDFT_NODE_ID_LEN];
    primary_id_for_view(&core->config, core->view, primary);
    core->is_primary = (strncmp(primary, core->node_id->id, EPDFT_NODE_ID_LEN) == 0);
}

static Slot *slot_get(CoreImpl *impl, uint64_t sequence, bool create)
{
    for (int i = 0; i < EPDFT_MAX_SLOTS; i++) {
        if (impl->slots[i].in_use && impl->slots[i].sequence == sequence) {
            return &impl->slots[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (int i = 0; i < EPDFT_MAX_SLOTS; i++) {
        if (!impl->slots[i].in_use) {
            memset(&impl->slots[i], 0, sizeof(impl->slots[i]));
            impl->slots[i].in_use = true;
            impl->slots[i].sequence = sequence;
            return &impl->slots[i];
        }
    }
    return NULL;
}

static void slot_clear(Slot *s)
{
    free(s->data);
    memset(s, 0, sizeof(*s));
}

static ConsensusError dispatch(ConsensusCore *core, const PbftMessage *msg)
{
    /* Always apply locally (Rust mesh delivers to self). */
    ConsensusError local = consensus_core_handle_pbft(core, msg);
    if (core->outbound) {
        core->outbound(msg, core->outbound_user);
    }
    return local;
}

ConsensusCore *consensus_core_create(NodeId *node_id,
                                     const ConsensusConfig *config,
                                     SecurityManager *security)
{
    if (!node_id || !security) {
        return NULL;
    }

    ConsensusCore *core = calloc(1, sizeof(*core));
    if (!core) {
        return NULL;
    }
    CoreImpl *impl = calloc(1, sizeof(*impl));
    if (!impl) {
        free(core);
        return NULL;
    }

    core->node_id = node_id;
    core->config = config ? *config : consensus_config_default();
    if (core->config.replica_count == 0) {
        strncpy(core->config.replica_ids[0], node_id->id, EPDFT_NODE_ID_LEN - 1);
        core->config.replica_count = 1;
        core->config.fault_tolerance = 0;
        core->config.min_nodes = 1;
    }
    if (core->config.max_message_size == 0) {
        core->config.max_message_size = 16u * 1024u * 1024u;
    }
    if (consensus_config_validate(&core->config) != CONSENSUS_OK) {
        free(impl);
        free(core);
        return NULL;
    }
    if (replica_index(&core->config, node_id->id) < 0) {
        free(impl);
        free(core);
        return NULL;
    }

    core->security = security;
    core->impl = impl;
    core->view = 0;
    core->last_committed_seq = 0;
    if (pthread_mutex_init(&core->lock, NULL) != 0) {
        free(impl);
        free(core);
        return NULL;
    }
    core->commit_channel = broadcast_channel_create();
    if (!core->commit_channel) {
        pthread_mutex_destroy(&core->lock);
        free(impl);
        free(core);
        return NULL;
    }
    refresh_primary(core);
    return core;
}

void consensus_core_set_outbound(ConsensusCore *core,
                                 pbft_outbound_fn outbound,
                                 void *user_data)
{
    if (!core) {
        return;
    }
    core->outbound = outbound;
    core->outbound_user = user_data;
}

void consensus_core_destroy(ConsensusCore *core)
{
    if (!core) {
        return;
    }
    consensus_core_stop_liveness(core);
    CoreImpl *impl = core->impl;
    if (impl) {
        for (int i = 0; i < EPDFT_MAX_SLOTS; i++) {
            slot_clear(&impl->slots[i]);
        }
        for (size_t i = 0; i < 256; i++) {
            free(impl->history[i].data);
        }
        free(impl);
    }
    broadcast_channel_destroy(core->commit_channel);
    security_manager_destroy(core->security);
    node_id_destroy(core->node_id);
    pthread_mutex_destroy(&core->lock);
    free(core);
}

BroadcastChannel *consensus_core_commit_channel(ConsensusCore *core)
{
    return core ? core->commit_channel : NULL;
}

bool consensus_core_is_primary(const ConsensusCore *core)
{
    return core && core->is_primary;
}

uint32_t consensus_core_view(const ConsensusCore *core)
{
    return core ? (uint32_t)core->view : 0;
}

uint32_t consensus_core_sequence(const ConsensusCore *core)
{
    return core ? (uint32_t)core->last_committed_seq : 0;
}

uint64_t consensus_core_last_committed(const ConsensusCore *core)
{
    return core ? core->last_committed_seq : 0;
}

static ConsensusError on_pre_prepare(ConsensusCore *core, const PbftMessage *msg)
{
    char primary[EPDFT_NODE_ID_LEN];
    primary_id_for_view(&core->config, msg->view, primary);
    if (strncmp(msg->from, primary, EPDFT_NODE_ID_LEN) != 0) {
        return CONSENSUS_OK; /* ignore forged */
    }

    pthread_mutex_lock(&core->lock);
    if (msg->view != core->view) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    uint64_t expected = core->last_committed_seq + 1;
    if (msg->sequence != expected) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }

    uint8_t computed[SECURITY_DIGEST_LEN];
    security_manager_hash_consensus(core->security, msg->view, msg->sequence,
                                    msg->data, msg->data_len, computed);
    if (!security_manager_digest_eq(computed, msg->digest)) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }

    CoreImpl *impl = core->impl;
    Slot *slot = slot_get(impl, msg->sequence, true);
    if (!slot) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_MEMORY_ERROR;
    }

    PbftMessage prepare;
    memset(&prepare, 0, sizeof(prepare));
    bool send_prepare = false;

    if (!slot->sent_prepare) {
        if (!slot->data && msg->data_len > 0) {
            slot->data = malloc(msg->data_len);
            if (!slot->data) {
                pthread_mutex_unlock(&core->lock);
                return CONSENSUS_ERROR_MEMORY_ERROR;
            }
            memcpy(slot->data, msg->data, msg->data_len);
            slot->data_len = msg->data_len;
        }
        memcpy(slot->digest, msg->digest, SECURITY_DIGEST_LEN);
        int self = replica_index(&core->config, core->node_id->id);
        if (self >= 0) {
            slot->prepare_bits |= (1ull << self);
        }
        slot->sent_prepare = true;
        prepare.type = MSG_PREPARE;
        prepare.view = msg->view;
        prepare.sequence = msg->sequence;
        memcpy(prepare.digest, msg->digest, SECURITY_DIGEST_LEN);
        strncpy(prepare.from, core->node_id->id, sizeof(prepare.from) - 1);
        send_prepare = true;
    }
    pthread_mutex_unlock(&core->lock);

    if (send_prepare) {
        return dispatch(core, &prepare);
    }
    return CONSENSUS_OK;
}

static ConsensusError on_prepare(ConsensusCore *core, const PbftMessage *msg)
{
    uint32_t q = consensus_config_quorum(&core->config);
    int from_i = replica_index(&core->config, msg->from);
    if (from_i < 0) {
        return CONSENSUS_OK;
    }

    PbftMessage commit;
    memset(&commit, 0, sizeof(commit));
    bool send_commit = false;

    pthread_mutex_lock(&core->lock);
    if (msg->view != core->view) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    CoreImpl *impl = core->impl;
    Slot *slot = slot_get(impl, msg->sequence, false);
    if (!slot || !security_manager_digest_eq(slot->digest, msg->digest)) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    slot->prepare_bits |= (1ull << from_i);
    uint32_t prepares = (uint32_t)__builtin_popcountll(slot->prepare_bits);
    if (prepares >= q && !slot->sent_commit) {
        slot->sent_commit = true;
        int self = replica_index(&core->config, core->node_id->id);
        if (self >= 0) {
            slot->commit_bits |= (1ull << self);
        }
        commit.type = MSG_COMMIT;
        commit.view = msg->view;
        commit.sequence = msg->sequence;
        memcpy(commit.digest, slot->digest, SECURITY_DIGEST_LEN);
        strncpy(commit.from, core->node_id->id, sizeof(commit.from) - 1);
        send_commit = true;
    }
    pthread_mutex_unlock(&core->lock);

    if (send_commit) {
        return dispatch(core, &commit);
    }
    return CONSENSUS_OK;
}

static ConsensusError on_commit(ConsensusCore *core, const PbftMessage *msg)
{
    uint32_t q = consensus_config_quorum(&core->config);
    int from_i = replica_index(&core->config, msg->from);
    if (from_i < 0) {
        return CONSENSUS_OK;
    }

    uint8_t *commit_data = NULL;
    size_t commit_len = 0;
    bool executed = false;

    pthread_mutex_lock(&core->lock);
    if (msg->view != core->view) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    CoreImpl *impl = core->impl;
    Slot *slot = slot_get(impl, msg->sequence, false);
    if (!slot || !security_manager_digest_eq(slot->digest, msg->digest) || slot->executed) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    slot->commit_bits |= (1ull << from_i);
    uint32_t commits = (uint32_t)__builtin_popcountll(slot->commit_bits);
    if (commits >= q) {
        slot->executed = true;
        if (slot->data_len > 0 && slot->data) {
            commit_data = malloc(slot->data_len);
            if (commit_data) {
                memcpy(commit_data, slot->data, slot->data_len);
                commit_len = slot->data_len;
            }
        }
        if (msg->sequence > core->last_committed_seq) {
            core->last_committed_seq = msg->sequence;
        }
        history_push(impl, msg->sequence, commit_data, commit_len);
        core->metrics.commits++;
        slot_clear(slot);
        executed = true;
        arm_liveness(core, LIVE_WAIT_PRE_PREPARE, core->config.timeouts.wait_pre_prepare_ms);
    }
    pthread_mutex_unlock(&core->lock);

    if (executed) {
        if (commit_data) {
            (void)broadcast_channel_publish(core->commit_channel, commit_data, commit_len);
            free(commit_data);
        } else {
            (void)broadcast_channel_publish(core->commit_channel, (const uint8_t *)"", 0);
        }
    }
    return CONSENSUS_OK;
}

static ConsensusError on_view_change(ConsensusCore *core, const PbftMessage *msg)
{
    uint32_t q = consensus_config_quorum(&core->config);
    int from_i = replica_index(&core->config, msg->from);
    if (from_i < 0) {
        return CONSENSUS_OK;
    }

    pthread_mutex_lock(&core->lock);
    if (msg->view <= core->view) { /* new_view stored in msg->view for VC */
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    CoreImpl *impl = core->impl;
    VcEntry *entry = NULL;
    for (int i = 0; i < 16; i++) {
        if (impl->vc[i].used && impl->vc[i].new_view == msg->view) {
            entry = &impl->vc[i];
            break;
        }
    }
    if (!entry) {
        for (int i = 0; i < 16; i++) {
            if (!impl->vc[i].used) {
                entry = &impl->vc[i];
                memset(entry, 0, sizeof(*entry));
                entry->used = true;
                entry->new_view = msg->view;
                break;
            }
        }
    }
    if (!entry) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_MEMORY_ERROR;
    }
    entry->support_bits |= (1ull << from_i);
    if (msg->last_stable_seq > entry->stable_max) {
        entry->stable_max = msg->last_stable_seq;
    }
    uint32_t supporters = (uint32_t)__builtin_popcountll(entry->support_bits);
    bool switched = false;
    uint64_t new_view = 0;
    uint64_t stable = 0;
    if (supporters >= q) {
        core->view = entry->new_view;
        if (entry->stable_max > core->last_committed_seq) {
            core->last_committed_seq = entry->stable_max;
        }
        new_view = core->view;
        stable = core->last_committed_seq;
        for (int i = 0; i < EPDFT_MAX_SLOTS; i++) {
            slot_clear(&impl->slots[i]);
        }
        memset(impl->vc, 0, sizeof(impl->vc));
        refresh_primary(core);
        core->metrics.view_changes++;
        switched = true;
        arm_liveness(core, LIVE_WAIT_PRE_PREPARE, core->config.timeouts.wait_pre_prepare_ms);
    }
    pthread_mutex_unlock(&core->lock);

    if (switched) {
        PbftMessage nv;
        memset(&nv, 0, sizeof(nv));
        nv.type = MSG_NEW_VIEW;
        nv.view = new_view;
        nv.sequence = stable;
        nv.last_stable_seq = stable;
        strncpy(nv.from, core->node_id->id, sizeof(nv.from) - 1);
        (void)dispatch(core, &nv);
    }
    return CONSENSUS_OK;
}

static ConsensusError on_new_view(ConsensusCore *core, const PbftMessage *msg)
{
    pthread_mutex_lock(&core->lock);
    if (msg->view > core->view) {
        core->view = msg->view;
        if (msg->last_stable_seq > core->last_committed_seq) {
            core->last_committed_seq = msg->last_stable_seq;
        }
        refresh_primary(core);
        core->metrics.view_changes++;
        arm_liveness(core, LIVE_WAIT_PRE_PREPARE, core->config.timeouts.wait_pre_prepare_ms);
    }
    pthread_mutex_unlock(&core->lock);
    return CONSENSUS_OK;
}

static ConsensusError on_checkpoint(ConsensusCore *core, const PbftMessage *msg)
{
    pthread_mutex_lock(&core->lock);
    if (msg->sequence >= core->stable_checkpoint) {
        core->stable_checkpoint = msg->sequence;
        core->metrics.checkpoints++;
        /* GC slots below stable checkpoint */
        CoreImpl *impl = core->impl;
        for (int i = 0; i < EPDFT_MAX_SLOTS; i++) {
            if (impl->slots[i].in_use && impl->slots[i].sequence <= core->stable_checkpoint) {
                slot_clear(&impl->slots[i]);
            }
        }
    }
    pthread_mutex_unlock(&core->lock);
    return CONSENSUS_OK;
}

static ConsensusError on_state_req(ConsensusCore *core, const PbftMessage *msg)
{
    CoreImpl *impl = core->impl;
    /* Build response: concatenate history entries with sequence > after_seq (in msg->sequence) */
    size_t total = 0;
    for (size_t i = 0; i < 256; i++) {
        if (impl->history[i].used && impl->history[i].sequence > msg->sequence) {
            total += 8 + 4 + impl->history[i].len;
        }
    }
    uint8_t *buf = malloc(total ? total : 1);
    if (!buf) {
        return CONSENSUS_ERROR_MEMORY_ERROR;
    }
    size_t o = 0;
    pthread_mutex_lock(&core->lock);
    for (size_t i = 0; i < 256; i++) {
        if (impl->history[i].used && impl->history[i].sequence > msg->sequence) {
            dislmdb_write_u64(buf + o, impl->history[i].sequence); o += 8;
            dislmdb_write_u32(buf + o, (uint32_t)impl->history[i].len); o += 4;
            if (impl->history[i].len > 0 && impl->history[i].data) {
                memcpy(buf + o, impl->history[i].data, impl->history[i].len);
                o += impl->history[i].len;
            }
        }
    }
    core->metrics.state_transfers++;
    pthread_mutex_unlock(&core->lock);

    PbftMessage resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = MSG_STATE_RESP;
    resp.view = core->view;
    resp.sequence = core->last_committed_seq;
    resp.last_stable_seq = core->stable_checkpoint;
    strncpy(resp.from, core->node_id->id, sizeof(resp.from) - 1);
    resp.data = buf;
    resp.data_len = o;
    ConsensusError err = dispatch(core, &resp);
    /* dispatch copies via handle; free our buffer after */
    free(buf);
    resp.data = NULL;
    return err;
}

static ConsensusError on_state_resp(ConsensusCore *core, const PbftMessage *msg)
{
    if (!msg->data || msg->data_len == 0) {
        return CONSENSUS_OK;
    }
    if (strncmp(msg->from, core->node_id->id, EPDFT_NODE_ID_LEN) == 0) {
        return CONSENSUS_OK; /* ignore our own state responses */
    }
    /* Replay each retained payload into commit channel */
    size_t o = 0;
    while (o + 12 <= msg->data_len) {
        uint64_t seq = dislmdb_read_u64(msg->data + o); o += 8;
        uint32_t len = dislmdb_read_u32(msg->data + o); o += 4;
        if (o + len > msg->data_len) {
            break;
        }
        pthread_mutex_lock(&core->lock);
        if (seq > core->last_committed_seq) {
            history_push(core->impl, seq, msg->data + o, len);
            core->last_committed_seq = seq;
            core->metrics.state_transfers++;
            pthread_mutex_unlock(&core->lock);
            (void)broadcast_channel_publish(core->commit_channel, msg->data + o, len);
        } else {
            pthread_mutex_unlock(&core->lock);
        }
        o += len;
    }
    return CONSENSUS_OK;
}

ConsensusError consensus_core_handle_pbft(ConsensusCore *core, const PbftMessage *msg)
{
    if (!core || !msg) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    switch (msg->type) {
        case MSG_PRE_PREPARE:
            return on_pre_prepare(core, msg);
        case MSG_PREPARE:
            return on_prepare(core, msg);
        case MSG_COMMIT:
            return on_commit(core, msg);
        case MSG_VIEW_CHANGE:
            return on_view_change(core, msg);
        case MSG_NEW_VIEW:
            return on_new_view(core, msg);
        case MSG_CHECKPOINT:
            return on_checkpoint(core, msg);
        case MSG_STATE_REQ:
            return on_state_req(core, msg);
        case MSG_STATE_RESP:
            return on_state_resp(core, msg);
        default:
            return CONSENSUS_OK;
    }
}

ConsensusError consensus_core_propose(ConsensusCore *core,
                                      const uint8_t *data,
                                      size_t size)
{
    if (!core || (!data && size > 0)) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    if (size > core->config.max_message_size) {
        return CONSENSUS_ERROR_MESSAGE_TOO_LARGE;
    }

    pthread_mutex_lock(&core->lock);
    refresh_primary(core);
    if (!core->is_primary) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_NOT_LEADER;
    }
    uint64_t view = core->view;
    uint64_t sequence = core->last_committed_seq + 1;
    pthread_mutex_unlock(&core->lock);

    PbftMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = MSG_PRE_PREPARE;
    msg.view = view;
    msg.sequence = sequence;
    strncpy(msg.from, core->node_id->id, sizeof(msg.from) - 1);
    msg.data_len = size;
    if (size > 0) {
        msg.data = malloc(size);
        if (!msg.data) {
            return CONSENSUS_ERROR_MEMORY_ERROR;
        }
        memcpy(msg.data, data, size);
    }
    security_manager_hash_consensus(core->security, view, sequence, data, size, msg.digest);

    pthread_mutex_lock(&core->lock);
    core->metrics.proposes++;
    arm_liveness(core, LIVE_WAIT_PREPARE, core->config.timeouts.prepare_certificate_ms);
    pthread_mutex_unlock(&core->lock);

    ConsensusError err = dispatch(core, &msg);
    free(msg.data);
    return err;
}

ConsensusError consensus_core_handle_message(ConsensusCore *core,
                                             MessageType type,
                                             const char *from_node,
                                             const uint8_t *data,
                                             size_t size)
{
    if (!core || !from_node) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    /* Prefer framed PBFT payloads */
    PbftMessage msg;
    if (pbft_message_deserialize(data, size, &msg) == 0) {
        ConsensusError err = consensus_core_handle_pbft(core, &msg);
        pbft_message_clear(&msg);
        return err;
    }

    /* Fallback: treat raw bytes as pre-prepare data only if primary-shaped (legacy) */
    (void)type;
    return CONSENSUS_ERROR_STATE;
}

void pbft_message_clear(PbftMessage *msg)
{
    if (!msg) {
        return;
    }
    free(msg->data);
    msg->data = NULL;
    msg->data_len = 0;
}

int pbft_message_serialize(const PbftMessage *msg, uint8_t **out, size_t *out_len)
{
    if (!msg || !out || !out_len) {
        return -1;
    }
    size_t total = 1 + 8 + 8 + 32 + 64 + 8 + 4 + msg->data_len;
    uint8_t *buf = malloc(total);
    if (!buf) {
        return -1;
    }
    size_t o = 0;
    buf[o++] = (uint8_t)msg->type;
    dislmdb_write_u64(buf + o, msg->view); o += 8;
    dislmdb_write_u64(buf + o, msg->sequence); o += 8;
    memcpy(buf + o, msg->digest, 32); o += 32;
    memset(buf + o, 0, 64);
    strncpy((char *)(buf + o), msg->from, 63); o += 64;
    dislmdb_write_u64(buf + o, msg->last_stable_seq); o += 8;
    dislmdb_write_u32(buf + o, (uint32_t)msg->data_len); o += 4;
    if (msg->data_len > 0 && msg->data) {
        memcpy(buf + o, msg->data, msg->data_len);
        o += msg->data_len;
    }
    *out = buf;
    *out_len = o;
    return 0;
}

int pbft_message_deserialize(const uint8_t *buf, size_t len, PbftMessage *out)
{
    if (!buf || !out || len < 1 + 8 + 8 + 32 + 64 + 8 + 4) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    size_t o = 0;
    out->type = (MessageType)buf[o++];
    out->view = dislmdb_read_u64(buf + o); o += 8;
    out->sequence = dislmdb_read_u64(buf + o); o += 8;
    memcpy(out->digest, buf + o, 32); o += 32;
    memcpy(out->from, buf + o, 64);
    out->from[63] = '\0';
    o += 64;
    out->last_stable_seq = dislmdb_read_u64(buf + o); o += 8;
    uint32_t dlen = dislmdb_read_u32(buf + o); o += 4;
    if (o + dlen > len) {
        return -1;
    }
    out->data_len = dlen;
    if (dlen > 0) {
        out->data = malloc(dlen);
        if (!out->data) {
            return -1;
        }
        memcpy(out->data, buf + o, dlen);
    }
    return 0;
}

static void *liveness_thread(void *arg)
{
    ConsensusCore *core = arg;
    CoreImpl *impl = core->impl;
    while (impl->live_running) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
        nanosleep(&ts, NULL);
        if (!core->config.timeouts.enabled) {
            continue;
        }
        uint64_t now = now_ms();
        bool fire = false;
        pthread_mutex_lock(&core->lock);
        if (impl->live_phase != LIVE_INACTIVE && now >= impl->live_deadline_ms) {
            fire = true;
            impl->live_deadline_ms = now + core->config.timeouts.view_change_resend_ms;
            impl->live_phase = LIVE_WAIT_PRE_PREPARE;
        }
        uint64_t nv = core->view + 1;
        uint64_t stable = core->last_committed_seq;
        pthread_mutex_unlock(&core->lock);
        if (fire) {
            PbftMessage vc;
            memset(&vc, 0, sizeof(vc));
            vc.type = MSG_VIEW_CHANGE;
            vc.view = nv;
            vc.last_stable_seq = stable;
            strncpy(vc.from, core->node_id->id, sizeof(vc.from) - 1);
            (void)dispatch(core, &vc);
        }
    }
    return NULL;
}

void consensus_core_start_liveness(ConsensusCore *core)
{
    if (!core || !core->impl) {
        return;
    }
    CoreImpl *impl = core->impl;
    if (impl->live_running) {
        return;
    }
    core->config.timeouts.enabled = true;
    impl->live_running = true;
    arm_liveness(core, LIVE_WAIT_PRE_PREPARE, core->config.timeouts.wait_pre_prepare_ms);
    if (pthread_create(&impl->live_thread, NULL, liveness_thread, core) != 0) {
        impl->live_running = false;
    }
}

void consensus_core_stop_liveness(ConsensusCore *core)
{
    if (!core || !core->impl) {
        return;
    }
    CoreImpl *impl = core->impl;
    if (!impl->live_running) {
        return;
    }
    impl->live_running = false;
    pthread_join(impl->live_thread, NULL);
}

ConsensusError consensus_core_checkpoint(ConsensusCore *core)
{
    if (!core) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    PbftMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = MSG_CHECKPOINT;
    msg.view = core->view;
    msg.sequence = core->last_committed_seq;
    msg.last_stable_seq = core->last_committed_seq;
    strncpy(msg.from, core->node_id->id, sizeof(msg.from) - 1);
    return dispatch(core, &msg);
}

ConsensusError consensus_core_request_state(ConsensusCore *core, uint64_t after_seq)
{
    if (!core) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    PbftMessage msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = MSG_STATE_REQ;
    msg.view = core->view;
    msg.sequence = after_seq;
    strncpy(msg.from, core->node_id->id, sizeof(msg.from) - 1);
    return dispatch(core, &msg);
}

ConsensusError consensus_core_add_replica(ConsensusCore *core, const char *replica_id)
{
    if (!core || !replica_id || replica_id[0] == '\0') {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&core->lock);
    if (replica_index(&core->config, replica_id) >= 0) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_OK;
    }
    if (core->config.replica_count >= EPDFT_MAX_REPLICAS) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_INSUFFICIENT_REPLICAS;
    }
    strncpy(core->config.replica_ids[core->config.replica_count], replica_id,
            EPDFT_NODE_ID_LEN - 1);
    core->config.replica_count++;
    refresh_primary(core);
    pthread_mutex_unlock(&core->lock);
    return CONSENSUS_OK;
}

ConsensusError consensus_core_remove_replica(ConsensusCore *core, const char *replica_id)
{
    if (!core || !replica_id) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&core->lock);
    int idx = replica_index(&core->config, replica_id);
    if (idx < 0) {
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_UNKNOWN_REPLICA;
    }
    for (uint32_t i = (uint32_t)idx; i + 1 < core->config.replica_count; i++) {
        memcpy(core->config.replica_ids[i], core->config.replica_ids[i + 1],
               EPDFT_NODE_ID_LEN);
    }
    core->config.replica_count--;
    if (consensus_config_validate(&core->config) != CONSENSUS_OK) {
        /* roll forward anyway but flag */
        pthread_mutex_unlock(&core->lock);
        return CONSENSUS_ERROR_INSUFFICIENT_REPLICAS;
    }
    refresh_primary(core);
    pthread_mutex_unlock(&core->lock);
    return CONSENSUS_OK;
}

void consensus_core_restore(ConsensusCore *core, uint64_t view, uint64_t last_committed)
{
    if (!core) {
        return;
    }
    pthread_mutex_lock(&core->lock);
    core->view = view;
    core->last_committed_seq = last_committed;
    core->stable_checkpoint = last_committed;
    refresh_primary(core);
    pthread_mutex_unlock(&core->lock);
}

void consensus_core_get_metrics(const ConsensusCore *core, ConsensusMetrics *out)
{
    if (!core || !out) {
        return;
    }
    *out = core->metrics;
}
