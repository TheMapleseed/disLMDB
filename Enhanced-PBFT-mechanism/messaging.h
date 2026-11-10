/**
 * @file messaging.h
 * @brief Broadcast channel for committed consensus payloads
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#ifndef EPDFT_MESSAGING_H
#define EPDFT_MESSAGING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum MessageType {
    MSG_PRE_PREPARE   = 1,
    MSG_PREPARE       = 2,
    MSG_COMMIT        = 3,
    MSG_VIEW_CHANGE   = 4,
    MSG_CHECKPOINT    = 5,
    MSG_REPLY         = 6,
    MSG_NEW_VIEW      = 7,
    MSG_STATE_REQ     = 8,
    MSG_STATE_RESP    = 9
} MessageType;

#define BROADCAST_MAX_SUBSCRIBERS 16
#define BROADCAST_QUEUE_DEPTH     64

typedef struct BroadcastMessage {
    uint8_t *data;
    size_t size;
} BroadcastMessage;

typedef struct BroadcastSubscriber {
    bool active;
    size_t read_index;
} BroadcastSubscriber;

typedef struct BroadcastChannel {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    BroadcastMessage queue[BROADCAST_QUEUE_DEPTH];
    size_t write_index;
    size_t count;
    BroadcastSubscriber subscribers[BROADCAST_MAX_SUBSCRIBERS];
} BroadcastChannel;

BroadcastChannel *broadcast_channel_create(void);
void broadcast_channel_destroy(BroadcastChannel *channel);

int broadcast_channel_subscribe(BroadcastChannel *channel);
void broadcast_channel_unsubscribe(BroadcastChannel *channel, int subscriber_id);

/**
 * @brief Publish a copy of data to all subscribers.
 * @return 0 on success
 */
int broadcast_channel_publish(BroadcastChannel *channel,
                              const uint8_t *data,
                              size_t size);

/**
 * @brief Receive next message for a subscriber. Allocates *data (caller frees).
 * @return CONSENSUS_OK / CONSENSUS_ERROR_TIMEOUT / other
 */
int broadcast_channel_receive(BroadcastChannel *channel,
                              int subscriber_id,
                              uint8_t **data,
                              size_t *data_size,
                              const struct timespec *timeout);

#ifdef __cplusplus
}
#endif

#endif /* EPDFT_MESSAGING_H */
