/**
 * @file messaging.c
 * @brief Broadcast channel implementation
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */

#include "messaging.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* Consensus error codes mirrored for receive return values */
#ifndef CONSENSUS_OK
#define CONSENSUS_OK 0
#define CONSENSUS_ERROR_INVALID_PARAMETER 1
#define CONSENSUS_ERROR_MEMORY_ERROR 2
#define CONSENSUS_ERROR_TIMEOUT 3
#define CONSENSUS_ERROR_STATE 7
#endif

BroadcastChannel *broadcast_channel_create(void)
{
    BroadcastChannel *ch = calloc(1, sizeof(*ch));
    if (!ch) {
        return NULL;
    }
    if (pthread_mutex_init(&ch->mutex, NULL) != 0) {
        free(ch);
        return NULL;
    }
    if (pthread_cond_init(&ch->cond, NULL) != 0) {
        pthread_mutex_destroy(&ch->mutex);
        free(ch);
        return NULL;
    }
    return ch;
}

void broadcast_channel_destroy(BroadcastChannel *channel)
{
    if (!channel) {
        return;
    }
    pthread_mutex_lock(&channel->mutex);
    for (size_t i = 0; i < BROADCAST_QUEUE_DEPTH; i++) {
        free(channel->queue[i].data);
        channel->queue[i].data = NULL;
        channel->queue[i].size = 0;
    }
    pthread_mutex_unlock(&channel->mutex);
    pthread_cond_destroy(&channel->cond);
    pthread_mutex_destroy(&channel->mutex);
    free(channel);
}

int broadcast_channel_subscribe(BroadcastChannel *channel)
{
    if (!channel) {
        return -1;
    }
    pthread_mutex_lock(&channel->mutex);
    int id = -1;
    for (int i = 0; i < BROADCAST_MAX_SUBSCRIBERS; i++) {
        if (!channel->subscribers[i].active) {
            channel->subscribers[i].active = true;
            channel->subscribers[i].read_index = channel->write_index;
            id = i;
            break;
        }
    }
    pthread_mutex_unlock(&channel->mutex);
    return id;
}

void broadcast_channel_unsubscribe(BroadcastChannel *channel, int subscriber_id)
{
    if (!channel || subscriber_id < 0 || subscriber_id >= BROADCAST_MAX_SUBSCRIBERS) {
        return;
    }
    pthread_mutex_lock(&channel->mutex);
    channel->subscribers[subscriber_id].active = false;
    pthread_mutex_unlock(&channel->mutex);
}

int broadcast_channel_publish(BroadcastChannel *channel,
                              const uint8_t *data,
                              size_t size)
{
    if (!channel || (!data && size > 0)) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }

    uint8_t *copy = NULL;
    if (size > 0) {
        copy = malloc(size);
        if (!copy) {
            return CONSENSUS_ERROR_MEMORY_ERROR;
        }
        memcpy(copy, data, size);
    }

    pthread_mutex_lock(&channel->mutex);

    /* Refuse overwrite when any subscriber is more than DEPTH behind */
    for (int i = 0; i < BROADCAST_MAX_SUBSCRIBERS; i++) {
        if (!channel->subscribers[i].active) {
            continue;
        }
        if (channel->write_index > channel->subscribers[i].read_index + BROADCAST_QUEUE_DEPTH) {
            pthread_mutex_unlock(&channel->mutex);
            free(copy);
            return CONSENSUS_ERROR_STATE;
        }
    }

    size_t idx = channel->write_index % BROADCAST_QUEUE_DEPTH;
    free(channel->queue[idx].data);
    channel->queue[idx].data = copy;
    channel->queue[idx].size = size;
    channel->write_index++;
    if (channel->count < BROADCAST_QUEUE_DEPTH) {
        channel->count++;
    }

    pthread_cond_broadcast(&channel->cond);
    pthread_mutex_unlock(&channel->mutex);
    return CONSENSUS_OK;
}

int broadcast_channel_receive(BroadcastChannel *channel,
                              int subscriber_id,
                              uint8_t **data,
                              size_t *data_size,
                              const struct timespec *timeout)
{
    if (!channel || !data || !data_size ||
        subscriber_id < 0 || subscriber_id >= BROADCAST_MAX_SUBSCRIBERS) {
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }

    *data = NULL;
    *data_size = 0;

    pthread_mutex_lock(&channel->mutex);
    BroadcastSubscriber *sub = &channel->subscribers[subscriber_id];
    if (!sub->active) {
        pthread_mutex_unlock(&channel->mutex);
        return CONSENSUS_ERROR_INVALID_PARAMETER;
    }

    struct timespec abs_deadline;
    if (timeout) {
        clock_gettime(CLOCK_REALTIME, &abs_deadline);
        abs_deadline.tv_sec += timeout->tv_sec;
        abs_deadline.tv_nsec += timeout->tv_nsec;
        if (abs_deadline.tv_nsec >= 1000000000L) {
            abs_deadline.tv_sec += 1;
            abs_deadline.tv_nsec -= 1000000000L;
        }
    }

    while (sub->read_index >= channel->write_index) {
        int wait_rc;
        if (timeout) {
            wait_rc = pthread_cond_timedwait(&channel->cond, &channel->mutex, &abs_deadline);
            if (wait_rc == ETIMEDOUT) {
                pthread_mutex_unlock(&channel->mutex);
                return CONSENSUS_ERROR_TIMEOUT;
            }
        } else {
            wait_rc = pthread_cond_wait(&channel->cond, &channel->mutex);
        }
        if (wait_rc != 0 && wait_rc != ETIMEDOUT) {
            pthread_mutex_unlock(&channel->mutex);
            return CONSENSUS_ERROR_STATE;
        }
        if (!sub->active) {
            pthread_mutex_unlock(&channel->mutex);
            return CONSENSUS_ERROR_INVALID_PARAMETER;
        }
    }

    size_t idx = sub->read_index % BROADCAST_QUEUE_DEPTH;
    size_t msg_size = channel->queue[idx].size;
    uint8_t *msg_data = channel->queue[idx].data;
    uint8_t *out = NULL;
    if (msg_size > 0 && msg_data) {
        out = malloc(msg_size);
        if (!out) {
            pthread_mutex_unlock(&channel->mutex);
            return CONSENSUS_ERROR_MEMORY_ERROR;
        }
        memcpy(out, msg_data, msg_size);
    }
    sub->read_index++;
    pthread_mutex_unlock(&channel->mutex);

    *data = out;
    *data_size = msg_size;
    return CONSENSUS_OK;
}
