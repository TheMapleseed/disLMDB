/**
 * @file dislmdb_iouring.h
 * @brief Linux io_uring wait helper for the DisLMDB net thread
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#ifndef DISLMDB_IOURING_H
#define DISLMDB_IOURING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dislmdb_iouring dislmdb_iouring;

/**
 * @brief True when this process successfully set up an io_uring instance.
 * Non-Linux always false. Linux probes at first @ref dislmdb_iouring_create.
 */
bool dislmdb_iouring_available(void);

/** Status string (never NULL). */
const char *dislmdb_iouring_status(void);

/**
 * @brief Create a small io_uring for POLL_ADD rebuild-each-tick waits.
 * @return NULL if unavailable (caller must use poll/kqueue).
 */
dislmdb_iouring *dislmdb_iouring_create(unsigned entries);

void dislmdb_iouring_destroy(dislmdb_iouring *ring);

/**
 * @brief Wait until any of @p fds is readable or @p timeout_ms elapses.
 *
 * Submits IORING_OP_POLL_ADD for each fd (level-triggered POLLIN), waits once,
 * then fills @p ready_fds[0..*nready) with readable descriptors. Mirrors the
 * poll/kqueue rebuild model used by the net thread.
 *
 * @return number of ready fds (>=0), or -1 on error (errno set).
 */
int dislmdb_iouring_wait_readable(dislmdb_iouring *ring, const int *fds, int nfds,
                                  int *ready_fds, int ready_cap, int *nready,
                                  int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* DISLMDB_IOURING_H */
