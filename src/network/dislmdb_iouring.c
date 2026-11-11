/**
 * @file dislmdb_iouring.c
 * @brief Linux io_uring POLL_ADD wait backend (poll/kqueue fallback elsewhere)
 *
 * @copyright Copyright 2025 David Harmon, The Mapleseed Inc.
 */
#include "dislmdb_iouring.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__)
#include <linux/io_uring.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

struct dislmdb_iouring {
#if defined(__linux__)
    int fd;
    void *sq_ptr;
    void *cq_ptr;
    size_t sq_map_sz;
    size_t cq_map_sz;
    size_t sqe_map_sz;
    struct io_uring_sqe *sqes;
    unsigned *sq_head;
    unsigned *sq_tail;
    unsigned *sq_mask;
    unsigned *sq_array;
    unsigned *cq_head;
    unsigned *cq_tail;
    unsigned *cq_mask;
    struct io_uring_cqe *cqes;
    unsigned entries;
    int single_mmap;
#else
    int unused;
#endif
};

static const char *g_status = "io_uring not probed";
#if defined(__linux__)
static bool g_probed;
static bool g_available;
#endif

#if defined(__linux__)

static int sys_io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                              unsigned flags)
{
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                        NULL, 0);
}

dislmdb_iouring *dislmdb_iouring_create(unsigned entries)
{
    if (entries < 2) {
        entries = 2;
    }
    if (entries > 256) {
        entries = 256;
    }
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    int fd = sys_io_uring_setup(entries, &params);
    if (fd < 0) {
        return NULL;
    }

    dislmdb_iouring *ring = calloc(1, sizeof(*ring));
    if (!ring) {
        close(fd);
        return NULL;
    }
    ring->fd = fd;
    ring->entries = params.sq_entries;
    ring->single_mmap = (params.features & IORING_FEAT_SINGLE_MMAP) ? 1 : 0;

    size_t sq_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
    size_t cq_sz =
        params.cq_off.cqes + params.cq_entries * sizeof(struct io_uring_cqe);
    size_t map_sz = sq_sz;
    if (ring->single_mmap && cq_sz > map_sz) {
        map_sz = cq_sz;
    }

    ring->sq_ptr = mmap(NULL, map_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (ring->sq_ptr == MAP_FAILED) {
        close(fd);
        free(ring);
        return NULL;
    }
    ring->sq_map_sz = map_sz;

    if (ring->single_mmap) {
        ring->cq_ptr = ring->sq_ptr;
        ring->cq_map_sz = 0;
    } else {
        ring->cq_ptr = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
        if (ring->cq_ptr == MAP_FAILED) {
            munmap(ring->sq_ptr, ring->sq_map_sz);
            close(fd);
            free(ring);
            return NULL;
        }
        ring->cq_map_sz = cq_sz;
    }

    ring->sqe_map_sz = params.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, ring->sqe_map_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) {
        if (!ring->single_mmap) {
            munmap(ring->cq_ptr, ring->cq_map_sz);
        }
        munmap(ring->sq_ptr, ring->sq_map_sz);
        close(fd);
        free(ring);
        return NULL;
    }

    uint8_t *sq = (uint8_t *)ring->sq_ptr;
    ring->sq_head = (unsigned *)(sq + params.sq_off.head);
    ring->sq_tail = (unsigned *)(sq + params.sq_off.tail);
    ring->sq_mask = (unsigned *)(sq + params.sq_off.ring_mask);
    ring->sq_array = (unsigned *)(sq + params.sq_off.array);

    uint8_t *cq = (uint8_t *)ring->cq_ptr;
    ring->cq_head = (unsigned *)(cq + params.cq_off.head);
    ring->cq_tail = (unsigned *)(cq + params.cq_off.tail);
    ring->cq_mask = (unsigned *)(cq + params.cq_off.ring_mask);
    ring->cqes = (struct io_uring_cqe *)(cq + params.cq_off.cqes);
    return ring;
}

void dislmdb_iouring_destroy(dislmdb_iouring *ring)
{
    if (!ring) {
        return;
    }
    if (ring->sqes && ring->sqes != MAP_FAILED) {
        munmap(ring->sqes, ring->sqe_map_sz);
    }
    if (!ring->single_mmap && ring->cq_ptr && ring->cq_ptr != MAP_FAILED &&
        ring->cq_map_sz > 0) {
        munmap(ring->cq_ptr, ring->cq_map_sz);
    }
    if (ring->sq_ptr && ring->sq_ptr != MAP_FAILED) {
        munmap(ring->sq_ptr, ring->sq_map_sz);
    }
    if (ring->fd >= 0) {
        close(ring->fd);
    }
    free(ring);
}

int dislmdb_iouring_wait_readable(dislmdb_iouring *ring, const int *fds, int nfds,
                                  int *ready_fds, int ready_cap, int *nready,
                                  int timeout_ms)
{
    if (!ring || !fds || nfds < 0 || !ready_fds || !nready || ready_cap < 1) {
        errno = EINVAL;
        return -1;
    }
    *nready = 0;
    if (nfds == 0) {
        if (timeout_ms > 0) {
            struct timespec ts = {
                .tv_sec = timeout_ms / 1000,
                .tv_nsec = (long)(timeout_ms % 1000) * 1000000L};
            nanosleep(&ts, NULL);
        }
        return 0;
    }
    if (nfds > (int)ring->entries) {
        nfds = (int)ring->entries;
    }

    unsigned tail = *ring->sq_tail;
    unsigned mask = *ring->sq_mask;
    for (int i = 0; i < nfds; i++) {
        unsigned idx = tail & mask;
        struct io_uring_sqe *sqe = &ring->sqes[idx];
        memset(sqe, 0, sizeof(*sqe));
        sqe->opcode = IORING_OP_POLL_ADD;
        sqe->fd = fds[i];
        sqe->poll_events = (__u16)POLLIN;
        sqe->user_data = (uint64_t)(unsigned)fds[i];
        ring->sq_array[idx] = idx;
        tail++;
    }
    *ring->sq_tail = tail;

    /*
     * Block for completion. Timeout is approximate: if nothing is ready the
     * kernel waits until an event; callers also rebuild frequently (250ms
     * net-thread cadence). A linked TIMEOUT sqe can be added later.
     */
    (void)timeout_ms;
    int rc = sys_io_uring_enter(ring->fd, (unsigned)nfds, 1, IORING_ENTER_GETEVENTS);
    if (rc < 0) {
        return -1;
    }

    unsigned head = *ring->cq_head;
    unsigned cmask = *ring->cq_mask;
    unsigned ctail = *ring->cq_tail;
    while (head != ctail && *nready < ready_cap) {
        struct io_uring_cqe *cqe = &ring->cqes[head & cmask];
        if (cqe->res >= 0) {
            ready_fds[(*nready)++] = (int)cqe->user_data;
        }
        head++;
    }
    *ring->cq_head = head;
    return *nready;
}

#else /* !__linux__ */

dislmdb_iouring *dislmdb_iouring_create(unsigned entries)
{
    (void)entries;
    return NULL;
}

void dislmdb_iouring_destroy(dislmdb_iouring *ring)
{
    (void)ring;
}

int dislmdb_iouring_wait_readable(dislmdb_iouring *ring, const int *fds, int nfds,
                                  int *ready_fds, int ready_cap, int *nready,
                                  int timeout_ms)
{
    (void)ring;
    (void)fds;
    (void)nfds;
    (void)ready_fds;
    (void)ready_cap;
    (void)timeout_ms;
    if (nready) {
        *nready = 0;
    }
    errno = ENOTSUP;
    return -1;
}

#endif

bool dislmdb_iouring_available(void)
{
#if defined(__linux__)
    if (!g_probed) {
        dislmdb_iouring *r = dislmdb_iouring_create(8);
        if (r) {
            g_available = true;
            g_status = "Linux io_uring POLL_ADD wait available";
            dislmdb_iouring_destroy(r);
        } else {
            g_available = false;
            g_status = "Linux io_uring setup failed; using poll";
        }
        g_probed = true;
    }
    return g_available;
#else
    g_status = "io_uring unavailable on this platform (using poll/kqueue)";
    return false;
#endif
}

const char *dislmdb_iouring_status(void)
{
    (void)dislmdb_iouring_available();
    return g_status;
}
