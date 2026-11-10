/**
 * @file test_harness.h
 * @brief Minimal C test harness for DisLMDB suites
 */
#ifndef DISLMDB_TEST_HARNESS_H
#define DISLMDB_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct {
    int total;
    int failed;
    const char *suite;
} test_ctx_t;

static inline void test_begin(test_ctx_t *ctx, const char *suite)
{
    ctx->total = 0;
    ctx->failed = 0;
    ctx->suite = suite;
    printf("=== %s ===\n", suite);
}

static inline void test_case(test_ctx_t *ctx, const char *name, bool ok)
{
    ctx->total++;
    if (ok) {
        printf("  PASS  %s\n", name);
    } else {
        ctx->failed++;
        printf("  FAIL  %s\n", name);
    }
}

static inline int test_end(test_ctx_t *ctx)
{
    printf("--- %s: %d/%d passed ---\n",
           ctx->suite, ctx->total - ctx->failed, ctx->total);
    return ctx->failed == 0 ? 0 : 1;
}

#define EXPECT_TRUE(ctx, name, expr) \
    do { test_case((ctx), (name), !!(expr)); } while (0)

#define EXPECT_EQ_INT(ctx, name, a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        bool _ok = (_a == _b); \
        if (!_ok) { \
            fprintf(stderr, "    expected %lld == %lld\n", _a, _b); \
        } \
        test_case((ctx), (name), _ok); \
    } while (0)

#define EXPECT_STREQ(ctx, name, a, b) \
    do { \
        const char *_a = (a); \
        const char *_b = (b); \
        bool _ok = (_a && _b && strcmp(_a, _b) == 0); \
        if (!_ok) { \
            fprintf(stderr, "    expected \"%s\" == \"%s\"\n", \
                    _a ? _a : "(null)", _b ? _b : "(null)"); \
        } \
        test_case((ctx), (name), _ok); \
    } while (0)

#define EXPECT_MEMEQ(ctx, name, a, b, n) \
    do { \
        bool _ok = (memcmp((a), (b), (n)) == 0); \
        test_case((ctx), (name), _ok); \
    } while (0)

#endif /* DISLMDB_TEST_HARNESS_H */
