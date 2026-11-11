/**
 * @file dislmdb_acl.c
 * @brief In-process access-control for DisLMDB ops (independent of transport crypto)
 */
#include "dislmdb_internal.h"
#include "dislmdb_errors.h"
#include "dislmdb_crypto.h"

#include <stdlib.h>
#include <string.h>

/** On-disk: magic 'ACL1' + count + N × (name[65] + perms u32). */
#define ACL_PERSIST_MAGIC 0x314C4341u
#define ACL_PERSIST_NAME  (DISLMDB_ACL_PRINCIPAL_MAX + 1)
#define ACL_PERSIST_REC   (ACL_PERSIST_NAME + 4)
/** Prefix grants: magic 'ACL2' + count + N × (name[65] + prefix[65] + perms u32). */
#define ACL_PREFIX_MAGIC  0x324C4341u
#define ACL_PREFIX_FIELD  (DISLMDB_ACL_PREFIX_MAX + 1)
#define ACL_PREFIX_REC    (ACL_PERSIST_NAME + ACL_PREFIX_FIELD + 4)

static int acl_find(DISLMDB_env *env, const char *principal)
{
    if (!env || !principal || principal[0] == '\0') {
        return -1;
    }
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_PRINCIPALS; i++) {
        if (env->acl_grants[i].used &&
            strncmp(env->acl_grants[i].name, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int acl_alloc_slot(DISLMDB_env *env)
{
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_PRINCIPALS; i++) {
        if (!env->acl_grants[i].used) {
            return (int)i;
        }
    }
    return -1;
}

/* Forward: defined with require helpers below. */
static unsigned int acl_global_effective_locked(DISLMDB_env *env,
                                                const char *principal);

static bool acl_caller_is_admin_locked(DISLMDB_env *env)
{
    if (env->acl_principal[0] == '\0') {
        return false;
    }
    return (acl_global_effective_locked(env, env->acl_principal) &
            DISLMDB_ACL_ADMIN) != 0;
}

static int acl_prefix_find(DISLMDB_env *env, const char *principal,
                           const char *prefix)
{
    if (!env || !principal || !prefix || principal[0] == '\0' ||
        prefix[0] == '\0') {
        return -1;
    }
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_PREFIX_GRANTS; i++) {
        if (env->acl_prefix_grants[i].used &&
            strncmp(env->acl_prefix_grants[i].name, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) == 0 &&
            strncmp(env->acl_prefix_grants[i].prefix, prefix,
                    DISLMDB_ACL_PREFIX_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int acl_prefix_alloc_slot(DISLMDB_env *env)
{
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_PREFIX_GRANTS; i++) {
        if (!env->acl_prefix_grants[i].used) {
            return (int)i;
        }
    }
    return -1;
}

/** Direct grant | empty-prefix role memberships (caller holds acl_mutex). */
static unsigned int acl_global_effective_locked(DISLMDB_env *env,
                                                const char *principal)
{
    unsigned int have = 0;
    int idx = acl_find(env, principal);
    if (idx >= 0) {
        have |= env->acl_grants[idx].perms;
    }
    for (uint32_t m = 0; m < DISLMDB_ACL_MAX_ROLE_MEMBERS; m++) {
        if (!env->acl_role_members[m].used) {
            continue;
        }
        if (strncmp(env->acl_role_members[m].principal, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) != 0) {
            continue;
        }
        for (uint32_t r = 0; r < DISLMDB_ACL_MAX_ROLES; r++) {
            if (!env->acl_roles[r].used) {
                continue;
            }
            if (strncmp(env->acl_roles[r].name, env->acl_role_members[m].role,
                        DISLMDB_ACL_ROLE_MAX) != 0) {
                continue;
            }
            if (env->acl_roles[r].prefix[0] == '\0') {
                have |= env->acl_roles[r].perms;
            }
            break;
        }
    }
    return have;
}

/**
 * Longest matching prefix from direct prefix grants + prefix-scoped roles.
 * Caller holds acl_mutex. ADMIN never granted here.
 */
static unsigned int acl_prefix_effective_locked(DISLMDB_env *env,
                                                const char *principal,
                                                const void *key, size_t key_len)
{
    size_t best = 0;
    unsigned int best_perms = 0;
    const uint8_t *kb = (const uint8_t *)key;

    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_PREFIX_GRANTS; i++) {
        if (!env->acl_prefix_grants[i].used) {
            continue;
        }
        if (strncmp(env->acl_prefix_grants[i].name, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) != 0) {
            continue;
        }
        size_t plen = strnlen(env->acl_prefix_grants[i].prefix,
                              DISLMDB_ACL_PREFIX_MAX);
        if (plen == 0 || plen > key_len || plen < best) {
            continue;
        }
        if (memcmp(kb, env->acl_prefix_grants[i].prefix, plen) != 0) {
            continue;
        }
        best = plen;
        best_perms = env->acl_prefix_grants[i].perms;
    }

    for (uint32_t m = 0; m < DISLMDB_ACL_MAX_ROLE_MEMBERS; m++) {
        if (!env->acl_role_members[m].used) {
            continue;
        }
        if (strncmp(env->acl_role_members[m].principal, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) != 0) {
            continue;
        }
        for (uint32_t r = 0; r < DISLMDB_ACL_MAX_ROLES; r++) {
            if (!env->acl_roles[r].used) {
                continue;
            }
            if (strncmp(env->acl_roles[r].name, env->acl_role_members[m].role,
                        DISLMDB_ACL_ROLE_MAX) != 0) {
                continue;
            }
            size_t plen =
                strnlen(env->acl_roles[r].prefix, DISLMDB_ACL_PREFIX_MAX);
            if (plen == 0 || plen > key_len || plen < best) {
                break;
            }
            if (memcmp(kb, env->acl_roles[r].prefix, plen) != 0) {
                break;
            }
            best = plen;
            best_perms = env->acl_roles[r].perms &
                         (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE);
            break;
        }
    }
    return best_perms;
}

int dislmdb_acl_require(DISLMDB_env *env, unsigned int need)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.enable_acl || need == 0) {
        return DISLMDB_SUCCESS;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    pthread_mutex_lock(&env->acl_mutex);
    if (env->acl_principal[0] == '\0') {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    unsigned int have =
        acl_global_effective_locked(env, env->acl_principal);
    pthread_mutex_unlock(&env->acl_mutex);
    if ((have & need) != need) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_require_key(DISLMDB_env *env, unsigned int need,
                            const void *key, size_t key_len)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->config.enable_acl || need == 0) {
        return DISLMDB_SUCCESS;
    }
    /* ADMIN is env-wide only — never via prefix / prefix-scoped roles. */
    if ((need & DISLMDB_ACL_ADMIN) != 0) {
        return dislmdb_acl_require(env, need);
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!key && key_len > 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&env->acl_mutex);
    if (env->acl_principal[0] == '\0') {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    unsigned int have =
        acl_global_effective_locked(env, env->acl_principal);
    if ((have & need) == need) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_SUCCESS;
    }
    unsigned int pfx =
        acl_prefix_effective_locked(env, env->acl_principal, key, key_len);
    pthread_mutex_unlock(&env->acl_mutex);
    if ((pfx & need) == need) {
        return DISLMDB_SUCCESS;
    }
    return DISLMDB_ERR_NOT_AUTHORIZED;
}

int dislmdb_acl_set_principal(DISLMDB_env *env, const char *principal)
{
    if (!env || env->magic != DISLMDB_MAGIC) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (principal && strnlen(principal, DISLMDB_ACL_PRINCIPAL_MAX + 1) >
                         DISLMDB_ACL_PRINCIPAL_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->acl_mutex);
    if (!principal || principal[0] == '\0') {
        env->acl_principal[0] = '\0';
    } else {
        strncpy(env->acl_principal, principal, DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_principal[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_grant(DISLMDB_env *env, const char *principal, unsigned int perms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal ||
        principal[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strnlen(principal, DISLMDB_ACL_PRINCIPAL_MAX + 1) >
        DISLMDB_ACL_PRINCIPAL_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }

    pthread_mutex_lock(&env->acl_mutex);
    bool empty = (env->acl_grant_count == 0);
    if (!empty) {
        if (env->acl_principal[0] == '\0') {
            pthread_mutex_unlock(&env->acl_mutex);
            return DISLMDB_ERR_NOT_AUTHORIZED;
        }
        int self = acl_find(env, env->acl_principal);
        if (self < 0 ||
            (env->acl_grants[self].perms & DISLMDB_ACL_ADMIN) == 0) {
            pthread_mutex_unlock(&env->acl_mutex);
            return DISLMDB_ERR_NOT_AUTHORIZED;
        }
    }

    int idx = acl_find(env, principal);
    if (idx < 0) {
        idx = acl_alloc_slot(env);
        if (idx < 0) {
            pthread_mutex_unlock(&env->acl_mutex);
            return DISLMDB_ERR_BUFFER_OVERFLOW;
        }
        memset(&env->acl_grants[idx], 0, sizeof(env->acl_grants[idx]));
        strncpy(env->acl_grants[idx].name, principal, DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_grants[idx].name[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
        env->acl_grants[idx].used = true;
        env->acl_grant_count++;
    }
    env->acl_grants[idx].perms |= perms;
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_revoke(DISLMDB_env *env, const char *principal, unsigned int perms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal ||
        principal[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }

    pthread_mutex_lock(&env->acl_mutex);
    if (env->acl_principal[0] == '\0') {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int self = acl_find(env, env->acl_principal);
    if (self < 0 || (env->acl_grants[self].perms & DISLMDB_ACL_ADMIN) == 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }

    int idx = acl_find(env, principal);
    if (idx < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    env->acl_grants[idx].perms &= ~perms;
    if (env->acl_grants[idx].perms == 0) {
        env->acl_grants[idx].used = false;
        env->acl_grants[idx].name[0] = '\0';
        if (env->acl_grant_count > 0) {
            env->acl_grant_count--;
        }
    }
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_persist_pack(DISLMDB_env *env, uint8_t **out, size_t *out_len)
{
    if (!env || !out || !out_len || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->acl_mutex);
    uint32_t n = env->acl_grant_count;
    size_t need = 8 + (size_t)n * ACL_PERSIST_REC;
    uint8_t *buf = calloc(1, need ? need : 8);
    if (!buf) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(buf, ACL_PERSIST_MAGIC);
    dislmdb_write_u32(buf + 4, n);
    size_t o = 8;
    uint32_t written = 0;
    for (uint32_t i = 0;
         i < DISLMDB_ACL_MAX_PRINCIPALS && written < n; i++) {
        if (!env->acl_grants[i].used) {
            continue;
        }
        memcpy(buf + o, env->acl_grants[i].name, ACL_PERSIST_NAME);
        dislmdb_write_u32(buf + o + ACL_PERSIST_NAME, env->acl_grants[i].perms);
        o += ACL_PERSIST_REC;
        written++;
    }
    dislmdb_write_u32(buf + 4, written);
    pthread_mutex_unlock(&env->acl_mutex);
    *out = buf;
    *out_len = 8 + (size_t)written * ACL_PERSIST_REC;
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_persist_unpack(DISLMDB_env *env, const uint8_t *data, size_t len)
{
    if (!env || !data || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (len < 8 || dislmdb_read_u32(data) != ACL_PERSIST_MAGIC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    uint32_t n = dislmdb_read_u32(data + 4);
    if (n > DISLMDB_ACL_MAX_PRINCIPALS ||
        len < 8 + (size_t)n * ACL_PERSIST_REC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    memset(env->acl_grants, 0, sizeof(env->acl_grants));
    env->acl_grant_count = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = data + 8 + (size_t)i * ACL_PERSIST_REC;
        char name[ACL_PERSIST_NAME];
        memcpy(name, rec, ACL_PERSIST_NAME);
        name[ACL_PERSIST_NAME - 1] = '\0';
        if (name[0] == '\0') {
            continue;
        }
        unsigned int perms = dislmdb_read_u32(rec + ACL_PERSIST_NAME);
        if (perms == 0) {
            continue;
        }
        int slot = acl_alloc_slot(env);
        if (slot < 0) {
            break;
        }
        strncpy(env->acl_grants[slot].name, name, DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_grants[slot].name[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
        env->acl_grants[slot].perms = perms;
        env->acl_grants[slot].used = true;
        env->acl_grant_count++;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_get(DISLMDB_env *env, const char *principal, unsigned int *perms_out)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !perms_out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    *perms_out = 0;
    if (!env->config.enable_acl) {
        return DISLMDB_SUCCESS;
    }
    pthread_mutex_lock(&env->acl_mutex);
    int idx = acl_find(env, principal);
    if (idx >= 0) {
        *perms_out = env->acl_grants[idx].perms;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_grant_prefix(DISLMDB_env *env, const char *principal,
                             const char *key_prefix, unsigned int perms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !key_prefix ||
        principal[0] == '\0' || key_prefix[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strnlen(principal, DISLMDB_ACL_PRINCIPAL_MAX + 1) >
            DISLMDB_ACL_PRINCIPAL_MAX ||
        strnlen(key_prefix, DISLMDB_ACL_PREFIX_MAX + 1) >
            DISLMDB_ACL_PREFIX_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    /* Prefix grants are data-plane only. */
    if ((perms & ~(DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) != 0 ||
        (perms & (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }

    pthread_mutex_lock(&env->acl_mutex);
    if (env->acl_grant_count == 0 || !acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }

    int idx = acl_prefix_find(env, principal, key_prefix);
    if (idx < 0) {
        idx = acl_prefix_alloc_slot(env);
        if (idx < 0) {
            pthread_mutex_unlock(&env->acl_mutex);
            return DISLMDB_ERR_BUFFER_OVERFLOW;
        }
        memset(&env->acl_prefix_grants[idx], 0,
               sizeof(env->acl_prefix_grants[idx]));
        strncpy(env->acl_prefix_grants[idx].name, principal,
                DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_prefix_grants[idx].name[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
        strncpy(env->acl_prefix_grants[idx].prefix, key_prefix,
                DISLMDB_ACL_PREFIX_MAX);
        env->acl_prefix_grants[idx].prefix[DISLMDB_ACL_PREFIX_MAX] = '\0';
        env->acl_prefix_grants[idx].used = true;
        env->acl_prefix_grant_count++;
    }
    env->acl_prefix_grants[idx].perms |= perms;
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_revoke_prefix(DISLMDB_env *env, const char *principal,
                              const char *key_prefix, unsigned int perms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !key_prefix ||
        principal[0] == '\0' || key_prefix[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }

    pthread_mutex_lock(&env->acl_mutex);
    if (!acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int idx = acl_prefix_find(env, principal, key_prefix);
    if (idx < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    env->acl_prefix_grants[idx].perms &= ~perms;
    if (env->acl_prefix_grants[idx].perms == 0) {
        env->acl_prefix_grants[idx].used = false;
        env->acl_prefix_grants[idx].name[0] = '\0';
        env->acl_prefix_grants[idx].prefix[0] = '\0';
        if (env->acl_prefix_grant_count > 0) {
            env->acl_prefix_grant_count--;
        }
    }
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_get_prefix(DISLMDB_env *env, const char *principal,
                           const char *key_prefix, unsigned int *perms_out)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !key_prefix ||
        !perms_out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    *perms_out = 0;
    if (!env->config.enable_acl) {
        return DISLMDB_SUCCESS;
    }
    pthread_mutex_lock(&env->acl_mutex);
    int idx = acl_prefix_find(env, principal, key_prefix);
    if (idx >= 0) {
        *perms_out = env->acl_prefix_grants[idx].perms;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_prefix_persist_pack(DISLMDB_env *env, uint8_t **out,
                                    size_t *out_len)
{
    if (!env || !out || !out_len || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->acl_mutex);
    uint32_t n = env->acl_prefix_grant_count;
    size_t need = 8 + (size_t)n * ACL_PREFIX_REC;
    uint8_t *buf = calloc(1, need ? need : 8);
    if (!buf) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(buf, ACL_PREFIX_MAGIC);
    dislmdb_write_u32(buf + 4, n);
    size_t o = 8;
    uint32_t written = 0;
    for (uint32_t i = 0;
         i < DISLMDB_ACL_MAX_PREFIX_GRANTS && written < n; i++) {
        if (!env->acl_prefix_grants[i].used) {
            continue;
        }
        memcpy(buf + o, env->acl_prefix_grants[i].name, ACL_PERSIST_NAME);
        memcpy(buf + o + ACL_PERSIST_NAME, env->acl_prefix_grants[i].prefix,
               ACL_PREFIX_FIELD);
        dislmdb_write_u32(buf + o + ACL_PERSIST_NAME + ACL_PREFIX_FIELD,
                          env->acl_prefix_grants[i].perms);
        o += ACL_PREFIX_REC;
        written++;
    }
    dislmdb_write_u32(buf + 4, written);
    pthread_mutex_unlock(&env->acl_mutex);
    *out = buf;
    *out_len = 8 + (size_t)written * ACL_PREFIX_REC;
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_prefix_persist_unpack(DISLMDB_env *env, const uint8_t *data,
                                      size_t len)
{
    if (!env || !data || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (len < 8 || dislmdb_read_u32(data) != ACL_PREFIX_MAGIC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    uint32_t n = dislmdb_read_u32(data + 4);
    if (n > DISLMDB_ACL_MAX_PREFIX_GRANTS ||
        len < 8 + (size_t)n * ACL_PREFIX_REC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    memset(env->acl_prefix_grants, 0, sizeof(env->acl_prefix_grants));
    env->acl_prefix_grant_count = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = data + 8 + (size_t)i * ACL_PREFIX_REC;
        char name[ACL_PERSIST_NAME];
        char prefix[ACL_PREFIX_FIELD];
        memcpy(name, rec, ACL_PERSIST_NAME);
        name[ACL_PERSIST_NAME - 1] = '\0';
        memcpy(prefix, rec + ACL_PERSIST_NAME, ACL_PREFIX_FIELD);
        prefix[ACL_PREFIX_FIELD - 1] = '\0';
        unsigned int perms =
            dislmdb_read_u32(rec + ACL_PERSIST_NAME + ACL_PREFIX_FIELD);
        perms &= (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE);
        if (name[0] == '\0' || prefix[0] == '\0' || perms == 0) {
            continue;
        }
        int slot = acl_prefix_alloc_slot(env);
        if (slot < 0) {
            break;
        }
        strncpy(env->acl_prefix_grants[slot].name, name,
                DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_prefix_grants[slot].name[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
        strncpy(env->acl_prefix_grants[slot].prefix, prefix,
                DISLMDB_ACL_PREFIX_MAX);
        env->acl_prefix_grants[slot].prefix[DISLMDB_ACL_PREFIX_MAX] = '\0';
        env->acl_prefix_grants[slot].perms = perms;
        env->acl_prefix_grants[slot].used = true;
        env->acl_prefix_grant_count++;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

#define ACL_ROLE_MAGIC   0x334C4341u /* ACL3 */
#define ACL_MEMBER_MAGIC 0x344C4341u /* ACL4 */
#define ACL_ROLE_NAME    (DISLMDB_ACL_ROLE_MAX + 1)
#define ACL_ROLE_REC     (ACL_ROLE_NAME + ACL_PREFIX_FIELD + 4)
#define ACL_MEMBER_REC   (ACL_PERSIST_NAME + ACL_ROLE_NAME)

static int acl_role_find(DISLMDB_env *env, const char *role)
{
    if (!role || role[0] == '\0') {
        return -1;
    }
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_ROLES; i++) {
        if (env->acl_roles[i].used &&
            strncmp(env->acl_roles[i].name, role, DISLMDB_ACL_ROLE_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int acl_role_alloc(DISLMDB_env *env)
{
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_ROLES; i++) {
        if (!env->acl_roles[i].used) {
            return (int)i;
        }
    }
    return -1;
}

static int acl_member_find(DISLMDB_env *env, const char *principal,
                           const char *role)
{
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_ROLE_MEMBERS; i++) {
        if (env->acl_role_members[i].used &&
            strncmp(env->acl_role_members[i].principal, principal,
                    DISLMDB_ACL_PRINCIPAL_MAX) == 0 &&
            strncmp(env->acl_role_members[i].role, role,
                    DISLMDB_ACL_ROLE_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int acl_member_alloc(DISLMDB_env *env)
{
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_ROLE_MEMBERS; i++) {
        if (!env->acl_role_members[i].used) {
            return (int)i;
        }
    }
    return -1;
}

int dislmdb_acl_role_define(DISLMDB_env *env, const char *role,
                            const char *key_prefix, unsigned int perms)
{
    if (!env || env->magic != DISLMDB_MAGIC || !role || role[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strnlen(role, DISLMDB_ACL_ROLE_MAX + 1) > DISLMDB_ACL_ROLE_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    const char *pfx = key_prefix ? key_prefix : "";
    if (strnlen(pfx, DISLMDB_ACL_PREFIX_MAX + 1) > DISLMDB_ACL_PREFIX_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (pfx[0] != '\0') {
        if ((perms & ~(DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) != 0 ||
            (perms & (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE)) == 0) {
            return DISLMDB_ERR_INVALID_PARAMETER;
        }
    } else if (perms == 0) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }

    pthread_mutex_lock(&env->acl_mutex);
    if (env->acl_grant_count == 0 || !acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int idx = acl_role_find(env, role);
    if (idx < 0) {
        idx = acl_role_alloc(env);
        if (idx < 0) {
            pthread_mutex_unlock(&env->acl_mutex);
            return DISLMDB_ERR_BUFFER_OVERFLOW;
        }
        memset(&env->acl_roles[idx], 0, sizeof(env->acl_roles[idx]));
        strncpy(env->acl_roles[idx].name, role, DISLMDB_ACL_ROLE_MAX);
        env->acl_roles[idx].name[DISLMDB_ACL_ROLE_MAX] = '\0';
        env->acl_roles[idx].used = true;
        env->acl_role_count++;
    }
    strncpy(env->acl_roles[idx].prefix, pfx, DISLMDB_ACL_PREFIX_MAX);
    env->acl_roles[idx].prefix[DISLMDB_ACL_PREFIX_MAX] = '\0';
    env->acl_roles[idx].perms = perms;
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_undefine(DISLMDB_env *env, const char *role)
{
    if (!env || env->magic != DISLMDB_MAGIC || !role || role[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    if (!acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int idx = acl_role_find(env, role);
    if (idx < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    env->acl_roles[idx].used = false;
    env->acl_roles[idx].name[0] = '\0';
    env->acl_roles[idx].prefix[0] = '\0';
    env->acl_roles[idx].perms = 0;
    if (env->acl_role_count > 0) {
        env->acl_role_count--;
    }
    for (uint32_t i = 0; i < DISLMDB_ACL_MAX_ROLE_MEMBERS; i++) {
        if (!env->acl_role_members[i].used) {
            continue;
        }
        if (strncmp(env->acl_role_members[i].role, role,
                    DISLMDB_ACL_ROLE_MAX) == 0) {
            env->acl_role_members[i].used = false;
            env->acl_role_members[i].principal[0] = '\0';
            env->acl_role_members[i].role[0] = '\0';
            if (env->acl_role_member_count > 0) {
                env->acl_role_member_count--;
            }
        }
    }
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_get(DISLMDB_env *env, const char *role,
                         unsigned int *perms_out, char *prefix_out,
                         size_t prefix_cap)
{
    if (!env || env->magic != DISLMDB_MAGIC || !role || !perms_out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    *perms_out = 0;
    if (prefix_out && prefix_cap > 0) {
        prefix_out[0] = '\0';
    }
    if (!env->config.enable_acl) {
        return DISLMDB_SUCCESS;
    }
    pthread_mutex_lock(&env->acl_mutex);
    int idx = acl_role_find(env, role);
    if (idx >= 0) {
        *perms_out = env->acl_roles[idx].perms;
        if (prefix_out && prefix_cap > 0) {
            strncpy(prefix_out, env->acl_roles[idx].prefix, prefix_cap - 1);
            prefix_out[prefix_cap - 1] = '\0';
        }
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_assign(DISLMDB_env *env, const char *principal,
                            const char *role)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !role ||
        principal[0] == '\0' || role[0] == '\0') {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (strnlen(principal, DISLMDB_ACL_PRINCIPAL_MAX + 1) >
            DISLMDB_ACL_PRINCIPAL_MAX ||
        strnlen(role, DISLMDB_ACL_ROLE_MAX + 1) > DISLMDB_ACL_ROLE_MAX) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    if (!acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    if (acl_role_find(env, role) < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    if (acl_member_find(env, principal, role) >= 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_SUCCESS;
    }
    int slot = acl_member_alloc(env);
    if (slot < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_BUFFER_OVERFLOW;
    }
    memset(&env->acl_role_members[slot], 0, sizeof(env->acl_role_members[slot]));
    strncpy(env->acl_role_members[slot].principal, principal,
            DISLMDB_ACL_PRINCIPAL_MAX);
    env->acl_role_members[slot].principal[DISLMDB_ACL_PRINCIPAL_MAX] = '\0';
    strncpy(env->acl_role_members[slot].role, role, DISLMDB_ACL_ROLE_MAX);
    env->acl_role_members[slot].role[DISLMDB_ACL_ROLE_MAX] = '\0';
    env->acl_role_members[slot].used = true;
    env->acl_role_member_count++;
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_unassign(DISLMDB_env *env, const char *principal,
                              const char *role)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !role) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    if (!env->config.enable_acl) {
        return DISLMDB_ERR_INVALID_OPERATION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    if (!acl_caller_is_admin_locked(env)) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    int idx = acl_member_find(env, principal, role);
    if (idx < 0) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_NODE_NOT_FOUND;
    }
    env->acl_role_members[idx].used = false;
    env->acl_role_members[idx].principal[0] = '\0';
    env->acl_role_members[idx].role[0] = '\0';
    if (env->acl_role_member_count > 0) {
        env->acl_role_member_count--;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    if (env->config.consensus.persist_state) {
        (void)dislmdb_persist_save(env);
    }
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_effective(DISLMDB_env *env, const char *principal,
                          unsigned int *perms_out)
{
    if (!env || env->magic != DISLMDB_MAGIC || !principal || !perms_out) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (!env->acl_mutex_ready) {
        return DISLMDB_ERR_NOT_INITIALIZED;
    }
    *perms_out = 0;
    if (!env->config.enable_acl) {
        return DISLMDB_SUCCESS;
    }
    pthread_mutex_lock(&env->acl_mutex);
    *perms_out = acl_global_effective_locked(env, principal);
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_roles_persist_pack(DISLMDB_env *env, uint8_t **out,
                                   size_t *out_len)
{
    if (!env || !out || !out_len || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->acl_mutex);
    uint32_t n = env->acl_role_count;
    size_t need = 8 + (size_t)n * ACL_ROLE_REC;
    uint8_t *buf = calloc(1, need ? need : 8);
    if (!buf) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(buf, ACL_ROLE_MAGIC);
    size_t o = 8;
    uint32_t written = 0;
    for (uint32_t i = 0;
         i < DISLMDB_ACL_MAX_ROLES && written < n; i++) {
        if (!env->acl_roles[i].used) {
            continue;
        }
        memcpy(buf + o, env->acl_roles[i].name, ACL_ROLE_NAME);
        memcpy(buf + o + ACL_ROLE_NAME, env->acl_roles[i].prefix,
               ACL_PREFIX_FIELD);
        dislmdb_write_u32(buf + o + ACL_ROLE_NAME + ACL_PREFIX_FIELD,
                          env->acl_roles[i].perms);
        o += ACL_ROLE_REC;
        written++;
    }
    dislmdb_write_u32(buf + 4, written);
    pthread_mutex_unlock(&env->acl_mutex);
    *out = buf;
    *out_len = 8 + (size_t)written * ACL_ROLE_REC;
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_roles_persist_unpack(DISLMDB_env *env, const uint8_t *data,
                                     size_t len)
{
    if (!env || !data || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (len < 8 || dislmdb_read_u32(data) != ACL_ROLE_MAGIC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    uint32_t n = dislmdb_read_u32(data + 4);
    if (n > DISLMDB_ACL_MAX_ROLES ||
        len < 8 + (size_t)n * ACL_ROLE_REC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    memset(env->acl_roles, 0, sizeof(env->acl_roles));
    env->acl_role_count = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = data + 8 + (size_t)i * ACL_ROLE_REC;
        char name[ACL_ROLE_NAME];
        char prefix[ACL_PREFIX_FIELD];
        memcpy(name, rec, ACL_ROLE_NAME);
        name[ACL_ROLE_NAME - 1] = '\0';
        memcpy(prefix, rec + ACL_ROLE_NAME, ACL_PREFIX_FIELD);
        prefix[ACL_PREFIX_FIELD - 1] = '\0';
        unsigned int perms =
            dislmdb_read_u32(rec + ACL_ROLE_NAME + ACL_PREFIX_FIELD);
        if (name[0] == '\0' || perms == 0) {
            continue;
        }
        if (prefix[0] != '\0') {
            perms &= (DISLMDB_ACL_READ | DISLMDB_ACL_WRITE);
            if (perms == 0) {
                continue;
            }
        }
        int slot = acl_role_alloc(env);
        if (slot < 0) {
            break;
        }
        strncpy(env->acl_roles[slot].name, name, DISLMDB_ACL_ROLE_MAX);
        env->acl_roles[slot].name[DISLMDB_ACL_ROLE_MAX] = '\0';
        strncpy(env->acl_roles[slot].prefix, prefix, DISLMDB_ACL_PREFIX_MAX);
        env->acl_roles[slot].prefix[DISLMDB_ACL_PREFIX_MAX] = '\0';
        env->acl_roles[slot].perms = perms;
        env->acl_roles[slot].used = true;
        env->acl_role_count++;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_members_persist_pack(DISLMDB_env *env, uint8_t **out,
                                          size_t *out_len)
{
    if (!env || !out || !out_len || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    pthread_mutex_lock(&env->acl_mutex);
    uint32_t n = env->acl_role_member_count;
    size_t need = 8 + (size_t)n * ACL_MEMBER_REC;
    uint8_t *buf = calloc(1, need ? need : 8);
    if (!buf) {
        pthread_mutex_unlock(&env->acl_mutex);
        return DISLMDB_ERR_MEMORY_ERROR;
    }
    dislmdb_write_u32(buf, ACL_MEMBER_MAGIC);
    size_t o = 8;
    uint32_t written = 0;
    for (uint32_t i = 0;
         i < DISLMDB_ACL_MAX_ROLE_MEMBERS && written < n; i++) {
        if (!env->acl_role_members[i].used) {
            continue;
        }
        memcpy(buf + o, env->acl_role_members[i].principal, ACL_PERSIST_NAME);
        memcpy(buf + o + ACL_PERSIST_NAME, env->acl_role_members[i].role,
               ACL_ROLE_NAME);
        o += ACL_MEMBER_REC;
        written++;
    }
    dislmdb_write_u32(buf + 4, written);
    pthread_mutex_unlock(&env->acl_mutex);
    *out = buf;
    *out_len = 8 + (size_t)written * ACL_MEMBER_REC;
    return DISLMDB_SUCCESS;
}

int dislmdb_acl_role_members_persist_unpack(DISLMDB_env *env,
                                            const uint8_t *data, size_t len)
{
    if (!env || !data || !env->acl_mutex_ready) {
        return DISLMDB_ERR_INVALID_PARAMETER;
    }
    if (len < 8 || dislmdb_read_u32(data) != ACL_MEMBER_MAGIC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    uint32_t n = dislmdb_read_u32(data + 4);
    if (n > DISLMDB_ACL_MAX_ROLE_MEMBERS ||
        len < 8 + (size_t)n * ACL_MEMBER_REC) {
        return DISLMDB_ERR_DATA_CORRUPTION;
    }
    pthread_mutex_lock(&env->acl_mutex);
    memset(env->acl_role_members, 0, sizeof(env->acl_role_members));
    env->acl_role_member_count = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = data + 8 + (size_t)i * ACL_MEMBER_REC;
        char principal[ACL_PERSIST_NAME];
        char role[ACL_ROLE_NAME];
        memcpy(principal, rec, ACL_PERSIST_NAME);
        principal[ACL_PERSIST_NAME - 1] = '\0';
        memcpy(role, rec + ACL_PERSIST_NAME, ACL_ROLE_NAME);
        role[ACL_ROLE_NAME - 1] = '\0';
        if (principal[0] == '\0' || role[0] == '\0') {
            continue;
        }
        int slot = acl_member_alloc(env);
        if (slot < 0) {
            break;
        }
        strncpy(env->acl_role_members[slot].principal, principal,
                DISLMDB_ACL_PRINCIPAL_MAX);
        env->acl_role_members[slot].principal[DISLMDB_ACL_PRINCIPAL_MAX] =
            '\0';
        strncpy(env->acl_role_members[slot].role, role, DISLMDB_ACL_ROLE_MAX);
        env->acl_role_members[slot].role[DISLMDB_ACL_ROLE_MAX] = '\0';
        env->acl_role_members[slot].used = true;
        env->acl_role_member_count++;
    }
    pthread_mutex_unlock(&env->acl_mutex);
    return DISLMDB_SUCCESS;
}
