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
    int idx = acl_find(env, env->acl_principal);
    unsigned int have = (idx >= 0) ? env->acl_grants[idx].perms : 0;
    pthread_mutex_unlock(&env->acl_mutex);
    if ((have & need) != need) {
        return DISLMDB_ERR_NOT_AUTHORIZED;
    }
    return DISLMDB_SUCCESS;
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
