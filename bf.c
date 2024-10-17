// Copyright (c) 2024 hippie68

#include "bf.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CHUNK_SIZE 4096

struct bf_pool {
    unsigned char *passcode;       // Current global password mapped to digits.
    int len;                       // Current global passcode length in bytes.
    int min_len;                   // Minimum passcode length in bytes.
    int max_len;                   // Maximum passcode length in bytes.
    char *charset;                 // Character set used to translate passcodes
                                   // into ASCII strings (passwords).
    int charset_len;               // Character set string length.
    unsigned char *final_passcode; // Further passcode generation stops after
                                   // reaching this specific passcode.
    int final_passcode_len;        // Final passcode length in bytes.
    int chunk_size;                // Number of passcodes for each thread to try
                                   // at a time.
    char *password;                // Used to store a password found by a task.
    enum bf_pool_status status;    // The current pool status (see bf.h).
    pthread_mutex_t mutex;
};

struct bf_task {
    unsigned char *passcode;       // Current local password mapped to digits.
    int len;                       // Current local password length in bytes.
    struct bf_pool *pool;          // Pool the task is tied to.
    int max_len;                   // Some members are copied to increase speed.
    char *charset;                 // ------------------ " ---------------------
    int charset_len;               // ------------------ " ---------------------
    int counter;                   // Remaining passcode iterations.
};

struct bf_pool *bf_pool_create(const char *character_set, int min_len,
    int max_len, const char *start, const char *end)
{
    if (character_set == NULL || min_len < 1 || max_len < min_len)
        return NULL;

    struct bf_pool *pool = malloc(sizeof(*pool));
    if (pool == NULL)
        return NULL;

    pool->min_len = min_len;
    pool->max_len = max_len;
    pool->charset_len = strlen(character_set);

    pool->passcode = malloc(max_len * 2 + pool->charset_len);
    if (pool->passcode == NULL)
        goto error;
    pool->final_passcode = pool->passcode + max_len;

    pool->charset = (char *) pool->passcode + max_len * 2;
    memcpy(pool->charset, character_set, pool->charset_len);

    if (start) {
        pool->len = strlen(start);
        if (pool->len > max_len)
            goto error;

        for (int i = 0; i < pool->len; i++) {
            for (int j = 0; j < pool->charset_len; j++) {
                if (start[i] == pool->charset[j]) {
                    pool->passcode[i] = j;
                    goto next_start;
                }
            }
            goto error;
next_start:
            ;
        }
    } else {
        pool->len = min_len;
        memset(pool->passcode, 0, max_len);
    }

    if (end) {
        pool->final_passcode_len = strlen(end);
        if (pool->final_passcode_len < pool->len)
            goto error;

        for (int i = 0; i < max_len; i++) {
            for (int j = 0; j < pool->charset_len; j++) {
                if (end[i] == pool->charset[j]) {
                    pool->final_passcode[i] = j;
                    goto next_end;
                }
            }
            goto error;
next_end:
            ;
        }
    } else {
        pool->final_passcode_len = max_len;
        memset(pool->final_passcode, pool->charset_len - 1, max_len);
    }

    pool->chunk_size = DEFAULT_CHUNK_SIZE;
    pool->password = NULL;
    pool->status = BF_OPEN;

    if (pthread_mutex_init(&pool->mutex, NULL))
        goto error;

    return pool;

error:
    free(pool);
    return NULL;
}

void bf_pool_destroy(struct bf_pool *pool)
{
    free(pool->passcode);
    pthread_mutex_destroy(&pool->mutex);
    free(pool);
}

void bf_pool_set_chunk_size(struct bf_pool *pool, int chunk_size)
{
    pthread_mutex_lock(&pool->mutex);
    pool->chunk_size = chunk_size;
    pthread_mutex_unlock(&pool->mutex);
}

enum bf_pool_status bf_pool_get_status(struct bf_pool *pool)
{
    int ret;
    pthread_mutex_lock(&pool->mutex);
    ret = pool->status;
    pthread_mutex_unlock(&pool->mutex);
    return ret;
}

static void bf_pool_set_status(struct bf_pool *pool, enum bf_pool_status status)
{
    pthread_mutex_lock(&pool->mutex);
    pool->status = status;
    pthread_mutex_unlock(&pool->mutex);
}

int bf_pool_set_password(struct bf_pool *pool, char *password, int len)
{
    pthread_mutex_lock(&pool->mutex);

    if (pool->password || len > pool->max_len)
        return 1;

    pool->password = malloc(len + 1);
    if (pool->password == NULL)
        return -1;

    memcpy(pool->password, password, len);
    pool->password[len] = '\0';
    pool->status = BF_PASSWORD_FOUND;

    pthread_mutex_unlock(&pool->mutex);

    return 0;
}

char *bf_pool_get_password(struct bf_pool *pool)
{
    char *ret;
    pthread_mutex_lock(&pool->mutex);
    ret = pool->password;
    if (ret == NULL) {
        ret = malloc(pool->len + 1);
        if (ret == NULL)
            return NULL;
        for (int i = 0; i < pool->len; i++)
            ret[i] = pool->charset[pool->passcode[i]];
        ret[pool->len] = '\0';
    }
    pthread_mutex_unlock(&pool->mutex);
    return ret;
}

void bf_pool_close(struct bf_pool *pool)
{
    bf_pool_set_status(pool, BF_CLOSED);
}

struct bf_task *bf_task_create(const struct bf_pool *pool)
{
    struct bf_task *task = malloc(sizeof(*task));
    if (task == NULL)
        return NULL;

    task->passcode = malloc(pool->charset_len);
    if (task->passcode == NULL) {
        free(task);
        return NULL;
    }
    task->charset = pool->charset;
    task->charset_len = pool->charset_len;
    task->len = pool->min_len;
    task->pool = (struct bf_pool *) pool;
    task->max_len = pool->max_len;
    task->counter = 0;

    return task;
}

void bf_task_destroy(struct bf_task *task)
{
    free(task);
}

// Return value: 0 on success, non-zero on overflow.
static inline int int_to_map(int val, int base, unsigned char *buf, int buf_len)
{
    for (int i = 0; i < buf_len; i++) {
        int r = val % base;
        buf[i] = r;
        val = val / base;
    }

    return val % base;
}

// Return value: 0 on success, non-zero on overflow.
static inline int add_map_to_map(unsigned char *target,
    const unsigned char *source, int base, int len)
{
    int r = 0;

    for (int i = 0; i < len; i++) {
        int result = target[i] + source[i] + r;
        if (result >= base) {
            target[i] = result - base;
            r = 1;
        } else {
            target[i] = result;
            r = 0;
        }
    }

    return r;
}

// Return value: 0 on success, non-zero on overflow.
static inline int add_int_to_map(int val, int base, unsigned char *map,
    int map_len)
{
    unsigned char temp_map[map_len];
    if (int_to_map(val, base, temp_map, map_len))
        return -1;
    return add_map_to_map(map, temp_map, base, map_len);
}

// -1: mutex error, 1: pool closed/exhausted, 0: success.
int bf_task_update(struct bf_task *task)
{
    struct bf_pool *pool = task->pool;

    if (pthread_mutex_lock(&pool->mutex))
        return -1;

    if (pool->status) {
        pthread_mutex_unlock(&pool->mutex);
        return 1;
    }

    if (memcmp(pool->passcode, pool->final_passcode, pool->max_len) == 0) {
        pool->status = BF_PASSWORD_NOT_FOUND;
        pthread_mutex_unlock(&pool->mutex);
        return 1;
    }

    // First, pass current chunk of pool task to thread.
    memcpy(task->passcode, pool->passcode, pool->max_len);
    task->passcode[0] -= 1;
    task->counter = pool->chunk_size;
    task->len = pool->len;

    // Then increase the pool passcode in advance for a later call.
    if (add_int_to_map(pool->chunk_size, pool->charset_len, pool->passcode,
        pool->max_len))
        memcpy(pool->passcode, pool->final_passcode, pool->max_len);
    int len = 1;
    for (int i = pool->max_len - 1; i >= 0; i--) {
        if (pool->passcode[i]) {
            len = i + 1;
            break;
        }
    }
    pool->len = len;

    if (pthread_mutex_unlock(&pool->mutex))
        return -1;

    return 0;
}

int bf_task_generate_password(char *buf, struct bf_task *task)
{
    if (task->counter-- == 0)
        if (bf_task_update(task))
            return 0;

    for (int i = 0; i < task->len; i++) {
        task->passcode[i]++;
        if (task->passcode[i] == task->charset_len) {
            task->passcode[i] = 0;
        } else {
            for (int j = 0; j < task->len; j++)
                buf[j] = task->charset[task->passcode[j]];
            return task->len;
        }
    }
    // Still here? All possible combinations for the current passcode length
    // have been generated.

    if (task->len < task->max_len) {
        task->len++;
        for (int i = 0; i < task->len; i++)
            buf[i] = task->charset[task->passcode[i]];
        return task->len;
    }

    return 0;
}
