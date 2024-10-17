// Copyright (c) 2024 hippie68

// This is a simple example program to show how to use the brute-force library.

#include "bf.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWORD_MIN_LEN 1
#define PASSWORD_MAX_LEN 8
#define N_THREADS 4          // Adjust this to match your CPU specs.

struct bf_pool *global_pool; // This global variable is only used to demonstrate
                             // a way to properly stop all tasks and receive a
                             // resumption password (by pressing Ctrl-C).

int password_correct(char *pw, int pw_len)
{
    static const char secret[PASSWORD_MAX_LEN] = "Pw1234";
    return (pw_len == strlen(secret) && memcmp(pw, secret, pw_len) == 0);
}

void *thread_fn(void *arg)
{
    struct bf_pool *pool = arg;
    struct bf_task *task = bf_task_create(pool);

    char password[PASSWORD_MAX_LEN];
    int len;
    while ((len = bf_task_generate_password(password, task))) {
        // Note: printing here will slow down the program a lot.
        // printf("%.*s\n", len, password);

        if (password_correct(password, len)) {
            bf_pool_set_password(pool, password, len);
            break;
        }
    }

    bf_task_destroy(task);
    return NULL;
}

// One of the threads will call this function when receiving the SIGINT signal.
void close_pool(int sig)
{
    bf_pool_close(global_pool);
}

int main(void) {
    char *charset = BF_CHARSET_ALNUM;
    struct bf_pool *pool = bf_pool_create(charset, PASSWORD_MIN_LEN,
        PASSWORD_MAX_LEN, NULL, NULL);
    if (pool == NULL)
        return 1;

    // Make sure the program handles the SIGINT signal (pressing Ctrl-C).
    global_pool = pool;
    signal(SIGINT, close_pool);
    puts("Please wait... (press Ctrl-C to stop)");

    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++)
        pthread_create(&threads[i], NULL, thread_fn, pool);
    for (int i = 0; i < N_THREADS; i++)
        pthread_join(threads[i], NULL);

    switch (bf_pool_get_status(pool)) {
        case BF_PASSWORD_FOUND:
            printf("Password found: %s\n", bf_pool_get_password(pool));
            break;
        case BF_PASSWORD_NOT_FOUND:
            puts("Password not found (all combinations have been tried).");
            break;
        case BF_CLOSED:
            printf("Execution properly stopped. Resumption password: %s\n",
                bf_pool_get_password(pool));
            break;
         case BF_OPEN:
            puts("Execution improperly stopped.");
            break;
    }

    bf_pool_destroy(pool);
}
