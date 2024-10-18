// Copyright (c) 2024 hippie68

// Small C library to run brute-force attacks with generated ASCII passwords.
// It employs multi-threading and can resume previous runs.
// Project homepage: https://github.com/hippie68/bf

#ifndef BF_H
#define BF_H

#define BF_CHARSET_DIGITS "0123456789"
#define BF_CHARSET_LOWER "abcdefghijklmnopqrstuvwxyz"
#define BF_CHARSET_UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define BF_CHARSET_ALNUM BF_CHARSET_DIGITS BF_CHARSET_LOWER BF_CHARSET_UPPER

enum bf_pool_status {
    BF_OPEN,
    BF_PASSWORD_FOUND,
    BF_PASSWORD_NOT_FOUND,
    BF_CLOSED,
};

struct bf_pool; // Central data structure that contains all dictionary entries
                // and password generation instructions.
struct bf_task; // Stores information to generate a limited number of unique
                // passwords.

// Creates a dynamically allocated data structure containing information about a
// planned password generation task.
// charset: The full character set used to generate the password.
//          E.g. "0123456789abcdefg..."
// min_len: The password's minimum length.
// max_len: The password's maximum length.
// start (optional): The first password to generate.
// end (optional): The last password to generate.
struct bf_pool *bf_pool_create(const char *charset, int min_len, int max_len,
    const char *start, const char *end);

// Properly frees the data structure's allocated memory.
void bf_pool_destroy(struct bf_pool *pool);

// Changes the number of passcodes bf_task_generate_password() takes from the
// pool. The default number is 4096.
void bf_pool_set_chunk_size(struct bf_pool *pool, int chunk_size);

// Returns the pool's current status.
enum bf_pool_status bf_pool_get_status(struct bf_pool *pool);

// Informs the pool about a found password. This will set the pool's status to
// BF_PASSWORD_FOUND.
// Returns 0 on success.
int bf_pool_set_password(struct bf_pool *pool, char *password, int len);

// Returns the found password, the resumption password, or NULL.
// Which one it is depends on the pool status:
//   BF_PASSWORD_FOUND -> the found password
//   BF_CLOSED -> the resumption password
//   BF_PASSWORD_NOT_FOUND/BF_OPENED -> NULL
// The password is allocated and must be freed manually.
char *bf_pool_get_password(struct bf_pool *pool);

// Sets a pool's status to BF_CLOSED, causing follow-up calls to
// bf_task_generate_password() to return 0.
void bf_pool_close(struct bf_pool *pool);

// Creates a new data structure required by bf_gen() and ties it to an existing
// pool.
struct bf_task *bf_task_create(const struct bf_pool *pool);

// Properly frees the data structure's allocated memory.
void bf_task_destroy(struct bf_task *task);

// Generates a new password and stores it in a buffer which must be large enough
// to store the maximum password length specified in bf_pool_create().
// Returns the generated password's length or 0 when the pool is closed (in
// which case no password was generated).
int bf_task_generate_password(char *buf, struct bf_task *task);

#endif
