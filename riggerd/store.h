/**
 * Persistent storage in /var/run/dnssec-trigger/ directory.
 */

#if !defined STORE_H && defined FWD_ZONES_SUPPORT
#define STORE_H

#include "string_list.h"

/* Directory used for storage of all files available through
 * this module. */
#define STORE_BASE_DIR "/var/run/dnssec-trigger"
/* Concatenate file name with the base directory. */
#define STORE_PATH(NAME) (STORE_BASE_DIR "/" NAME)
/* Concatenate file name with the base directory and append ".tmp"
 * to the path. As the name suggests this file will be stored
 * temporarily and eventually it will replace the normal file. */
#define STORE_PATH_TMP(NAME) (STORE_BASE_DIR "/" NAME ".tmp")

struct store {
    const char *dir;
    const char *path;
    const char *path_tmp;
    struct string_list cache;
};

/**
 * Create the store structure from directory name and absolute path of the file used for
 * persistent storage. The last argument is an absolute path of the file with tmp suffix.
 */
struct store store_init(const char *dir, const char *full_path, const char *full_path_tmp);

/**
 * Write the cache back to disk into file specified in the 'path' member
 */
int store_commit(const struct store *self);

/**
 * Destroy cache
 */
void store_destroy(struct store *self);

/*
 * Remove a string from the cache
 */
void store_remove(struct store *self, char *string, size_t len);

/*
 * Push a string into the cache
 */
void store_add(struct store *self, char *string, size_t len);


/*
 * Return true if the cache contains the string
 */
bool store_contains(struct store *self, char *string, size_t len);

/**
 * Macro that wraps up the init function in order to reduce typing.
 */
#define STORE_INIT(NAME) store_init((STORE_BASE_DIR),(STORE_PATH(NAME)),(STORE_PATH_TMP(NAME)))

#endif /* STORE_H */
