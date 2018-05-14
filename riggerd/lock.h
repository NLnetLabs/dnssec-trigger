/**
 * Syncronization primitive to be used by the daemon and script in
 * order serialize execution. So far it should be just 1:1 rewrite of
 * the Python implementation.
 */

#if !defined LOCK_H && defined FWD_ZONES_SUPPORT
#define LOCK_H

#define __LOCK_FILE_DIR "/var/run/dnssec-trigger"
#define __LOCK_FILE_PATH "/var/run/dnssec-trigger/lock"

/** Check lock file presence and acquire the lock. If the file is
 * already locked, block until it is released.
 * TODO: possible errors
 */
void lock_acquire();

/** 
 * Release the lock.
 * TODO: possible errors
 */
void lock_release();

/**
 * Override lock file location. For testing purposes only. The function
 * stores the pointer, it does not copy the content, so the content must
 * live as long as the lock is used.
 */
void lock_override(const char *path, size_t len);

#endif /* LOCK_H */
