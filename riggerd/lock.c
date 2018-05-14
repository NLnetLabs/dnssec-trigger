#include "config.h"
#include "lock.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static char *LF_PATH = __LOCK_FILE_PATH;
static size_t LF_PATH_LEN = sizeof(__LOCK_FILE_PATH);

static char *LF_DIR = __LOCK_FILE_DIR;
static size_t LF_DIR_LEN = sizeof(__LOCK_FILE_DIR);

static bool check_dir = true;
static int fd = 0;

void lock_acquire() {
    if (check_dir) {
        // TODO check & create dir
    }
    const char* path = LF_PATH;
    fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC, 0600);
    if (fd == -1) {
        // TODO error handling
        return;
    }
    struct flock f = {
        .l_type=F_WRLCK,
        .l_whence=SEEK_SET,
        .l_start=0,
        .l_len=0
    };
    int ret = fcntl(fd, F_SETLKW, f);
    if (ret == -1) {
        // TODO error handling
        return;
    }
}

void lock_release() {
    if (fd == 0) {
        return;
    }
    struct flock f = {
        .l_type=F_UNLCK,
        .l_whence=SEEK_SET,
        .l_start=0,
        .l_len=0
    };
    int ret = fcntl(fd, F_SETLKW, f);
    if (ret == -1) {
        // TODO error handling
        return;
    }
    
    close(fd);
    fd = 0;
}

void lock_override(const char *path, size_t len) {
    LF_PATH = path;
    LF_PATH_LEN = len;
    check_dir = false;
}

