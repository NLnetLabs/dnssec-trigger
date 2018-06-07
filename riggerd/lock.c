#include "config.h"
#include "lock.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const char *LF_PATH = __LOCK_FILE_PATH;
static size_t LF_PATH_LEN = sizeof(__LOCK_FILE_PATH);

static int check_dir = 1;
static int fd = 0;

void lock_acquire() {
    const char* path;
    struct flock f = {
        .l_type=F_WRLCK,
        .l_whence=SEEK_SET,
        .l_start=0,
        .l_len=0
    };
    int ret;
    if (check_dir) {
        // TODO check & create dir
    }
    path = LF_PATH;
    fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC, 0600);
    if (fd == -1) {
        // TODO error handling
        return;
    }
    ret = fcntl(fd, F_SETLKW, f);
    if (ret == -1) {
        // TODO error handling
        return;
    }
}

void lock_release() {
    struct flock f = {
        .l_type=F_UNLCK,
        .l_whence=SEEK_SET,
        .l_start=0,
        .l_len=0
    };
    int ret;
    if (fd == 0) {
        return;
    }
    ret = fcntl(fd, F_SETLKW, f);
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
    check_dir = 0;
}

