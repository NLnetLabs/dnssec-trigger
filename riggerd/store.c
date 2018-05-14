#include <string.h>
#include <stdio.h>

#include "config.h"
#include "store.h"
#include "string_list.h"

struct store store_init(const char *dir, const char *full_path, const char *full_path_tmp) {
    struct string_list cache;
    string_list_init(&cache);
    struct store s = {
        .dir = dir,
        .path = full_path,
        .path_tmp = full_path_tmp,
        .cache = cache
    };
    // Read cache into the string list??
    FILE *fp = fopen(full_path, "r");
    if (fp == NULL) {
        // TODO: log debug output
        return s;
    }
    size_t line_len = 512;
    ssize_t read_len;
    char *line = (char *)calloc_or_die(line_len);
    memset(line, 0, line_len);
    while ((read_len = getline(&line, &line_len, fp) != -1)){
        // Hack: the getline function return 1 on any output, I have no idea how to fix it
        // so I will just workaround it
        size_t string_length = strnlen(line, line_len);
        for (size_t i=0; i<string_length; ++i) {
            if (line[i] == '\n') {
                line[i] = '\0';
            }
        }
        string_length = strnlen(line, line_len);
        string_list_push_back(&s.cache, line, string_length);
        memset(line, 0, line_len);
    }
    free(line);
    fclose(fp);
    return s;
}

int store_commit(const struct store *self) {
    // Open the tmp file
    FILE *fp = fopen(self->path_tmp, "w");
    if (fp == NULL) {
        return -1;
    }
    // Write its content
    FOR_EACH_STRING_IN_LIST(iter, &self->cache) {
        fprintf(fp, "%s\n", iter->string);
    }
    // Close it
    fclose(fp);
    return rename(self->path_tmp, self->path);
}

void store_destroy(struct store *self) {
    string_list_clear(&self->cache);
}

void store_remove(struct store *self, char *string, size_t len) {
    string_list_remove(&self->cache, string, len);
}

void store_add(struct store *self, char *string, size_t len) {
    if (!string_list_contains(&self->cache, string, len)) {
        string_list_push_back(&self->cache, string, len);
    }
}

bool store_contains(struct store *self, char *string, size_t len) {
    return string_list_contains(&(self->cache), string, len);
}