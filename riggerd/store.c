#include "config.h"
#include <string.h>
#include <stdio.h>

#include "store.h"
#include "string_list.h"
#include "log.h"

struct store store_init(const char *dir, const char *full_path, const char *full_path_tmp) {
    struct string_list cache;
    struct store s;
    FILE *fp;
    size_t line_len = 512;
    ssize_t read_len;
    char* line;
    string_list_init(&cache);
    s.dir = dir,
    s.path = full_path,
    s.path_tmp = full_path_tmp,
    s.cache = cache;
    // Read cache into the string list
    fp = fopen(full_path, "r");
    if (fp == NULL) {
	log_err("cannot open %s: %s", full_path, strerror(errno));
        return s;
    }
    line = (char *)calloc_or_die(line_len);
    memset(line, 0, line_len);
    while ((read_len = getline(&line, &line_len, fp)) != -1){
	if(read_len > 0 && line[read_len-1]=='\n')
		line[--read_len] = 0; /* remove \n */
        string_list_push_back(&s.cache, line, read_len);
        memset(line, 0, line_len);
    }
    if(ferror(fp)) {
	    log_err("error reading %s: %s", full_path, strerror(errno));
    }
    free(line);
    fclose(fp);
    return s;
}

int store_commit(const struct store *self) {
    // Open the tmp file
    FILE *fp = fopen(self->path_tmp, "w");
    if (fp == NULL) {
	log_err("cannot open %s for write: %s", self->path_tmp, strerror(errno));
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
    return string_list_contains(&self->cache, string, len);
}
