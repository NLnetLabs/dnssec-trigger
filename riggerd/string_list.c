/*
FIXME:
usr/include/libpng16 -o build/riggerd/string_list.o -c riggerd/string_list.c
riggerd/string_list.c:40:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
riggerd/string_list.c:158:17: warning: comparison of unsigned expression < 0 is always false [-Wtautological-compare]
    if (orig-len<0)
        ~~~~~~~~^~
2 warnings generated.
 */

#include "config.h"
#include "string_list.h"

#ifdef FWD_ZONES_SUPPORT

#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


void string_list_init(struct string_list* list)
{
	if (NULL == list)
		return;

	list->first = NULL;
}

void string_list_clear(struct string_list* list)
{
	if (NULL == list)
		return;

	struct string_entry* iter = list->first;
	while (NULL != iter) {
		struct string_entry* node = iter;
		iter = node->next;
		free(node->string);
		if (NULL != node->extension) {
			free(node->extension);
		}
		free(node);
	}
	list->first = NULL;
}

void* calloc_or_die(size_t size) {
	void* mem = calloc(1, size);
	if (NULL == mem){
		fatal_exit("out of memory");
	} else {
		return mem;
	}
	// Cannot reach this point
	return NULL;
}

void string_list_push_back(struct string_list* list, const char* new_value, const size_t buffer_size)
{
	if (NULL == list || NULL == new_value || buffer_size == 0) {
			return;
	}

	size_t len = strnlen(new_value, buffer_size);
	struct string_entry** node = &list->first;

	while (NULL != *node) {
		node = &(*node)->next;
	}

	*node = (struct string_entry*) calloc_or_die(sizeof(struct string_entry));
	(*node)->extension = NULL;
	(*node)->length = len;
	(*node)->string = (char*) calloc_or_die(len+1);
	strncpy((*node)->string, new_value, len);
}

bool string_list_contains(const struct string_list* list, const char* value, const size_t buffer_size)
{
	if (NULL == list || NULL == value || buffer_size == 0) {
		return false;
	}

	size_t len = strnlen(value, buffer_size);

	/*
	 * Iterate through the whole list
	 */
	for (struct string_entry* iter = list->first; NULL != iter; iter = iter->next) {
		/*
		 * We already know size of both buffers, so we take advantage of that
		 * and also of short-cut evaluation.
		 */
		if (len == iter->length && strncmp(iter->string, value, len) == 0) {
			return true;
		}
	}
	return false;
}

void string_list_diplicate(const struct string_list* original, struct string_list *copy) {
	if (NULL == original || NULL == copy) {
		return;
	}

	string_list_clear(copy);
	string_list_init(copy);

	FOR_EACH_STRING_IN_LIST(iter, original) {
		string_list_push_back(copy, iter->string, iter->length);
	}
}

void string_list_copy_and_append(struct string_list* original, struct string_list *append) {
	if (NULL == original || NULL == append) {
		return;
	}
	FOR_EACH_STRING_IN_LIST(iter, append) {
		string_list_push_back(original, iter->string, iter->length);
	}
}

void string_list_remove(struct string_list* list, const char* value, const size_t buffer_size) {
	if (NULL == list || NULL == value || buffer_size == 0) {
		return;
	}

	size_t len = strnlen(value, buffer_size);

	/*
	 * Iterate through the whole list
	 */
	struct string_entry* prev = NULL;
	bool first = true;
	for (struct string_entry* iter = list->first; NULL != iter; prev = iter, iter = iter->next) {
		/*
		 * We already know size of both buffers, so we take advantage of that
		 * and also of short-cut evaluation.
		 */
		if (len == iter->length && strncmp(iter->string, value, len) == 0) {
			// Remove the item
			if (first) {
				list->first = iter->next;
			} else {
				prev->next = iter->next;
			}
			free(iter->string);
			if (NULL != iter->extension) {
				free(iter->extension);
			}
			free(iter);
			return;
		}
		first = false;
	}
}

size_t string_list_length(const struct string_list* list)
{
	if (NULL == list)
		return 0;

	size_t len = 0;
	struct string_entry* iter = list->first;
	while (NULL != iter) {
		iter = iter->next;
		++len;
	}
	return len;
}

bool string_list_is_equal(const struct string_list* l1, const struct string_list* l2)
{
	if (NULL == l1 && NULL == l2)
		return true;

	if ((NULL == l1 && NULL != l2) || (NULL == l2 && NULL != l1))
		return false;

	// Assumption: Every value is unique
	if (string_list_length(l1) != string_list_length(l2)) {
		return false;
	}

	for (struct string_entry* iter = l1->first; NULL != iter; iter = iter->next) {
		if (!string_list_contains(l2, iter->string, iter->length))
			return false;
	}

	return true;
}

void string_list_dbg_print_inner(const struct string_list* list, FILE *fp)
{
    if (NULL == list)
        return;

	//fprintf(stderr, "DBG: %d, %d, %zu\n", list, list->first, list->first->length);

    struct string_entry *iter = list->first;
    while(NULL != iter) {
        fprintf(fp, "%s, ", iter->string);
        iter = iter->next;
    }
}

void string_list_dbg_print(const struct string_list* list)
{
    string_list_dbg_print_inner(list, stdout);
}

void string_list_dbg_eprint(const struct string_list* list){
	string_list_dbg_print_inner(list, stderr);
}

int string_list_sprint(const struct string_list* list, char *buffer, size_t len)
{
    if (NULL == list || NULL == buffer || 0 == len)
        return 0;

    size_t orig = len;

    struct string_entry *iter = list->first;
    while(NULL != iter) {
        // TODO: print into the buffer
        if (iter->length > len) {
            // This address wouldn't fit into the buffer
            return -1;
        }

        int print_ret = snprintf(buffer, len, "%s ", iter->string);
        if (print_ret >= len || print_ret < 0)
        {
            // This should never happen because we have already checked the length
            return -1;
        }
        buffer += print_ret;
        len -= print_ret;

        iter = iter->next;
    }

    if (orig-len<0)
        log_err("string_list_sprint: arithmetic error");

    return orig-len;
}

#endif
