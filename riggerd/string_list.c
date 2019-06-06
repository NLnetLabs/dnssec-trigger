#include "config.h"
#include "string_list.h"

#ifdef FWD_ZONES_SUPPORT

#include "log.h"
#include <string.h>
#include <stdlib.h>


void string_list_init(struct string_list* list)
{
	if (NULL == list)
		return;

	list->first = NULL;
}

void string_list_clear(struct string_list* list)
{
	struct string_entry* iter;
	if (NULL == list)
		return;

	iter = list->first;
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
	/* ENOTREACH */
	return NULL;
}

void string_list_push_back(struct string_list* list, const char* new_value, const size_t buffer_size)
{
	size_t len;
	struct string_entry** node;
	if (NULL == list || NULL == new_value || buffer_size == 0) {
		return;
	}

	len = strnlen(new_value, buffer_size);
	node = &list->first;

	while (NULL != *node) {
		node = &(*node)->next;
	}

	*node = (struct string_entry*) calloc_or_die(sizeof(struct string_entry));
	(*node)->extension = NULL;
	(*node)->next = NULL;
	(*node)->length = len;
	(*node)->string = strdup(new_value);
	if(!(*node)->string) fatal_exit("malloc failure");
}

int string_list_contains(const struct string_list* list, const char* value, const size_t buffer_size)
{
	size_t len;
	struct string_entry* iter;
	if (NULL == list || NULL == value || buffer_size == 0) {
		return 0;
	}

	len = strnlen(value, buffer_size);

	/*
	 * Iterate through the whole list
	 */
	for (iter = list->first; NULL != iter; iter = iter->next) {
		/*
		 * We already know size of both buffers, so we take advantage of that
		 * and also of short-cut evaluation.
		 */
		if (iter->string && len == iter->length && strncmp(iter->string, value, len) == 0) {
			return 1;
		}
	}
	return 0;
}

void string_list_duplicate(const struct string_list* original, struct string_list *copy) {
	struct string_entry* iter;
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
	struct string_entry* iter;
	if (NULL == original || NULL == append) {
		return;
	}
	FOR_EACH_STRING_IN_LIST(iter, append) {
		string_list_push_back(original, iter->string, iter->length);
	}
}

void string_list_remove(struct string_list* list, const char* value, const size_t buffer_size) {
	size_t len;
	struct string_entry* prev;
	struct string_entry* iter;
	int first;
	if (NULL == list || NULL == value || buffer_size == 0) {
		return;
	}

	len = strnlen(value, buffer_size);

	/*
	 * Iterate through the whole list
	 */
	prev = NULL;
	first = 1;
	for (iter = list->first; NULL != iter; prev = iter, iter = iter->next) {
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
		first = 0;
	}
}

size_t string_list_length(const struct string_list* list)
{
	size_t len;
	struct string_entry* iter;
	if (NULL == list)
		return 0;

	len = 0;
	iter = list->first;
	while (NULL != iter) {
		iter = iter->next;
		++len;
	}
	return len;
}

int string_list_is_equal(const struct string_list* l1, const struct string_list* l2)
{
	struct string_entry* iter;
	if (NULL == l1 && NULL == l2)
		return 1;

	if ((NULL == l1 && NULL != l2) || (NULL == l2 && NULL != l1))
		return 0;

	// Assumption: Every value is unique
	if (string_list_length(l1) != string_list_length(l2)) {
		return 0;
	}

	for (iter = l1->first; NULL != iter; iter = iter->next) {
		if (!string_list_contains(l2, iter->string, iter->length))
			return 0;
	}

	return 1;
}

void string_list_dbg_print_inner(const struct string_list* list, FILE *fp)
{
    struct string_entry *iter;
    if (NULL == list)
        return;

    iter = list->first;
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
    size_t orig;
    struct string_entry *iter;
    if (NULL == buffer || 0 == len)
        return 0;
    buffer[0] = 0;
    if(list == NULL)
	    return 0;

    orig = len;

    iter = list->first;
    while(NULL != iter) {
	int print_ret;
        // print into the buffer
        if (iter->length+1+1 > len) {
            // This address wouldn't fit into the buffer
            return -1;
        }

        print_ret = snprintf(buffer, len, "%s ", iter->string);
        if (print_ret >= (int)len || print_ret < 0)
        {
            // This should never happen because we have already checked the length
            return -1;
        }
        buffer += print_ret;
        len -= print_ret;

        iter = iter->next;
    }

    if (orig < len)
        log_err("string_list_sprint: arithmetic error");

    return orig-len;
}

#endif /* FWD_ZONES_SUPPORT */
