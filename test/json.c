#include "../config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../riggerd/fwd_zones.h"
#include "../riggerd/connection_list.h"
#include "../riggerd/string_list.h"
#include "../riggerd/string_buffer.h"
#include "../vendor/ccan/json/json.h"

char *json = 
"{"
"\n    \"connections\": ["
"\n        {"
"\n            \"default\": false,"
"\n            \"servers\": ["
"\n                \"10.2.0.4\","
"\n                \"10.9.2.4\","
"\n                \"10.2.0.6\""
"\n            ],"
"\n            \"type\": \"wifi\","
"\n            \"zones\": ["
"\n                \"example.com\""
"\n            ]"
"\n        },"
"\n        {"
"\n            \"default\": true,"
"\n            \"servers\": ["
"\n                \"10.60.0.16\","
"\n                \"10.67.5.56\""
"\n            ],"
"\n            \"type\": \"other\","
"\n            \"zones\": ["
"\n                \"brno.example.com\","
"\n                \"prague.example.com\","
"\n                \"finance.prague.example.com\","
"\n                \"laboratory.prague.example.com\","
"\n                \"lab2.prague.example.com\""
"\n            ]"
"\n        },"
"\n        {"
"\n            \"default\": false,"
"\n            \"servers\": ["
"\n                \"10.148.8.37\","
"\n                \"10.145.245.24\""
"\n            ],"
"\n            \"type\": \"vpn\","
"\n            \"zones\": ["
"\n                \"example.com\""
"\n            ]"
"\n        }"
"\n    ]"
"\n}\n";

#define assert_true(x) assert_true_fp((x), __FILE__, __LINE__)
static void assert_true_fp(int x, const char* f, int l)
{
	assert(x);
	if(!x) {
		printf("%s:%d: assert_true failed\n", f, l);
		exit(1);
	}
}

/* A test case that does nothing and succeeds. */
static void null_test_success(void) {
}

static void load_json_into_list_and_test_length(void) {
    struct nm_connection_list l = yield_connections_from_json(json);
    assert_true(nm_connection_list_length(&l) == 3);
    nm_connection_list_clear(&l);
}

static void filter_connection_list_and_test_length0(void) {
    struct nm_connection_list l = yield_connections_from_json(json);
    struct nm_connection_list l2 = nm_connection_list_filter(&l, 0);
    assert_true(nm_connection_list_length(&l2) == 3);
    nm_connection_list_clear(&l2);
    nm_connection_list_clear(&l);
}

static void filter_connection_list_and_test_length1(void) {
    struct nm_connection_list l = yield_connections_from_json(json);
    struct nm_connection_list l2 = nm_connection_list_filter(&l, 1, &nm_connection_filter_type_vpn);
    assert_true(nm_connection_list_length(&l2) == 1);
    nm_connection_list_clear(&l2);
    nm_connection_list_clear(&l);
}

int main() {
    // printf("Test json parser:\n%s\n", json);
    // struct nm_connection_list l = yield_connections_from_json(json);
    // nm_connection_list_dbg_print(&l);
    // printf("Length is: %zu\n", nm_connection_list_length(&l));
    // struct nm_connection_list l2 = nm_connection_list_filter(&l, 0);
    // printf("Length is: %zu\n", nm_connection_list_length(&l2));
    // struct nm_connection_list l3 = nm_connection_list_filter(&l, 1, &nm_connection_filter_type_vpn);
    // printf("Length is: %zu\n", nm_connection_list_length(&l3));
    // struct nm_connection_list l4 = nm_connection_list_filter(&l, 1, &nm_connection_filter_default);
    // printf("Length is: %zu\n", nm_connection_list_length(&l4));
    // struct nm_connection_list l5 = nm_connection_list_filter(&l, 2, &nm_connection_filter_type_other, &nm_connection_filter_default);
    // printf("Length is: %zu\n", nm_connection_list_length(&l5));
    // struct nm_connection_list l6 = nm_connection_list_filter(&l, 2, &nm_connection_filter_type_vpn, &nm_connection_filter_default);
    // printf("Length is: %zu\n", nm_connection_list_length(&l6));

    // {
    // struct string_buffer buffer = nm_connection_list_sprint_servers(&l);
    // printf("Servers: %s\n", buffer.string);
    // free(buffer.string);
    // }

    // char *buffer = calloc_or_die(1000);
    // string_list_sprint(&l.first->self->servers, buffer, 1000);
    // printf("%s\n", buffer);
    // free(buffer);
    // nm_connection_list_clear(&l);

    /* run tests */
    printf("null_test_success: ");
    null_test_success();
    printf("OK\n");

    printf("load_json_into_list_and_test_length: ");
    load_json_into_list_and_test_length();
    printf("OK\n");

    printf("filter_connection_list_and_test_length0: ");
    filter_connection_list_and_test_length0();
    printf("OK\n");

    printf("filter_connection_list_and_test_length1: ");
    filter_connection_list_and_test_length1();
    printf("OK\n");

    printf("\n");
    printf("OK\n");
    return 0;
}
