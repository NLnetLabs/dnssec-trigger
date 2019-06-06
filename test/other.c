#include "../config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../riggerd/lock.h"
#include "../riggerd/store.h"
#include "../riggerd/string_buffer.h"
#include "../riggerd/string_list.h"
#include "../riggerd/ubhook.h"

#define assert_true(x) assert_true_fp((x), __FILE__, __LINE__)
static void assert_true_fp(int x, const char* f, int l)
{
	assert(x);
	if(!x) {
		printf("%s:%d: assert_true failed\n", f, l);
		exit(1);
	}
}

#define assert_false(x) assert_false_fp((x), __FILE__, __LINE__)
static void assert_false_fp(int x, const char* f, int l)
{
	assert(!x);
	if(x) {
		printf("%s:%d: assert_false failed\n", f, l);
		exit(1);
	}
}

#define assert_int_equal(x, y) assert_int_equal_fp((x), (y), __FILE__, __LINE__)
static void assert_int_equal_fp(int x, int y, const char* f, int l)
{
	assert(x == y);
	if(x != y) {
		printf("%s:%d: assert_int_equal(%d, %d) failed\n", f, l, x, y);
		exit(1);
	}
}


static void string_list_test_remove_at_the_beginning(void) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "aaa", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
}

static void string_list_test_remove_in_the_middle(void) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "bbb", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
}

static void string_list_test_remove_at_the_end(void) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "aaa", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
}

static void lock_file_call_fn(void) {
    lock_override("/tmp/dnssec0123456789", 21);
    lock_acquire();
    lock_release();
}

static void lock_file_check_file_presence(void) {
    const char *name = "/tmp/dnssec0002";
    lock_override(name, 15);
    lock_acquire();
    assert_true(access(name, F_OK) == 0);
    lock_release();
}

static void lock_file_check_file_permissions(void) {
    const char *name = "/tmp/dnssec0002";
    lock_override(name, 15);
    lock_acquire();
    assert_true(access(name, R_OK) == 0);
    assert_true(access(name, W_OK) == 0);
    assert_true(access(name, X_OK) == -1);
    // TODO: check that the file is indeed locked
    lock_release();
    assert_true(access(name, R_OK) == 0);
    assert_true(access(name, W_OK) == 0);
    assert_true(access(name, X_OK) == -1);
}

static void store_macro_creation(void) {
    struct store s = STORE_INIT("test");
    assert_true(strcmp(s.dir, "/var/run/dnssec-trigger") == 0);
    assert_true(strcmp(s.path, "/var/run/dnssec-trigger/test") == 0);
    assert_true(strcmp(s.path_tmp, "/var/run/dnssec-trigger/test.tmp") == 0);
}

static void store_read_file_content(void) {
    const char *file_name = "test/servers-list-ipv4";
    struct store s;
    assert_true(access(file_name, R_OK) == 0);

    s = store_init("", "test/servers-list-ipv4", "");

    assert_true(string_list_contains(&s.cache, "1.2.3.4", 8));
    assert_true(string_list_contains(&s.cache, "192.168.168.168", 15));
    assert_true(string_list_length(&s.cache) == 2);

    store_destroy(&s);
}

static void store_commit_cache(void) {
    const char *dir_name = "test/tmp";
    const char *file_name = "test/tmp/commit-cache";
    const char *tmp_file_name = "test/tmp/commit-cache.tmp";
    struct string_buffer sb = string_builder("5.6.7.8");
    struct string_buffer sb2 = string_builder("9.10.11.12");

    // write to file
    {
        struct store s = store_init(dir_name, file_name, tmp_file_name);
        string_list_clear(&s.cache);
        string_list_push_back(&s.cache, sb.string, sb.length);
        string_list_push_back(&s.cache, sb2.string, sb2.length);
        store_commit(&s);
        store_destroy(&s);
    }

    // read from file
    {
        struct store s = store_init(dir_name, file_name, tmp_file_name);
        assert_true(string_list_contains(&s.cache, sb.string, sb.length));
        assert_true(string_list_contains(&s.cache, sb2.string, sb2.length));
        assert_true(string_list_length(&s.cache) == 2);
        store_destroy(&s);
    }
}

static void ubhook_list_forwards_test(void) {
    FILE *fp;
    struct nm_connection_list ret;
    struct string_buffer zone = string_builder("ny.mylovelycorporate.io.");
    struct string_buffer zone2 = string_builder(".");

    fp = fopen("test/list_forwards_example", "r");
    ret = hook_unbound_list_forwards_inner(NULL, fp);
    //nm_connection_list_dbg_eprint(&ret);
    assert_true(nm_connection_list_contains_zone(&ret, zone.string, zone.length));
    assert_true(nm_connection_list_contains_zone(&ret, zone2.string, zone2.length));
    nm_connection_list_clear(&ret);
    fclose(fp);
}

static void ubhook_list_local_zones_test(void) {
    FILE *fp;
    struct string_buffer zone = string_builder("test.");
    struct string_buffer zone2 = string_builder("invalid.");
    struct string_list ret;

    fp = fopen("test/list_local_zones_example", "r");
    if (!fp)
        assert_false(true);

    ret = hook_unbound_list_local_zones_inner(NULL, fp);
    //string_list_dbg_eprint(&ret);
    assert_true(string_list_contains(&ret, zone.string, zone.length));
    assert_true(string_list_contains(&ret, zone2.string, zone2.length));
    string_list_clear(&ret);

    fclose(fp);
}

static void ubhook_add_local_zone(void) {
    struct string_buffer exe = string_builder("./test/unbound-control-fake.sh");
    struct string_buffer stat = string_builder("static");
    struct string_buffer zone = string_builder("test");
    int ret = hook_unbound_add_local_zone_inner(exe, zone, stat);
    assert_int_equal(ret, 0);
}

static void ubhook_remove_local_zone(void) {
    struct string_buffer exe = string_builder("./test/unbound-control-fake.sh");
    struct string_buffer zone = string_builder("test");
    int ret = hook_unbound_remove_local_zone_inner(exe, zone);
    assert_int_equal(ret, 0);
}

static void nm_list_remove(void) {
    FILE *fp;
    struct nm_connection_list ret;
    struct string_buffer zone = string_builder("ny.mylovelycorporate.io.");
    struct string_buffer zone2 = string_builder(".");

    fp = fopen("test/list_forwards_example", "r");
    ret = hook_unbound_list_forwards_inner(NULL, fp);
    //nm_connection_list_dbg_eprint(&ret);

    assert_true(nm_connection_list_contains_zone(&ret, zone.string, zone.length));
    nm_connection_list_remove(&ret, zone.string, zone.length);
    assert_false(nm_connection_list_contains_zone(&ret, zone.string, zone.length));

    assert_true(nm_connection_list_contains_zone(&ret, zone2.string, zone2.length));
    nm_connection_list_remove(&ret, zone2.string, zone2.length);
    assert_false(nm_connection_list_contains_zone(&ret, zone2.string, zone2.length));

    nm_connection_list_clear(&ret);
    fclose(fp);
}

static void string_list_extension(void) {
    struct string_list new;

    /* You need to run this test with address sanitizer, otherwise it does nothing */

    string_list_init(&new);
    string_list_push_back(&new, "aaa", 3);
    new.first->extension = malloc(666);
    string_list_remove(&new, "aaa", 3);
    string_list_clear(&new);

    string_list_init(&new);
    string_list_push_back(&new, "aaa", 3);
    new.first->extension = malloc(666);
    string_list_clear(&new);
}

int main() {
    printf("string_list_test_remove_at_the_beginning: ");
    string_list_test_remove_at_the_beginning();
    printf("OK\n");

    printf("string_list_test_remove_in_the_middle: ");
    string_list_test_remove_in_the_middle();
    printf("OK\n");

    printf("string_list_test_remove_at_the_end: ");
    string_list_test_remove_at_the_end();
    printf("OK\n");

    printf("lock_file_call_fn: ");
    lock_file_call_fn();
    printf("OK\n");

    printf("lock_file_check_file_presence: ");
    lock_file_check_file_presence();
    printf("OK\n");

    printf("lock_file_check_file_permissions: ");
    lock_file_check_file_permissions();
    printf("OK\n");

    printf("store_macro_creation: ");
    store_macro_creation();
    printf("OK\n");

    printf("store_read_file_content: ");
    store_read_file_content();
    printf("OK\n");

    printf("store_commit_cache: ");
    store_commit_cache();
    printf("OK\n");

    printf("ubhook_list_forwards_test: ");
    ubhook_list_forwards_test();
    printf("OK\n");

    printf("ubhook_list_local_zones_test: ");
    ubhook_list_local_zones_test();
    printf("OK\n");

    printf("ubhook_add_local_zone: ");
    ubhook_add_local_zone();
    printf("OK\n");

    printf("ubhook_remove_local_zone: ");
    ubhook_remove_local_zone();
    printf("OK\n");

    printf("nm_list_remove: ");
    nm_list_remove();
    printf("OK\n");

    printf("string_list_extension: ");
    string_list_extension();
    printf("OK\n");

    printf("\n");
    printf("OK\n");
    return 0;
}
