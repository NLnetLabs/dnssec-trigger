#include "../config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../riggerd/lock.h"
#include "../riggerd/store.h"
#include "../riggerd/string_buffer.h"
#include "../riggerd/string_list.h"
#include "../riggerd/ubhook.h"

static void string_list_test_remove_at_the_beginning(void **state) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "aaa", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
    (void) state; /* unused */
}

static void string_list_test_remove_in_the_middle(void **state) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "bbb", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
    (void) state; /* unused */
}

static void string_list_test_remove_at_the_end(void **state) {
    struct string_list test;
    string_list_init(&test);
    string_list_push_back(&test, "aaa", 3);
    string_list_push_back(&test, "bbb", 3);
    string_list_push_back(&test, "ccc", 3);
    string_list_remove(&test, "aaa", 3);
    assert_int_equal((int) string_list_length(&test), 2);
    string_list_clear(&test);
    (void) state; /* unused */
}

static void lock_file_call_fn(void **state) {
    lock_override("/tmp/dnssec0123456789", 21);
    lock_acquire();
    lock_release();
    (void) state; /* unused */
}

static void lock_file_check_file_presence(void **state) {
    const char *name = "/tmp/dnssec0002";
    lock_override(name, 15);
    lock_acquire();
    assert_true(access(name, F_OK) == 0);
    lock_release();
    (void) state; /* unused */
}

static void lock_file_check_file_permissions(void **state) {
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
    (void) state; /* unused */
}

static void store_macro_creation(void **state) {
    struct store s = STORE_INIT("test");
    assert_true(strcmp(s.dir, "/var/run/dnssec-trigger") == 0);
    assert_true(strcmp(s.path, "/var/run/dnssec-trigger/test") == 0);
    assert_true(strcmp(s.path_tmp, "/var/run/dnssec-trigger/test.tmp") == 0);
    (void) state; /* unused */
}

static void store_read_file_content(void **state) {
    const char *file_name = "test/servers-list-ipv4";
    struct store s;
    assert_true(access(file_name, R_OK) == 0);

    s = store_init("", "test/servers-list-ipv4", "");

    assert_true(string_list_contains(&s.cache, "1.2.3.4", 8));
    assert_true(string_list_contains(&s.cache, "192.168.168.168", 15));
    assert_true(string_list_length(&s.cache) == 2);

    store_destroy(&s);
    
    (void) state; /* unused */
}

static void store_commit_cache(void **state) {
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
    
    (void) state; /* unused */
}

static void ubhook_list_forwards_test(void **state) {
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
    (void) state; /* unused */
}

static void ubhook_list_local_zones_test(void **state) {
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
    (void) state; /* unused */
}

static void ubhook_add_local_zone(void **state) {
    struct string_buffer exe = string_builder("./test/unbound-control-fake.sh");
    struct string_buffer stat = string_builder("static");
    struct string_buffer zone = string_builder("test");
    int ret = hook_unbound_add_local_zone_inner(exe, zone, stat);
    assert_int_equal(ret, 0);
    (void) state; /* unused */
}

static void ubhook_remove_local_zone(void **state) {
    struct string_buffer exe = string_builder("./test/unbound-control-fake.sh");
    struct string_buffer zone = string_builder("test");
    int ret = hook_unbound_remove_local_zone_inner(exe, zone);
    assert_int_equal(ret, 0);
    (void) state; /* unused */
}

static void nm_list_remove(void **state) {
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
    (void) state; /* unused */
}

static void string_list_extension(void **state) {
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

    (void) state; /* unused */
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(string_list_test_remove_at_the_beginning),
        cmocka_unit_test(string_list_test_remove_in_the_middle),
        cmocka_unit_test(string_list_test_remove_at_the_end),
        cmocka_unit_test(lock_file_call_fn),
        cmocka_unit_test(lock_file_check_file_presence),
        cmocka_unit_test(lock_file_check_file_permissions),
        cmocka_unit_test(store_macro_creation),
        cmocka_unit_test(store_read_file_content),
        cmocka_unit_test(store_commit_cache),
        cmocka_unit_test(ubhook_list_forwards_test),
        cmocka_unit_test(ubhook_list_local_zones_test),
        cmocka_unit_test(ubhook_add_local_zone),
        cmocka_unit_test(ubhook_remove_local_zone),
        cmocka_unit_test(nm_list_remove),
        cmocka_unit_test(string_list_extension)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
