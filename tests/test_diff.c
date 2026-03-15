#include "firewallo/diff.h"
#include "firewallo/rule_compiler.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
    } \
} while(0)

/* ── fw_ruleset_diff tests ────────────────────────────────────────── */

static void test_diff_empty_inputs(void)
{
    printf("test_diff_empty_inputs\n");
    char diff[1024];

    /* Both NULL */
    int ret = fw_ruleset_diff(NULL, NULL, diff, sizeof(diff));
    ASSERT(ret == 0, "both NULL returns 0");
    ASSERT(diff[0] == '\0', "both NULL produces empty diff");

    /* Both empty strings */
    ret = fw_ruleset_diff("", "", diff, sizeof(diff));
    ASSERT(ret == 0, "both empty returns 0");
    ASSERT(diff[0] == '\0', "both empty produces empty diff");

    /* Current NULL, proposed empty */
    ret = fw_ruleset_diff(NULL, "", diff, sizeof(diff));
    ASSERT(ret == 0, "NULL/empty returns 0");
    ASSERT(diff[0] == '\0', "NULL/empty produces empty diff");

    /* Current empty, proposed NULL */
    ret = fw_ruleset_diff("", NULL, diff, sizeof(diff));
    ASSERT(ret == 0, "empty/NULL returns 0");
    ASSERT(diff[0] == '\0', "empty/NULL produces empty diff");
}

static void test_diff_identical(void)
{
    printf("test_diff_identical\n");
    char diff[1024];

    const char *text = "line1\nline2\nline3\n";
    int ret = fw_ruleset_diff(text, text, diff, sizeof(diff));
    ASSERT(ret == 0, "identical returns 0");
    /* All lines should be unchanged (prefixed with space) */
    ASSERT(strstr(diff, "  line1\n") != NULL, "line1 unchanged");
    ASSERT(strstr(diff, "  line2\n") != NULL, "line2 unchanged");
    ASSERT(strstr(diff, "  line3\n") != NULL, "line3 unchanged");
    /* No additions or removals */
    ASSERT(strstr(diff, "+ ") == NULL, "no additions");
    ASSERT(strstr(diff, "- ") == NULL, "no removals");
}

static void test_diff_all_added(void)
{
    printf("test_diff_all_added\n");
    char diff[1024];

    int ret = fw_ruleset_diff("", "new1\nnew2\n", diff, sizeof(diff));
    ASSERT(ret == 0, "all added returns 0");
    ASSERT(strstr(diff, "+ new1\n") != NULL, "new1 added");
    ASSERT(strstr(diff, "+ new2\n") != NULL, "new2 added");
}

static void test_diff_all_removed(void)
{
    printf("test_diff_all_removed\n");
    char diff[1024];

    int ret = fw_ruleset_diff("old1\nold2\n", "", diff, sizeof(diff));
    ASSERT(ret == 0, "all removed returns 0");
    ASSERT(strstr(diff, "- old1\n") != NULL, "old1 removed");
    ASSERT(strstr(diff, "- old2\n") != NULL, "old2 removed");
}

static void test_diff_mixed_changes(void)
{
    printf("test_diff_mixed_changes\n");
    char diff[2048];

    const char *current  = "keep1\nremove1\nkeep2\nremove2\n";
    const char *proposed = "keep1\nadd1\nkeep2\nadd2\n";

    int ret = fw_ruleset_diff(current, proposed, diff, sizeof(diff));
    ASSERT(ret == 0, "mixed returns 0");
    ASSERT(strstr(diff, "  keep1\n") != NULL, "keep1 unchanged");
    ASSERT(strstr(diff, "  keep2\n") != NULL, "keep2 unchanged");
    ASSERT(strstr(diff, "- remove1\n") != NULL, "remove1 removed");
    ASSERT(strstr(diff, "- remove2\n") != NULL, "remove2 removed");
    ASSERT(strstr(diff, "+ add1\n") != NULL, "add1 added");
    ASSERT(strstr(diff, "+ add2\n") != NULL, "add2 added");
}

static void test_diff_duplicate_lines(void)
{
    printf("test_diff_duplicate_lines\n");
    char diff[2048];

    /* Current has 2 copies of "dup", proposed has 1 */
    const char *current  = "dup\ndup\nunique\n";
    const char *proposed = "dup\nunique\n";

    int ret = fw_ruleset_diff(current, proposed, diff, sizeof(diff));
    ASSERT(ret == 0, "duplicate returns 0");
    /* First "dup" should match; second should be removed */
    ASSERT(strstr(diff, "  dup\n") != NULL, "first dup matched");
    ASSERT(strstr(diff, "- dup\n") != NULL, "second dup removed");
    ASSERT(strstr(diff, "  unique\n") != NULL, "unique unchanged");
}

static void test_diff_buffer_truncation(void)
{
    printf("test_diff_buffer_truncation\n");
    char diff[32]; /* Very small buffer */

    const char *current  = "a_very_long_line_that_will_fill_the_buffer\n";
    const char *proposed = "another_long_line\n";

    int ret = fw_ruleset_diff(current, proposed, diff, sizeof(diff));
    ASSERT(ret == 0, "truncation returns 0");
    ASSERT(strlen(diff) < sizeof(diff), "output within buffer");
    ASSERT(diff[sizeof(diff) - 1] == '\0', "null terminated");
}

static void test_diff_null_buffer(void)
{
    printf("test_diff_null_buffer\n");
    int ret = fw_ruleset_diff("a\n", "b\n", NULL, 0);
    ASSERT(ret == -1, "NULL buffer returns -1");

    char diff[64];
    ret = fw_ruleset_diff("a\n", "b\n", diff, 0);
    ASSERT(ret == -1, "zero length returns -1");
}

static void test_diff_large_line_count(void)
{
    printf("test_diff_large_line_count\n");
    /* Generate >512 lines to test heap allocation path */
    size_t bufsize = 600 * 8;
    char *text = malloc(bufsize);
    ASSERT(text != NULL, "malloc text");
    if (!text) return;

    size_t off = 0;
    for (int i = 0; i < 600; i++) {
        int n = snprintf(text + off, bufsize - off, "line%d\n", i);
        if (n > 0 && (size_t)n < bufsize - off)
            off += (size_t)n;
    }

    char *diff = malloc(bufsize * 4);
    ASSERT(diff != NULL, "malloc diff");
    if (!diff) { free(text); return; }

    int ret = fw_ruleset_diff(text, text, diff, bufsize * 4);
    ASSERT(ret == 0, "large identical returns 0");
    ASSERT(strstr(diff, "  line0\n") != NULL, "first line present");
    ASSERT(strstr(diff, "  line599\n") != NULL, "last line present");
    ASSERT(strstr(diff, "+ ") == NULL, "no additions in identical");
    ASSERT(strstr(diff, "- ") == NULL, "no removals in identical");

    free(diff);
    free(text);
}

/* ── fw_cmdlist_dump tests ────────────────────────────────────────── */

static void test_cmdlist_dump_empty(void)
{
    printf("test_cmdlist_dump_empty\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);

    char buf[256];
    int ret = fw_cmdlist_dump(&list, buf, sizeof(buf));
    ASSERT(ret == 0, "empty list returns 0 bytes");
    ASSERT(buf[0] == '\0', "empty list produces empty string");

    fw_cmdlist_free(&list);
}

static void test_cmdlist_dump_single(void)
{
    printf("test_cmdlist_dump_single\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);
    fw_cmdlist_append(&list, "echo hello");

    char buf[256];
    int ret = fw_cmdlist_dump(&list, buf, sizeof(buf));
    ASSERT(ret > 0, "single command returns positive");
    ASSERT(strstr(buf, "[000] echo hello\n") != NULL, "single command formatted");

    fw_cmdlist_free(&list);
}

static void test_cmdlist_dump_multiple(void)
{
    printf("test_cmdlist_dump_multiple\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);
    fw_cmdlist_append(&list, "cmd1");
    fw_cmdlist_append(&list, "cmd2");
    fw_cmdlist_append(&list, "cmd3");

    char buf[256];
    int ret = fw_cmdlist_dump(&list, buf, sizeof(buf));
    ASSERT(ret > 0, "multiple commands returns positive");
    ASSERT(strstr(buf, "[000] cmd1\n") != NULL, "cmd1 present");
    ASSERT(strstr(buf, "[001] cmd2\n") != NULL, "cmd2 present");
    ASSERT(strstr(buf, "[002] cmd3\n") != NULL, "cmd3 present");

    fw_cmdlist_free(&list);
}

static void test_cmdlist_dump_truncation(void)
{
    printf("test_cmdlist_dump_truncation\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);
    fw_cmdlist_append(&list, "a_long_command_that_should_get_truncated");
    fw_cmdlist_append(&list, "second_command_wont_fit");

    /* Use a small buffer that can only fit part of the first command */
    char buf[32];
    int ret = fw_cmdlist_dump(&list, buf, sizeof(buf));
    ASSERT(ret >= 0, "truncation does not return error");
    ASSERT(strlen(buf) < sizeof(buf), "output within buffer");
    ASSERT(buf[sizeof(buf) - 1] == '\0', "null terminated");

    fw_cmdlist_free(&list);
}

static void test_cmdlist_dump_null_buffer(void)
{
    printf("test_cmdlist_dump_null_buffer\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);

    int ret = fw_cmdlist_dump(&list, NULL, 0);
    ASSERT(ret == -1, "NULL buffer returns -1");

    char buf[64];
    ret = fw_cmdlist_dump(&list, buf, 0);
    ASSERT(ret == -1, "zero length returns -1");

    fw_cmdlist_free(&list);
}

int main(void)
{
    printf("=== Diff & Dump Tests ===\n\n");

    /* fw_ruleset_diff tests */
    test_diff_empty_inputs();
    test_diff_identical();
    test_diff_all_added();
    test_diff_all_removed();
    test_diff_mixed_changes();
    test_diff_duplicate_lines();
    test_diff_buffer_truncation();
    test_diff_null_buffer();
    test_diff_large_line_count();

    /* fw_cmdlist_dump tests */
    test_cmdlist_dump_empty();
    test_cmdlist_dump_single();
    test_cmdlist_dump_multiple();
    test_cmdlist_dump_truncation();
    test_cmdlist_dump_null_buffer();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
