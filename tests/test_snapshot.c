#include "firewallo/snapshot.h"
#include "firewallo/config.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

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

#define TEST_SNAP_DIR  "/tmp/firewallo_test_snapshots"
#define TEST_CONFIG    "/tmp/firewallo_test_config.json"

/* Clean up test directories */
static void cleanup(void)
{
    /* Remove snapshot files */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", TEST_SNAP_DIR, TEST_CONFIG);
    (void)system(cmd);
}

/* Create a minimal test config */
static void create_test_config(void)
{
    fw_config_t cfg;
    fw_config_init(&cfg);
    fw_strlcpy(cfg.lan_ifs[0], "eth0", sizeof(cfg.lan_ifs[0]));
    cfg.lan_if_count = 1;
    fw_strlcpy(cfg.wan_ifs[0], "eth1", sizeof(cfg.wan_ifs[0]));
    cfg.wan_if_count = 1;
    fw_config_save(TEST_CONFIG, &cfg);
}

static void test_create_snapshot(void)
{
    printf("test_create_snapshot\n");

    fw_snapshot_info_t info;
    int ret = fw_snapshot_create(TEST_SNAP_DIR, TEST_CONFIG,
                                 "Test snapshot", "cli", &info);
    ASSERT(ret == 0, "snapshot create succeeds");
    ASSERT(info.id[0] != '\0', "snapshot ID is non-empty");
    ASSERT(strcmp(info.source, "cli") == 0, "source is cli");
    ASSERT(strcmp(info.description, "Test snapshot") == 0, "description matches");
    ASSERT(info.created_at[0] != '\0', "created_at is non-empty");
}

static void test_list_snapshots(void)
{
    printf("test_list_snapshots\n");

    fw_snapshot_info_t infos[FW_MAX_SNAPSHOTS];
    int count = fw_snapshot_list(TEST_SNAP_DIR, infos, FW_MAX_SNAPSHOTS);
    ASSERT(count >= 1, "at least 1 snapshot listed");
    ASSERT(infos[0].id[0] != '\0', "first snapshot has ID");
}

static void test_load_snapshot(void)
{
    printf("test_load_snapshot\n");

    /* Get the ID of the first snapshot */
    fw_snapshot_info_t infos[FW_MAX_SNAPSHOTS];
    int count = fw_snapshot_list(TEST_SNAP_DIR, infos, FW_MAX_SNAPSHOTS);
    ASSERT(count >= 1, "has snapshots to load");

    if (count >= 1) {
        size_t len;
        char *data = fw_snapshot_load(TEST_SNAP_DIR, infos[0].id, &len);
        ASSERT(data != NULL, "snapshot data loaded");
        ASSERT(len > 0, "snapshot data is non-empty");
        if (data) {
            /* Verify it's valid JSON with "version" key */
            ASSERT(strstr(data, "version") != NULL, "contains version key");
            free(data);
        }
    }
}

static void test_diff_snapshot(void)
{
    printf("test_diff_snapshot\n");

    fw_snapshot_info_t infos[FW_MAX_SNAPSHOTS];
    int count = fw_snapshot_list(TEST_SNAP_DIR, infos, FW_MAX_SNAPSHOTS);
    ASSERT(count >= 1, "has snapshots to diff");

    if (count >= 1) {
        char *diff = fw_snapshot_diff(TEST_SNAP_DIR, infos[0].id, TEST_CONFIG);
        ASSERT(diff != NULL, "diff result is non-null");
        if (diff) {
            ASSERT(strstr(diff, "snapshot_id") != NULL, "diff has snapshot_id");
            ASSERT(strstr(diff, "change_count") != NULL, "diff has change_count");
            /* Same config, so 0 changes */
            ASSERT(strstr(diff, "\"change_count\": 0") != NULL ||
                   strstr(diff, "\"change_count\":0") != NULL,
                   "no changes when same config");
            free(diff);
        }
    }
}

static void test_diff_after_change(void)
{
    printf("test_diff_after_change\n");

    fw_snapshot_info_t infos[FW_MAX_SNAPSHOTS];
    int count = fw_snapshot_list(TEST_SNAP_DIR, infos, FW_MAX_SNAPSHOTS);
    ASSERT(count >= 1, "has snapshots");

    if (count >= 1) {
        /* Modify the config */
        fw_config_t cfg;
        char err[256];
        fw_config_load(TEST_CONFIG, &cfg, err, sizeof(err));
        fw_strlcpy(cfg.version, "3.0.0", sizeof(cfg.version));
        cfg.dns_count = 1;
        fw_strlcpy(cfg.dns[0], "8.8.8.8", sizeof(cfg.dns[0]));
        fw_config_save(TEST_CONFIG, &cfg);

        char *diff = fw_snapshot_diff(TEST_SNAP_DIR, infos[0].id, TEST_CONFIG);
        ASSERT(diff != NULL, "diff after change is non-null");
        if (diff) {
            /* Should have changes now */
            ASSERT(strstr(diff, "modified") != NULL, "has modified entries");
            free(diff);
        }

        /* Restore original config */
        create_test_config();
    }
}

static void test_delete_snapshot(void)
{
    printf("test_delete_snapshot\n");

    /* Create a snapshot just to delete it */
    fw_snapshot_info_t info;
    fw_snapshot_create(TEST_SNAP_DIR, TEST_CONFIG, "to-delete", "cli", &info);

    int ret = fw_snapshot_delete(TEST_SNAP_DIR, info.id);
    ASSERT(ret == 0, "delete succeeds");

    /* Verify it's gone */
    size_t len;
    char *data = fw_snapshot_load(TEST_SNAP_DIR, info.id, &len);
    ASSERT(data == NULL, "deleted snapshot not loadable");
}

static void test_invalid_id(void)
{
    printf("test_invalid_id\n");

    /* Attempt to load with invalid IDs */
    size_t len;
    char *data;

    data = fw_snapshot_load(TEST_SNAP_DIR, "../etc/passwd", &len);
    ASSERT(data == NULL, "path traversal rejected");

    data = fw_snapshot_load(TEST_SNAP_DIR, "id with spaces", &len);
    ASSERT(data == NULL, "spaces rejected");

    data = fw_snapshot_load(TEST_SNAP_DIR, "", &len);
    ASSERT(data == NULL, "empty id rejected");

    int ret = fw_snapshot_delete(TEST_SNAP_DIR, "../etc/passwd");
    ASSERT(ret == -1, "delete path traversal rejected");
}

static void test_prune(void)
{
    printf("test_prune\n");

    /* Create many snapshots to test pruning.
     * We just verify the function runs without error. */
    int ret = fw_snapshot_prune(TEST_SNAP_DIR);
    ASSERT(ret >= 0, "prune does not error");
}

static void test_create_no_description(void)
{
    printf("test_create_no_description\n");

    fw_snapshot_info_t info;
    int ret = fw_snapshot_create(TEST_SNAP_DIR, TEST_CONFIG,
                                 NULL, "auto", &info);
    ASSERT(ret == 0, "create without description succeeds");
    ASSERT(strcmp(info.source, "auto") == 0, "source is auto");
    ASSERT(info.description[0] == '\0', "description is empty");

    /* Clean up */
    fw_snapshot_delete(TEST_SNAP_DIR, info.id);
}

static void test_empty_list(void)
{
    printf("test_empty_list\n");

    /* List from non-existent directory */
    fw_snapshot_info_t infos[10];
    int count = fw_snapshot_list("/tmp/nonexistent_snap_dir_12345", infos, 10);
    ASSERT(count == 0, "empty directory returns 0");
}

int main(void)
{
    printf("=== Snapshot tests ===\n");

    cleanup();
    create_test_config();

    test_empty_list();
    test_create_snapshot();
    test_list_snapshots();
    test_load_snapshot();
    test_diff_snapshot();
    test_diff_after_change();
    test_delete_snapshot();
    test_invalid_id();
    test_prune();
    test_create_no_description();

    cleanup();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
