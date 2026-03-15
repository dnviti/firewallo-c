#include "firewallo/rollback.h"
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

/* ── Test state file I/O ──────────────────────────────────────────── */

static void test_state_file_save_load(void)
{
    printf("test_state_file_save_load\n");

    fw_rollback_state_t state;
    memset(&state, 0, sizeof(state));
    state.pending = 1;
    state.deadline = 1700000000;
    fw_strlcpy(state.backup_path, "/tmp/test_backup.json", sizeof(state.backup_path));
    fw_strlcpy(state.config_path, "/etc/firewallo/firewallo.json", sizeof(state.config_path));

    int ret = fw_rollback_state_save(&state);
    ASSERT(ret == 0, "state save succeeds");

    fw_rollback_state_t loaded;
    ret = fw_rollback_state_load(&loaded);
    ASSERT(ret == 0, "state load succeeds");
    ASSERT(loaded.pending == 1, "pending preserved");
    ASSERT(loaded.deadline == 1700000000, "deadline preserved");
    ASSERT(strcmp(loaded.backup_path, "/tmp/test_backup.json") == 0, "backup_path preserved");
    ASSERT(strcmp(loaded.config_path, "/etc/firewallo/firewallo.json") == 0, "config_path preserved");

    fw_rollback_state_remove();
}

static void test_state_file_load_missing(void)
{
    printf("test_state_file_load_missing\n");

    /* Ensure no state file */
    fw_rollback_state_remove();

    fw_rollback_state_t state;
    int ret = fw_rollback_state_load(&state);
    ASSERT(ret == -1, "load returns -1 when no file");
}

static void test_state_file_remove(void)
{
    printf("test_state_file_remove\n");

    fw_rollback_state_t state;
    memset(&state, 0, sizeof(state));
    state.pending = 1;
    state.deadline = 1700000000;
    fw_rollback_state_save(&state);

    /* Verify file can be loaded (it exists somewhere) */
    fw_rollback_state_t loaded;
    int can_load = fw_rollback_state_load(&loaded) == 0;
    ASSERT(can_load, "state file exists after save");

    fw_rollback_state_remove();

    can_load = fw_rollback_state_load(&loaded) == 0;
    ASSERT(!can_load, "state file removed");
}

/* ── Test backup and rollback functions ───────────────────────────── */

static void test_config_backup_and_rollback(void)
{
    printf("test_config_backup_and_rollback\n");

    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config for backup test");

    const char *backup = "/tmp/firewallo_test_backup.json";

    ret = fw_config_backup(&cfg, backup);
    ASSERT(ret == 0, "backup succeeds");

    /* Verify backup file exists */
    struct stat st;
    ASSERT(stat(backup, &st) == 0, "backup file exists");

    /* Modify config */
    cfg.ip_forward = 0;
    fw_strlcpy(cfg.version, "9.9.9", sizeof(cfg.version));

    /* Rollback */
    ret = fw_config_rollback(backup, &cfg);
    ASSERT(ret == 0, "rollback succeeds");
    ASSERT(cfg.ip_forward == 1, "ip_forward restored");
    ASSERT(strcmp(cfg.version, "2.0.0") == 0, "version restored");

    unlink(backup);
}

/* ── Test rollback start and confirm ──────────────────────────────── */

static void test_rollback_start_confirm(void)
{
    printf("test_rollback_start_confirm\n");

    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config for rollback test");

    fw_rollback_set_context(&cfg, "/tmp/firewallo_test_rollback_cfg.json");

    /* Save config to disk so rollback can work */
    fw_config_save("/tmp/firewallo_test_rollback_cfg.json", &cfg);

    ret = fw_rollback_start(30);
    ASSERT(ret == 0, "rollback start succeeds");

    /* Check state */
    fw_rollback_state_t state;
    fw_rollback_status(&state);
    ASSERT(state.pending == 1, "rollback is pending");
    ASSERT(state.backup_path[0] != '\0', "backup path is set");

    /* Confirm */
    ret = fw_rollback_confirm();
    ASSERT(ret == 0, "confirm succeeds");

    fw_rollback_status(&state);
    ASSERT(state.pending == 0, "rollback no longer pending after confirm");

    /* Clean up */
    unlink("/tmp/firewallo_test_rollback_cfg.json");
}

/* ── Test rollback start and cancel ───────────────────────────────── */

static void test_rollback_start_cancel(void)
{
    printf("test_rollback_start_cancel\n");

    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config for cancel test");

    fw_rollback_set_context(&cfg, "/tmp/firewallo_test_cancel_cfg.json");
    fw_config_save("/tmp/firewallo_test_cancel_cfg.json", &cfg);

    ret = fw_rollback_start(30);
    ASSERT(ret == 0, "rollback start succeeds");

    ret = fw_rollback_cancel();
    ASSERT(ret == 0, "cancel succeeds");

    fw_rollback_state_t state;
    fw_rollback_status(&state);
    ASSERT(state.pending == 0, "rollback not pending after cancel");

    unlink("/tmp/firewallo_test_cancel_cfg.json");
}

/* ── Test confirm without pending rollback ─────────────────────────── */

static void test_confirm_no_pending(void)
{
    printf("test_confirm_no_pending\n");

    /* Make sure no state file exists */
    fw_rollback_state_remove();

    int ret = fw_rollback_confirm();
    ASSERT(ret == -1, "confirm returns -1 when nothing pending");
}

/* ── Test cancel without pending rollback ──────────────────────────── */

static void test_cancel_no_pending(void)
{
    printf("test_cancel_no_pending\n");

    fw_rollback_state_remove();

    int ret = fw_rollback_cancel();
    ASSERT(ret == -1, "cancel returns -1 when nothing pending");
}

/* ── Test rollback status ──────────────────────────────────────────── */

static void test_status_null(void)
{
    printf("test_status_null\n");

    int ret = fw_rollback_status(NULL);
    ASSERT(ret == -1, "status returns -1 for null");
}

/* ── Test already-pending rollback cleanup ─────────────────────────── */

static void test_already_pending_cleanup(void)
{
    printf("test_already_pending_cleanup\n");

    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config for already-pending test");

    fw_rollback_set_context(&cfg, "/tmp/firewallo_test_pending_cfg.json");
    fw_config_save("/tmp/firewallo_test_pending_cfg.json", &cfg);

    /* Start first rollback */
    ret = fw_rollback_start(30);
    ASSERT(ret == 0, "first rollback start succeeds");

    fw_rollback_state_t state1;
    fw_rollback_status(&state1);
    char first_backup[FW_ROLLBACK_BACKUP_PATH_MAX];
    fw_strlcpy(first_backup, state1.backup_path, sizeof(first_backup));

    /* Start second rollback (should clean up the first) */
    ret = fw_rollback_start(60);
    ASSERT(ret == 0, "second rollback start succeeds");

    /* First backup file should be cleaned up */
    struct stat st;
    ASSERT(stat(first_backup, &st) != 0, "first backup file was cleaned up");

    /* Confirm the second one */
    fw_rollback_confirm();

    unlink("/tmp/firewallo_test_pending_cfg.json");
}

/* ── Test cross-process confirm via state file ─────────────────────── */

static void test_cross_process_state_file(void)
{
    printf("test_cross_process_state_file\n");

    /* Simulate: write a state file as if another process started rollback */
    fw_rollback_state_t state;
    memset(&state, 0, sizeof(state));
    state.pending = 1;
    state.deadline = time(NULL) + 300; /* far future */
    fw_strlcpy(state.backup_path, "/tmp/firewallo_test_xprocess.json", sizeof(state.backup_path));
    fw_strlcpy(state.config_path, "/tmp/firewallo_test_xprocess_cfg.json", sizeof(state.config_path));

    /* Create a dummy backup file */
    fw_config_t cfg;
    char err[256] = {0};
    fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    fw_config_save("/tmp/firewallo_test_xprocess.json", &cfg);

    fw_rollback_state_save(&state);

    /* Now "confirm" from a different process context (no in-process state) */
    int ret = fw_rollback_confirm();
    ASSERT(ret == 0, "cross-process confirm succeeds via state file");

    /* State file should be gone */
    fw_rollback_state_t loaded;
    ret = fw_rollback_state_load(&loaded);
    ASSERT(ret == -1 || !loaded.pending, "state file removed after confirm");

    /* Clean up */
    unlink("/tmp/firewallo_test_xprocess.json");
    unlink("/tmp/firewallo_test_xprocess_cfg.json");
}

/* ── Test fw_rollback_check without alarm ──────────────────────────── */

static void test_rollback_check_no_alarm(void)
{
    printf("test_rollback_check_no_alarm\n");

    /* Should return 0 when no alarm has fired */
    int ret = fw_rollback_check();
    ASSERT(ret == 0, "check returns 0 when no alarm");
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== Rollback Tests ===\n\n");

    test_state_file_save_load();
    test_state_file_load_missing();
    test_state_file_remove();
    test_config_backup_and_rollback();
    test_rollback_start_confirm();
    test_rollback_start_cancel();
    test_confirm_no_pending();
    test_cancel_no_pending();
    test_status_null();
    test_already_pending_cleanup();
    test_cross_process_state_file();
    test_rollback_check_no_alarm();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
