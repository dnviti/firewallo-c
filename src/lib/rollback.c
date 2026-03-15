#include "firewallo/rollback.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include "firewallo/util.h"
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


/* ── Static rollback state ────────────────────────────────────────── */

static fw_rollback_state_t rollback_state;
static fw_config_t *rollback_cfg_ptr;
static char rollback_config_path[FW_ROLLBACK_BACKUP_PATH_MAX];

/* Atomic flag for async-signal-safe SIGALRM handler (comment 9) */
static volatile sig_atomic_t rollback_alarm_fired = 0;

/* ── Signal handler for SIGALRM ───────────────────────────────────── */

/* Only sets an atomic flag. All real work is done in fw_rollback_check()
   which must be called from the main loop. (comment 9) */
static void sigalrm_handler(int sig)
{
    (void)sig;
    rollback_alarm_fired = 1;
}

/* ── State file I/O for cross-process communication (comment 3) ──── */

/* Fallback state file path when /run/firewallo is not writable */
#define FW_ROLLBACK_STATE_FILE_FALLBACK "/tmp/.firewallo_rollback.state"

/* Determine the usable state file path. Try primary, fall back to /tmp. */
static const char *get_state_file_path(void)
{
    /* Try creating /run/firewallo */
    if (mkdir(FW_ROLLBACK_STATE_DIR, 0755) == 0 || errno == EEXIST) {
        /* Check if we can write there */
        if (access(FW_ROLLBACK_STATE_DIR, W_OK) == 0)
            return FW_ROLLBACK_STATE_FILE;
    }
    return FW_ROLLBACK_STATE_FILE_FALLBACK;
}

/* Check both possible locations for the state file */
static const char *find_state_file(void)
{
    if (access(FW_ROLLBACK_STATE_FILE, R_OK) == 0)
        return FW_ROLLBACK_STATE_FILE;
    if (access(FW_ROLLBACK_STATE_FILE_FALLBACK, R_OK) == 0)
        return FW_ROLLBACK_STATE_FILE_FALLBACK;
    return NULL;
}

int fw_rollback_state_save(const fw_rollback_state_t *state)
{
    const char *path = get_state_file_path();

    FILE *f = fopen(path, "w");
    if (!f)
        return -1;

    fprintf(f, "pending=%d\n", state->pending);
    fprintf(f, "deadline=%ld\n", (long)state->deadline);
    fprintf(f, "backup_path=%s\n", state->backup_path);
    fprintf(f, "config_path=%s\n", state->config_path);
    fclose(f);
    return 0;
}

int fw_rollback_state_load(fw_rollback_state_t *state)
{
    const char *path = find_state_file();
    if (!path)
        return -1;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    memset(state, 0, sizeof(*state));

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        if (strncmp(line, "pending=", 8) == 0)
            state->pending = atoi(line + 8);
        else if (strncmp(line, "deadline=", 9) == 0)
            state->deadline = (time_t)atol(line + 9);
        else if (strncmp(line, "backup_path=", 12) == 0)
            fw_strlcpy(state->backup_path, line + 12, sizeof(state->backup_path));
        else if (strncmp(line, "config_path=", 12) == 0)
            fw_strlcpy(state->config_path, line + 12, sizeof(state->config_path));
    }
    fclose(f);
    return 0;
}

void fw_rollback_state_remove(void)
{
    unlink(FW_ROLLBACK_STATE_FILE);
    unlink(FW_ROLLBACK_STATE_FILE_FALLBACK);
}

/* ── Public API ───────────────────────────────────────────────────── */

void fw_rollback_set_context(fw_config_t *cfg, const char *config_path)
{
    rollback_cfg_ptr = cfg;
    if (config_path)
        fw_strlcpy(rollback_config_path, config_path, sizeof(rollback_config_path));
    else
        rollback_config_path[0] = '\0';
}

int fw_config_backup(const fw_config_t *cfg, const char *backup_path)
{
    return fw_config_save(backup_path, cfg);
}

int fw_config_rollback(const char *backup_path, fw_config_t *cfg)
{
    char err[256] = {0};
    if (fw_config_load(backup_path, cfg, err, sizeof(err)) != 0)
        return -1;
    return 0;
}

int fw_rollback_start(int timeout_seconds)
{
    if (timeout_seconds <= 0)
        timeout_seconds = FW_ROLLBACK_DEFAULT_TIMEOUT;

    if (!rollback_cfg_ptr) {
        fw_log(LOG_ERROR, "rollback: context not set, call fw_rollback_set_context first");
        return -1;
    }

    /* Handle already-pending rollback: clean up previous state (comment 4) */
    if (rollback_state.pending) {
        fw_log(LOG_WARN, "rollback: cleaning up previous pending rollback");
        alarm(0); /* cancel previous alarm */
        if (rollback_state.backup_path[0])
            unlink(rollback_state.backup_path);
        rollback_state.pending = 0;
        rollback_state.deadline = 0;
        memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));
        fw_rollback_state_remove();
    }

    /* Generate backup path using mkstemp for safety (comment 6) */
    /* Try /run/firewallo first, fall back to /tmp */
    char template[FW_ROLLBACK_BACKUP_PATH_MAX];
    mkdir(FW_ROLLBACK_STATE_DIR, 0755);
    snprintf(template, sizeof(template), "%s/.rollback_XXXXXX.json",
             FW_ROLLBACK_STATE_DIR);

    /* mkstemp needs a mutable template without the .json suffix,
       so we use mkstemps if available, otherwise manual approach */
    int fd = -1;
    /* Use a simple template and rename approach.
       Reserve 6 bytes for ".json\0" in final_path. */
    char tmppath[FW_ROLLBACK_BACKUP_PATH_MAX - 5];
    snprintf(tmppath, sizeof(tmppath), "%s/.rollback_XXXXXX", FW_ROLLBACK_STATE_DIR);
    fd = mkstemp(tmppath);
    if (fd < 0) {
        /* Fall back to /tmp */
        snprintf(tmppath, sizeof(tmppath), "/tmp/.firewallo_rollback_XXXXXX");
        fd = mkstemp(tmppath);
    }
    if (fd < 0) {
        fw_log(LOG_ERROR, "rollback: failed to create temp file: %s", strerror(errno));
        return -1;
    }
    close(fd);

    /* Rename to add .json extension */
    char final_path[FW_ROLLBACK_BACKUP_PATH_MAX];
    snprintf(final_path, sizeof(final_path), "%s.json", tmppath);
    rename(tmppath, final_path);

    fw_strlcpy(rollback_state.backup_path, final_path,
                sizeof(rollback_state.backup_path));

    /* Create backup of current config */
    if (fw_config_backup(rollback_cfg_ptr, rollback_state.backup_path) != 0) {
        fw_log(LOG_ERROR, "rollback: failed to create backup at %s",
               rollback_state.backup_path);
        unlink(rollback_state.backup_path);
        rollback_state.backup_path[0] = '\0';
        return -1;
    }

    /* Set up signal handler (only sets atomic flag) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sa.sa_flags = 0; /* No SA_RESTART so alarm can interrupt */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);

    /* Reset the flag */
    rollback_alarm_fired = 0;

    /* Set state */
    rollback_state.pending = 1;
    rollback_state.deadline = time(NULL) + timeout_seconds;
    fw_strlcpy(rollback_state.config_path, rollback_config_path,
                sizeof(rollback_state.config_path));

    /* Write state file for cross-process communication (comment 3) */
    fw_rollback_state_save(&rollback_state);

    /* Start the countdown */
    alarm((unsigned int)timeout_seconds);

    fw_log(LOG_INFO, "rollback: timer started, %d seconds to confirm", timeout_seconds);
    return 0;
}

/* Perform the actual rollback: stop current rules, load backup, reapply (comment 5) */
int fw_rollback_perform(void)
{
    if (!rollback_state.pending && !rollback_state.backup_path[0]) {
        /* Try loading from state file */
        fw_rollback_state_t file_state;
        if (fw_rollback_state_load(&file_state) == 0 && file_state.pending) {
            rollback_state = file_state;
        } else {
            fw_log(LOG_ERROR, "rollback: no pending rollback to perform");
            return -1;
        }
    }

    fw_log(LOG_WARN, "rollback: performing automatic rollback");

    fw_config_t backup_cfg;
    char err[256] = {0};

    if (fw_config_load(rollback_state.backup_path, &backup_cfg, err, sizeof(err)) != 0) {
        fw_log(LOG_ERROR, "rollback: failed to load backup: %s", err);
        return -1;
    }

    /* Stop current rules using the CURRENT running config, not the backup (comment 5) */
    fw_config_t *current_cfg = rollback_cfg_ptr;
    if (current_cfg) {
        fw_cmdlist_t stop_cmds;
        fw_compile_stop(current_cfg, &stop_cmds);
        int fail_idx;
        fw_cmdlist_exec(&stop_cmds, &fail_idx);
        fw_cmdlist_free(&stop_cmds);
    } else {
        /* No in-process config pointer; load config from disk to stop */
        fw_config_t disk_cfg;
        char cerr[256] = {0};
        if (rollback_state.config_path[0] &&
            fw_config_load(rollback_state.config_path, &disk_cfg, cerr, sizeof(cerr)) == 0) {
            fw_cmdlist_t stop_cmds;
            fw_compile_stop(&disk_cfg, &stop_cmds);
            int fail_idx;
            fw_cmdlist_exec(&stop_cmds, &fail_idx);
            fw_cmdlist_free(&stop_cmds);
        }
    }

    /* Apply sysctl from backup */
    fw_sysctl_apply(&backup_cfg);

    /* Recompile and apply backup rules */
    fw_cmdlist_t start_cmds;
    fw_compile_start(&backup_cfg, &start_cmds);
    int fail_idx;
    fw_cmdlist_exec(&start_cmds, &fail_idx);
    fw_cmdlist_free(&start_cmds);

    /* Restore the config struct if we have a pointer */
    if (rollback_cfg_ptr)
        *rollback_cfg_ptr = backup_cfg;

    /* Save the restored config to disk */
    if (rollback_state.config_path[0])
        fw_config_save(rollback_state.config_path, &backup_cfg);

    /* Clean up backup file */
    if (rollback_state.backup_path[0])
        unlink(rollback_state.backup_path);

    /* Reset state */
    rollback_state.pending = 0;
    rollback_state.deadline = 0;
    memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));

    /* Remove state file */
    fw_rollback_state_remove();

    fw_log(LOG_INFO, "rollback: configuration rolled back successfully");
    return 0;
}

int fw_rollback_check(void)
{
    if (rollback_alarm_fired) {
        rollback_alarm_fired = 0;
        if (rollback_state.pending) {
            fw_rollback_perform();
            return 1;
        }
    }
    return 0;
}

int fw_rollback_confirm(void)
{
    /* First check in-process state */
    if (rollback_state.pending) {
        /* Cancel the alarm */
        alarm(0);

        /* Remove backup file */
        if (rollback_state.backup_path[0])
            unlink(rollback_state.backup_path);

        /* Reset state */
        rollback_state.pending = 0;
        rollback_state.deadline = 0;
        memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));

        /* Remove state file */
        fw_rollback_state_remove();

        fw_log(LOG_INFO, "rollback: configuration confirmed, timer cancelled");
        return 0;
    }

    /* Cross-process: try state file (comment 3) */
    fw_rollback_state_t file_state;
    if (fw_rollback_state_load(&file_state) == 0 && file_state.pending) {
        /* Check if the deadline has already passed */
        time_t now = time(NULL);
        if (now > file_state.deadline) {
            fw_rollback_state_remove();
            return -1; /* too late, rollback already happened */
        }

        /* Remove backup file */
        if (file_state.backup_path[0])
            unlink(file_state.backup_path);

        /* Remove state file to signal the waiting process */
        fw_rollback_state_remove();

        fw_log(LOG_INFO, "rollback: configuration confirmed via state file");
        return 0;
    }

    return -1;
}

int fw_rollback_cancel(void)
{
    if (!rollback_state.pending) {
        /* Try state file */
        fw_rollback_state_t file_state;
        if (fw_rollback_state_load(&file_state) == 0 && file_state.pending) {
            if (file_state.backup_path[0])
                unlink(file_state.backup_path);
            fw_rollback_state_remove();
            return 0;
        }
        return -1;
    }

    /* Cancel the alarm */
    alarm(0);

    /* Remove backup file */
    if (rollback_state.backup_path[0])
        unlink(rollback_state.backup_path);

    /* Reset state */
    rollback_state.pending = 0;
    rollback_state.deadline = 0;
    memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));

    /* Remove state file */
    fw_rollback_state_remove();

    fw_log(LOG_INFO, "rollback: timer cancelled");
    return 0;
}

int fw_rollback_status(fw_rollback_state_t *state)
{
    if (!state)
        return -1;

    /* Check in-process state first */
    if (rollback_state.pending) {
        *state = rollback_state;
        return 0;
    }

    /* Try state file for cross-process queries */
    if (fw_rollback_state_load(state) == 0)
        return 0;

    /* No rollback pending */
    memset(state, 0, sizeof(*state));
    return 0;
}
