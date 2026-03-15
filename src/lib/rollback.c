#include "firewallo/rollback.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include "firewallo/util.h"
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* ── Static rollback state ────────────────────────────────────────── */

static fw_rollback_state_t rollback_state;
static fw_config_t *rollback_cfg_ptr;
static char rollback_config_path[FW_ROLLBACK_BACKUP_PATH_MAX];

/* ── Signal handler for SIGALRM ───────────────────────────────────── */

static void sigalrm_handler(int sig)
{
    (void)sig;

    if (!rollback_state.pending)
        return;

    /* Perform rollback: load backup and reapply rules */
    if (rollback_cfg_ptr && rollback_state.backup_path[0]) {
        fw_config_t backup_cfg;
        char err[256] = {0};

        if (fw_config_load(rollback_state.backup_path, &backup_cfg, err, sizeof(err)) == 0) {
            /* Stop current rules */
            fw_cmdlist_t stop_cmds;
            fw_compile_stop(&backup_cfg, &stop_cmds);
            int fail_idx;
            fw_cmdlist_exec(&stop_cmds, &fail_idx);
            fw_cmdlist_free(&stop_cmds);

            /* Apply sysctl from backup */
            fw_sysctl_apply(&backup_cfg);

            /* Recompile and apply backup rules */
            fw_cmdlist_t start_cmds;
            fw_compile_start(&backup_cfg, &start_cmds);
            fw_cmdlist_exec(&start_cmds, &fail_idx);
            fw_cmdlist_free(&start_cmds);

            /* Restore the config struct */
            *rollback_cfg_ptr = backup_cfg;

            /* Save the restored config to disk */
            if (rollback_config_path[0])
                fw_config_save(rollback_config_path, &backup_cfg);
        }

        /* Clean up backup file */
        unlink(rollback_state.backup_path);
    }

    /* Reset state */
    rollback_state.pending = 0;
    rollback_state.deadline = 0;
    memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));
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

    /* Generate backup path */
    snprintf(rollback_state.backup_path, sizeof(rollback_state.backup_path),
             "/tmp/.firewallo_rollback_%d.json", (int)getpid());

    /* Create backup of current config */
    if (fw_config_backup(rollback_cfg_ptr, rollback_state.backup_path) != 0) {
        fw_log(LOG_ERROR, "rollback: failed to create backup at %s",
               rollback_state.backup_path);
        rollback_state.backup_path[0] = '\0';
        return -1;
    }

    /* Set up signal handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sa.sa_flags = 0; /* No SA_RESTART so alarm can interrupt */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);

    /* Set state */
    rollback_state.pending = 1;
    rollback_state.deadline = time(NULL) + timeout_seconds;

    /* Start the countdown */
    alarm((unsigned int)timeout_seconds);

    fw_log(LOG_INFO, "rollback: timer started, %d seconds to confirm", timeout_seconds);
    return 0;
}

int fw_rollback_confirm(void)
{
    if (!rollback_state.pending)
        return -1;

    /* Cancel the alarm */
    alarm(0);

    /* Remove backup file */
    if (rollback_state.backup_path[0])
        unlink(rollback_state.backup_path);

    /* Reset state */
    rollback_state.pending = 0;
    rollback_state.deadline = 0;
    memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));

    fw_log(LOG_INFO, "rollback: configuration confirmed, timer cancelled");
    return 0;
}

int fw_rollback_cancel(void)
{
    if (!rollback_state.pending)
        return -1;

    /* Cancel the alarm */
    alarm(0);

    /* Remove backup file */
    if (rollback_state.backup_path[0])
        unlink(rollback_state.backup_path);

    /* Reset state */
    rollback_state.pending = 0;
    rollback_state.deadline = 0;
    memset(rollback_state.backup_path, 0, sizeof(rollback_state.backup_path));

    fw_log(LOG_INFO, "rollback: timer cancelled");
    return 0;
}

int fw_rollback_status(fw_rollback_state_t *state)
{
    if (!state)
        return -1;

    *state = rollback_state;
    return 0;
}
