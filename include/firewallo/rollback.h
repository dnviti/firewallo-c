#ifndef FIREWALLO_ROLLBACK_H
#define FIREWALLO_ROLLBACK_H

#include "firewallo/types.h"
#include <time.h>

/* Maximum path length for backup file */
#define FW_ROLLBACK_BACKUP_PATH_MAX 256

/* Default rollback timeout in seconds */
#define FW_ROLLBACK_DEFAULT_TIMEOUT 60

/* Rollback state */
typedef struct {
    int pending;                                /* 1 if a rollback is pending */
    time_t deadline;                            /* UNIX timestamp when rollback triggers */
    char backup_path[FW_ROLLBACK_BACKUP_PATH_MAX]; /* Path to backup config file */
} fw_rollback_state_t;

/* Create a backup of the current config at the given path.
   Returns 0 on success, -1 on error. */
int fw_config_backup(const fw_config_t *cfg, const char *backup_path);

/* Restore config from a backup file and reload it into cfg.
   Returns 0 on success, -1 on error. */
int fw_config_rollback(const char *backup_path, fw_config_t *cfg);

/* Start the rollback timer. After timeout_seconds, if not confirmed,
   the config will be automatically rolled back. Returns 0 on success. */
int fw_rollback_start(int timeout_seconds);

/* Confirm the current configuration, cancelling any pending rollback.
   Returns 0 on success, -1 if no rollback is pending. */
int fw_rollback_confirm(void);

/* Cancel the pending rollback timer without confirming (e.g. on error).
   Returns 0 on success, -1 if no rollback is pending. */
int fw_rollback_cancel(void);

/* Query the current rollback state. Returns 0 on success. */
int fw_rollback_status(fw_rollback_state_t *state);

/* Set the config pointer and config path used by the signal handler
   for automatic rollback. Must be called before fw_rollback_start(). */
void fw_rollback_set_context(fw_config_t *cfg, const char *config_path);

#endif /* FIREWALLO_ROLLBACK_H */
