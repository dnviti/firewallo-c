#ifndef FIREWALLO_ROLLBACK_H
#define FIREWALLO_ROLLBACK_H

#include "firewallo/types.h"
#include <time.h>

/* Maximum path length for backup file */
#define FW_ROLLBACK_BACKUP_PATH_MAX 256

/* Default rollback timeout in seconds */
#define FW_ROLLBACK_DEFAULT_TIMEOUT 60

/* State file path for cross-process rollback communication */
#define FW_ROLLBACK_STATE_DIR  "/run/firewallo"
#define FW_ROLLBACK_STATE_FILE "/run/firewallo/rollback.state"

/* Rollback state */
typedef struct {
    int pending;                                /* 1 if a rollback is pending */
    time_t deadline;                            /* UNIX timestamp when rollback triggers */
    char backup_path[FW_ROLLBACK_BACKUP_PATH_MAX]; /* Path to backup config file */
    char config_path[FW_ROLLBACK_BACKUP_PATH_MAX]; /* Original config file path */
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

/* Perform an immediate rollback using the saved backup.
   Stops current rules, loads backup config, and reapplies.
   Returns 0 on success, -1 on error. */
int fw_rollback_perform(void);

/* Query the current rollback state. Returns 0 on success. */
int fw_rollback_status(fw_rollback_state_t *state);

/* Set the config pointer and config path used for rollback.
   Must be called before fw_rollback_start(). */
void fw_rollback_set_context(fw_config_t *cfg, const char *config_path);

/* Check the volatile flag set by SIGALRM and perform rollback if needed.
   Call this from a main loop or poll loop. Returns 1 if rollback was
   triggered, 0 otherwise. */
int fw_rollback_check(void);

/* Write rollback state to the state file for cross-process communication.
   Returns 0 on success. */
int fw_rollback_state_save(const fw_rollback_state_t *state);

/* Read rollback state from the state file.
   Returns 0 on success, -1 if no state file or error. */
int fw_rollback_state_load(fw_rollback_state_t *state);

/* Remove the state file. */
void fw_rollback_state_remove(void);

#endif /* FIREWALLO_ROLLBACK_H */
