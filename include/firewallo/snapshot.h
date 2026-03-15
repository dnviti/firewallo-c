#ifndef FIREWALLO_SNAPSHOT_H
#define FIREWALLO_SNAPSHOT_H

#include <stddef.h>

/* Maximum snapshots kept on disk */
#define FW_MAX_SNAPSHOTS 50

/* Default snapshot directory */
#define FW_SNAPSHOT_DIR "/var/lib/firewallo/snapshots"

/* Snapshot metadata */
typedef struct {
    char id[64];           /* Timestamp-based identifier (e.g. "20260315_143022") */
    char description[256]; /* User-provided description */
    char created_at[32];   /* ISO 8601 timestamp */
    char source[16];       /* "cli", "api", or "auto" */
} fw_snapshot_info_t;

/* Create a snapshot of the current config file.
 * snapshot_dir: directory to store snapshots (NULL = default)
 * config_path: path to the config file to snapshot
 * description: user description (may be NULL)
 * source: one of "cli", "api", "auto"
 * out_info: if non-NULL, populated with the new snapshot's info
 * Returns 0 on success, -1 on error. */
int fw_snapshot_create(const char *snapshot_dir, const char *config_path,
                       const char *description, const char *source,
                       fw_snapshot_info_t *out_info);

/* List all snapshots, sorted newest-first.
 * infos: output array of snapshot info structs
 * max: maximum entries to return
 * Returns number of snapshots found, or -1 on error. */
int fw_snapshot_list(const char *snapshot_dir,
                     fw_snapshot_info_t *infos, int max);

/* Load a snapshot's config content into a malloc'd buffer.
 * Caller must free() the returned string.
 * Returns NULL on error. */
char *fw_snapshot_load(const char *snapshot_dir, const char *id, size_t *out_len);

/* Compare a snapshot's config with the current config file.
 * Returns a malloc'd JSON string describing the differences.
 * Caller must free(). Returns NULL on error. */
char *fw_snapshot_diff(const char *snapshot_dir, const char *id,
                       const char *config_path);

/* Delete a snapshot by ID. Returns 0 on success, -1 on error. */
int fw_snapshot_delete(const char *snapshot_dir, const char *id);

/* Prune oldest snapshots to stay within FW_MAX_SNAPSHOTS limit.
 * Returns number of snapshots pruned, or -1 on error. */
int fw_snapshot_prune(const char *snapshot_dir);

#endif /* FIREWALLO_SNAPSHOT_H */
