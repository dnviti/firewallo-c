#include "firewallo/snapshot.h"
#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static const char *default_dir(const char *snapshot_dir)
{
    return snapshot_dir ? snapshot_dir : FW_SNAPSHOT_DIR;
}

static int ensure_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        /* Path exists — succeed only if it is a directory */
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }

    /* Try to create parent first (one level up) */
    char parent[512];
    fw_strlcpy(parent, path, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = '\0';
        ensure_dir(parent);
    }

    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Build path: <dir>/<id>.json */
static void snapshot_path(char *buf, size_t buflen,
                          const char *dir, const char *id)
{
    snprintf(buf, buflen, "%s/%s.json", dir, id);
}

/* Build metadata path: <dir>/<id>.meta */
static void meta_path(char *buf, size_t buflen,
                      const char *dir, const char *id)
{
    snprintf(buf, buflen, "%s/%s.meta", dir, id);
}

/* Generate a timestamp-based snapshot ID: YYYYMMDD_HHMMSS */
static void generate_id(char *id, size_t idlen, const struct tm *tm)
{
    snprintf(id, idlen, "%04d%02d%02d_%02d%02d%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* Format ISO 8601 timestamp */
static void format_timestamp(char *buf, size_t buflen, const struct tm *tm)
{
    snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/* Escape a metadata value: replace '\n' with "\\n" and '=' with "\\=" */
static void escape_meta_value(char *dst, size_t dstlen, const char *src)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 2 < dstlen; si++) {
        if (src[si] == '\n') {
            dst[di++] = '\\';
            dst[di++] = 'n';
        } else if (src[si] == '=') {
            dst[di++] = '\\';
            dst[di++] = '=';
        } else if (src[si] == '\\') {
            dst[di++] = '\\';
            dst[di++] = '\\';
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

/* Write metadata file (simple key=value format) */
static int write_meta(const char *dir, const fw_snapshot_info_t *info)
{
    char path[512];
    meta_path(path, sizeof(path), dir, info->id);

    /* Escape values to prevent newline/= corruption */
    char esc_desc[512];
    escape_meta_value(esc_desc, sizeof(esc_desc), info->description);

    char buf[1024];
    snprintf(buf, sizeof(buf),
             "id=%s\ndescription=%s\ncreated_at=%s\nsource=%s\n",
             info->id, esc_desc, info->created_at, info->source);

    return fw_write_file(path, buf, strlen(buf));
}

/* Unescape a metadata value: reverse of escape_meta_value */
static void unescape_meta_value(char *dst, size_t dstlen, const char *src)
{
    size_t di = 0;
    for (size_t si = 0; src[si] && di + 1 < dstlen; si++) {
        if (src[si] == '\\' && src[si + 1]) {
            si++;
            if (src[si] == 'n')
                dst[di++] = '\n';
            else if (src[si] == '=')
                dst[di++] = '=';
            else if (src[si] == '\\')
                dst[di++] = '\\';
            else
                dst[di++] = src[si];
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

/* Read metadata file */
static int read_meta(const char *dir, const char *id, fw_snapshot_info_t *info)
{
    char path[512];
    meta_path(path, sizeof(path), dir, id);

    size_t len;
    char *text = fw_read_file(path, &len);
    if (!text)
        return -1;

    memset(info, 0, sizeof(*info));
    fw_strlcpy(info->id, id, sizeof(info->id));

    /* Parse key=value lines (first unescaped '=' is the delimiter) */
    char *line = text;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char *eq = strchr(line, '=');
        if (eq) {
            *eq = '\0';
            const char *key = line;
            const char *val = eq + 1;

            if (strcmp(key, "description") == 0)
                unescape_meta_value(info->description, sizeof(info->description), val);
            else if (strcmp(key, "created_at") == 0)
                fw_strlcpy(info->created_at, val, sizeof(info->created_at));
            else if (strcmp(key, "source") == 0)
                fw_strlcpy(info->source, val, sizeof(info->source));
        }

        line = nl ? nl + 1 : NULL;
    }

    free(text);
    return 0;
}

/* Validate snapshot ID: must be alphanumeric with underscores only */
static int valid_id(const char *id)
{
    if (!id || !*id)
        return 0;
    for (const char *p = id; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') ||
              (*p >= 'A' && *p <= 'Z') || *p == '_'))
            return 0;
    }
    return 1;
}

/* ── Public API ────────────────────────────────────────────────────── */

int fw_snapshot_create(const char *snapshot_dir, const char *config_path,
                       const char *description, const char *source,
                       fw_snapshot_info_t *out_info)
{
    const char *dir = default_dir(snapshot_dir);

    if (ensure_dir(dir) != 0)
        return -1;

    /* Read current config */
    size_t cfg_len;
    char *cfg_data = fw_read_file(config_path, &cfg_len);
    if (!cfg_data)
        return -1;

    /* Generate snapshot ID and timestamp */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    fw_snapshot_info_t info;
    memset(&info, 0, sizeof(info));
    generate_id(info.id, sizeof(info.id), &tm);
    format_timestamp(info.created_at, sizeof(info.created_at), &tm);
    fw_strlcpy(info.source, source ? source : "api", sizeof(info.source));
    if (description)
        fw_strlcpy(info.description, description, sizeof(info.description));

    /* Handle ID collision (same second) — append _N */
    char snap_file[512];
    snapshot_path(snap_file, sizeof(snap_file), dir, info.id);
    struct stat st;
    if (stat(snap_file, &st) == 0) {
        /* Append counter */
        char base_id[64];
        fw_strlcpy(base_id, info.id, sizeof(base_id));
        int found_unique = 0;
        for (int n = 1; n < 100; n++) {
            snprintf(info.id, sizeof(info.id), "%.*s_%d",
                     (int)(sizeof(info.id) - 5), base_id, n);
            snapshot_path(snap_file, sizeof(snap_file), dir, info.id);
            if (stat(snap_file, &st) != 0) {
                found_unique = 1;
                break;
            }
        }
        if (!found_unique) {
            free(cfg_data);
            return -1; /* Exhausted all collision suffixes */
        }
    }

    /* Write snapshot config */
    snapshot_path(snap_file, sizeof(snap_file), dir, info.id);
    if (fw_write_file(snap_file, cfg_data, cfg_len) != 0) {
        free(cfg_data);
        return -1;
    }
    free(cfg_data);

    /* Write metadata — delete snapshot file on failure to avoid orphans */
    if (write_meta(dir, &info) != 0) {
        remove(snap_file);
        return -1;
    }

    /* Auto-prune */
    fw_snapshot_prune(dir);

    if (out_info)
        *out_info = info;

    return 0;
}

int fw_snapshot_list(const char *snapshot_dir,
                     fw_snapshot_info_t *infos, int max)
{
    const char *dir = default_dir(snapshot_dir);

    DIR *d = opendir(dir);
    if (!d)
        return (errno == ENOENT) ? 0 : -1;

    /* Collect .json file basenames (without extension) */
    char ids[FW_MAX_SNAPSHOTS][64];
    int count = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < FW_MAX_SNAPSHOTS) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen > 5 && strcmp(name + nlen - 5, ".json") == 0) {
            size_t idlen = nlen - 5;
            if (idlen >= sizeof(ids[0])) idlen = sizeof(ids[0]) - 1;
            memcpy(ids[count], name, idlen);
            ids[count][idlen] = '\0';
            count++;
        }
    }
    closedir(d);

    /* Sort IDs in reverse (newest first) — simple insertion sort */
    for (int i = 1; i < count; i++) {
        char tmp[64];
        memcpy(tmp, ids[i], sizeof(tmp));
        int j = i - 1;
        while (j >= 0 && strcmp(ids[j], tmp) < 0) {
            memcpy(ids[j + 1], ids[j], sizeof(ids[0]));
            j--;
        }
        memcpy(ids[j + 1], tmp, sizeof(ids[0]));
    }

    /* Read metadata for each */
    int result = 0;
    for (int i = 0; i < count && result < max; i++) {
        if (read_meta(dir, ids[i], &infos[result]) == 0)
            result++;
    }

    return result;
}

char *fw_snapshot_load(const char *snapshot_dir, const char *id, size_t *out_len)
{
    if (!valid_id(id))
        return NULL;

    const char *dir = default_dir(snapshot_dir);
    char path[512];
    snapshot_path(path, sizeof(path), dir, id);

    return fw_read_file(path, out_len);
}

char *fw_snapshot_diff(const char *snapshot_dir, const char *id,
                       const char *config_path)
{
    if (!valid_id(id))
        return NULL;

    const char *dir = default_dir(snapshot_dir);

    /* Load snapshot config */
    size_t snap_len;
    char *snap_data = fw_snapshot_load(dir, id, &snap_len);
    if (!snap_data)
        return NULL;

    /* Load current config */
    size_t cur_len;
    char *cur_data = fw_read_file(config_path, &cur_len);
    if (!cur_data) {
        free(snap_data);
        return NULL;
    }

    /* Parse both as JSON and compare top-level keys */
    char err[256];
    json_value_t *snap_json = json_parse(snap_data, err, sizeof(err));
    json_value_t *cur_json = json_parse(cur_data, err, sizeof(err));
    free(snap_data);
    free(cur_data);

    if (!snap_json || !cur_json) {
        if (snap_json) json_free(snap_json);
        if (cur_json) json_free(cur_json);
        return NULL;
    }

    /* Build diff result — compare serialized top-level keys */
    json_value_t *result = json_new_object();
    json_value_t *changes = json_new_array();

    if (snap_json->type == JSON_OBJECT && cur_json->type == JSON_OBJECT) {
        /* Compare each key in current config with snapshot */
        for (int i = 0; i < cur_json->u.object.count; i++) {
            const char *key = cur_json->u.object.keys[i];
            json_value_t *cur_val = cur_json->u.object.values[i];
            json_value_t *snap_val = json_object_get(snap_json, key);

            char *cur_ser = json_serialize(cur_val, 0);
            char *snap_ser = snap_val ? json_serialize(snap_val, 0) : NULL;

            int differs = 0;
            if (!snap_ser)
                differs = 1; /* Key added */
            else if (strcmp(cur_ser, snap_ser) != 0)
                differs = 1;

            if (differs) {
                json_value_t *change = json_new_object();
                json_object_set(change, "key", json_new_string(key));
                json_object_set(change, "status",
                                json_new_string(snap_ser ? "modified" : "added"));
                json_array_append(changes, change);
            }

            free(cur_ser);
            free(snap_ser);
        }

        /* Check for keys in snapshot but not in current (removed) */
        for (int i = 0; i < snap_json->u.object.count; i++) {
            const char *key = snap_json->u.object.keys[i];
            if (!json_object_get(cur_json, key)) {
                json_value_t *change = json_new_object();
                json_object_set(change, "key", json_new_string(key));
                json_object_set(change, "status", json_new_string("removed"));
                json_array_append(changes, change);
            }
        }
    }

    json_object_set(result, "snapshot_id", json_new_string(id));
    json_object_set(result, "change_count",
                    json_new_number(json_array_count(changes)));
    json_object_set(result, "changes", changes);

    json_free(snap_json);
    json_free(cur_json);

    char *json_str = json_serialize(result, 1);
    json_free(result);
    return json_str;
}

int fw_snapshot_delete(const char *snapshot_dir, const char *id)
{
    if (!valid_id(id))
        return -1;

    const char *dir = default_dir(snapshot_dir);

    char path[512];
    snapshot_path(path, sizeof(path), dir, id);
    if (remove(path) != 0 && errno != ENOENT)
        return -1;

    meta_path(path, sizeof(path), dir, id);
    remove(path); /* best effort for meta */

    return 0;
}

int fw_snapshot_prune(const char *snapshot_dir)
{
    const char *dir = default_dir(snapshot_dir);

    DIR *d = opendir(dir);
    if (!d)
        return 0;

    /* Collect IDs from .json files */
    char ids[FW_MAX_SNAPSHOTS + 50][64];
    int count = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < FW_MAX_SNAPSHOTS + 50) {
        const char *name = ent->d_name;
        size_t nlen = strlen(name);
        if (nlen > 5 && strcmp(name + nlen - 5, ".json") == 0) {
            size_t idlen = nlen - 5;
            if (idlen >= sizeof(ids[0])) idlen = sizeof(ids[0]) - 1;
            memcpy(ids[count], name, idlen);
            ids[count][idlen] = '\0';
            count++;
        }
    }
    closedir(d);

    if (count <= FW_MAX_SNAPSHOTS)
        return 0;

    /* Sort ascending (oldest first) */
    for (int i = 1; i < count; i++) {
        char tmp[64];
        memcpy(tmp, ids[i], sizeof(tmp));
        int j = i - 1;
        while (j >= 0 && strcmp(ids[j], tmp) > 0) {
            memcpy(ids[j + 1], ids[j], sizeof(ids[0]));
            j--;
        }
        memcpy(ids[j + 1], tmp, sizeof(ids[0]));
    }

    /* Delete oldest until we're at the limit */
    int pruned = 0;
    int to_delete = count - FW_MAX_SNAPSHOTS;
    for (int i = 0; i < to_delete; i++) {
        if (fw_snapshot_delete(dir, ids[i]) == 0)
            pruned++;
    }

    return pruned;
}
