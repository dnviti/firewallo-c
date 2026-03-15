#include "firewallo/api.h"
#include "firewallo/snapshot.h"
#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Helpers (same pattern as api.c) ──────────────────────────────── */

static void backup_error(http_response_t *resp, int status, const char *msg)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(1));
    json_object_set(envelope, "message", json_new_string(msg));
    char *json = json_serialize(envelope, 0);
    json_free(envelope);
    http_response_set_json(resp, status, json);
}

static void backup_ok_json(http_response_t *resp, json_value_t *data)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(0));
    json_object_set(envelope, "data", data);
    char *json = json_serialize(envelope, 1);
    json_free(envelope);
    http_response_set_json(resp, 200, json);
}

static void backup_ok_msg(http_response_t *resp, const char *msg)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "message", json_new_string(msg));
    backup_ok_json(resp, data);
}

/* ── GET /api/v1/config/snapshots — list all snapshots ────────────── */

static void api_list_snapshots(httpd_t *srv, http_response_t *resp)
{
    (void)srv;

    fw_snapshot_info_t infos[FW_MAX_SNAPSHOTS];
    int count = fw_snapshot_list(NULL, infos, FW_MAX_SNAPSHOTS);
    if (count < 0) {
        backup_error(resp, 500, "Failed to list snapshots");
        return;
    }

    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        json_value_t *obj = json_new_object();
        json_object_set(obj, "id", json_new_string(infos[i].id));
        json_object_set(obj, "description", json_new_string(infos[i].description));
        json_object_set(obj, "created_at", json_new_string(infos[i].created_at));
        json_object_set(obj, "source", json_new_string(infos[i].source));
        json_array_append(arr, obj);
    }

    json_value_t *data = json_new_object();
    json_object_set(data, "count", json_new_number(count));
    json_object_set(data, "snapshots", arr);
    backup_ok_json(resp, data);
}

/* ── POST /api/v1/config/snapshots — create a snapshot ────────────── */

static void api_create_snapshot(httpd_t *srv, const http_request_t *req,
                                http_response_t *resp)
{
    const char *desc = NULL;

    /* Parse optional description from body */
    if (req->body && req->body_len > 0) {
        char err[256];
        json_value_t *body = json_parse(req->body, err, sizeof(err));
        if (!body) {
            backup_error(resp, 400, "Invalid JSON in request body");
            return;
        }
        desc = json_string_value(json_object_get(body, "description"));
        /* desc points into body tree; copy if needed */
        char desc_buf[256] = {0};
        if (desc)
            fw_strlcpy(desc_buf, desc, sizeof(desc_buf));
        json_free(body);

        fw_snapshot_info_t info;
        if (fw_snapshot_create(NULL, srv->config_path,
                               desc_buf[0] ? desc_buf : NULL,
                               "api", &info) != 0) {
            backup_error(resp, 500, "Failed to create snapshot");
            return;
        }

        json_value_t *data = json_new_object();
        json_object_set(data, "id", json_new_string(info.id));
        json_object_set(data, "description", json_new_string(info.description));
        json_object_set(data, "created_at", json_new_string(info.created_at));
        json_object_set(data, "source", json_new_string(info.source));
        json_object_set(data, "message", json_new_string("Snapshot created"));
        backup_ok_json(resp, data);
        return;
    }

    /* No body — create without description */
    fw_snapshot_info_t info;
    if (fw_snapshot_create(NULL, srv->config_path, NULL, "api", &info) != 0) {
        backup_error(resp, 500, "Failed to create snapshot");
        return;
    }

    json_value_t *data = json_new_object();
    json_object_set(data, "id", json_new_string(info.id));
    json_object_set(data, "description", json_new_string(info.description));
    json_object_set(data, "created_at", json_new_string(info.created_at));
    json_object_set(data, "source", json_new_string(info.source));
    json_object_set(data, "message", json_new_string("Snapshot created"));
    backup_ok_json(resp, data);
}

/* ── GET /api/v1/config/snapshots/{id} — download snapshot config ─── */

static void api_get_snapshot(const char *id, http_response_t *resp)
{
    size_t len;
    char *data = fw_snapshot_load(NULL, id, &len);
    if (!data) {
        backup_error(resp, 404, "Snapshot not found");
        return;
    }

    /* Parse and wrap in envelope */
    char err[256];
    json_value_t *cfg_json = json_parse(data, err, sizeof(err));
    free(data);

    if (!cfg_json) {
        backup_error(resp, 500, "Failed to parse snapshot config");
        return;
    }

    backup_ok_json(resp, cfg_json);
}

/* ── POST /api/v1/config/snapshots/{id}/restore — restore config ──── */

static void api_restore_snapshot(httpd_t *srv, const char *id,
                                 http_response_t *resp)
{
    /* Load the snapshot first — validate before creating auto-backup */
    size_t len;
    char *snap_data = fw_snapshot_load(NULL, id, &len);
    if (!snap_data) {
        backup_error(resp, 404, "Snapshot not found");
        return;
    }

    /* Validate the snapshot as a valid config */
    fw_config_t new_cfg;
    char err[256];

    /* Write to secure temp file, load and validate */
    char tmp[] = "/tmp/.firewallo_restore_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) {
        free(snap_data);
        backup_error(resp, 500, "Failed to create temp file");
        return;
    }
    close(fd);

    if (fw_write_file(tmp, snap_data, len) != 0) {
        free(snap_data);
        remove(tmp);
        backup_error(resp, 500, "Failed to write temp file");
        return;
    }
    free(snap_data);

    if (fw_config_load(tmp, &new_cfg, err, sizeof(err)) != 0) {
        remove(tmp);
        backup_error(resp, 400, err);
        return;
    }
    remove(tmp);

    if (fw_config_validate(&new_cfg, err, sizeof(err)) != 0) {
        backup_error(resp, 400, err);
        return;
    }

    /* Snapshot validated — now create auto-backup of current config */
    fw_snapshot_info_t backup_info;
    if (fw_snapshot_create(NULL, srv->config_path,
                           "Auto-backup before restore", "auto",
                           &backup_info) != 0) {
        backup_error(resp, 500, "Failed to create auto-backup");
        return;
    }

    /* Apply the config */
    *srv->config = new_cfg;
    if (fw_config_save(srv->config_path, srv->config) != 0) {
        backup_error(resp, 500, "Failed to save restored config");
        return;
    }

    json_value_t *data = json_new_object();
    json_object_set(data, "message", json_new_string("Configuration restored from snapshot"));
    json_object_set(data, "restored_from", json_new_string(id));
    json_object_set(data, "backup_id", json_new_string(backup_info.id));
    backup_ok_json(resp, data);
}

/* ── GET /api/v1/config/snapshots/{id}/diff — diff with current ───── */
/* NOTE: Currently only supports comparing a snapshot against the active
 * configuration.  Snapshot-vs-snapshot comparison (e.g. via a `compare=`
 * query parameter) is not implemented yet. */

static void api_diff_snapshot(httpd_t *srv, const char *id,
                              http_response_t *resp)
{
    char *diff_json = fw_snapshot_diff(NULL, id, srv->config_path);
    if (!diff_json) {
        backup_error(resp, 404, "Snapshot not found or diff failed");
        return;
    }

    /* Parse the diff JSON and wrap in envelope */
    char err[256];
    json_value_t *diff_val = json_parse(diff_json, err, sizeof(err));
    free(diff_json);

    if (!diff_val) {
        backup_error(resp, 500, "Failed to parse diff result");
        return;
    }

    backup_ok_json(resp, diff_val);
}

/* ── DELETE /api/v1/config/snapshots/{id} — delete a snapshot ─────── */

static void api_delete_snapshot(const char *id, http_response_t *resp)
{
    if (fw_snapshot_delete(NULL, id) != 0) {
        backup_error(resp, 404, "Snapshot not found");
        return;
    }

    backup_ok_msg(resp, "Snapshot deleted");
}

/* ── Dispatcher ───────────────────────────────────────────────────── */

int api_handle_backup(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp)
{
    /* path is relative to "config/snapshots" (already stripped of /api/v1/) */
    const char *path = req->path + 8; /* skip "/api/v1/" */
    const char *method = req->method;

    /* Must start with "config/snapshots" */
    if (strncmp(path, "config/snapshots", 16) != 0)
        return -1; /* not handled */

    const char *rest = path + 16; /* after "config/snapshots" */

    /* GET/POST /api/v1/config/snapshots */
    if (*rest == '\0') {
        if (strcmp(method, "GET") == 0) {
            api_list_snapshots(srv, resp);
            return 0;
        }
        if (strcmp(method, "POST") == 0) {
            api_create_snapshot(srv, req, resp);
            return 0;
        }
        backup_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* rest must start with '/' */
    if (*rest != '/')
        return -1;

    rest++; /* skip '/' */

    /* Extract snapshot ID */
    char id[64];
    const char *slash = strchr(rest, '/');
    if (!slash) {
        /* /api/v1/config/snapshots/{id} */
        fw_strlcpy(id, rest, sizeof(id));

        if (strcmp(method, "GET") == 0) {
            api_get_snapshot(id, resp);
            return 0;
        }
        if (strcmp(method, "DELETE") == 0) {
            api_delete_snapshot(id, resp);
            return 0;
        }
        backup_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* Extract id and sub-resource */
    size_t idlen = (size_t)(slash - rest);
    if (idlen >= sizeof(id)) idlen = sizeof(id) - 1;
    memcpy(id, rest, idlen);
    id[idlen] = '\0';

    const char *sub = slash + 1;

    /* POST /api/v1/config/snapshots/{id}/restore */
    if (strcmp(sub, "restore") == 0 && strcmp(method, "POST") == 0) {
        api_restore_snapshot(srv, id, resp);
        return 0;
    }

    /* GET /api/v1/config/snapshots/{id}/diff */
    if (strcmp(sub, "diff") == 0 && strcmp(method, "GET") == 0) {
        api_diff_snapshot(srv, id, resp);
        return 0;
    }

    backup_error(resp, 404, "Unknown backup endpoint");
    return 0;
}
