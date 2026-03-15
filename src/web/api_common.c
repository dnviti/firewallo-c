#include "firewallo/api_common.h"
#include "firewallo/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Shared API response helpers ──────────────────────────────────── */

void api_error(http_response_t *resp, int status, const char *msg)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(1));
    json_object_set(envelope, "message", json_new_string(msg));
    char *json = json_serialize(envelope, 0);
    json_free(envelope);
    http_response_set_json(resp, status, json);
}

void api_ok_json(http_response_t *resp, json_value_t *data)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(0));
    json_object_set(envelope, "data", data);
    char *json = json_serialize(envelope, 1);
    json_free(envelope);
    http_response_set_json(resp, 200, json);
}

void api_ok_msg(http_response_t *resp, const char *msg)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "message", json_new_string(msg));
    api_ok_json(resp, data);
}

int api_save_config(httpd_t *srv, http_response_t *resp)
{
    if (fw_config_save(srv->config_path, srv->config) != 0) {
        api_error(resp, 500, "Failed to save config");
        return -1;
    }
    return 0;
}

const char *api_path_after(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) == 0)
        return path + plen;
    return NULL;
}

int api_read_sysctl(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int val = 0;
    if (fscanf(f, "%d", &val) != 1) val = -1;
    fclose(f);
    return val;
}
