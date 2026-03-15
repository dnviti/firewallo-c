#include "firewallo/api_common.h"
#include "firewallo/config.h"
#include "firewallo/validate.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── GET /api/v1/version ──────────────────────────────────────────── */

static void api_version(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "version", json_new_string(srv->config->version));
    json_object_set(data, "backend",
                    json_new_string(srv->config->backend == BACKEND_NFT ? "nft" : "ipt"));
    api_ok_json(resp, data);
}

/* ── GET/PUT /api/v1/config ───────────────────────────────────────── */

static void api_get_config(httpd_t *srv, http_response_t *resp)
{
    const char *tmp = "/tmp/.firewallo_api_cfg.json";
    if (fw_config_save(tmp, srv->config) != 0) {
        api_error(resp, 500, "Serialization failed");
        return;
    }
    size_t len;
    char *json = fw_read_file(tmp, &len);
    remove(tmp);
    if (!json) {
        api_error(resp, 500, "Read failed");
        return;
    }

    char parse_err[256];
    json_value_t *cfg_json = json_parse(json, parse_err, sizeof(parse_err));
    free(json);
    if (!cfg_json) {
        api_error(resp, 500, "Parse error");
        return;
    }
    api_ok_json(resp, cfg_json);
}

static void api_put_config(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    if (!req->body || req->body_len == 0) {
        api_error(resp, 400, "Empty body");
        return;
    }

    const char *tmp = "/tmp/.firewallo_api_put.json";
    if (fw_write_file(tmp, req->body, req->body_len) != 0) {
        api_error(resp, 500, "Write failed");
        return;
    }

    fw_config_t new_cfg;
    char err[256];
    if (fw_config_load(tmp, &new_cfg, err, sizeof(err)) != 0) {
        remove(tmp);
        api_error(resp, 400, err);
        return;
    }
    remove(tmp);

    if (fw_config_validate(&new_cfg, err, sizeof(err)) != 0) {
        api_error(resp, 400, err);
        return;
    }

    *srv->config = new_cfg;
    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Configuration updated");
}

/* ── GET /api/v1/config/interfaces ────────────────────────────────── */

static void api_get_interfaces(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *data = json_new_object();

    json_value_t *lan = json_new_array();
    for (int i = 0; i < cfg->lan_if_count; i++)
        json_array_append(lan, json_new_string(cfg->lan_ifs[i]));
    json_object_set(data, "lan", lan);

    json_value_t *wan = json_new_array();
    for (int i = 0; i < cfg->wan_if_count; i++)
        json_array_append(wan, json_new_string(cfg->wan_ifs[i]));
    json_object_set(data, "wan", wan);

    json_value_t *dmz = json_new_array();
    for (int i = 0; i < cfg->dmz_if_count; i++)
        json_array_append(dmz, json_new_string(cfg->dmz_ifs[i]));
    json_object_set(data, "dmz", dmz);

    json_value_t *vpn = json_new_array();
    for (int i = 0; i < cfg->vpn_if_count; i++)
        json_array_append(vpn, json_new_string(cfg->vpn_ifs[i]));
    json_object_set(data, "vpn", vpn);

    api_ok_json(resp, data);
}

/* ── GET /api/v1/config/dns ───────────────────────────────────────── */

static void api_get_dns(httpd_t *srv, http_response_t *resp)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < srv->config->dns_count; i++)
        json_array_append(arr, json_new_string(srv->config->dns[i]));
    api_ok_json(resp, arr);
}

/* ── GET/PUT /api/v1/config/backend ───────────────────────────────── */

static void api_get_backend(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "backend",
                    json_new_string(srv->config->backend == BACKEND_NFT ? "nft" : "ipt"));
    api_ok_json(resp, data);
}

static void api_put_backend(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    const char *val = json_string_value(json_object_get(body, "backend"));
    if (!val) {
        json_free(body);
        api_error(resp, 400, "Missing 'backend' field");
        return;
    }

    if (strcmp(val, "nft") == 0)
        srv->config->backend = BACKEND_NFT;
    else if (strcmp(val, "ipt") == 0)
        srv->config->backend = BACKEND_IPT;
    else {
        json_free(body);
        api_error(resp, 400, "Backend must be 'nft' or 'ipt'");
        return;
    }
    json_free(body);

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Backend updated");
}

/* ── GET /api/v1/validate ─────────────────────────────────────────── */

static void api_validate(httpd_t *srv, http_response_t *resp)
{
    char err[256] = {0};
    int valid = fw_config_validate(srv->config, err, sizeof(err)) == 0;

    json_value_t *data = json_new_object();
    json_object_set(data, "valid", json_new_bool(valid));
    if (!valid)
        json_object_set(data, "error", json_new_string(err));

    fw_cmdlist_t cmds;
    fw_compile_start(srv->config, &cmds);
    json_object_set(data, "command_count", json_new_number(cmds.count));
    fw_cmdlist_free(&cmds);

    api_ok_json(resp, data);
}

/* ── Config domain dispatcher ─────────────────────────────────────── */

int api_handle_config(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method)
{
    if (strcmp(path, "version") == 0 && strcmp(method, "GET") == 0) {
        api_version(srv, resp);
        return 1;
    }

    if (strcmp(path, "config") == 0) {
        if (strcmp(method, "GET") == 0) api_get_config(srv, resp);
        else if (strcmp(method, "PUT") == 0) api_put_config(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 1;
    }

    if (strcmp(path, "config/interfaces") == 0 && strcmp(method, "GET") == 0) {
        api_get_interfaces(srv, resp);
        return 1;
    }

    if (strcmp(path, "config/dns") == 0 && strcmp(method, "GET") == 0) {
        api_get_dns(srv, resp);
        return 1;
    }

    if (strcmp(path, "config/backend") == 0) {
        if (strcmp(method, "GET") == 0) api_get_backend(srv, resp);
        else if (strcmp(method, "PUT") == 0) api_put_backend(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 1;
    }

    if (strcmp(path, "validate") == 0 && strcmp(method, "GET") == 0) {
        api_validate(srv, resp);
        return 1;
    }

    return 0; /* not handled */
}
