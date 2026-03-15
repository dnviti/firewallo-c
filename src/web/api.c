#include "firewallo/api.h"
#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static void api_error(http_response_t *resp, int status, const char *msg)
{
    char *buf = malloc(256);
    snprintf(buf, 256, "{\"error\":true,\"message\":\"%s\"}", msg);
    http_response_set_json(resp, status, buf);
}

static void api_ok_json(http_response_t *resp, json_value_t *data)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(0));
    json_object_set(envelope, "data", data);
    char *json = json_serialize(envelope, 1);
    json_free(envelope);
    http_response_set_json(resp, 200, json);
}

static void api_ok_msg(http_response_t *resp, const char *msg)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "message", json_new_string(msg));
    api_ok_json(resp, data);
}

/* Save config to disk after modification */
static int save_config(httpd_t *srv, http_response_t *resp)
{
    if (fw_config_save(srv->config_path, srv->config) != 0) {
        api_error(resp, 500, "Failed to save config");
        return -1;
    }
    return 0;
}

/* Extract path segment after prefix. Returns pointer into path string. */
static const char *path_after(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) == 0)
        return path + plen;
    return NULL;
}

/* ── GET /api/v1/version ───────────────────────────────────────────── */

static void api_version(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "version", json_new_string(srv->config->version));
    json_object_set(data, "backend",
                    json_new_string(srv->config->backend == BACKEND_NFT ? "nft" : "ipt"));
    api_ok_json(resp, data);
}

/* ── GET/PUT /api/v1/config ────────────────────────────────────────── */

static void api_get_config(httpd_t *srv, http_response_t *resp)
{
    /* Serialize config via mkstemp to avoid predictable temp file paths */
    char tmp[] = "/tmp/.firewallo_api_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) {
        api_error(resp, 500, "Failed to create temp file");
        return;
    }
    close(fd);
    if (fw_config_save(tmp, srv->config) != 0) {
        unlink(tmp);
        api_error(resp, 500, "Serialization failed");
        return;
    }
    size_t len;
    char *json = fw_read_file(tmp, &len);
    unlink(tmp);
    if (!json) {
        api_error(resp, 500, "Read failed");
        return;
    }

    /* Wrap in envelope */
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

    /* Write body to mkstemp temp file to avoid predictable paths (TOCTOU) */
    char tmp[] = "/tmp/.firewallo_api_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) {
        api_error(resp, 500, "Failed to create temp file");
        return;
    }
    close(fd);
    if (fw_write_file(tmp, req->body, req->body_len) != 0) {
        unlink(tmp);
        api_error(resp, 500, "Write failed");
        return;
    }

    fw_config_t new_cfg;
    char err[256];
    if (fw_config_load(tmp, &new_cfg, err, sizeof(err)) != 0) {
        unlink(tmp);
        api_error(resp, 400, err);
        return;
    }
    unlink(tmp);

    if (fw_config_validate(&new_cfg, err, sizeof(err)) != 0) {
        api_error(resp, 400, err);
        return;
    }

    *srv->config = new_cfg;
    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Configuration updated");
}

/* ── GET/PUT /api/v1/config/interfaces ─────────────────────────────── */

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

/* ── GET/PUT /api/v1/config/dns ────────────────────────────────────── */

static void api_get_dns(httpd_t *srv, http_response_t *resp)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < srv->config->dns_count; i++)
        json_array_append(arr, json_new_string(srv->config->dns[i]));
    api_ok_json(resp, arr);
}

/* ── GET /api/v1/config/backend ────────────────────────────────────── */

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

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Backend updated");
}

/* ── GET /api/v1/filter ────────────────────────────────────────────── */

static void api_get_filter_overview(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    for (int i = 0; i < FW_CHAIN_COUNT; i++) {
        const fw_chain_t *ch = &srv->config->chains[i];
        json_value_t *info = json_new_object();
        json_object_set(info, "tcp_count", json_new_number(ch->tcp_port_count));
        json_object_set(info, "udp_count", json_new_number(ch->udp_port_count));
        json_object_set(info, "rule_count", json_new_number(ch->rule_count));
        json_object_set(data, ch->name, info);
    }
    api_ok_json(resp, data);
}

/* ── GET /api/v1/filter/{chain} ────────────────────────────────────── */

static void api_get_filter_chain(httpd_t *srv, const char *chain_name, http_response_t *resp)
{
    int idx = fw_config_chain_index(chain_name);
    if (idx < 0) {
        api_error(resp, 404, "Chain not found");
        return;
    }

    const fw_chain_t *ch = &srv->config->chains[idx];
    json_value_t *data = json_new_object();
    json_object_set(data, "name", json_new_string(ch->name));

    json_value_t *tcp = json_new_array();
    for (int i = 0; i < ch->tcp_port_count; i++)
        json_array_append(tcp, json_new_number(ch->tcp_ports[i]));
    json_object_set(data, "tcp_ports", tcp);

    json_value_t *udp = json_new_array();
    for (int i = 0; i < ch->udp_port_count; i++)
        json_array_append(udp, json_new_number(ch->udp_ports[i]));
    json_object_set(data, "udp_ports", udp);

    json_value_t *rules = json_new_array();
    for (int i = 0; i < ch->rule_count; i++) {
        const fw_filter_rule_t *r = &ch->rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "src_addr", json_new_string(r->src_addr));
        json_object_set(obj, "dst_addr", json_new_string(r->dst_addr));
        json_object_set(obj, "protocol", json_new_string(r->protocol == PROTO_UDP ? "udp" : "tcp"));
        json_object_set(obj, "dst_port", json_new_number(r->dst_port.start));
        json_object_set(obj, "action", json_new_string(
            r->action == ACTION_DROP ? "drop" : r->action == ACTION_REJECT ? "reject" : "accept"));
        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(rules, obj);
    }
    json_object_set(data, "rules", rules);

    api_ok_json(resp, data);
}

/* ── POST /api/v1/filter/{chain}/tcp ───────────────────────────────── */

static void api_add_port(httpd_t *srv, const char *chain_name,
                          const http_request_t *req, int is_tcp, http_response_t *resp)
{
    int idx = fw_config_chain_index(chain_name);
    if (idx < 0) { api_error(resp, 404, "Chain not found"); return; }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    json_value_t *pv = json_object_get(body, "port");
    if (!pv || pv->type != JSON_NUMBER) {
        json_free(body);
        api_error(resp, 400, "Missing 'port' field");
        return;
    }
    int port = (int)json_number_value(pv);
    json_free(body);

    if (!fw_validate_port(port)) {
        api_error(resp, 400, "Invalid port (1-65535)");
        return;
    }

    fw_chain_t *ch = &srv->config->chains[idx];
    int *ports = is_tcp ? ch->tcp_ports : ch->udp_ports;
    int *count = is_tcp ? &ch->tcp_port_count : &ch->udp_port_count;

    /* Check duplicate */
    for (int i = 0; i < *count; i++) {
        if (ports[i] == port) {
            api_error(resp, 400, "Port already exists");
            return;
        }
    }

    if (*count >= FW_MAX_PORTS) {
        api_error(resp, 400, "Max ports reached");
        return;
    }

    ports[(*count)++] = port;
    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Port added");
}

/* ── DELETE /api/v1/filter/{chain}/tcp/{port} ──────────────────────── */

static void api_delete_port(httpd_t *srv, const char *chain_name,
                             int port, int is_tcp, http_response_t *resp)
{
    int idx = fw_config_chain_index(chain_name);
    if (idx < 0) { api_error(resp, 404, "Chain not found"); return; }

    fw_chain_t *ch = &srv->config->chains[idx];
    int *ports = is_tcp ? ch->tcp_ports : ch->udp_ports;
    int *count = is_tcp ? &ch->tcp_port_count : &ch->udp_port_count;

    int found = -1;
    for (int i = 0; i < *count; i++) {
        if (ports[i] == port) { found = i; break; }
    }
    if (found < 0) {
        api_error(resp, 404, "Port not found");
        return;
    }

    /* Remove by shifting */
    for (int i = found; i < *count - 1; i++)
        ports[i] = ports[i + 1];
    (*count)--;

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Port removed");
}

/* ── GET /api/v1/nat ───────────────────────────────────────────────── */

static void api_get_nat(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *data = json_new_object();

    json_value_t *post = json_new_array();
    for (int i = 0; i < cfg->nat_post_count; i++) {
        json_value_t *obj = json_new_object();
        json_object_set(obj, "src", json_new_string(cfg->nat_post[i].src));
        json_object_set(obj, "oif", json_new_string(cfg->nat_post[i].oif));
        json_object_set(obj, "type", json_new_string(
            cfg->nat_post[i].type == NAT_SNAT ? "snat" : "masquerade"));
        json_object_set(obj, "comment", json_new_string(cfg->nat_post[i].comment));
        json_array_append(post, obj);
    }
    json_object_set(data, "postrouting", post);

    json_value_t *pre = json_new_array();
    for (int i = 0; i < cfg->nat_pre_count; i++) {
        json_value_t *obj = json_new_object();
        json_object_set(obj, "iif", json_new_string(cfg->nat_pre[i].iif));
        json_object_set(obj, "protocol", json_new_string(
            cfg->nat_pre[i].protocol == PROTO_UDP ? "udp" : "tcp"));
        json_object_set(obj, "dport", json_new_number(cfg->nat_pre[i].dport));
        json_object_set(obj, "to_dest_ip", json_new_string(cfg->nat_pre[i].to_dest_ip));
        json_object_set(obj, "to_dest_port", json_new_number(cfg->nat_pre[i].to_dest_port));
        json_object_set(obj, "comment", json_new_string(cfg->nat_pre[i].comment));
        json_array_append(pre, obj);
    }
    json_object_set(data, "prerouting", pre);

    api_ok_json(resp, data);
}

/* ── POST /api/v1/firewall/{action} ───────────────────────────────── */

static void api_firewall_action(httpd_t *srv, const char *action, http_response_t *resp)
{
    fw_cmdlist_t cmds;
    if (strcmp(action, "start") == 0) {
        char err[256];
        if (fw_config_validate(srv->config, err, sizeof(err)) != 0) {
            api_error(resp, 400, err);
            return;
        }
        fw_sysctl_apply(srv->config);
        fw_compile_start(srv->config, &cmds);
    } else if (strcmp(action, "stop") == 0) {
        fw_compile_stop(srv->config, &cmds);
    } else if (strcmp(action, "restart") == 0) {
        fw_cmdlist_t stop_cmds;
        fw_compile_stop(srv->config, &stop_cmds);
        int fail_idx;
        fw_cmdlist_exec(&stop_cmds, &fail_idx);
        fw_cmdlist_free(&stop_cmds);

        fw_sysctl_apply(srv->config);
        fw_compile_start(srv->config, &cmds);
    } else if (strcmp(action, "reset") == 0) {
        fw_compile_reset(srv->config, &cmds);
    } else {
        api_error(resp, 404, "Unknown firewall action");
        return;
    }

    int fail_idx;
    int ret = fw_cmdlist_exec(&cmds, &fail_idx);
    fw_cmdlist_free(&cmds);

    if (ret != 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Command failed at index %d", fail_idx);
        api_error(resp, 500, msg);
        return;
    }

    char msg[64];
    snprintf(msg, sizeof(msg), "Firewall %s completed", action);
    api_ok_msg(resp, msg);
}

/* ── GET /api/v1/firewall/status ───────────────────────────────────── */

static void api_firewall_status(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "backend",
                    json_new_string(srv->config->backend == BACKEND_NFT ? "nft" : "ipt"));
    json_object_set(data, "version", json_new_string(srv->config->version));

    char buf[4096] = {0};
    int active = 0;
    if (srv->config->backend == BACKEND_NFT) {
        fw_exec_capture("/usr/sbin/nft list tables 2>/dev/null", buf, sizeof(buf));
        active = strstr(buf, "filter") != NULL;
    } else {
        fw_exec_capture("/sbin/iptables -L -n 2>/dev/null | head -3", buf, sizeof(buf));
        active = strstr(buf, "DROP") != NULL;
    }
    json_object_set(data, "active", json_new_bool(active));

    api_ok_json(resp, data);
}

/* ── GET /api/v1/firewall/rules ────────────────────────────────────── */

static void api_firewall_rules(httpd_t *srv, http_response_t *resp)
{
    char buf[65536] = {0};
    if (srv->config->backend == BACKEND_NFT)
        fw_exec_capture("/usr/sbin/nft list ruleset 2>/dev/null", buf, sizeof(buf));
    else
        fw_exec_capture("/sbin/iptables -L -n -v 2>/dev/null", buf, sizeof(buf));

    json_value_t *data = json_new_object();
    json_object_set(data, "ruleset", json_new_string(buf));
    api_ok_json(resp, data);
}

/* ── GET /api/v1/validate ──────────────────────────────────────────── */

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

/* ── Main API dispatcher ──────────────────────────────────────────── */

int api_handle(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    const char *path = req->path + 8; /* skip "/api/v1/" */
    const char *method = req->method;

    /* GET /api/v1/version */
    if (strcmp(path, "version") == 0 && strcmp(method, "GET") == 0) {
        api_version(srv, resp);
        return 0;
    }

    /* GET/PUT /api/v1/config */
    if (strcmp(path, "config") == 0) {
        if (strcmp(method, "GET") == 0) api_get_config(srv, resp);
        else if (strcmp(method, "PUT") == 0) api_put_config(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* GET /api/v1/config/interfaces */
    if (strcmp(path, "config/interfaces") == 0 && strcmp(method, "GET") == 0) {
        api_get_interfaces(srv, resp);
        return 0;
    }

    /* GET /api/v1/config/dns */
    if (strcmp(path, "config/dns") == 0 && strcmp(method, "GET") == 0) {
        api_get_dns(srv, resp);
        return 0;
    }

    /* GET/PUT /api/v1/config/backend */
    if (strcmp(path, "config/backend") == 0) {
        if (strcmp(method, "GET") == 0) api_get_backend(srv, resp);
        else if (strcmp(method, "PUT") == 0) api_put_backend(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* GET /api/v1/filter */
    if (strcmp(path, "filter") == 0 && strcmp(method, "GET") == 0) {
        api_get_filter_overview(srv, resp);
        return 0;
    }

    /* GET /api/v1/filter/{chain} */
    const char *sub;
    if ((sub = path_after(path, "filter/")) != NULL) {
        /* Parse chain name and sub-resource */
        char chain_name[32];
        const char *slash = strchr(sub, '/');

        if (!slash) {
            /* GET /api/v1/filter/{chain} */
            fw_strlcpy(chain_name, sub, sizeof(chain_name));
            if (strcmp(method, "GET") == 0)
                api_get_filter_chain(srv, chain_name, resp);
            else
                api_error(resp, 405, "Method not allowed");
            return 0;
        }

        /* Extract chain name */
        size_t clen = (size_t)(slash - sub);
        if (clen >= sizeof(chain_name)) clen = sizeof(chain_name) - 1;
        memcpy(chain_name, sub, clen);
        chain_name[clen] = '\0';

        const char *resource = slash + 1;

        /* POST /api/v1/filter/{chain}/tcp */
        if (strcmp(resource, "tcp") == 0 && strcmp(method, "POST") == 0) {
            api_add_port(srv, chain_name, req, 1, resp);
            return 0;
        }
        /* POST /api/v1/filter/{chain}/udp */
        if (strcmp(resource, "udp") == 0 && strcmp(method, "POST") == 0) {
            api_add_port(srv, chain_name, req, 0, resp);
            return 0;
        }

        /* DELETE /api/v1/filter/{chain}/tcp/{port} */
        const char *port_str;
        if ((port_str = path_after(resource, "tcp/")) != NULL && strcmp(method, "DELETE") == 0) {
            api_delete_port(srv, chain_name, atoi(port_str), 1, resp);
            return 0;
        }
        if ((port_str = path_after(resource, "udp/")) != NULL && strcmp(method, "DELETE") == 0) {
            api_delete_port(srv, chain_name, atoi(port_str), 0, resp);
            return 0;
        }
    }

    /* GET /api/v1/nat */
    if (strcmp(path, "nat") == 0 && strcmp(method, "GET") == 0) {
        api_get_nat(srv, resp);
        return 0;
    }

    /* POST /api/v1/firewall/{action} */
    if ((sub = path_after(path, "firewall/")) != NULL) {
        if (strcmp(sub, "status") == 0 && strcmp(method, "GET") == 0) {
            api_firewall_status(srv, resp);
            return 0;
        }
        if (strcmp(sub, "rules") == 0 && strcmp(method, "GET") == 0) {
            api_firewall_rules(srv, resp);
            return 0;
        }
        if (strcmp(method, "POST") == 0) {
            /* sub is start/stop/restart/reset */
            char action[16];
            fw_strlcpy(action, sub, sizeof(action));
            api_firewall_action(srv, action, resp);
            return 0;
        }
    }

    /* GET /api/v1/validate */
    if (strcmp(path, "validate") == 0 && strcmp(method, "GET") == 0) {
        api_validate(srv, resp);
        return 0;
    }

    api_error(resp, 404, "API endpoint not found");
    return 0;
}
