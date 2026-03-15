#include "firewallo/api.h"
#include "firewallo/api_common.h"
#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/rollback.h"
#include "firewallo/sysctl.h"
#include "firewallo/validate.h"
#include "firewallo/webhook.h"
#include "firewallo/alias.h"
#include "firewallo/util.h"
#include "firewallo/diff.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static const char API_ERR_FALLBACK[] = "{\"error\":true,\"message\":\"internal error\"}";

void api_error(http_response_t *resp, int status, const char *msg)
{
    json_value_t *envelope = json_new_object();
    if (!envelope) {
        http_response_set_json(resp, status, strdup(API_ERR_FALLBACK));
        return;
    }

    json_value_t *err_val = json_new_bool(1);
    json_value_t *msg_val = json_new_string(msg);

    if (json_object_set(envelope, "error", err_val) != 0) {
        json_free(err_val);
        json_free(msg_val);
        json_free(envelope);
        http_response_set_json(resp, status, strdup(API_ERR_FALLBACK));
        return;
    }
    if (json_object_set(envelope, "message", msg_val) != 0) {
        json_free(msg_val);
        json_free(envelope);
        http_response_set_json(resp, status, strdup(API_ERR_FALLBACK));
        return;
    }

    char *json = json_serialize(envelope, 1);
    json_free(envelope);

    if (!json) {
        http_response_set_json(resp, status, strdup(API_ERR_FALLBACK));
        return;
    }
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

/* Save config to disk after modification */
static int save_config(httpd_t *srv, http_response_t *resp)
{
    if (fw_config_save(srv->config_path, srv->config) != 0) {
        api_error(resp, 500, "Failed to save config");
        return -1;
    }
    return 0;
}

/* Non-static alias for api_vpn.c and other API modules */
int api_save_config(httpd_t *srv, http_response_t *resp)
{
    return save_config(srv, resp);
}

/* Extract path segment after prefix. Returns pointer into path string. */
static const char *path_after(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) == 0)
        return path + plen;
    return NULL;
}

/* Non-static alias for api_vpn.c and other API modules */
const char *api_path_after(const char *path, const char *prefix)
{
    return path_after(path, prefix);
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
    /* Make a copy and redact secrets before serialization */
    fw_config_t redacted = *srv->config;
    for (int i = 0; i < redacted.webhook_count; i++) {
        if (redacted.webhooks[i].secret[0])
            fw_strlcpy(redacted.webhooks[i].secret, "***",
                        sizeof(redacted.webhooks[i].secret));
    }
    /* Redact VPN private keys and PSKs */
    for (int i = 0; i < redacted.vpn_tunnel_count; i++) {
        if (redacted.vpn_tunnels[i].wg_private_key[0])
            fw_strlcpy(redacted.vpn_tunnels[i].wg_private_key, "[REDACTED]",
                        sizeof(redacted.vpn_tunnels[i].wg_private_key));
        if (redacted.vpn_tunnels[i].wg_preshared_key[0])
            fw_strlcpy(redacted.vpn_tunnels[i].wg_preshared_key, "[REDACTED]",
                        sizeof(redacted.vpn_tunnels[i].wg_preshared_key));
        if (redacted.vpn_tunnels[i].ipsec_psk[0])
            fw_strlcpy(redacted.vpn_tunnels[i].ipsec_psk, "[REDACTED]",
                        sizeof(redacted.vpn_tunnels[i].ipsec_psk));
    }
    for (int i = 0; i < redacted.vpn_peer_count; i++) {
        if (redacted.vpn_peers[i].preshared_key[0])
            fw_strlcpy(redacted.vpn_peers[i].preshared_key, "[REDACTED]",
                        sizeof(redacted.vpn_peers[i].preshared_key));
    }

    /* Serialize redacted config directly to memory — no temp files needed */
    char *json = fw_config_serialize(&redacted);
    if (!json) {
        api_error(resp, 500, "Serialization failed");
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

    /* Write body directly to mkstemp fd to avoid predictable temp paths (TOCTOU) */
    char tmp[] = "/tmp/.firewallo_api_XXXXXX";
    int fd = mkstemp(tmp);
    if (fd < 0) {
        api_error(resp, 500, "Failed to create temp file");
        return;
    }

    ssize_t written = write(fd, req->body, req->body_len);
    close(fd);
    if (written < 0 || (size_t)written != req->body_len) {
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

        /* Include schedule if enabled */
        if (r->schedule.enabled) {
            json_value_t *sched = json_new_object();
            json_object_set(sched, "enabled", json_new_bool(1));
            char tbuf[8];
            snprintf(tbuf, sizeof(tbuf), "%02d:%02d",
                     r->schedule.hour_start, r->schedule.minute_start);
            json_object_set(sched, "start", json_new_string(tbuf));
            snprintf(tbuf, sizeof(tbuf), "%02d:%02d",
                     r->schedule.hour_end, r->schedule.minute_end);
            json_object_set(sched, "end", json_new_string(tbuf));

            static const char *day_names[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
            char days_str[64];
            fw_schedule_days_str(r->schedule.days, days_str, sizeof(days_str), day_names, ",");
            json_object_set(sched, "days", json_new_string(days_str));
            json_object_set(obj, "schedule", sched);
        }

        json_array_append(rules, obj);
    }
    json_object_set(data, "rules", rules);

    api_ok_json(resp, data);
}

/* ── GET /api/v1/filter/{chain}/ratelimit ───────────────────────────── */

static void api_get_ratelimit(httpd_t *srv, const char *chain_name, http_response_t *resp)
{
    int idx = fw_config_chain_index(chain_name);
    if (idx < 0) { api_error(resp, 404, "Chain not found"); return; }

    const fw_rate_limit_t *rl = &srv->config->chains[idx].rate_limit;
    json_value_t *data = json_new_object();
    json_object_set(data, "enabled", json_new_bool(rl->enabled));
    json_object_set(data, "max", json_new_number(rl->max_connections));
    json_object_set(data, "period", json_new_number(rl->period_seconds));
    json_object_set(data, "ban", json_new_number(rl->ban_seconds));
    api_ok_json(resp, data);
}

/* ── PUT /api/v1/filter/{chain}/ratelimit ──────────────────────────── */

static void api_put_ratelimit(httpd_t *srv, const char *chain_name,
                               const http_request_t *req, http_response_t *resp)
{
    int idx = fw_config_chain_index(chain_name);
    if (idx < 0) { api_error(resp, 404, "Chain not found"); return; }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    fw_rate_limit_t *rl = &srv->config->chains[idx].rate_limit;

    json_value_t *v;
    v = json_object_get(body, "enabled");
    if (v) rl->enabled = json_bool_value(v);

    v = json_object_get(body, "max");
    if (v && v->type == JSON_NUMBER) {
        int val = (int)json_number_value(v);
        if (val <= 0 && rl->enabled) {
            json_free(body);
            api_error(resp, 400, "max must be positive when enabled");
            return;
        }
        rl->max_connections = val;
    }

    v = json_object_get(body, "period");
    if (v && v->type == JSON_NUMBER) {
        int val = (int)json_number_value(v);
        if (val <= 0 && rl->enabled) {
            json_free(body);
            api_error(resp, 400, "period must be positive when enabled");
            return;
        }
        rl->period_seconds = val;
    }

    v = json_object_get(body, "ban");
    if (v && v->type == JSON_NUMBER) {
        int val = (int)json_number_value(v);
        if (val <= 0 && rl->enabled) {
            json_free(body);
            api_error(resp, 400, "ban must be positive when enabled");
            return;
        }
        rl->ban_seconds = val;
    }

    json_free(body);

    /* When enabling, validate that all required fields have valid values,
     * even if they were not supplied in this request (they may have been
     * left at zero from a previous disabled state). */
    if (rl->enabled) {
        if (rl->max_connections <= 0) {
            api_error(resp, 400, "max must be positive when enabled");
            return;
        }
        if (rl->period_seconds <= 0) {
            api_error(resp, 400, "period must be positive when enabled");
            return;
        }
        if (rl->ban_seconds <= 0) {
            api_error(resp, 400, "ban must be positive when enabled");
            return;
        }
    }

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Rate limit updated");
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

static void api_firewall_action(httpd_t *srv, const char *action,
                                 const http_request_t *req, http_response_t *resp)
{
    /* Check for optional rollback_timeout in request body */
    int rollback_timeout = 0;
    if (req->body && req->body_len > 0) {
        char perr[256];
        json_value_t *body = json_parse(req->body, perr, sizeof(perr));
        if (body) {
            json_value_t *tv = json_object_get(body, "rollback_timeout");
            if (tv && tv->type == JSON_NUMBER)
                rollback_timeout = (int)json_number_value(tv);
            json_free(body);
        }
    }

    /* Set up rollback for start/restart if requested (comment 2) */
    int use_rollback = (rollback_timeout > 0 &&
                        (strcmp(action, "start") == 0 || strcmp(action, "restart") == 0));
    if (use_rollback) {
        fw_rollback_set_context(srv->config, srv->config_path);
        if (fw_rollback_start(rollback_timeout) != 0) {
            api_error(resp, 500, "Failed to start rollback timer");
            return;
        }
    }

    fw_cmdlist_t cmds;
    if (strcmp(action, "start") == 0) {
        char err[256];
        if (fw_config_validate(srv->config, err, sizeof(err)) != 0) {
            if (use_rollback) fw_rollback_cancel();
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
        if (use_rollback) {
            fw_rollback_perform();
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "Command failed at index %d", fail_idx);
        api_error(resp, 500, msg);
        return;
    }

    char msg[128];
    if (use_rollback) {
        snprintf(msg, sizeof(msg),
                 "Firewall %s completed, confirm within %d seconds",
                 action, rollback_timeout);
    } else {
        snprintf(msg, sizeof(msg), "Firewall %s completed", action);
    }
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

/* ── POST /api/v1/firewall/preview ─────────────────────────────────── */

static void api_firewall_preview(httpd_t *srv, http_response_t *resp)
{
    char err[256] = {0};
    if (fw_config_validate(srv->config, err, sizeof(err)) != 0) {
        api_error(resp, 400, err);
        return;
    }

    /* Compile proposed ruleset */
    fw_cmdlist_t cmds;
    fw_compile_start(srv->config, &cmds);

    /* Build commands array */
    json_value_t *cmd_arr = json_new_array();
    for (int i = 0; i < cmds.count; i++) {
        json_value_t *val = json_new_string(cmds.cmds[i].command);
        if (!val || json_array_append(cmd_arr, val) != 0) {
            json_free(val);
            json_free(cmd_arr);
            fw_cmdlist_free(&cmds);
            api_error(resp, 500, "Out of memory building command list");
            return;
        }
    }

    /* Dump commands to string */
    char *dump = malloc(131072);
    if (dump) {
        fw_cmdlist_dump(&cmds, dump, 131072);
    }

    /* Compare two compiled command lists: load saved (on-disk) config,
       compile it, and diff its dump against the proposed dump.
       This ensures both sides use the same format for a meaningful diff. */
    char *diff_buf = NULL;
    {
        fw_config_t saved_cfg;
        char load_err[256];
        if (fw_config_load(srv->config_path, &saved_cfg, load_err,
                           sizeof(load_err)) == 0) {
            fw_cmdlist_t saved_cmds;
            fw_compile_start(&saved_cfg, &saved_cmds);

            char *saved_dump = malloc(131072);
            char *proposed_dump = malloc(131072);
            if (saved_dump && proposed_dump) {
                fw_cmdlist_dump(&saved_cmds, saved_dump, 131072);
                fw_cmdlist_dump(&cmds, proposed_dump, 131072);

                diff_buf = malloc(131072);
                if (diff_buf) {
                    diff_buf[0] = '\0';
                    fw_ruleset_diff(saved_dump, proposed_dump,
                                    diff_buf, 131072);
                }
            }
            free(saved_dump);
            free(proposed_dump);
            fw_cmdlist_free(&saved_cmds);
        }
    }

    /* Build response */
    json_value_t *data = json_new_object();
    json_object_set(data, "command_count", json_new_number(cmds.count));
    json_object_set(data, "commands", cmd_arr);
    if (dump)
        json_object_set(data, "dump", json_new_string(dump));
    if (diff_buf && diff_buf[0])
        json_object_set(data, "diff", json_new_string(diff_buf));
    else
        json_object_set(data, "diff", json_new_string(""));

    free(dump);
    free(diff_buf);
    fw_cmdlist_free(&cmds);

    api_ok_json(resp, data);
}

/* ── POST /api/v1/firewall/confirm ─────────────────────────────────── */

static void api_firewall_confirm(http_response_t *resp)
{
    if (fw_rollback_confirm() != 0) {
        api_error(resp, 400, "No pending rollback to confirm");
        return;
    }
    api_ok_msg(resp, "Configuration confirmed, rollback timer cancelled");
}

/* ── GET /api/v1/firewall/rollback-status ──────────────────────────── */

static void api_firewall_rollback_status(http_response_t *resp)
{
    fw_rollback_state_t state;
    fw_rollback_status(&state);

    json_value_t *data = json_new_object();
    json_object_set(data, "pending", json_new_bool(state.pending));

    if (state.pending) {
        time_t now = time(NULL);
        int remaining = (int)(state.deadline - now);
        if (remaining < 0) remaining = 0;
        json_object_set(data, "remaining_seconds", json_new_number(remaining));
        json_object_set(data, "deadline", json_new_number((double)state.deadline));
    } else {
        json_object_set(data, "remaining_seconds", json_new_number(0));
        json_object_set(data, "deadline", json_new_number(0));
    }

    api_ok_json(resp, data);
}

/* ── GET /api/v1/config/webhooks ───────────────────────────────────── */

static void api_get_webhooks(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *arr = json_new_array();
    for (int i = 0; i < cfg->webhook_count; i++) {
        const fw_webhook_t *w = &cfg->webhooks[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "url", json_new_string(w->url));
        /* Redact secret: show only "***" if set */
        json_object_set(obj, "secret", json_new_string(w->secret[0] ? "***" : ""));
        json_object_set(obj, "events", json_new_number(w->events));
        json_object_set(obj, "enabled", json_new_bool(w->enabled));
        json_object_set(obj, "retry_count", json_new_number(w->retry_count));
        json_object_set(obj, "comment", json_new_string(w->comment));
        json_array_append(arr, obj);
    }
    api_ok_json(resp, arr);
}

/* ── POST /api/v1/config/webhooks ─────────────────────────────────── */

static void api_add_webhook(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    if (cfg->webhook_count >= FW_MAX_WEBHOOKS) {
        api_error(resp, 400, "Max webhooks reached");
        return;
    }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    fw_webhook_t *w = &cfg->webhooks[cfg->webhook_count];
    memset(w, 0, sizeof(*w));

    const char *s;
    s = json_string_value(json_object_get(body, "url"));
    if (!s || !fw_webhook_validate_url(s)) {
        json_free(body);
        api_error(resp, 400, "Invalid or missing 'url'");
        return;
    }
    fw_strlcpy(w->url, s, sizeof(w->url));

    s = json_string_value(json_object_get(body, "secret"));
    if (s) {
        if (!fw_webhook_validate_secret(s)) {
            json_free(body);
            api_error(resp, 400, "Secret contains invalid control characters");
            return;
        }
        fw_strlcpy(w->secret, s, sizeof(w->secret));
    }

    json_value_t *ev = json_object_get(body, "events");
    if (ev && ev->type == JSON_NUMBER)
        w->events = (unsigned int)json_number_value(ev);
    else
        w->events = WH_EVENT_ALL;

    if (!fw_webhook_validate_events(w->events)) {
        json_free(body);
        api_error(resp, 400, "Invalid event mask");
        return;
    }

    json_value_t *en = json_object_get(body, "enabled");
    if (en)
        w->enabled = json_bool_value(en);
    else
        w->enabled = 1;

    json_value_t *rc = json_object_get(body, "retry_count");
    if (rc && rc->type == JSON_NUMBER) {
        int rcv = (int)json_number_value(rc);
        if (rcv < 0 || rcv > FW_MAX_WEBHOOK_RETRY) {
            json_free(body);
            api_error(resp, 400, "retry_count must be 0-5");
            return;
        }
        w->retry_count = rcv;
    } else {
        w->retry_count = 3;
    }

    s = json_string_value(json_object_get(body, "comment"));
    if (s) fw_strlcpy(w->comment, s, sizeof(w->comment));

    json_free(body);

    cfg->webhook_count++;
    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Webhook added");
}

/* ── PUT /api/v1/config/webhooks/{index} ──────────────────────────── */

static void api_update_webhook(httpd_t *srv, int idx,
                                const http_request_t *req, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    if (idx < 0 || idx >= cfg->webhook_count) {
        api_error(resp, 404, "Webhook index out of range");
        return;
    }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    fw_webhook_t *w = &cfg->webhooks[idx];

    const char *s;
    s = json_string_value(json_object_get(body, "url"));
    if (s) {
        if (!fw_webhook_validate_url(s)) {
            json_free(body);
            api_error(resp, 400, "Invalid 'url'");
            return;
        }
        fw_strlcpy(w->url, s, sizeof(w->url));
    }

    s = json_string_value(json_object_get(body, "secret"));
    if (s && strcmp(s, "***") != 0) {
        if (!fw_webhook_validate_secret(s)) {
            json_free(body);
            api_error(resp, 400, "Secret contains invalid control characters");
            return;
        }
        fw_strlcpy(w->secret, s, sizeof(w->secret));
    }
    /* "***" means "unchanged" — skip updating the secret */

    json_value_t *ev = json_object_get(body, "events");
    if (ev && ev->type == JSON_NUMBER) {
        unsigned int events = (unsigned int)json_number_value(ev);
        if (!fw_webhook_validate_events(events)) {
            json_free(body);
            api_error(resp, 400, "Invalid event mask");
            return;
        }
        w->events = events;
    }

    json_value_t *en = json_object_get(body, "enabled");
    if (en) w->enabled = json_bool_value(en);

    json_value_t *rc = json_object_get(body, "retry_count");
    if (rc && rc->type == JSON_NUMBER) {
        int rcv = (int)json_number_value(rc);
        if (rcv < 0 || rcv > FW_MAX_WEBHOOK_RETRY) {
            json_free(body);
            api_error(resp, 400, "retry_count must be 0-5");
            return;
        }
        w->retry_count = rcv;
    }

    s = json_string_value(json_object_get(body, "comment"));
    if (s) fw_strlcpy(w->comment, s, sizeof(w->comment));

    json_free(body);

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Webhook updated");
}

/* ── DELETE /api/v1/config/webhooks/{index} ───────────────────────── */

static void api_delete_webhook(httpd_t *srv, int idx, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    if (idx < 0 || idx >= cfg->webhook_count) {
        api_error(resp, 404, "Webhook index out of range");
        return;
    }

    /* Shift remaining webhooks */
    for (int i = idx; i < cfg->webhook_count - 1; i++)
        cfg->webhooks[i] = cfg->webhooks[i + 1];
    cfg->webhook_count--;

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Webhook deleted");
}

/* ── POST /api/v1/config/webhooks/{index}/test ────────────────────── */

static void api_test_webhook(httpd_t *srv, int idx, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    if (idx < 0 || idx >= cfg->webhook_count) {
        api_error(resp, 404, "Webhook index out of range");
        return;
    }

    int status = fw_webhook_test(&cfg->webhooks[idx]);
    json_value_t *data = json_new_object();
    json_object_set(data, "webhook_index", json_new_number(idx));
    json_object_set(data, "http_status", json_new_number(status));
    json_object_set(data, "success", json_new_bool(status >= 200 && status < 300));
    api_ok_json(resp, data);
}

/* ── GET /api/v1/config/aliases ─────────────────────────────────────── */

static void api_get_aliases(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *arr = json_new_array();
    for (int i = 0; i < cfg->alias_count; i++) {
        const fw_alias_t *a = &cfg->aliases[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "name", json_new_string(a->name));
        json_object_set(obj, "type",
                        json_new_string(a->type == ALIAS_TYPE_PORT ? "port" : "ip"));
        json_value_t *entries = json_new_array();
        for (int e = 0; e < a->entry_count; e++)
            json_array_append(entries, json_new_string(a->entries[e]));
        json_object_set(obj, "entries", entries);
        json_object_set(obj, "comment", json_new_string(a->comment));
        json_array_append(arr, obj);
    }
    api_ok_json(resp, arr);
}

/* ── GET /api/v1/config/aliases/{name} ─────────────────────────────── */

static void api_get_alias(httpd_t *srv, const char *name, http_response_t *resp)
{
    const fw_alias_t *a = fw_alias_find(srv->config, name);
    if (!a) { api_error(resp, 404, "Alias not found"); return; }

    json_value_t *obj = json_new_object();
    json_object_set(obj, "name", json_new_string(a->name));
    json_object_set(obj, "type",
                    json_new_string(a->type == ALIAS_TYPE_PORT ? "port" : "ip"));
    json_value_t *entries = json_new_array();
    for (int e = 0; e < a->entry_count; e++)
        json_array_append(entries, json_new_string(a->entries[e]));
    json_object_set(obj, "entries", entries);
    json_object_set(obj, "comment", json_new_string(a->comment));
    api_ok_json(resp, obj);
}

/* ── POST /api/v1/config/aliases ───────────────────────────────────── */

static void api_create_alias(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    fw_config_t *cfg = srv->config;
    if (cfg->alias_count >= FW_MAX_ALIASES) {
        json_free(body);
        api_error(resp, 400, "Max aliases reached");
        return;
    }

    const char *name = json_string_value(json_object_get(body, "name"));
    if (!name || !fw_alias_validate_name(name)) {
        json_free(body);
        api_error(resp, 400, "Invalid alias name");
        return;
    }

    /* Check duplicate */
    if (fw_alias_find(cfg, name)) {
        json_free(body);
        api_error(resp, 400, "Alias already exists");
        return;
    }

    /* Require explicit valid type */
    const char *type_str = json_string_value(json_object_get(body, "type"));
    if (!type_str || (strcmp(type_str, "ip") != 0 && strcmp(type_str, "port") != 0)) {
        json_free(body);
        api_error(resp, 400, "Field 'type' must be 'ip' or 'port'");
        return;
    }

    fw_alias_t a;
    memset(&a, 0, sizeof(a));
    fw_strlcpy(a.name, name, sizeof(a.name));
    a.type = (strcmp(type_str, "port") == 0) ? ALIAS_TYPE_PORT : ALIAS_TYPE_IP;

    json_value_t *entries = json_object_get(body, "entries");
    if (entries && entries->type == JSON_ARRAY) {
        int n = json_array_count(entries);
        for (int i = 0; i < n && a.entry_count < FW_MAX_ALIAS_ENTRIES; i++) {
            const char *e = json_string_value(json_array_get(entries, i));
            if (e) {
                fw_strlcpy(a.entries[a.entry_count], e, FW_MAX_ADDR);
                a.entry_count++;
            }
        }
    }

    /* Validate entries match type */
    if (a.entry_count == 0) {
        json_free(body);
        api_error(resp, 400, "Alias must have at least one entry");
        return;
    }
    for (int i = 0; i < a.entry_count; i++) {
        if (a.type == ALIAS_TYPE_IP) {
            if (!fw_validate_ipv4(a.entries[i]) &&
                !fw_validate_ipv4_cidr(a.entries[i])) {
                json_free(body);
                api_error(resp, 400, "Invalid IP entry in alias");
                return;
            }
        } else {
            if (!fw_validate_port_single(a.entries[i])) {
                json_free(body);
                api_error(resp, 400, "Invalid port entry in alias (single numeric port required)");
                return;
            }
        }
    }

    const char *comment = json_string_value(json_object_get(body, "comment"));
    if (comment) fw_strlcpy(a.comment, comment, sizeof(a.comment));

    cfg->aliases[cfg->alias_count] = a;
    cfg->alias_count++;
    json_free(body);

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Alias created");
}

/* ── PUT /api/v1/config/aliases/{name} ─────────────────────────────── */

static void api_update_alias(httpd_t *srv, const char *name,
                              const http_request_t *req, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    fw_alias_t *a = NULL;
    for (int i = 0; i < cfg->alias_count; i++) {
        if (strcmp(cfg->aliases[i].name, name) == 0) {
            a = &cfg->aliases[i];
            break;
        }
    }
    if (!a) { api_error(resp, 404, "Alias not found"); return; }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    /* Parse and validate entries before applying */
    json_value_t *entries = json_object_get(body, "entries");
    if (entries && entries->type == JSON_ARRAY) {
        /* Validate entries in a temporary buffer before overwriting */
        char tmp_entries[FW_MAX_ALIAS_ENTRIES][FW_MAX_ADDR];
        int tmp_count = 0;
        int n = json_array_count(entries);
        for (int i = 0; i < n && tmp_count < FW_MAX_ALIAS_ENTRIES; i++) {
            const char *e = json_string_value(json_array_get(entries, i));
            if (e) {
                fw_strlcpy(tmp_entries[tmp_count], e, FW_MAX_ADDR);
                tmp_count++;
            }
        }
        if (tmp_count == 0) {
            json_free(body);
            api_error(resp, 400, "Alias must have at least one entry");
            return;
        }
        for (int i = 0; i < tmp_count; i++) {
            if (a->type == ALIAS_TYPE_IP) {
                if (!fw_validate_ipv4(tmp_entries[i]) &&
                    !fw_validate_ipv4_cidr(tmp_entries[i])) {
                    json_free(body);
                    api_error(resp, 400, "Invalid IP entry in alias");
                    return;
                }
            } else {
                if (!fw_validate_port_single(tmp_entries[i])) {
                    json_free(body);
                    api_error(resp, 400, "Invalid port entry in alias (single numeric port required)");
                    return;
                }
            }
        }
        /* Validation passed, apply entries */
        a->entry_count = tmp_count;
        for (int i = 0; i < tmp_count; i++)
            fw_strlcpy(a->entries[i], tmp_entries[i], FW_MAX_ADDR);
    }

    /* Update comment if provided */
    const char *comment = json_string_value(json_object_get(body, "comment"));
    if (comment) fw_strlcpy(a->comment, comment, sizeof(a->comment));

    json_free(body);

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Alias updated");
}

/* ── DELETE /api/v1/config/aliases/{name} ──────────────────────────── */

static void api_delete_alias(httpd_t *srv, const char *name, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    int found = -1;
    for (int i = 0; i < cfg->alias_count; i++) {
        if (strcmp(cfg->aliases[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    if (found < 0) { api_error(resp, 404, "Alias not found"); return; }

    /* Check if alias is referenced by any filter rules */
    if (fw_alias_is_referenced(cfg, name)) {
        api_error(resp, 409, "Alias is referenced by filter rules and cannot be deleted");
        return;
    }

    /* Remove by shifting */
    for (int i = found; i < cfg->alias_count - 1; i++)
        cfg->aliases[i] = cfg->aliases[i + 1];
    cfg->alias_count--;

    if (save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Alias deleted");
}

/* ── Main API dispatcher ──────────────────────────────────────────── */

int api_handle(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    const char *path = req->path + 8; /* skip "/api/v1/" */
    const char *method = req->method;
    const char *sub;

    /* GET /api/v1/version */
    if (strcmp(path, "version") == 0 && strcmp(method, "GET") == 0) {
        api_version(srv, resp);
        return 0;
    }

    /* Backup/snapshot endpoints: /api/v1/config/snapshots... */
    if (strncmp(path, "config/snapshots", 16) == 0) {
        return api_handle_backup(srv, req, resp);
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

    /* GET/POST /api/v1/config/webhooks */
    if (strcmp(path, "config/webhooks") == 0) {
        if (strcmp(method, "GET") == 0) api_get_webhooks(srv, resp);
        else if (strcmp(method, "POST") == 0) api_add_webhook(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* PUT/DELETE /api/v1/config/webhooks/{index}[/test] */
    if ((sub = path_after(path, "config/webhooks/")) != NULL) {
        /* Extract the index segment and parse with strtol */
        const char *slash = strchr(sub, '/');
        const char *idx_str = sub;
        char idx_buf[8];
        if (slash) {
            size_t ilen = (size_t)(slash - sub);
            if (ilen == 0 || ilen >= sizeof(idx_buf)) {
                api_error(resp, 400, "Invalid webhook index");
                return 0;
            }
            memcpy(idx_buf, sub, ilen);
            idx_buf[ilen] = '\0';
            idx_str = idx_buf;
        }

        char *endptr = NULL;
        long widx_l = strtol(idx_str, &endptr, 10);
        if (endptr == idx_str || *endptr != '\0' ||
            widx_l < 0 || widx_l > FW_MAX_WEBHOOKS) {
            api_error(resp, 400, "Invalid webhook index");
            return 0;
        }
        int widx = (int)widx_l;

        if (slash) {
            if (strcmp(slash + 1, "test") == 0 && strcmp(method, "POST") == 0) {
                api_test_webhook(srv, widx, resp);
                return 0;
            }
        } else {
            if (strcmp(method, "PUT") == 0) {
                api_update_webhook(srv, widx, req, resp);
                return 0;
            }
            if (strcmp(method, "DELETE") == 0) {
                api_delete_webhook(srv, widx, resp);
                return 0;
            }
        }
        api_error(resp, 404, "Webhook endpoint not found");
        return 0;
    }

    /* GET/POST /api/v1/config/aliases */
    if (strcmp(path, "config/aliases") == 0) {
        if (strcmp(method, "GET") == 0) api_get_aliases(srv, resp);
        else if (strcmp(method, "POST") == 0) api_create_alias(srv, req, resp);
        else api_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* GET/PUT/DELETE /api/v1/config/aliases/{name} */
    if ((sub = path_after(path, "config/aliases/")) != NULL) {
        char alias_name[FW_MAX_ALIAS_NAME];
        fw_strlcpy(alias_name, sub, sizeof(alias_name));
        if (strcmp(method, "GET") == 0) api_get_alias(srv, alias_name, resp);
        else if (strcmp(method, "PUT") == 0) api_update_alias(srv, alias_name, req, resp);
        else if (strcmp(method, "DELETE") == 0) api_delete_alias(srv, alias_name, resp);
        else api_error(resp, 405, "Method not allowed");
        return 0;
    }

    /* GET /api/v1/filter */
    if (strcmp(path, "filter") == 0 && strcmp(method, "GET") == 0) {
        api_get_filter_overview(srv, resp);
        return 0;
    }

    /* GET /api/v1/filter/{chain} */
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

        /* GET/PUT /api/v1/filter/{chain}/ratelimit */
        if (strcmp(resource, "ratelimit") == 0) {
            if (strcmp(method, "GET") == 0)
                api_get_ratelimit(srv, chain_name, resp);
            else if (strcmp(method, "PUT") == 0)
                api_put_ratelimit(srv, chain_name, req, resp);
            else
                api_error(resp, 405, "Method not allowed");
            return 0;
        }

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
            char *endptr;
            long port_val = strtol(port_str, &endptr, 10);
            if (*endptr != '\0' || endptr == port_str) {
                api_error(resp, 400, "Invalid port number");
                return 0;
            }
            if (!fw_validate_port((int)port_val)) {
                api_error(resp, 400, "Invalid port (1-65535)");
                return 0;
            }
            api_delete_port(srv, chain_name, (int)port_val, 1, resp);
            return 0;
        }
        if ((port_str = path_after(resource, "udp/")) != NULL && strcmp(method, "DELETE") == 0) {
            char *endptr;
            long port_val = strtol(port_str, &endptr, 10);
            if (*endptr != '\0' || endptr == port_str) {
                api_error(resp, 400, "Invalid port number");
                return 0;
            }
            if (!fw_validate_port((int)port_val)) {
                api_error(resp, 400, "Invalid port (1-65535)");
                return 0;
            }
            api_delete_port(srv, chain_name, (int)port_val, 0, resp);
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
        if (strcmp(sub, "preview") == 0 && strcmp(method, "POST") == 0) {
            api_firewall_preview(srv, resp);
            return 0;
        }
        if (strcmp(sub, "confirm") == 0 && strcmp(method, "POST") == 0) {
            api_firewall_confirm(resp);
            return 0;
        }
        if (strcmp(sub, "rollback-status") == 0 && strcmp(method, "GET") == 0) {
            api_firewall_rollback_status(resp);
            return 0;
        }
        if (strcmp(method, "POST") == 0) {
            /* sub is start/stop/restart/reset */
            char action[16];
            fw_strlcpy(action, sub, sizeof(action));
            api_firewall_action(srv, action, req, resp);
            return 0;
        }
    }

    /* GET /api/v1/validate */
    if (strcmp(path, "validate") == 0 && strcmp(method, "GET") == 0) {
        api_validate(srv, resp);
        return 0;
    }

    /* /api/v1/monitor/... */
    if ((sub = path_after(path, "monitor/")) != NULL) {
        return api_handle_monitor(srv, req, resp, sub);
    }

    /* /api/v1/vpn/... */
    if (strncmp(path, "vpn/", 4) == 0 || strcmp(path, "vpn") == 0) {
        if (api_handle_vpn(srv, req, resp, path, method))
            return 0;
    }

    api_error(resp, 404, "API endpoint not found");
    return 0;
}
