#include "firewallo/api_common.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <string.h>

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

/* ── GET /api/v1/firewall/status ──────────────────────────────────── */

static void api_firewall_status(httpd_t *srv, http_response_t *resp)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "backend",
                    json_new_string(srv->config->backend == BACKEND_NFT ? "nft" : "ipt"));
    json_object_set(data, "version", json_new_string(srv->config->version));

    /* Detect if firewallo rules are active by looking for the unique
     * "stato" chain that only firewallo creates. */
    char buf[8192] = {0};
    int active = 0;
    if (srv->config->backend == BACKEND_NFT) {
        fw_exec_capture("nft list chains 2>/dev/null", buf, sizeof(buf));
        active = strstr(buf, "stato") != NULL;
    } else {
        fw_exec_capture("iptables -L -n 2>/dev/null", buf, sizeof(buf));
        active = strstr(buf, "stato") != NULL;
    }
    json_object_set(data, "active", json_new_bool(active));

    /* Live sysctl values from the running kernel */
    json_value_t *live_sysctl = json_new_object();
    json_object_set(live_sysctl, "ip_forward",
        json_new_bool(api_read_sysctl("/proc/sys/net/ipv4/ip_forward") == 1));
    json_object_set(live_sysctl, "ip_dynaddr",
        json_new_bool(api_read_sysctl("/proc/sys/net/ipv4/ip_dynaddr") == 1));
    json_object_set(live_sysctl, "tcp_syncookies",
        json_new_bool(api_read_sysctl("/proc/sys/net/ipv4/tcp_syncookies") == 1));
    json_object_set(live_sysctl, "accept_source_route",
        json_new_bool(api_read_sysctl("/proc/sys/net/ipv4/conf/all/accept_source_route") == 1));
    json_object_set(data, "live_sysctl", live_sysctl);

    api_ok_json(resp, data);
}

/* ── GET /api/v1/firewall/rules ───────────────────────────────────── */

static void api_firewall_rules(httpd_t *srv, http_response_t *resp)
{
    char buf[65536] = {0};
    if (srv->config->backend == BACKEND_NFT)
        fw_exec_capture("nft list ruleset 2>/dev/null", buf, sizeof(buf));
    else
        fw_exec_capture("iptables -L -n -v 2>/dev/null", buf, sizeof(buf));

    json_value_t *data = json_new_object();
    json_object_set(data, "ruleset", json_new_string(buf));
    api_ok_json(resp, data);
}

/* ── GET /api/v1/nat ──────────────────────────────────────────────── */

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

/* ── Firewall domain dispatcher ───────────────────────────────────── */

int api_handle_firewall(httpd_t *srv, const http_request_t *req,
                        http_response_t *resp, const char *path, const char *method)
{
    (void)req;
    /* GET /api/v1/nat */
    if (strcmp(path, "nat") == 0 && strcmp(method, "GET") == 0) {
        api_get_nat(srv, resp);
        return 1;
    }

    /* firewall sub-routes */
    const char *sub;
    if ((sub = api_path_after(path, "firewall/")) != NULL) {
        if (strcmp(sub, "status") == 0 && strcmp(method, "GET") == 0) {
            api_firewall_status(srv, resp);
            return 1;
        }
        if (strcmp(sub, "rules") == 0 && strcmp(method, "GET") == 0) {
            api_firewall_rules(srv, resp);
            return 1;
        }
        if (strcmp(method, "POST") == 0) {
            char action[16];
            fw_strlcpy(action, sub, sizeof(action));
            api_firewall_action(srv, action, resp);
            return 1;
        }
    }

    return 0; /* not handled */
}
