#include "firewallo/api_common.h"
#include "firewallo/config.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── GET /api/v1/filter ───────────────────────────────────────────── */

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

/* ── GET /api/v1/filter/{chain} ───────────────────────────────────── */

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

/* ── POST /api/v1/filter/{chain}/tcp|udp ──────────────────────────── */

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
    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Port added");
}

/* ── DELETE /api/v1/filter/{chain}/tcp|udp/{port} ─────────────────── */

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

    for (int i = found; i < *count - 1; i++)
        ports[i] = ports[i + 1];
    (*count)--;

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Port removed");
}

/* ── Filter domain dispatcher ─────────────────────────────────────── */

int api_handle_filter(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method)
{
    if (strcmp(path, "filter") == 0 && strcmp(method, "GET") == 0) {
        api_get_filter_overview(srv, resp);
        return 1;
    }

    const char *sub;
    if ((sub = api_path_after(path, "filter/")) != NULL) {
        char chain_name[32];
        const char *slash = strchr(sub, '/');

        if (!slash) {
            fw_strlcpy(chain_name, sub, sizeof(chain_name));
            if (strcmp(method, "GET") == 0)
                api_get_filter_chain(srv, chain_name, resp);
            else
                api_error(resp, 405, "Method not allowed");
            return 1;
        }

        size_t clen = (size_t)(slash - sub);
        if (clen >= sizeof(chain_name)) clen = sizeof(chain_name) - 1;
        memcpy(chain_name, sub, clen);
        chain_name[clen] = '\0';

        const char *resource = slash + 1;

        if (strcmp(resource, "tcp") == 0 && strcmp(method, "POST") == 0) {
            api_add_port(srv, chain_name, req, 1, resp);
            return 1;
        }
        if (strcmp(resource, "udp") == 0 && strcmp(method, "POST") == 0) {
            api_add_port(srv, chain_name, req, 0, resp);
            return 1;
        }

        const char *port_str;
        if ((port_str = api_path_after(resource, "tcp/")) != NULL && strcmp(method, "DELETE") == 0) {
            api_delete_port(srv, chain_name, atoi(port_str), 1, resp);
            return 1;
        }
        if ((port_str = api_path_after(resource, "udp/")) != NULL && strcmp(method, "DELETE") == 0) {
            api_delete_port(srv, chain_name, atoi(port_str), 0, resp);
            return 1;
        }
    }

    return 0; /* not handled */
}
