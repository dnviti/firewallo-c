#include "firewallo/api_common.h"
#include "firewallo/ifinfo.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* ── Convert one fw_ifinfo_t to a JSON object ─────────────────────── */

static const char *type_name(int type)
{
    switch (type) {
    case FW_IFTYPE_ETHERNET: return "ethernet";
    case FW_IFTYPE_LOOPBACK: return "loopback";
    default:                 return "other";
    }
}

static json_value_t *ifinfo_to_json(const fw_ifinfo_t *info)
{
    json_value_t *obj = json_new_object();
    json_object_set(obj, "name",      json_new_string(info->name));
    json_object_set(obj, "state",     json_new_string(info->state));
    json_object_set(obj, "mac",       json_new_string(info->mac));
    json_object_set(obj, "mtu",       json_new_number(info->mtu));
    json_object_set(obj, "speed",     json_new_number(info->speed));
    json_object_set(obj, "type",      json_new_number(info->type));
    json_object_set(obj, "type_name", json_new_string(type_name(info->type)));

    /* Addresses */
    json_value_t *addrs = json_new_array();
    for (int i = 0; i < info->addr_count; i++) {
        json_value_t *a = json_new_object();
        json_object_set(a, "address", json_new_string(info->addrs[i].address));
        json_object_set(a, "netmask", json_new_string(info->addrs[i].netmask));
        json_object_set(a, "family",
                        json_new_string(info->addrs[i].family == 2 ? "ipv4" : "ipv6"));
        json_array_append(addrs, a);
    }
    json_object_set(obj, "addresses", addrs);

    /* Statistics — serialize as strings to avoid double precision loss >2^53 */
    json_value_t *stats = json_new_object();
    char sbuf[32];
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.rx_bytes);
    json_object_set(stats, "rx_bytes",   json_new_string(sbuf));
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.tx_bytes);
    json_object_set(stats, "tx_bytes",   json_new_string(sbuf));
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.rx_packets);
    json_object_set(stats, "rx_packets", json_new_string(sbuf));
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.tx_packets);
    json_object_set(stats, "tx_packets", json_new_string(sbuf));
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.rx_errors);
    json_object_set(stats, "rx_errors",  json_new_string(sbuf));
    snprintf(sbuf, sizeof(sbuf), "%" PRIu64, info->stats.tx_errors);
    json_object_set(stats, "tx_errors",  json_new_string(sbuf));
    json_object_set(obj, "stats", stats);

    return obj;
}

/* ── GET /api/v1/system/interfaces ────────────────────────────────── */

static void api_get_system_interfaces(http_response_t *resp)
{
    fw_ifinfo_list_t list;
    if (fw_ifinfo_list(&list) != 0) {
        api_error(resp, 500, "Failed to enumerate interfaces");
        return;
    }

    json_value_t *arr = json_new_array();
    for (int i = 0; i < list.count; i++)
        json_array_append(arr, ifinfo_to_json(&list.ifaces[i]));

    api_ok_json(resp, arr);
}

/* ── GET /api/v1/system/interfaces/{name} ─────────────────────────── */

static void api_get_system_interface(const char *name, http_response_t *resp)
{
    fw_ifinfo_t info;
    if (fw_ifinfo_get(name, &info) != 0) {
        api_error(resp, 404, "Interface not found");
        return;
    }
    api_ok_json(resp, ifinfo_to_json(&info));
}

/* ── System domain dispatcher ─────────────────────────────────────── */

int api_handle_system(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method)
{
    (void)srv;
    (void)req;

    if (strcmp(method, "GET") != 0)
        return 0;

    /* GET /api/v1/system/interfaces */
    if (strcmp(path, "system/interfaces") == 0) {
        api_get_system_interfaces(resp);
        return 1;
    }

    /* GET /api/v1/system/interfaces/{name} */
    const char *iface_name = api_path_after(path, "system/interfaces/");
    if (iface_name && iface_name[0]) {
        api_get_system_interface(iface_name, resp);
        return 1;
    }

    return 0;
}
