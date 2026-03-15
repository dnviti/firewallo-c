#include "firewallo/api.h"
#include "firewallo/config.h"
#include "firewallo/counters.h"
#include "firewallo/json.h"
#include "firewallo/util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static void mon_error(http_response_t *resp, int status, const char *msg)
{
    char *buf = malloc(256);
    snprintf(buf, 256, "{\"error\":true,\"message\":\"%s\"}", msg);
    http_response_set_json(resp, status, buf);
}

static void mon_ok_json(http_response_t *resp, json_value_t *data)
{
    json_value_t *envelope = json_new_object();
    json_object_set(envelope, "error", json_new_bool(0));
    json_object_set(envelope, "data", data);
    char *json = json_serialize(envelope, 1);
    json_free(envelope);
    http_response_set_json(resp, 200, json);
}

static void mon_ok_msg(http_response_t *resp, const char *msg)
{
    json_value_t *data = json_new_object();
    json_object_set(data, "message", json_new_string(msg));
    mon_ok_json(resp, data);
}

/* Format uint64_t as string to avoid double precision loss */
static json_value_t *u64_to_json_string(uint64_t val)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%" PRIu64, val);
    return json_new_string(buf);
}

/* Build JSON array from counter data */
static json_value_t *counters_to_json(const fw_counter_data_t *data)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < data->count; i++) {
        const fw_rule_counter_t *rc = &data->rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "chain", json_new_string(rc->chain));
        json_object_set(obj, "rule_index", json_new_number(rc->rule_index));
        json_object_set(obj, "packets", u64_to_json_string(rc->packets));
        json_object_set(obj, "bytes", u64_to_json_string(rc->bytes));
        json_array_append(arr, obj);
    }
    return arr;
}

/* ── GET /api/v1/monitor/counters ──────────────────────────────────── */

static void api_monitor_counters(httpd_t *srv, http_response_t *resp)
{
    fw_counter_data_t data;
    if (fw_counters_collect(srv->config->backend, &data) != 0) {
        mon_error(resp, 500, "Failed to collect counters");
        return;
    }

    json_value_t *result = json_new_object();
    json_object_set(result, "collected_at", json_new_number((double)data.collected_at));
    json_object_set(result, "counters", counters_to_json(&data));
    mon_ok_json(resp, result);
}

/* ── GET /api/v1/monitor/counters/{chain} ──────────────────────────── */

static void api_monitor_chain_counters(httpd_t *srv, const char *chain, http_response_t *resp)
{
    /* Validate chain name against known chains */
    if (fw_config_chain_index(chain) < 0) {
        mon_error(resp, 404, "Unknown chain name");
        return;
    }

    fw_counter_data_t data;
    if (fw_counters_collect(srv->config->backend, &data) != 0) {
        mon_error(resp, 500, "Failed to collect counters");
        return;
    }

    json_value_t *result = json_new_object();
    json_object_set(result, "chain", json_new_string(chain));
    json_object_set(result, "collected_at", json_new_number((double)data.collected_at));

    json_value_t *arr = json_new_array();
    for (int i = 0; i < data.count; i++) {
        if (strcmp(data.rules[i].chain, chain) == 0) {
            const fw_rule_counter_t *rc = &data.rules[i];
            json_value_t *obj = json_new_object();
            json_object_set(obj, "rule_index", json_new_number(rc->rule_index));
            json_object_set(obj, "packets", u64_to_json_string(rc->packets));
            json_object_set(obj, "bytes", u64_to_json_string(rc->bytes));
            json_array_append(arr, obj);
        }
    }
    json_object_set(result, "counters", arr);
    mon_ok_json(resp, result);
}

/* ── POST /api/v1/monitor/counters/reset ───────────────────────────── */

static void api_monitor_reset(httpd_t *srv, http_response_t *resp)
{
    if (fw_counters_reset(srv->config->backend) != 0) {
        mon_error(resp, 500, "Failed to reset counters");
        return;
    }
    mon_ok_msg(resp, "Counters reset");
}

/* ── GET /api/v1/monitor/top-rules?limit=N ─────────────────────────── */

static int cmp_packets_desc(const void *a, const void *b)
{
    const fw_rule_counter_t *ra = (const fw_rule_counter_t *)a;
    const fw_rule_counter_t *rb = (const fw_rule_counter_t *)b;
    if (rb->packets > ra->packets) return 1;
    if (rb->packets < ra->packets) return -1;
    return 0;
}

static void api_monitor_top_rules(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    fw_counter_data_t data;
    if (fw_counters_collect(srv->config->backend, &data) != 0) {
        mon_error(resp, 500, "Failed to collect counters");
        return;
    }

    /* Parse limit from query string: "limit=N" */
    int limit = 10; /* default */
    if (req->query[0]) {
        const char *lp = strstr(req->query, "limit=");
        if (lp) {
            char *endptr;
            errno = 0;
            long val = strtol(lp + 6, &endptr, 10);
            if (endptr != lp + 6 && errno == 0 &&
                val > 0 && val <= FW_MAX_COUNTERS)
                limit = (int)val;
        }
    }

    /* Sort by packets descending */
    qsort(data.rules, (size_t)data.count, sizeof(fw_rule_counter_t), cmp_packets_desc);

    json_value_t *result = json_new_object();
    json_object_set(result, "collected_at", json_new_number((double)data.collected_at));
    json_object_set(result, "limit", json_new_number(limit));

    json_value_t *arr = json_new_array();
    int n = data.count < limit ? data.count : limit;
    for (int i = 0; i < n; i++) {
        const fw_rule_counter_t *rc = &data.rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "chain", json_new_string(rc->chain));
        json_object_set(obj, "rule_index", json_new_number(rc->rule_index));
        json_object_set(obj, "packets", u64_to_json_string(rc->packets));
        json_object_set(obj, "bytes", u64_to_json_string(rc->bytes));
        json_array_append(arr, obj);
    }
    json_object_set(result, "top_rules", arr);
    mon_ok_json(resp, result);
}

/* ── GET /api/v1/monitor/zero-hit ──────────────────────────────────── */

static void api_monitor_zero_hit(httpd_t *srv, http_response_t *resp)
{
    fw_counter_data_t data;
    if (fw_counters_collect(srv->config->backend, &data) != 0) {
        mon_error(resp, 500, "Failed to collect counters");
        return;
    }

    json_value_t *result = json_new_object();
    json_object_set(result, "collected_at", json_new_number((double)data.collected_at));

    json_value_t *arr = json_new_array();
    int zero_count = 0;
    for (int i = 0; i < data.count; i++) {
        if (data.rules[i].packets == 0) {
            const fw_rule_counter_t *rc = &data.rules[i];
            json_value_t *obj = json_new_object();
            json_object_set(obj, "chain", json_new_string(rc->chain));
            json_object_set(obj, "rule_index", json_new_number(rc->rule_index));
            json_object_set(obj, "packets", u64_to_json_string(rc->packets));
            json_object_set(obj, "bytes", u64_to_json_string(rc->bytes));
            json_array_append(arr, obj);
            zero_count++;
        }
    }
    json_object_set(result, "zero_hit_count", json_new_number(zero_count));
    json_object_set(result, "zero_hit_rules", arr);
    mon_ok_json(resp, result);
}

/* ── Monitor API dispatcher ───────────────────────────────────────── */

int api_handle_monitor(httpd_t *srv, const http_request_t *req,
                       http_response_t *resp, const char *sub)
{
    const char *method = req->method;

    /* GET /api/v1/monitor/counters */
    if (strcmp(sub, "counters") == 0 && strcmp(method, "GET") == 0) {
        api_monitor_counters(srv, resp);
        return 0;
    }

    /* POST /api/v1/monitor/counters/reset */
    if (strcmp(sub, "counters/reset") == 0 && strcmp(method, "POST") == 0) {
        api_monitor_reset(srv, resp);
        return 0;
    }

    /* GET /api/v1/monitor/counters/{chain} */
    if (strncmp(sub, "counters/", 9) == 0 && strcmp(method, "GET") == 0) {
        const char *chain = sub + 9;
        if (chain[0]) {
            api_monitor_chain_counters(srv, chain, resp);
            return 0;
        }
    }

    /* GET /api/v1/monitor/top-rules */
    if (strcmp(sub, "top-rules") == 0 && strcmp(method, "GET") == 0) {
        api_monitor_top_rules(srv, req, resp);
        return 0;
    }

    /* GET /api/v1/monitor/zero-hit */
    if (strcmp(sub, "zero-hit") == 0 && strcmp(method, "GET") == 0) {
        api_monitor_zero_hit(srv, resp);
        return 0;
    }

    mon_error(resp, 404, "Monitor endpoint not found");
    return 0;
}
