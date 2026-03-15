#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/validate.h"
#include "firewallo/webhook.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Chain name table ──────────────────────────────────────────────── */

/* Pre-computed chain names: chains[src * ZONE_COUNT + dst] */
static const char *chain_names[FW_CHAIN_COUNT] = {
    "fw2fw",    "fw2lan",    "fw2wan",    "fw2dmz",    "fw2vpns",
    "lan2fw",   "lan2lan",   "lan2wan",   "lan2dmz",   "lan2vpns",
    "wan2fw",   "wan2lan",   "wan2wan",   "wan2dmz",   "wan2vpns",
    "dmz2fw",   "dmz2lan",   "dmz2wan",   "dmz2dmz",   "dmz2vpns",
    "vpns2fw",  "vpns2lan",  "vpns2wan",  "vpns2dmz",  "vpns2vpns"
};

static const char *json_chain_keys[FW_CHAIN_COUNT] = {
    "fw2fw",    "fw2lan",    "fw2wan",    "fw2dmz",    "fw2vpns",
    "lan2fw",   "lan2lan",   "lan2wan",   "lan2dmz",   "lan2vpns",
    "wan2fw",   "wan2lan",   "wan2wan",   "wan2dmz",   "wan2vpns",
    "dmz2fw",   "dmz2lan",   "dmz2wan",   "dmz2dmz",   "dmz2vpns",
    "vpns2fw",  "vpns2lan",  "vpns2wan",  "vpns2dmz",  "vpns2vpns"
};

int fw_config_chain_index(const char *name)
{
    for (int i = 0; i < FW_CHAIN_COUNT; i++) {
        if (strcmp(chain_names[i], name) == 0)
            return i;
    }
    return -1;
}

const char *fw_config_chain_name(fw_zone_t src, fw_zone_t dst)
{
    int idx = src * ZONE_COUNT + dst;
    if (idx < 0 || idx >= FW_CHAIN_COUNT)
        return NULL;
    return chain_names[idx];
}

/* ── Init ──────────────────────────────────────────────────────────── */

void fw_config_init(fw_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    fw_strlcpy(cfg->version, "2.0.0", sizeof(cfg->version));
    cfg->language = LANG_EN;
    cfg->backend = BACKEND_NFT;
    cfg->ip_forward = 1;
    cfg->ip_dynaddr = 1;
    cfg->tcp_syncookies = 1;
    cfg->accept_source_route = 0;

    /* Initialize chain names */
    for (int i = 0; i < FW_CHAIN_COUNT; i++)
        fw_strlcpy(cfg->chains[i].name, chain_names[i], sizeof(cfg->chains[i].name));
}

/* ── JSON → Config helpers ─────────────────────────────────────────── */

static void load_string_array(const json_value_t *arr,
                              char out[][FW_MAX_ADDR], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        const char *s = json_string_value(json_array_get(arr, i));
        if (s) {
            fw_strlcpy(out[*count], s, FW_MAX_ADDR);
            (*count)++;
        }
    }
}

static void load_if_array(const json_value_t *arr,
                          char out[][FW_MAX_IF_NAME], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        const char *s = json_string_value(json_array_get(arr, i));
        if (s) {
            fw_strlcpy(out[*count], s, FW_MAX_IF_NAME);
            (*count)++;
        }
    }
}

static void load_int_array(const json_value_t *arr, int out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *item = json_array_get(arr, i);
        if (item && item->type == JSON_NUMBER) {
            out[*count] = (int)json_number_value(item);
            (*count)++;
        }
    }
}

static fw_action_t parse_action(const char *s)
{
    if (!s) return ACTION_ACCEPT;
    if (strcmp(s, "drop") == 0) return ACTION_DROP;
    if (strcmp(s, "reject") == 0) return ACTION_REJECT;
    return ACTION_ACCEPT;
}

static fw_proto_t parse_protocol(const char *s)
{
    if (s && strcmp(s, "udp") == 0) return PROTO_UDP;
    return PROTO_TCP;
}

static fw_port_t parse_port_field(const json_value_t *v)
{
    fw_port_t p = {0, 0};
    if (!v) return p;
    if (v->type == JSON_NUMBER) {
        p.start = (int)json_number_value(v);
    } else if (v->type == JSON_STRING) {
        const char *s = json_string_value(v);
        if (s && strcmp(s, "any") == 0) {
            p.start = 0; /* 0 = any */
        } else if (s) {
            const char *colon = strchr(s, ':');
            if (colon) {
                p.start = atoi(s);
                p.end = atoi(colon + 1);
            } else {
                p.start = atoi(s);
            }
        }
    }
    return p;
}

static void load_filter_rules(const json_value_t *arr, fw_filter_rule_t out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *rule = json_array_get(arr, i);
        if (!rule || rule->type != JSON_OBJECT) continue;

        fw_filter_rule_t *r = &out[*count];
        memset(r, 0, sizeof(*r));

        const char *s;
        s = json_string_value(json_object_get(rule, "src_addr"));
        if (s) fw_strlcpy(r->src_addr, s, sizeof(r->src_addr));

        s = json_string_value(json_object_get(rule, "dst_addr"));
        if (s) fw_strlcpy(r->dst_addr, s, sizeof(r->dst_addr));

        s = json_string_value(json_object_get(rule, "protocol"));
        r->protocol = parse_protocol(s);

        r->src_port = parse_port_field(json_object_get(rule, "src_port"));
        r->dst_port = parse_port_field(json_object_get(rule, "dst_port"));

        s = json_string_value(json_object_get(rule, "action"));
        r->action = parse_action(s);

        s = json_string_value(json_object_get(rule, "comment"));
        if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

        /* Parse schedule if present */
        json_value_t *sched = json_object_get(rule, "schedule");
        if (sched && sched->type == JSON_OBJECT) {
            json_value_t *en = json_object_get(sched, "enabled");
            if (en) r->schedule.enabled = json_bool_value(en);

            /* Parse start time "HH:MM" */
            s = json_string_value(json_object_get(sched, "start"));
            if (s) {
                int hh = 0, mm = 0;
                if (sscanf(s, "%d:%d", &hh, &mm) == 2) {
                    r->schedule.hour_start = hh;
                    r->schedule.minute_start = mm;
                }
            }

            /* Parse end time "HH:MM" */
            s = json_string_value(json_object_get(sched, "end"));
            if (s) {
                int hh = 0, mm = 0;
                if (sscanf(s, "%d:%d", &hh, &mm) == 2) {
                    r->schedule.hour_end = hh;
                    r->schedule.minute_end = mm;
                }
            }

            /* Parse days as comma-separated names */
            s = json_string_value(json_object_get(sched, "days"));
            if (s) {
                r->schedule.days = 0;
                const char *day_names[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
                /* Work on a copy to tokenize */
                char days_buf[128];
                fw_strlcpy(days_buf, s, sizeof(days_buf));
                char *tok = strtok(days_buf, ",");
                while (tok) {
                    /* Trim leading spaces */
                    while (*tok == ' ') tok++;
                    for (int d = 0; d < 7; d++) {
                        if (strncmp(tok, day_names[d], 3) == 0) {
                            r->schedule.days |= (unsigned char)(1 << d);
                            break;
                        }
                    }
                    tok = strtok(NULL, ",");
                }
            }
        }

        (*count)++;
    }
}

static void load_nat_post(const json_value_t *arr, fw_nat_post_t out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *rule = json_array_get(arr, i);
        if (!rule || rule->type != JSON_OBJECT) continue;

        fw_nat_post_t *r = &out[*count];
        memset(r, 0, sizeof(*r));

        const char *s;
        s = json_string_value(json_object_get(rule, "src"));
        if (s) fw_strlcpy(r->src, s, sizeof(r->src));

        s = json_string_value(json_object_get(rule, "oif"));
        if (s) fw_strlcpy(r->oif, s, sizeof(r->oif));

        s = json_string_value(json_object_get(rule, "type"));
        if (s) {
            if (strcmp(s, "snat") == 0) r->type = NAT_SNAT;
            else r->type = NAT_MASQUERADE;
        }

        r->dport = parse_port_field(json_object_get(rule, "dport"));

        s = json_string_value(json_object_get(rule, "to_source"));
        if (s) fw_strlcpy(r->to_source, s, sizeof(r->to_source));

        s = json_string_value(json_object_get(rule, "comment"));
        if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

        (*count)++;
    }
}

static void load_nat_pre(const json_value_t *arr, fw_nat_pre_t out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *rule = json_array_get(arr, i);
        if (!rule || rule->type != JSON_OBJECT) continue;

        fw_nat_pre_t *r = &out[*count];
        memset(r, 0, sizeof(*r));

        const char *s;
        s = json_string_value(json_object_get(rule, "src"));
        if (s) fw_strlcpy(r->src, s, sizeof(r->src));

        s = json_string_value(json_object_get(rule, "iif"));
        if (s) fw_strlcpy(r->iif, s, sizeof(r->iif));

        s = json_string_value(json_object_get(rule, "protocol"));
        r->protocol = parse_protocol(s);

        json_value_t *dp = json_object_get(rule, "dport");
        if (dp && dp->type == JSON_NUMBER)
            r->dport = (int)json_number_value(dp);

        s = json_string_value(json_object_get(rule, "to_dest_ip"));
        if (s) fw_strlcpy(r->to_dest_ip, s, sizeof(r->to_dest_ip));

        json_value_t *tdp = json_object_get(rule, "to_dest_port");
        if (tdp && tdp->type == JSON_NUMBER)
            r->to_dest_port = (int)json_number_value(tdp);

        s = json_string_value(json_object_get(rule, "comment"));
        if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

        (*count)++;
    }
}

static void load_mangle_rules(const json_value_t *arr, fw_mangle_rule_t out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *rule = json_array_get(arr, i);
        if (!rule || rule->type != JSON_OBJECT) continue;

        fw_mangle_rule_t *r = &out[*count];
        memset(r, 0, sizeof(*r));

        const char *s;
        s = json_string_value(json_object_get(rule, "iif"));
        if (s) fw_strlcpy(r->iif, s, sizeof(r->iif));

        s = json_string_value(json_object_get(rule, "src_addr"));
        if (s) fw_strlcpy(r->src_addr, s, sizeof(r->src_addr));

        s = json_string_value(json_object_get(rule, "dst_addr"));
        if (s) fw_strlcpy(r->dst_addr, s, sizeof(r->dst_addr));

        s = json_string_value(json_object_get(rule, "protocol"));
        r->protocol = parse_protocol(s);

        json_value_t *dp = json_object_get(rule, "dport");
        if (dp && dp->type == JSON_NUMBER)
            r->dport = (int)json_number_value(dp);

        s = json_string_value(json_object_get(rule, "mark"));
        if (s) fw_strlcpy(r->mark, s, sizeof(r->mark));

        s = json_string_value(json_object_get(rule, "comment"));
        if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

        (*count)++;
    }
}

static void load_routes(const json_value_t *arr, fw_route_t out[], int *count, int max)
{
    *count = 0;
    int n = json_array_count(arr);
    for (int i = 0; i < n && *count < max; i++) {
        json_value_t *route = json_array_get(arr, i);
        if (!route || route->type != JSON_OBJECT) continue;

        fw_route_t *r = &out[*count];
        memset(r, 0, sizeof(*r));

        const char *s;
        s = json_string_value(json_object_get(route, "destination"));
        if (s) fw_strlcpy(r->destination, s, sizeof(r->destination));

        s = json_string_value(json_object_get(route, "gateway"));
        if (s) fw_strlcpy(r->gateway, s, sizeof(r->gateway));

        s = json_string_value(json_object_get(route, "interface"));
        if (s) fw_strlcpy(r->interface, s, sizeof(r->interface));

        s = json_string_value(json_object_get(route, "comment"));
        if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

        (*count)++;
    }
}

/* ── Load ──────────────────────────────────────────────────────────── */

int fw_config_load(const char *path, fw_config_t *cfg, char *err, size_t errlen)
{
    fw_config_init(cfg);

    size_t flen;
    char *text = fw_read_file(path, &flen);
    if (!text) {
        snprintf(err, errlen, "cannot read config file: %s", path);
        return -1;
    }

    char parse_err[256] = {0};
    json_value_t *root = json_parse(text, parse_err, sizeof(parse_err));
    free(text);

    if (!root) {
        snprintf(err, errlen, "JSON parse error: %s", parse_err);
        return -1;
    }

    if (root->type != JSON_OBJECT) {
        json_free(root);
        snprintf(err, errlen, "config root must be a JSON object");
        return -1;
    }

    /* Version */
    const char *s;
    s = json_string_value(json_object_get(root, "version"));
    if (s) fw_strlcpy(cfg->version, s, sizeof(cfg->version));

    /* Language */
    s = json_string_value(json_object_get(root, "language"));
    if (s && strcmp(s, "it") == 0)
        cfg->language = LANG_IT;
    else
        cfg->language = LANG_EN;

    /* Backend */
    s = json_string_value(json_object_get(root, "backend"));
    if (s && strcmp(s, "ipt") == 0)
        cfg->backend = BACKEND_IPT;
    else
        cfg->backend = BACKEND_NFT;

    /* Interfaces */
    json_value_t *ifs = json_object_get(root, "interfaces");
    if (ifs && ifs->type == JSON_OBJECT) {
        load_if_array(json_object_get(ifs, "lan"), cfg->lan_ifs, &cfg->lan_if_count, FW_MAX_INTERFACES);
        load_if_array(json_object_get(ifs, "wan"), cfg->wan_ifs, &cfg->wan_if_count, FW_MAX_INTERFACES);
        load_if_array(json_object_get(ifs, "dmz"), cfg->dmz_ifs, &cfg->dmz_if_count, FW_MAX_INTERFACES);
        load_if_array(json_object_get(ifs, "vpn"), cfg->vpn_ifs, &cfg->vpn_if_count, FW_MAX_INTERFACES);
    }

    /* DNS */
    load_string_array(json_object_get(root, "dns_servers"),
                      cfg->dns, &cfg->dns_count, FW_MAX_DNS);

    /* Ranges */
    json_value_t *ranges = json_object_get(root, "ranges");
    if (ranges && ranges->type == JSON_OBJECT) {
        load_string_array(json_object_get(ranges, "lan"),
                          cfg->lan_ranges, &cfg->lan_range_count, FW_MAX_RANGES);
        load_string_array(json_object_get(ranges, "dmz"),
                          cfg->dmz_ranges, &cfg->dmz_range_count, FW_MAX_RANGES);
    }

    /* Sysctl */
    json_value_t *sysctl = json_object_get(root, "sysctl");
    if (sysctl && sysctl->type == JSON_OBJECT) {
        json_value_t *v;
        v = json_object_get(sysctl, "ip_forward");
        if (v) cfg->ip_forward = json_bool_value(v);
        v = json_object_get(sysctl, "ip_dynaddr");
        if (v) cfg->ip_dynaddr = json_bool_value(v);
        v = json_object_get(sysctl, "tcp_syncookies");
        if (v) cfg->tcp_syncookies = json_bool_value(v);
        v = json_object_get(sysctl, "accept_source_route");
        if (v) cfg->accept_source_route = json_bool_value(v);
    }

    /* Filter chains */
    json_value_t *filter = json_object_get(root, "filter");
    if (filter && filter->type == JSON_OBJECT) {
        for (int i = 0; i < FW_CHAIN_COUNT; i++) {
            json_value_t *chain = json_object_get(filter, json_chain_keys[i]);
            if (!chain || chain->type != JSON_OBJECT)
                continue;

            load_int_array(json_object_get(chain, "tcp_ports"),
                           cfg->chains[i].tcp_ports, &cfg->chains[i].tcp_port_count, FW_MAX_PORTS);
            load_int_array(json_object_get(chain, "udp_ports"),
                           cfg->chains[i].udp_ports, &cfg->chains[i].udp_port_count, FW_MAX_PORTS);
            load_filter_rules(json_object_get(chain, "rules"),
                              cfg->chains[i].rules, &cfg->chains[i].rule_count, FW_MAX_RULES);

            /* Rate limit */
            json_value_t *rl = json_object_get(chain, "rate_limit");
            if (rl && rl->type == JSON_OBJECT) {
                json_value_t *v;
                v = json_object_get(rl, "enabled");
                if (v) cfg->chains[i].rate_limit.enabled = json_bool_value(v);
                v = json_object_get(rl, "max");
                if (v && v->type == JSON_NUMBER)
                    cfg->chains[i].rate_limit.max_connections = (int)json_number_value(v);
                v = json_object_get(rl, "period");
                if (v && v->type == JSON_NUMBER)
                    cfg->chains[i].rate_limit.period_seconds = (int)json_number_value(v);
                v = json_object_get(rl, "ban");
                if (v && v->type == JSON_NUMBER)
                    cfg->chains[i].rate_limit.ban_seconds = (int)json_number_value(v);
            }
        }
    }

    /* NAT */
    json_value_t *nat = json_object_get(root, "nat");
    if (nat && nat->type == JSON_OBJECT) {
        load_nat_post(json_object_get(nat, "postrouting"),
                      cfg->nat_post, &cfg->nat_post_count, FW_MAX_NAT);
        load_nat_pre(json_object_get(nat, "prerouting"),
                     cfg->nat_pre, &cfg->nat_pre_count, FW_MAX_NAT);
    }

    /* Mangle */
    json_value_t *mangle = json_object_get(root, "mangle");
    if (mangle && mangle->type == JSON_OBJECT) {
        load_mangle_rules(json_object_get(mangle, "prerouting"),
                          cfg->mangle_pre, &cfg->mangle_pre_count, FW_MAX_MANGLE);
        load_mangle_rules(json_object_get(mangle, "postrouting"),
                          cfg->mangle_post, &cfg->mangle_post_count, FW_MAX_MANGLE);
    }

    /* Routes */
    load_routes(json_object_get(root, "routes"),
                cfg->routes, &cfg->route_count, FW_MAX_ROUTES);

    /* DPI */
    json_value_t *dpi = json_object_get(root, "dpi");
    if (dpi && dpi->type == JSON_OBJECT) {
        json_value_t *en = json_object_get(dpi, "enabled");
        if (en) cfg->dpi_enabled = json_bool_value(en);
        /* DPI rules use the same structure as filter rules */
        json_value_t *drules = json_object_get(dpi, "rules");
        if (drules && drules->type == JSON_ARRAY) {
            cfg->dpi_rule_count = 0;
            int n = json_array_count(drules);
            for (int i = 0; i < n && cfg->dpi_rule_count < FW_MAX_RULES; i++) {
                json_value_t *rule = json_array_get(drules, i);
                if (!rule || rule->type != JSON_OBJECT) continue;
                fw_dpi_rule_t *r = &cfg->dpi_rules[cfg->dpi_rule_count];
                memset(r, 0, sizeof(*r));

                const char *rs;
                rs = json_string_value(json_object_get(rule, "src_addr"));
                if (rs) fw_strlcpy(r->src_addr, rs, sizeof(r->src_addr));
                rs = json_string_value(json_object_get(rule, "dst_addr"));
                if (rs) fw_strlcpy(r->dst_addr, rs, sizeof(r->dst_addr));
                rs = json_string_value(json_object_get(rule, "protocol"));
                r->protocol = parse_protocol(rs);
                r->src_port = parse_port_field(json_object_get(rule, "src_port"));
                r->dst_port = parse_port_field(json_object_get(rule, "dst_port"));
                rs = json_string_value(json_object_get(rule, "comment"));
                if (rs) fw_strlcpy(r->comment, rs, sizeof(r->comment));

                cfg->dpi_rule_count++;
            }
        }
    }

    /* Suricata */
    json_value_t *suricata = json_object_get(root, "suricata");
    if (suricata && suricata->type == JSON_OBJECT) {
        json_value_t *en = json_object_get(suricata, "enabled");
        if (en) cfg->suricata_enabled = json_bool_value(en);
        load_string_array(json_object_get(suricata, "blocked_protocols"),
                          cfg->suricata_blocked, &cfg->suricata_blocked_count, FW_MAX_PROTOCOLS);
    }

    /* IPv6 transition mechanism filtering */
    json_value_t *ipv6_transition = json_object_get(root, "ipv6_transition");
    if (ipv6_transition && ipv6_transition->type == JSON_OBJECT) {
        json_value_t *v;
        v = json_object_get(ipv6_transition, "block_6to4");
        if (v) cfg->block_6to4 = json_bool_value(v);
        v = json_object_get(ipv6_transition, "block_teredo");
        if (v) cfg->block_teredo = json_bool_value(v);
        v = json_object_get(ipv6_transition, "block_isatap");
        if (v) cfg->block_isatap = json_bool_value(v);
    }

    /* Webhooks */
    json_value_t *webhooks = json_object_get(root, "webhooks");
    if (webhooks && webhooks->type == JSON_ARRAY) {
        cfg->webhook_count = 0;
        int wn = json_array_count(webhooks);
        for (int i = 0; i < wn && cfg->webhook_count < FW_MAX_WEBHOOKS; i++) {
            json_value_t *wh = json_array_get(webhooks, i);
            if (!wh || wh->type != JSON_OBJECT) continue;
            fw_webhook_t *w = &cfg->webhooks[cfg->webhook_count];
            memset(w, 0, sizeof(*w));

            const char *ws;
            ws = json_string_value(json_object_get(wh, "url"));
            if (ws) fw_strlcpy(w->url, ws, sizeof(w->url));

            ws = json_string_value(json_object_get(wh, "secret"));
            if (ws) fw_strlcpy(w->secret, ws, sizeof(w->secret));

            json_value_t *ev = json_object_get(wh, "events");
            if (ev && ev->type == JSON_NUMBER)
                w->events = (unsigned int)json_number_value(ev);
            else
                w->events = WH_EVENT_ALL;

            json_value_t *en = json_object_get(wh, "enabled");
            if (en)
                w->enabled = json_bool_value(en);
            else
                w->enabled = 1;

            json_value_t *rc = json_object_get(wh, "retry_count");
            if (rc && rc->type == JSON_NUMBER)
                w->retry_count = (int)json_number_value(rc);
            else
                w->retry_count = 3;

            ws = json_string_value(json_object_get(wh, "comment"));
            if (ws) fw_strlcpy(w->comment, ws, sizeof(w->comment));

            cfg->webhook_count++;
        }
    }

    json_free(root);
    return 0;
}

/* ── Config → JSON helpers ─────────────────────────────────────────── */

static json_value_t *build_string_array(char arr[][FW_MAX_ADDR], int count)
{
    json_value_t *ja = json_new_array();
    for (int i = 0; i < count; i++)
        json_array_append(ja, json_new_string(arr[i]));
    return ja;
}

static json_value_t *build_if_array(char arr[][FW_MAX_IF_NAME], int count)
{
    json_value_t *ja = json_new_array();
    for (int i = 0; i < count; i++)
        json_array_append(ja, json_new_string(arr[i]));
    return ja;
}

static json_value_t *build_int_array(int arr[], int count)
{
    json_value_t *ja = json_new_array();
    for (int i = 0; i < count; i++)
        json_array_append(ja, json_new_number(arr[i]));
    return ja;
}

static const char *action_to_string(fw_action_t a)
{
    switch (a) {
    case ACTION_DROP:   return "drop";
    case ACTION_REJECT: return "reject";
    default:            return "accept";
    }
}

static const char *proto_to_string(fw_proto_t p)
{
    return p == PROTO_UDP ? "udp" : "tcp";
}

static json_value_t *build_port_field(fw_port_t p)
{
    if (p.start == 0)
        return json_new_string("any");
    if (p.end > 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d:%d", p.start, p.end);
        return json_new_string(buf);
    }
    return json_new_number(p.start);
}

static json_value_t *build_filter_rules(const fw_filter_rule_t *rules, int count)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        const fw_filter_rule_t *r = &rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "src_addr", json_new_string(r->src_addr));
        json_object_set(obj, "dst_addr", json_new_string(r->dst_addr));
        json_object_set(obj, "protocol", json_new_string(proto_to_string(r->protocol)));
        json_object_set(obj, "src_port", build_port_field(r->src_port));
        json_object_set(obj, "dst_port", build_port_field(r->dst_port));
        json_object_set(obj, "action", json_new_string(action_to_string(r->action)));
        json_object_set(obj, "comment", json_new_string(r->comment));

        /* Serialize schedule if enabled */
        if (r->schedule.enabled) {
            json_value_t *sched = json_new_object();
            json_object_set(sched, "enabled", json_new_bool(1));

            char time_buf[8];
            snprintf(time_buf, sizeof(time_buf), "%02d:%02d",
                     r->schedule.hour_start, r->schedule.minute_start);
            json_object_set(sched, "start", json_new_string(time_buf));

            snprintf(time_buf, sizeof(time_buf), "%02d:%02d",
                     r->schedule.hour_end, r->schedule.minute_end);
            json_object_set(sched, "end", json_new_string(time_buf));

            /* Build day names string */
            static const char *day_names[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
            char days_str[64];
            fw_schedule_days_str(r->schedule.days, days_str, sizeof(days_str), day_names, ",");
            json_object_set(sched, "days", json_new_string(days_str));
            json_object_set(obj, "schedule", sched);
        }

        json_array_append(arr, obj);
    }
    return arr;
}

static json_value_t *build_nat_post_array(const fw_nat_post_t *rules, int count)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        const fw_nat_post_t *r = &rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "src", json_new_string(r->src));
        json_object_set(obj, "oif", json_new_string(r->oif));

        const char *type_str = r->type == NAT_SNAT ? "snat" : "masquerade";
        json_object_set(obj, "type", json_new_string(type_str));

        if (r->dport.start > 0)
            json_object_set(obj, "dport", build_port_field(r->dport));
        else
            json_object_set(obj, "dport", json_new_null());

        if (r->to_source[0])
            json_object_set(obj, "to_source", json_new_string(r->to_source));
        else
            json_object_set(obj, "to_source", json_new_null());

        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(arr, obj);
    }
    return arr;
}

static json_value_t *build_nat_pre_array(const fw_nat_pre_t *rules, int count)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        const fw_nat_pre_t *r = &rules[i];
        json_value_t *obj = json_new_object();
        if (r->src[0])
            json_object_set(obj, "src", json_new_string(r->src));
        json_object_set(obj, "iif", json_new_string(r->iif));
        json_object_set(obj, "protocol", json_new_string(proto_to_string(r->protocol)));
        json_object_set(obj, "dport", json_new_number(r->dport));
        json_object_set(obj, "to_dest_ip", json_new_string(r->to_dest_ip));
        json_object_set(obj, "to_dest_port", json_new_number(r->to_dest_port));
        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(arr, obj);
    }
    return arr;
}

static json_value_t *build_mangle_array(const fw_mangle_rule_t *rules, int count)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        const fw_mangle_rule_t *r = &rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "iif", json_new_string(r->iif));
        json_object_set(obj, "src_addr", json_new_string(r->src_addr));
        json_object_set(obj, "dst_addr", json_new_string(r->dst_addr));
        json_object_set(obj, "protocol", json_new_string(proto_to_string(r->protocol)));
        json_object_set(obj, "dport", json_new_number(r->dport));
        json_object_set(obj, "mark", json_new_string(r->mark));
        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(arr, obj);
    }
    return arr;
}

static json_value_t *build_routes_array(const fw_route_t *routes, int count)
{
    json_value_t *arr = json_new_array();
    for (int i = 0; i < count; i++) {
        const fw_route_t *r = &routes[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "destination", json_new_string(r->destination));
        json_object_set(obj, "gateway", json_new_string(r->gateway));
        json_object_set(obj, "interface", json_new_string(r->interface));
        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(arr, obj);
    }
    return arr;
}

/* ── Serialize ─────────────────────────────────────────────────────── */

static json_value_t *config_to_json(const fw_config_t *cfg)
{
    json_value_t *root = json_new_object();

    /* Top-level */
    json_object_set(root, "version", json_new_string(cfg->version));
    json_object_set(root, "language",
                    json_new_string(cfg->language == LANG_IT ? "it" : "en"));
    json_object_set(root, "backend",
                    json_new_string(cfg->backend == BACKEND_IPT ? "ipt" : "nft"));

    /* Interfaces */
    json_value_t *ifs = json_new_object();
    json_object_set(ifs, "lan", build_if_array((char(*)[FW_MAX_IF_NAME])cfg->lan_ifs, cfg->lan_if_count));
    json_object_set(ifs, "wan", build_if_array((char(*)[FW_MAX_IF_NAME])cfg->wan_ifs, cfg->wan_if_count));
    json_object_set(ifs, "dmz", build_if_array((char(*)[FW_MAX_IF_NAME])cfg->dmz_ifs, cfg->dmz_if_count));
    json_object_set(ifs, "vpn", build_if_array((char(*)[FW_MAX_IF_NAME])cfg->vpn_ifs, cfg->vpn_if_count));
    json_object_set(root, "interfaces", ifs);

    /* DNS */
    json_object_set(root, "dns_servers",
                    build_string_array((char(*)[FW_MAX_ADDR])cfg->dns, cfg->dns_count));

    /* Ranges */
    json_value_t *ranges = json_new_object();
    json_object_set(ranges, "lan",
                    build_string_array((char(*)[FW_MAX_ADDR])cfg->lan_ranges, cfg->lan_range_count));
    json_object_set(ranges, "dmz",
                    build_string_array((char(*)[FW_MAX_ADDR])cfg->dmz_ranges, cfg->dmz_range_count));
    json_object_set(root, "ranges", ranges);

    /* Sysctl */
    json_value_t *sysctl = json_new_object();
    json_object_set(sysctl, "ip_forward", json_new_bool(cfg->ip_forward));
    json_object_set(sysctl, "ip_dynaddr", json_new_bool(cfg->ip_dynaddr));
    json_object_set(sysctl, "tcp_syncookies", json_new_bool(cfg->tcp_syncookies));
    json_object_set(sysctl, "accept_source_route", json_new_bool(cfg->accept_source_route));
    json_object_set(root, "sysctl", sysctl);

    /* Filter */
    json_value_t *filter = json_new_object();
    for (int i = 0; i < FW_CHAIN_COUNT; i++) {
        const fw_chain_t *ch = &cfg->chains[i];
        json_value_t *chain = json_new_object();
        json_object_set(chain, "tcp_ports",
                        build_int_array((int *)ch->tcp_ports, ch->tcp_port_count));
        json_object_set(chain, "udp_ports",
                        build_int_array((int *)ch->udp_ports, ch->udp_port_count));
        json_object_set(chain, "rules",
                        build_filter_rules(ch->rules, ch->rule_count));

        /* Rate limit */
        json_value_t *rl = json_new_object();
        json_object_set(rl, "enabled", json_new_bool(ch->rate_limit.enabled));
        json_object_set(rl, "max", json_new_number(ch->rate_limit.max_connections));
        json_object_set(rl, "period", json_new_number(ch->rate_limit.period_seconds));
        json_object_set(rl, "ban", json_new_number(ch->rate_limit.ban_seconds));
        json_object_set(chain, "rate_limit", rl);

        json_object_set(filter, json_chain_keys[i], chain);
    }
    json_object_set(root, "filter", filter);

    /* NAT */
    json_value_t *nat = json_new_object();
    json_object_set(nat, "postrouting",
                    build_nat_post_array(cfg->nat_post, cfg->nat_post_count));
    json_object_set(nat, "prerouting",
                    build_nat_pre_array(cfg->nat_pre, cfg->nat_pre_count));
    json_object_set(root, "nat", nat);

    /* Mangle */
    json_value_t *mangle = json_new_object();
    json_object_set(mangle, "prerouting",
                    build_mangle_array(cfg->mangle_pre, cfg->mangle_pre_count));
    json_object_set(mangle, "postrouting",
                    build_mangle_array(cfg->mangle_post, cfg->mangle_post_count));
    json_object_set(root, "mangle", mangle);

    /* Routes */
    json_object_set(root, "routes",
                    build_routes_array(cfg->routes, cfg->route_count));

    /* DPI */
    json_value_t *dpi = json_new_object();
    json_object_set(dpi, "enabled", json_new_bool(cfg->dpi_enabled));
    json_value_t *dpi_rules = json_new_array();
    for (int i = 0; i < cfg->dpi_rule_count; i++) {
        const fw_dpi_rule_t *r = &cfg->dpi_rules[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "src_addr", json_new_string(r->src_addr));
        json_object_set(obj, "dst_addr", json_new_string(r->dst_addr));
        json_object_set(obj, "protocol", json_new_string(proto_to_string(r->protocol)));
        json_object_set(obj, "src_port", build_port_field(r->src_port));
        json_object_set(obj, "dst_port", build_port_field(r->dst_port));
        json_object_set(obj, "comment", json_new_string(r->comment));
        json_array_append(dpi_rules, obj);
    }
    json_object_set(dpi, "rules", dpi_rules);
    json_object_set(root, "dpi", dpi);

    /* Suricata */
    json_value_t *suricata = json_new_object();
    json_object_set(suricata, "enabled", json_new_bool(cfg->suricata_enabled));
    json_object_set(suricata, "blocked_protocols",
                    build_string_array((char(*)[FW_MAX_ADDR])cfg->suricata_blocked,
                                       cfg->suricata_blocked_count));
    json_object_set(root, "suricata", suricata);

    /* IPv6 transition mechanism filtering */
    json_value_t *ipv6_transition = json_new_object();
    json_object_set(ipv6_transition, "block_6to4", json_new_bool(cfg->block_6to4));
    json_object_set(ipv6_transition, "block_teredo", json_new_bool(cfg->block_teredo));
    json_object_set(ipv6_transition, "block_isatap", json_new_bool(cfg->block_isatap));
    json_object_set(root, "ipv6_transition", ipv6_transition);

    /* Webhooks */
    json_value_t *webhooks_arr = json_new_array();
    for (int i = 0; i < cfg->webhook_count; i++) {
        const fw_webhook_t *w = &cfg->webhooks[i];
        json_value_t *wobj = json_new_object();
        json_object_set(wobj, "url", json_new_string(w->url));
        json_object_set(wobj, "secret", json_new_string(w->secret));
        json_object_set(wobj, "events", json_new_number(w->events));
        json_object_set(wobj, "enabled", json_new_bool(w->enabled));
        json_object_set(wobj, "retry_count", json_new_number(w->retry_count));
        json_object_set(wobj, "comment", json_new_string(w->comment));
        json_array_append(webhooks_arr, wobj);
    }
    json_object_set(root, "webhooks", webhooks_arr);

    return root;
}

char *fw_config_serialize(const fw_config_t *cfg)
{
    json_value_t *root = config_to_json(cfg);
    if (!root)
        return NULL;
    char *json_str = json_serialize(root, 1);
    json_free(root);
    return json_str;
}

/* ── Save ──────────────────────────────────────────────────────────── */

int fw_config_save(const char *path, const fw_config_t *cfg)
{
    char *json_str = fw_config_serialize(cfg);
    if (!json_str)
        return -1;

    int ret = fw_write_file(path, json_str, strlen(json_str));
    free(json_str);
    return ret;
}

/* ── Validate ──────────────────────────────────────────────────────── */

int fw_config_validate(const fw_config_t *cfg, char *err, size_t errlen)
{
    /* Must have at least one interface */
    if (cfg->lan_if_count == 0 && cfg->wan_if_count == 0 &&
        cfg->dmz_if_count == 0 && cfg->vpn_if_count == 0) {
        snprintf(err, errlen, "no network interfaces configured");
        return -1;
    }

    /* Validate interface names */
    for (int i = 0; i < cfg->lan_if_count; i++) {
        if (!fw_validate_interface(cfg->lan_ifs[i])) {
            snprintf(err, errlen, "invalid LAN interface: %s", cfg->lan_ifs[i]);
            return -1;
        }
    }
    for (int i = 0; i < cfg->wan_if_count; i++) {
        if (!fw_validate_interface(cfg->wan_ifs[i])) {
            snprintf(err, errlen, "invalid WAN interface: %s", cfg->wan_ifs[i]);
            return -1;
        }
    }
    for (int i = 0; i < cfg->dmz_if_count; i++) {
        if (!fw_validate_interface(cfg->dmz_ifs[i])) {
            snprintf(err, errlen, "invalid DMZ interface: %s", cfg->dmz_ifs[i]);
            return -1;
        }
    }
    for (int i = 0; i < cfg->vpn_if_count; i++) {
        if (!fw_validate_interface(cfg->vpn_ifs[i])) {
            snprintf(err, errlen, "invalid VPN interface: %s", cfg->vpn_ifs[i]);
            return -1;
        }
    }

    /* Validate DNS servers (IPv4 only — backends generate IPv4-only DNS allow rules) */
    for (int i = 0; i < cfg->dns_count; i++) {
        if (!fw_validate_ipv4(cfg->dns[i])) {
            snprintf(err, errlen, "invalid DNS server: %s", cfg->dns[i]);
            return -1;
        }
    }

    /* Validate IP ranges (IPv4 CIDR only — used for NAT masquerading which is IPv4-only) */
    for (int i = 0; i < cfg->lan_range_count; i++) {
        if (!fw_validate_ipv4_cidr(cfg->lan_ranges[i])) {
            snprintf(err, errlen, "invalid LAN range: %s", cfg->lan_ranges[i]);
            return -1;
        }
    }
    for (int i = 0; i < cfg->dmz_range_count; i++) {
        if (!fw_validate_ipv4_cidr(cfg->dmz_ranges[i])) {
            snprintf(err, errlen, "invalid DMZ range: %s", cfg->dmz_ranges[i]);
            return -1;
        }
    }

    /* Validate NAT postrouting rules (IPv4 only — backends generate IPv4-only rules) */
    for (int i = 0; i < cfg->nat_post_count; i++) {
        const fw_nat_post_t *r = &cfg->nat_post[i];
        if (r->src[0] && !fw_validate_ipv4_cidr(r->src) && !fw_validate_ipv4(r->src)) {
            snprintf(err, errlen, "invalid src in NAT postrouting rule %d: %s", i, r->src);
            return -1;
        }
        if (r->oif[0] && !fw_validate_interface(r->oif)) {
            snprintf(err, errlen, "invalid oif in NAT postrouting rule %d: %s", i, r->oif);
            return -1;
        }
        if (r->type == NAT_SNAT && !r->to_source[0]) {
            snprintf(err, errlen, "NAT postrouting rule %d: snat requires to_source", i);
            return -1;
        }
        if (r->to_source[0] && !fw_validate_ipv4(r->to_source)) {
            snprintf(err, errlen, "invalid to_source in NAT postrouting rule %d: %s", i, r->to_source);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in NAT postrouting rule %d", i);
            return -1;
        }
    }

    /* Validate NAT prerouting rules (IPv4 only — DNAT rules are IPv4-only) */
    for (int i = 0; i < cfg->nat_pre_count; i++) {
        const fw_nat_pre_t *r = &cfg->nat_pre[i];
        if (r->src[0] && !fw_validate_ipv4_cidr(r->src) && !fw_validate_ipv4(r->src)) {
            snprintf(err, errlen, "invalid src in NAT prerouting rule %d: %s", i, r->src);
            return -1;
        }
        if (r->iif[0] && !fw_validate_interface(r->iif)) {
            snprintf(err, errlen, "invalid iif in NAT prerouting rule %d: %s", i, r->iif);
            return -1;
        }
        if (!fw_validate_port(r->dport)) {
            snprintf(err, errlen, "invalid dport in NAT prerouting rule %d: %d", i, r->dport);
            return -1;
        }
        if (!fw_validate_ipv4(r->to_dest_ip)) {
            snprintf(err, errlen, "invalid to_dest_ip in NAT prerouting rule %d: %s", i, r->to_dest_ip);
            return -1;
        }
        if (!fw_validate_port(r->to_dest_port)) {
            snprintf(err, errlen, "invalid to_dest_port in NAT prerouting rule %d: %d", i, r->to_dest_port);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in NAT prerouting rule %d", i);
            return -1;
        }
    }

    /* Validate webhooks */
    for (int i = 0; i < cfg->webhook_count; i++) {
        const fw_webhook_t *w = &cfg->webhooks[i];
        if (!fw_webhook_validate_url(w->url)) {
            snprintf(err, errlen, "invalid webhook URL at index %d: %s", i, w->url);
            return -1;
        }
        if (!fw_webhook_validate_events(w->events)) {
            snprintf(err, errlen, "invalid webhook events mask at index %d: %u", i, w->events);
            return -1;
        }
        if (w->retry_count < 0 || w->retry_count > 10) {
            snprintf(err, errlen, "invalid webhook retry_count at index %d: %d", i, w->retry_count);
            return -1;
        }
    }

    /* Validate ports, filter rules, and rate limits in all chains */
    for (int c = 0; c < FW_CHAIN_COUNT; c++) {
        const fw_chain_t *ch = &cfg->chains[c];
        for (int i = 0; i < ch->tcp_port_count; i++) {
            if (!fw_validate_port(ch->tcp_ports[i])) {
                snprintf(err, errlen, "invalid TCP port %d in chain %s",
                         ch->tcp_ports[i], ch->name);
                return -1;
            }
        }
        for (int i = 0; i < ch->udp_port_count; i++) {
            if (!fw_validate_port(ch->udp_ports[i])) {
                snprintf(err, errlen, "invalid UDP port %d in chain %s",
                         ch->udp_ports[i], ch->name);
                return -1;
            }
        }
        /* Validate explicit filter rules (addresses, comments, schedules) */
        for (int i = 0; i < ch->rule_count; i++) {
            const fw_filter_rule_t *r = &ch->rules[i];
            if (!fw_validate_addr_field(r->src_addr)) {
                snprintf(err, errlen, "invalid src_addr in chain %s rule %d: %s",
                         ch->name, i, r->src_addr);
                return -1;
            }
            if (!fw_validate_addr_field(r->dst_addr)) {
                snprintf(err, errlen, "invalid dst_addr in chain %s rule %d: %s",
                         ch->name, i, r->dst_addr);
                return -1;
            }
            if (!fw_validate_comment(r->comment)) {
                snprintf(err, errlen, "invalid comment in chain %s rule %d",
                         ch->name, i);
                return -1;
            }
            if (r->schedule.enabled &&
                !fw_validate_schedule(&r->schedule)) {
                snprintf(err, errlen, "invalid schedule on rule %d in chain %s",
                         i, ch->name);
                return -1;
            }
        }

        /* Validate rate limit if enabled */
        if (ch->rate_limit.enabled) {
            if (ch->rate_limit.max_connections <= 0) {
                snprintf(err, errlen,
                         "rate_limit.max must be positive in chain %s", ch->name);
                return -1;
            }
            if (ch->rate_limit.period_seconds <= 0) {
                snprintf(err, errlen,
                         "rate_limit.period must be positive in chain %s", ch->name);
                return -1;
            }
            if (ch->rate_limit.ban_seconds <= 0) {
                snprintf(err, errlen,
                         "rate_limit.ban must be positive in chain %s", ch->name);
                return -1;
            }
        }
    }

    /* Validate mangle rules */
    for (int i = 0; i < cfg->mangle_pre_count; i++) {
        const fw_mangle_rule_t *r = &cfg->mangle_pre[i];
        if (r->iif[0] && !fw_validate_interface(r->iif)) {
            snprintf(err, errlen, "invalid iif in mangle prerouting rule %d: %s", i, r->iif);
            return -1;
        }
        if (!fw_validate_addr_field(r->src_addr)) {
            snprintf(err, errlen, "invalid src_addr in mangle prerouting rule %d: %s", i, r->src_addr);
            return -1;
        }
        if (!fw_validate_addr_field(r->dst_addr)) {
            snprintf(err, errlen, "invalid dst_addr in mangle prerouting rule %d: %s", i, r->dst_addr);
            return -1;
        }
        if (!fw_validate_mark(r->mark)) {
            snprintf(err, errlen, "invalid mark in mangle prerouting rule %d: %s", i, r->mark);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in mangle prerouting rule %d", i);
            return -1;
        }
    }
    for (int i = 0; i < cfg->mangle_post_count; i++) {
        const fw_mangle_rule_t *r = &cfg->mangle_post[i];
        if (r->iif[0] && !fw_validate_interface(r->iif)) {
            snprintf(err, errlen, "invalid iif in mangle postrouting rule %d: %s", i, r->iif);
            return -1;
        }
        if (!fw_validate_addr_field(r->src_addr)) {
            snprintf(err, errlen, "invalid src_addr in mangle postrouting rule %d: %s", i, r->src_addr);
            return -1;
        }
        if (!fw_validate_addr_field(r->dst_addr)) {
            snprintf(err, errlen, "invalid dst_addr in mangle postrouting rule %d: %s", i, r->dst_addr);
            return -1;
        }
        if (!fw_validate_mark(r->mark)) {
            snprintf(err, errlen, "invalid mark in mangle postrouting rule %d: %s", i, r->mark);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in mangle postrouting rule %d", i);
            return -1;
        }
    }

    /* Validate routes */
    for (int i = 0; i < cfg->route_count; i++) {
        const fw_route_t *r = &cfg->routes[i];
        if (r->destination[0] && !fw_validate_ipv4_cidr(r->destination) && !fw_validate_ipv4(r->destination)) {
            snprintf(err, errlen, "invalid destination in route %d: %s", i, r->destination);
            return -1;
        }
        if (r->gateway[0] && !fw_validate_ipv4(r->gateway)) {
            snprintf(err, errlen, "invalid gateway in route %d: %s", i, r->gateway);
            return -1;
        }
        if (r->interface[0] && !fw_validate_interface(r->interface)) {
            snprintf(err, errlen, "invalid interface in route %d: %s", i, r->interface);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in route %d", i);
            return -1;
        }
    }

    /* Validate DPI rules */
    for (int i = 0; i < cfg->dpi_rule_count; i++) {
        const fw_dpi_rule_t *r = &cfg->dpi_rules[i];
        if (!fw_validate_addr_field(r->src_addr)) {
            snprintf(err, errlen, "invalid src_addr in DPI rule %d: %s", i, r->src_addr);
            return -1;
        }
        if (!fw_validate_addr_field(r->dst_addr)) {
            snprintf(err, errlen, "invalid dst_addr in DPI rule %d: %s", i, r->dst_addr);
            return -1;
        }
        if (!fw_validate_comment(r->comment)) {
            snprintf(err, errlen, "invalid comment in DPI rule %d", i);
            return -1;
        }
    }

    return 0;
}
