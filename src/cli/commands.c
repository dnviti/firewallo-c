#include "commands.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/rollback.h"
#include "firewallo/log.h"
#include "firewallo/i18n.h"
#include "firewallo/json.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
#include "firewallo/diff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

/* ── Helpers ───────────────────────────────────────────────────────── */

static void print_ok(const char *msg)
{
    printf("%s OK\n", msg);
}

static void print_err(const char *msg, const char *detail)
{
    fprintf(stderr, "%s %s\n", msg, detail ? detail : "");
}

/* ── Start ─────────────────────────────────────────────────────────── */

int cmd_start(fw_config_t *cfg, int verbose)
{
    char err[256] = {0};
    if (fw_config_validate(cfg, err, sizeof(err)) != 0) {
        print_err(_("config_invalid"), err);
        return 1;
    }

    printf("%s\n", _("starting_firewall"));

    /* Apply sysctl */
    fw_sysctl_apply(cfg);

    /* Compile and execute */
    fw_cmdlist_t cmds;
    fw_compile_start(cfg, &cmds);

    if (verbose) {
        printf("Executing %d commands...\n", cmds.count);
        for (int i = 0; i < cmds.count; i++)
            printf("  [%03d] %s\n", i, cmds.cmds[i].command);
    }

    int fail_idx;
    int ret = fw_cmdlist_exec(&cmds, &fail_idx);
    fw_cmdlist_free(&cmds);

    if (ret != 0) {
        print_err(_("error_start"), "");
        fprintf(stderr, "%s %d\n", _("cmd_failed"), fail_idx);
        return 1;
    }

    print_ok(_("firewall_started"));
    return 0;
}

/* ── Stop ──────────────────────────────────────────────────────────── */

int cmd_stop(fw_config_t *cfg, int verbose)
{
    printf("%s\n", _("stopping_firewall"));

    fw_cmdlist_t cmds;
    fw_compile_stop(cfg, &cmds);

    if (verbose)
        for (int i = 0; i < cmds.count; i++)
            printf("  [%03d] %s\n", i, cmds.cmds[i].command);

    int fail_idx;
    int ret = fw_cmdlist_exec(&cmds, &fail_idx);
    fw_cmdlist_free(&cmds);

    if (ret != 0) {
        fprintf(stderr, "%s %d\n", _("cmd_failed"), fail_idx);
        return 1;
    }

    print_ok(_("firewall_stopped"));
    return 0;
}

/* ── Restart ───────────────────────────────────────────────────────── */

int cmd_restart(fw_config_t *cfg, const char *config_path, int verbose)
{
    printf("%s\n", _("restarting_firewall"));

    int ret = cmd_stop(cfg, verbose);
    if (ret != 0)
        return ret;

    /* Reload config in case it changed */
    char err[256];
    if (fw_config_load(config_path, cfg, err, sizeof(err)) != 0) {
        print_err(_("error_load"), err);
        return 1;
    }

    return cmd_start(cfg, verbose);
}

/* ── Reset ─────────────────────────────────────────────────────────── */

int cmd_reset(fw_config_t *cfg, int verbose)
{
    printf("%s\n", _("resetting_firewall"));

    fw_cmdlist_t cmds;
    fw_compile_reset(cfg, &cmds);

    if (verbose)
        for (int i = 0; i < cmds.count; i++)
            printf("  [%03d] %s\n", i, cmds.cmds[i].command);

    int fail_idx;
    int ret = fw_cmdlist_exec(&cmds, &fail_idx);
    fw_cmdlist_free(&cmds);

    if (ret != 0) {
        fprintf(stderr, "%s %d\n", _("cmd_failed"), fail_idx);
        return 1;
    }

    print_ok(_("firewall_reset"));
    return 0;
}

/* ── Status ────────────────────────────────────────────────────────── */

int cmd_status(const fw_config_t *cfg)
{
    printf("Firewallo %s\n", cfg->version);
    printf("Backend: %s\n", cfg->backend == BACKEND_NFT ? "nftables" : "iptables");
    printf("Language: %s\n", cfg->language == LANG_IT ? "it" : "en");
    printf("\n");

    printf("Interfaces:\n");
    printf("  LAN: ");
    for (int i = 0; i < cfg->lan_if_count; i++)
        printf("%s ", cfg->lan_ifs[i]);
    printf("\n  WAN: ");
    for (int i = 0; i < cfg->wan_if_count; i++)
        printf("%s ", cfg->wan_ifs[i]);
    printf("\n  DMZ: ");
    for (int i = 0; i < cfg->dmz_if_count; i++)
        printf("%s ", cfg->dmz_ifs[i]);
    printf("\n  VPN: ");
    for (int i = 0; i < cfg->vpn_if_count; i++)
        printf("%s ", cfg->vpn_ifs[i]);
    printf("\n\n");

    printf("DNS: ");
    for (int i = 0; i < cfg->dns_count; i++)
        printf("%s ", cfg->dns[i]);
    printf("\n\n");

    /* Check if firewall is active by querying the backend */
    char buf[4096] = {0};
    if (cfg->backend == BACKEND_NFT) {
        fw_exec_capture("/usr/sbin/nft list tables 2>/dev/null", buf, sizeof(buf));
        if (strstr(buf, "filter"))
            printf("Status: active (nft filter table present)\n");
        else
            printf("Status: inactive\n");
    } else {
        fw_exec_capture("/sbin/iptables -L -n 2>/dev/null | head -5", buf, sizeof(buf));
        if (strstr(buf, "DROP"))
            printf("Status: active (DROP policy)\n");
        else
            printf("Status: inactive (ACCEPT policy)\n");
    }

    return 0;
}

/* ── Rules view ────────────────────────────────────────────────────── */

int cmd_rules(const fw_config_t *cfg)
{
    char buf[65536] = {0};
    if (cfg->backend == BACKEND_NFT) {
        fw_exec_capture("/usr/sbin/nft list ruleset 2>/dev/null", buf, sizeof(buf));
    } else {
        fw_exec_capture("/sbin/iptables -L -n -v 2>/dev/null", buf, sizeof(buf));
    }
    printf("%s", buf);
    return 0;
}

/* ── Validate ──────────────────────────────────────────────────────── */

int cmd_validate(const fw_config_t *cfg)
{
    char err[256] = {0};
    if (fw_config_validate(cfg, err, sizeof(err)) != 0) {
        print_err(_("config_invalid"), err);
        return 1;
    }

    printf("%s\n", _("config_valid"));

    /* Show summary */
    int total_tcp = 0, total_udp = 0, total_rules = 0;
    for (int i = 0; i < FW_CHAIN_COUNT; i++) {
        total_tcp += cfg->chains[i].tcp_port_count;
        total_udp += cfg->chains[i].udp_port_count;
        total_rules += cfg->chains[i].rule_count;
    }
    printf("  Chains: %d\n", FW_CHAIN_COUNT);
    printf("  TCP port rules: %d\n", total_tcp);
    printf("  UDP port rules: %d\n", total_udp);
    printf("  Explicit rules: %d\n", total_rules);
    printf("  NAT postrouting: %d\n", cfg->nat_post_count);
    printf("  NAT prerouting: %d\n", cfg->nat_pre_count);
    printf("  Routes: %d\n", cfg->route_count);

    /* Dry-run compile to show command count */
    fw_cmdlist_t cmds;
    fw_compile_start(cfg, &cmds);
    printf("  Start commands: %d\n", cmds.count);
    fw_cmdlist_free(&cmds);

    return 0;
}

/* ── Show config ───────────────────────────────────────────────────── */

int cmd_show_config(const fw_config_t *cfg)
{
    /* Save to a temporary JSON string and print */
    /* We'll build the JSON tree and serialize */
    const char *tmpfile = "/tmp/.firewallo_show.json";
    if (fw_config_save(tmpfile, cfg) != 0) {
        fprintf(stderr, "Error serializing config\n");
        return 1;
    }

    size_t len;
    char *content = fw_read_file(tmpfile, &len);
    if (content) {
        printf("%s", content);
        free(content);
    }
    remove(tmpfile);
    return 0;
}

/* ── Export ─────────────────────────────────────────────────────────── */

int cmd_export(const fw_config_t *cfg, const char *config_path)
{
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char filename[256];
    snprintf(filename, sizeof(filename),
             "firewallo-backup-%04d%02d%02d-%02d%02d%02d.json",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    if (fw_config_save(filename, cfg) != 0) {
        fprintf(stderr, "Error creating backup\n");
        return 1;
    }

    printf("%s %s\n", _("export_done"), filename);
    (void)config_path;
    return 0;
}

/* ── Restore ───────────────────────────────────────────────────────── */

int cmd_restore(fw_config_t *cfg, const char *backup_path, const char *config_path)
{
    char err[256] = {0};

    /* Load backup to validate it first */
    fw_config_t backup_cfg;
    if (fw_config_load(backup_path, &backup_cfg, err, sizeof(err)) != 0) {
        print_err(_("error_load"), err);
        return 1;
    }

    if (fw_config_validate(&backup_cfg, err, sizeof(err)) != 0) {
        print_err(_("config_invalid"), err);
        return 1;
    }

    /* Save to the actual config path */
    if (fw_config_save(config_path, &backup_cfg) != 0) {
        fprintf(stderr, "Error writing to %s\n", config_path);
        return 1;
    }

    *cfg = backup_cfg;
    printf("%s %s\n", _("restore_done"), backup_path);
    return 0;
}

/* ── Switch backend ────────────────────────────────────────────────── */

int cmd_switch_backend(fw_config_t *cfg, const char *backend, const char *config_path)
{
    if (strcmp(backend, "nft") == 0 || strcmp(backend, "nftables") == 0) {
        cfg->backend = BACKEND_NFT;
    } else if (strcmp(backend, "ipt") == 0 || strcmp(backend, "iptables") == 0) {
        cfg->backend = BACKEND_IPT;
    } else {
        fprintf(stderr, "Unknown backend: %s (use 'nft' or 'ipt')\n", backend);
        return 1;
    }

    if (fw_config_save(config_path, cfg) != 0) {
        fprintf(stderr, "Error saving config\n");
        return 1;
    }

    printf("%s %s\n", _("backend_switched"),
           cfg->backend == BACKEND_NFT ? "nftables" : "iptables");
    return 0;
}

/* ── Helper: save config with validation ──────────────────────────── */

static int validate_and_save(fw_config_t *cfg, const char *config_path)
{
    char err[256] = {0};
    if (fw_config_validate(cfg, err, sizeof(err)) != 0) {
        print_err("Validation failed:", err);
        return 1;
    }
    if (fw_config_save(config_path, cfg) != 0) {
        fprintf(stderr, "Error saving config to %s\n", config_path);
        return 1;
    }
    return 0;
}

/* ── Helper: find interface in array, returns index or -1 ─────────── */

static int find_if(char arr[][FW_MAX_IF_NAME], int count, const char *name)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(arr[i], name) == 0)
            return i;
    }
    return -1;
}

/* ── Helper: find string in address array, returns index or -1 ────── */

static int find_addr(char arr[][FW_MAX_ADDR], int count, const char *val)
{
    for (int i = 0; i < count; i++) {
        if (strcmp(arr[i], val) == 0)
            return i;
    }
    return -1;
}

/* ── Helper: find int in array, returns index or -1 ───────────────── */

static int find_int(const int arr[], int count, int val)
{
    for (int i = 0; i < count; i++) {
        if (arr[i] == val)
            return i;
    }
    return -1;
}

/* ── Helper: remove element from interface array ──────────────────── */

static void remove_if(char arr[][FW_MAX_IF_NAME], int *count, int idx)
{
    for (int i = idx; i < *count - 1; i++)
        fw_strlcpy(arr[i], arr[i + 1], FW_MAX_IF_NAME);
    memset(arr[*count - 1], 0, FW_MAX_IF_NAME);
    (*count)--;
}

/* ── Helper: remove element from address array ────────────────────── */

static void remove_addr(char arr[][FW_MAX_ADDR], int *count, int idx)
{
    for (int i = idx; i < *count - 1; i++)
        fw_strlcpy(arr[i], arr[i + 1], FW_MAX_ADDR);
    memset(arr[*count - 1], 0, FW_MAX_ADDR);
    (*count)--;
}

/* ── Helper: remove element from int array ────────────────────────── */

static void remove_int(int arr[], int *count, int idx)
{
    for (int i = idx; i < *count - 1; i++)
        arr[i] = arr[i + 1];
    arr[*count - 1] = 0;
    (*count)--;
}

/* ── Set interface ─────────────────────────────────────────────────── */

int cmd_set_interface(fw_config_t *cfg, const char *zone, const char *action,
                      const char *iface, const char *config_path)
{
    if (!fw_validate_interface(iface)) {
        fprintf(stderr, "Invalid interface name: %s\n", iface);
        return 1;
    }

    char (*arr)[FW_MAX_IF_NAME];
    int *count;
    int max = FW_MAX_INTERFACES;

    if (strcmp(zone, "lan") == 0) {
        arr = cfg->lan_ifs; count = &cfg->lan_if_count;
    } else if (strcmp(zone, "wan") == 0) {
        arr = cfg->wan_ifs; count = &cfg->wan_if_count;
    } else if (strcmp(zone, "dmz") == 0) {
        arr = cfg->dmz_ifs; count = &cfg->dmz_if_count;
    } else if (strcmp(zone, "vpn") == 0) {
        arr = cfg->vpn_ifs; count = &cfg->vpn_if_count;
    } else {
        fprintf(stderr, "Unknown zone: %s (use lan, wan, dmz, vpn)\n", zone);
        return 1;
    }

    if (strcmp(action, "add") == 0) {
        if (find_if(arr, *count, iface) >= 0) {
            fprintf(stderr, "Interface %s already in %s\n", iface, zone);
            return 1;
        }
        if (*count >= max) {
            fprintf(stderr, "Maximum interfaces reached for %s\n", zone);
            return 1;
        }
        fw_strlcpy(arr[*count], iface, FW_MAX_IF_NAME);
        (*count)++;
    } else if (strcmp(action, "remove") == 0) {
        int idx = find_if(arr, *count, iface);
        if (idx < 0) {
            fprintf(stderr, "Interface %s not found in %s\n", iface, zone);
            return 1;
        }
        remove_if(arr, count, idx);
    } else {
        fprintf(stderr, "Unknown action: %s (use add or remove)\n", action);
        return 1;
    }

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("Interface %s %sed %s %s\n", iface,
           strcmp(action, "add") == 0 ? "add" : "remov", action[0] == 'a' ? "to" : "from", zone);
    return 0;
}

/* ── Set DNS ───────────────────────────────────────────────────────── */

int cmd_set_dns(fw_config_t *cfg, const char *action, const char *ip,
                const char *config_path)
{
    if (!fw_validate_ipv4(ip)) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        return 1;
    }

    if (strcmp(action, "add") == 0) {
        if (find_addr(cfg->dns, cfg->dns_count, ip) >= 0) {
            fprintf(stderr, "DNS server %s already configured\n", ip);
            return 1;
        }
        if (cfg->dns_count >= FW_MAX_DNS) {
            fprintf(stderr, "Maximum DNS servers reached\n");
            return 1;
        }
        fw_strlcpy(cfg->dns[cfg->dns_count], ip, FW_MAX_ADDR);
        cfg->dns_count++;
    } else if (strcmp(action, "remove") == 0) {
        int idx = find_addr(cfg->dns, cfg->dns_count, ip);
        if (idx < 0) {
            fprintf(stderr, "DNS server %s not found\n", ip);
            return 1;
        }
        remove_addr(cfg->dns, &cfg->dns_count, idx);
    } else {
        fprintf(stderr, "Unknown action: %s (use add or remove)\n", action);
        return 1;
    }

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("DNS server %s %s\n", ip,
           strcmp(action, "add") == 0 ? "added" : "removed");
    return 0;
}

/* ── Set range ─────────────────────────────────────────────────────── */

int cmd_set_range(fw_config_t *cfg, const char *zone, const char *action,
                  const char *cidr, const char *config_path)
{
    if (!fw_validate_ipv4_cidr(cidr)) {
        fprintf(stderr, "Invalid CIDR range: %s\n", cidr);
        return 1;
    }

    char (*arr)[FW_MAX_ADDR];
    int *count;
    int max = FW_MAX_RANGES;

    if (strcmp(zone, "lan") == 0) {
        arr = cfg->lan_ranges; count = &cfg->lan_range_count;
    } else if (strcmp(zone, "dmz") == 0) {
        arr = cfg->dmz_ranges; count = &cfg->dmz_range_count;
    } else {
        fprintf(stderr, "Unknown zone: %s (use lan or dmz)\n", zone);
        return 1;
    }

    if (strcmp(action, "add") == 0) {
        if (find_addr(arr, *count, cidr) >= 0) {
            fprintf(stderr, "Range %s already in %s\n", cidr, zone);
            return 1;
        }
        if (*count >= max) {
            fprintf(stderr, "Maximum ranges reached for %s\n", zone);
            return 1;
        }
        fw_strlcpy(arr[*count], cidr, FW_MAX_ADDR);
        (*count)++;
    } else if (strcmp(action, "remove") == 0) {
        int idx = find_addr(arr, *count, cidr);
        if (idx < 0) {
            fprintf(stderr, "Range %s not found in %s\n", cidr, zone);
            return 1;
        }
        remove_addr(arr, count, idx);
    } else {
        fprintf(stderr, "Unknown action: %s (use add or remove)\n", action);
        return 1;
    }

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("Range %s %s %s\n", cidr,
           strcmp(action, "add") == 0 ? "added to" : "removed from", zone);
    return 0;
}

/* ── Set sysctl ────────────────────────────────────────────────────── */

int cmd_set_sysctl(fw_config_t *cfg, const char *key, const char *value,
                   const char *config_path)
{
    char *endptr;
    long val = strtol(value, &endptr, 10);
    if (*endptr != '\0' || (val != 0 && val != 1)) {
        fprintf(stderr, "Value must be 0 or 1\n");
        return 1;
    }

    int ival = (int)val;
    if (strcmp(key, "ip_forward") == 0)
        cfg->ip_forward = ival;
    else if (strcmp(key, "ip_dynaddr") == 0)
        cfg->ip_dynaddr = ival;
    else if (strcmp(key, "tcp_syncookies") == 0)
        cfg->tcp_syncookies = ival;
    else if (strcmp(key, "accept_source_route") == 0)
        cfg->accept_source_route = ival;
    else {
        fprintf(stderr, "Unknown sysctl key: %s\n", key);
        fprintf(stderr, "Valid keys: ip_forward, ip_dynaddr, tcp_syncookies, accept_source_route\n");
        return 1;
    }

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("sysctl %s = %d\n", key, ival);
    return 0;
}

/* ── Set chain ─────────────────────────────────────────────────────── */

int cmd_set_chain(fw_config_t *cfg, const char *chain, const char *proto,
                  const char *action, const char *port_str, const char *config_path)
{
    int idx = fw_config_chain_index(chain);
    if (idx < 0) {
        fprintf(stderr, "Unknown chain: %s\n", chain);
        return 1;
    }

    char *endptr;
    long port_l = strtol(port_str, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid port: %s (not a number)\n", port_str);
        return 1;
    }
    int port = (int)port_l;
    if (!fw_validate_port(port)) {
        fprintf(stderr, "Invalid port: %s (must be 1-65535)\n", port_str);
        return 1;
    }

    int *ports;
    int *count;
    int max = FW_MAX_PORTS;

    if (strcmp(proto, "tcp") == 0) {
        ports = cfg->chains[idx].tcp_ports;
        count = &cfg->chains[idx].tcp_port_count;
    } else if (strcmp(proto, "udp") == 0) {
        ports = cfg->chains[idx].udp_ports;
        count = &cfg->chains[idx].udp_port_count;
    } else {
        fprintf(stderr, "Unknown protocol: %s (use tcp or udp)\n", proto);
        return 1;
    }

    if (strcmp(action, "add") == 0) {
        if (find_int(ports, *count, port) >= 0) {
            fprintf(stderr, "Port %d already in %s %s\n", port, chain, proto);
            return 1;
        }
        if (*count >= max) {
            fprintf(stderr, "Maximum ports reached for %s %s\n", chain, proto);
            return 1;
        }
        ports[*count] = port;
        (*count)++;
    } else if (strcmp(action, "remove") == 0) {
        int pidx = find_int(ports, *count, port);
        if (pidx < 0) {
            fprintf(stderr, "Port %d not found in %s %s\n", port, chain, proto);
            return 1;
        }
        remove_int(ports, count, pidx);
    } else {
        fprintf(stderr, "Unknown action: %s (use add or remove)\n", action);
        return 1;
    }

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("Port %d/%s %s %s\n", port, proto,
           strcmp(action, "add") == 0 ? "added to" : "removed from", chain);
    return 0;
}

/* ── Set NAT ───────────────────────────────────────────────────────── */

int cmd_set_nat(fw_config_t *cfg, const char *direction, const char *action,
                const char *rule_json, const char *config_path)
{
    int is_post = (strcmp(direction, "post") == 0);
    int is_pre = (strcmp(direction, "pre") == 0);

    if (!is_post && !is_pre) {
        fprintf(stderr, "Unknown direction: %s (use post or pre)\n", direction);
        return 1;
    }

    char parse_err[256] = {0};
    json_value_t *root = json_parse(rule_json, parse_err, sizeof(parse_err));
    if (!root) {
        fprintf(stderr, "Invalid JSON: %s\n", parse_err);
        return 1;
    }
    if (root->type != JSON_OBJECT) {
        json_free(root);
        fprintf(stderr, "NAT rule must be a JSON object\n");
        return 1;
    }

    if (strcmp(action, "add") == 0) {
        if (is_post) {
            if (cfg->nat_post_count >= FW_MAX_NAT) {
                json_free(root);
                fprintf(stderr, "Maximum postrouting NAT rules reached\n");
                return 1;
            }
            fw_nat_post_t *r = &cfg->nat_post[cfg->nat_post_count];
            memset(r, 0, sizeof(*r));

            const char *s;
            s = json_string_value(json_object_get(root, "src"));
            if (s) fw_strlcpy(r->src, s, sizeof(r->src));
            s = json_string_value(json_object_get(root, "oif"));
            if (s) fw_strlcpy(r->oif, s, sizeof(r->oif));
            s = json_string_value(json_object_get(root, "type"));
            if (s && strcmp(s, "snat") == 0)
                r->type = NAT_SNAT;
            else
                r->type = NAT_MASQUERADE;
            s = json_string_value(json_object_get(root, "to_source"));
            if (s) fw_strlcpy(r->to_source, s, sizeof(r->to_source));
            s = json_string_value(json_object_get(root, "comment"));
            if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

            cfg->nat_post_count++;
        } else {
            if (cfg->nat_pre_count >= FW_MAX_NAT) {
                json_free(root);
                fprintf(stderr, "Maximum prerouting NAT rules reached\n");
                return 1;
            }
            fw_nat_pre_t *r = &cfg->nat_pre[cfg->nat_pre_count];
            memset(r, 0, sizeof(*r));

            const char *s;
            s = json_string_value(json_object_get(root, "src"));
            if (s) fw_strlcpy(r->src, s, sizeof(r->src));
            s = json_string_value(json_object_get(root, "iif"));
            if (s) fw_strlcpy(r->iif, s, sizeof(r->iif));
            s = json_string_value(json_object_get(root, "protocol"));
            if (s && strcmp(s, "udp") == 0)
                r->protocol = PROTO_UDP;
            else
                r->protocol = PROTO_TCP;

            json_value_t *dp = json_object_get(root, "dport");
            if (dp && dp->type == JSON_NUMBER) {
                r->dport = (int)json_number_value(dp);
            }
            if (!fw_validate_port(r->dport)) {
                json_free(root);
                fprintf(stderr, "Invalid or missing dport (must be 1-65535)\n");
                return 1;
            }

            s = json_string_value(json_object_get(root, "to_dest_ip"));
            if (!s || !fw_validate_ipv4(s)) {
                json_free(root);
                fprintf(stderr, "Invalid or missing to_dest_ip\n");
                return 1;
            }
            fw_strlcpy(r->to_dest_ip, s, sizeof(r->to_dest_ip));

            json_value_t *tdp = json_object_get(root, "to_dest_port");
            if (tdp && tdp->type == JSON_NUMBER) {
                r->to_dest_port = (int)json_number_value(tdp);
            }
            if (!fw_validate_port(r->to_dest_port)) {
                json_free(root);
                fprintf(stderr, "Invalid or missing to_dest_port (must be 1-65535)\n");
                return 1;
            }

            s = json_string_value(json_object_get(root, "comment"));
            if (s) fw_strlcpy(r->comment, s, sizeof(r->comment));

            cfg->nat_pre_count++;
        }
    } else if (strcmp(action, "remove") == 0) {
        json_value_t *idx_val = json_object_get(root, "index");
        if (!idx_val || idx_val->type != JSON_NUMBER) {
            json_free(root);
            fprintf(stderr, "Remove requires {\"index\": N} in JSON\n");
            return 1;
        }
        int rm_idx = (int)json_number_value(idx_val);

        if (is_post) {
            if (rm_idx < 0 || rm_idx >= cfg->nat_post_count) {
                json_free(root);
                fprintf(stderr, "NAT postrouting index %d out of range (0-%d)\n",
                        rm_idx, cfg->nat_post_count - 1);
                return 1;
            }
            for (int i = rm_idx; i < cfg->nat_post_count - 1; i++)
                cfg->nat_post[i] = cfg->nat_post[i + 1];
            cfg->nat_post_count--;
        } else {
            if (rm_idx < 0 || rm_idx >= cfg->nat_pre_count) {
                json_free(root);
                fprintf(stderr, "NAT prerouting index %d out of range (0-%d)\n",
                        rm_idx, cfg->nat_pre_count - 1);
                return 1;
            }
            for (int i = rm_idx; i < cfg->nat_pre_count - 1; i++)
                cfg->nat_pre[i] = cfg->nat_pre[i + 1];
            cfg->nat_pre_count--;
        }
    } else {
        json_free(root);
        fprintf(stderr, "Unknown action: %s (use add or remove)\n", action);
        return 1;
    }

    json_free(root);

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("NAT %srouting rule %s\n", direction,
           strcmp(action, "add") == 0 ? "added" : "removed");
    return 0;
}

/* ── Preview ───────────────────────────────────────────────────────── */

int cmd_preview(fw_config_t *cfg, const char *config_path)
{
    char err[256] = {0};
    if (fw_config_validate(cfg, err, sizeof(err)) != 0) {
        print_err(_("config_invalid"), err);
        return 1;
    }

    /* Compile proposed ruleset */
    fw_cmdlist_t cmds;
    fw_compile_start(cfg, &cmds);

    printf("=== Proposed ruleset (%d commands) ===\n\n", cmds.count);

    /* Heap-allocate large buffers to avoid ~450KB stack usage */
    enum { DUMP_SIZE = 131072, DIFF_SIZE = 131072 };

    char *dump = malloc(DUMP_SIZE);
    if (dump) {
        if (fw_cmdlist_dump(&cmds, dump, DUMP_SIZE) >= 0)
            printf("%s", dump);
    }

    /* Compare two compiled command lists: load saved (on-disk) config,
       compile it, and diff its dump against the proposed dump.
       This ensures both sides use the same format for a meaningful diff. */
    fw_config_t saved_cfg;
    char load_err[256];
    if (config_path &&
        fw_config_load(config_path, &saved_cfg, load_err,
                       sizeof(load_err)) == 0) {
        fw_cmdlist_t saved_cmds;
        fw_compile_start(&saved_cfg, &saved_cmds);

        char *saved_dump = malloc(DUMP_SIZE);
        char *proposed_dump = dump ? NULL : malloc(DUMP_SIZE);
        /* Reuse dump if already allocated, otherwise allocate proposed_dump */
        char *proposed_text = dump ? dump : proposed_dump;
        if (saved_dump && proposed_text) {
            fw_cmdlist_dump(&saved_cmds, saved_dump, DUMP_SIZE);
            if (!dump) {
                fw_cmdlist_dump(&cmds, proposed_text, DUMP_SIZE);
            }

            char *diff = malloc(DIFF_SIZE);
            if (diff) {
                diff[0] = '\0';
                if (fw_ruleset_diff(saved_dump, proposed_text,
                                    diff, DIFF_SIZE) == 0 && diff[0]) {
                    printf("\n=== Diff (saved vs proposed) ===\n\n");
                    printf("%s", diff);
                }
                free(diff);
            }
        }
        free(saved_dump);
        free(proposed_dump);
        fw_cmdlist_free(&saved_cmds);
    } else {
        printf("\n(Could not load saved config — diff not available)\n");
    }

    free(dump);
    fw_cmdlist_free(&cmds);
    return 0;
}

/* ── Set rate limit ────────────────────────────────────────────────── */

int cmd_set_ratelimit(fw_config_t *cfg, const char *chain, const char *max_str,
                      const char *period_str, const char *ban_str,
                      const char *config_path)
{
    int idx = fw_config_chain_index(chain);
    if (idx < 0) {
        fprintf(stderr, "Unknown chain: %s\n", chain);
        return 1;
    }

    char *endptr;
    long max_l = strtol(max_str, &endptr, 10);
    if (*endptr != '\0' || max_l <= 0) {
        fprintf(stderr, "Invalid max_connections: %s (must be positive integer)\n", max_str);
        return 1;
    }

    long period_l = strtol(period_str, &endptr, 10);
    if (*endptr != '\0' || period_l <= 0) {
        fprintf(stderr, "Invalid period_seconds: %s (must be positive integer)\n", period_str);
        return 1;
    }

    long ban_l = strtol(ban_str, &endptr, 10);
    if (*endptr != '\0' || ban_l <= 0) {
        fprintf(stderr, "Invalid ban_seconds: %s (must be positive integer)\n", ban_str);
        return 1;
    }

    cfg->chains[idx].rate_limit.max_connections = (int)max_l;
    cfg->chains[idx].rate_limit.period_seconds = (int)period_l;
    cfg->chains[idx].rate_limit.ban_seconds = (int)ban_l;
    cfg->chains[idx].rate_limit.enabled = 1;

    if (validate_and_save(cfg, config_path) != 0)
        return 1;

    printf("Rate limit set on %s: max=%d period=%ds ban=%ds\n",
           chain, (int)max_l, (int)period_l, (int)ban_l);
    return 0;
}

/* ── Reload ────────────────────────────────────────────────────────── */

int cmd_reload(fw_config_t *cfg, const char *config_path, int verbose)
{
    printf("Reloading configuration...\n");

    int ret = cmd_stop(cfg, verbose);
    if (ret != 0)
        return ret;

    char err[256] = {0};
    if (fw_config_load(config_path, cfg, err, sizeof(err)) != 0) {
        print_err(_("error_load"), err);
        return 1;
    }

    return cmd_start(cfg, verbose);
}

/* ── Confirm (rollback) ────────────────────────────────────────────── */

int cmd_confirm(void)
{
    /* Uses state file for cross-process communication (comment 3).
       fw_rollback_confirm() checks both in-process state and the
       state file written by the process that started the rollback. */
    if (fw_rollback_confirm() != 0) {
        fprintf(stderr, "No pending rollback to confirm\n");
        return 1;
    }
    printf("Configuration confirmed, rollback timer cancelled\n");
    return 0;
}

/* ── Wait for confirm or timeout (comment 10) ─────────────────────── */

/* Helper: wait in a loop for confirmation (via state file removal)
   or SIGALRM timeout. The CLI must stay running for the alarm to fire. */
static int wait_for_confirm_or_timeout(int rollback_timeout)
{
    printf("Run 'firewallo confirm' within %d seconds to keep this configuration\n",
           rollback_timeout);
    printf("Waiting for confirmation...\n");

    /* Poll loop: check if state file was removed (confirm from another process)
       or if SIGALRM fired (timeout). sleep(1) is interrupted by SIGALRM. */
    while (1) {
        /* Check if SIGALRM fired */
        if (fw_rollback_check()) {
            printf("Timeout reached, configuration rolled back automatically\n");
            return 1;
        }

        /* Check if state file was removed by 'firewallo confirm' */
        fw_rollback_state_t state;
        if (fw_rollback_state_load(&state) != 0 || !state.pending) {
            /* State file gone or no longer pending: confirmed by another process */
            alarm(0); /* cancel our alarm */
            printf("Configuration confirmed (by another process)\n");

            /* Clean up in-process state */
            fw_rollback_cancel();
            return 0;
        }

        sleep(1);
    }
}

/* ── Start with rollback ──────────────────────────────────────────── */

int cmd_start_with_rollback(fw_config_t *cfg, const char *config_path,
                            int verbose, int rollback_timeout)
{
    /* Set rollback context */
    fw_rollback_set_context(cfg, config_path);

    /* Start rollback timer before applying */
    if (fw_rollback_start(rollback_timeout) != 0) {
        fprintf(stderr, "Failed to start rollback timer\n");
        return 1;
    }

    printf("Rollback timer started: %d seconds to confirm\n", rollback_timeout);

    /* Apply rules */
    int ret = cmd_start(cfg, verbose);
    if (ret != 0) {
        /* Apply failed: perform immediate rollback using saved backup (comment 7) */
        fprintf(stderr, "Apply failed, performing immediate rollback...\n");
        fw_rollback_perform();
        return ret;
    }

    /* Keep CLI running until confirm or timeout (comment 10) */
    return wait_for_confirm_or_timeout(rollback_timeout);
}

/* ── Reload with rollback ─────────────────────────────────────────── */

int cmd_reload_with_rollback(fw_config_t *cfg, const char *config_path,
                             int verbose, int rollback_timeout)
{
    /* Set rollback context */
    fw_rollback_set_context(cfg, config_path);

    /* Start rollback timer before applying */
    if (fw_rollback_start(rollback_timeout) != 0) {
        fprintf(stderr, "Failed to start rollback timer\n");
        return 1;
    }

    printf("Rollback timer started: %d seconds to confirm\n", rollback_timeout);

    /* Reload rules */
    int ret = cmd_reload(cfg, config_path, verbose);
    if (ret != 0) {
        /* Reload failed: perform immediate rollback using saved backup (comment 7) */
        fprintf(stderr, "Reload failed, performing immediate rollback...\n");
        fw_rollback_perform();
        return ret;
    }

    /* Keep CLI running until confirm or timeout (comment 10) */
    return wait_for_confirm_or_timeout(rollback_timeout);
}

/* ── Version ───────────────────────────────────────────────────────── */

int cmd_version(const fw_config_t *cfg)
{
    printf("firewallo %s\n", cfg->version);
    return 0;
}
