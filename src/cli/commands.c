#include "commands.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include "firewallo/i18n.h"
#include "firewallo/json.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* ── Version ───────────────────────────────────────────────────────── */

int cmd_version(const fw_config_t *cfg)
{
    printf("firewallo %s\n", cfg->version);
    return 0;
}
