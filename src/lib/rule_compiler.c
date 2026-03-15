#include "firewallo/rule_compiler.h"
#include "firewallo/backend.h"
#include "firewallo/zone.h"
#include "firewallo/config.h"
#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* DNS root servers (verified 2024-09-10) */
static const char *root_servers[] = {
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
};
#define ROOT_SERVER_COUNT 13

/* ── Command list ──────────────────────────────────────────────────── */

void fw_cmdlist_init(fw_cmdlist_t *list)
{
    list->cmds = NULL;
    list->count = 0;
    list->capacity = 0;
}

int fw_cmdlist_append(fw_cmdlist_t *list, const char *fmt, ...)
{
    if (list->count >= list->capacity) {
        int newcap = list->capacity < 64 ? 64 : list->capacity * 2;
        fw_cmd_t *nc = realloc(list->cmds, sizeof(fw_cmd_t) * (size_t)newcap);
        if (!nc) return -1;
        list->cmds = nc;
        list->capacity = newcap;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(list->cmds[list->count].command,
              sizeof(list->cmds[list->count].command), fmt, ap);
    va_end(ap);
    list->count++;
    return 0;
}

int fw_cmdlist_dump(const fw_cmdlist_t *list, char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return -1;

    buf[0] = '\0';
    size_t written = 0;

    for (int i = 0; i < list->count; i++) {
        int n = snprintf(buf + written, buflen - written,
                         "[%03d] %s\n", i, list->cmds[i].command);
        if (n < 0)
            return -1;
        if ((size_t)n >= buflen - written) {
            /* Buffer full — truncate but still return what we have */
            written = buflen - 1;
            break;
        }
        written += (size_t)n;
    }

    return (int)written;
}

int fw_cmdlist_exec(const fw_cmdlist_t *list, int *fail_index)
{
    for (int i = 0; i < list->count; i++) {
        int ret = fw_exec(list->cmds[i].command);
        if (ret != 0) {
            if (fail_index) *fail_index = i;
            return ret;
        }
    }
    if (fail_index) *fail_index = -1;
    return 0;
}

void fw_cmdlist_free(fw_cmdlist_t *list)
{
    free(list->cmds);
    list->cmds = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* ── Backend lookup ────────────────────────────────────────────────── */

const fw_backend_ops_t *fw_backend_get(fw_backend_t type)
{
    if (type == BACKEND_IPT)
        return &fw_backend_ipt;
    return &fw_backend_nft;
}

/* ── Helper: add inter-zone FORWARD jumps ──────────────────────────── */

static void add_forward_jumps(const fw_config_t *cfg, const fw_backend_ops_t *ops,
                              fw_cmdlist_t *out,
                              fw_zone_t src_zone, fw_zone_t dst_zone)
{
    const char *src_ifs[FW_MAX_INTERFACES];
    const char *dst_ifs[FW_MAX_INTERFACES];
    int src_count = fw_zone_interfaces(cfg, src_zone, src_ifs, FW_MAX_INTERFACES);
    int dst_count = fw_zone_interfaces(cfg, dst_zone, dst_ifs, FW_MAX_INTERFACES);
    const char *chain = fw_zone_chain_name(src_zone, dst_zone);
    if (!chain) return;

    for (int s = 0; s < src_count; s++)
        for (int d = 0; d < dst_count; d++)
            ops->add_forward_jump(out, src_ifs[s], dst_ifs[d], chain);
}

/* ── Compile start ─────────────────────────────────────────────────── */

int fw_compile_start(const fw_config_t *cfg, fw_cmdlist_t *out)
{
    fw_cmdlist_init(out);
    const fw_backend_ops_t *ops = fw_backend_get(cfg->backend);

    /* 1. Flush existing rules */
    ops->flush_ruleset(out);

    /* 2. Create filter table and base chains with DROP policy */
    ops->create_filter_table(out);
    ops->create_base_chain(out, "INPUT", "input", 0, "drop");
    ops->create_base_chain(out, "FORWARD", "forward", 0, "drop");
    ops->create_base_chain(out, "OUTPUT", "output", 0, "drop");

    /* 3. Loopback accept */
    ops->add_loopback_accept(out, "INPUT");
    ops->add_loopback_accept(out, "OUTPUT");

    /* 4. Create user chains: system chains + 25 filter chains + dpi */
    const char *sys_chains[] = {"icmp_good", "tcp_flags", "stato", "dnserv", "dpi"};
    for (int i = 0; i < 5; i++)
        ops->create_user_chain(out, "filter", sys_chains[i]);

    for (int i = 0; i < FW_CHAIN_COUNT; i++)
        ops->create_user_chain(out, "filter", cfg->chains[i].name);

    /* 5. Setup mangle and NAT table structures */
    ops->create_mangle_table(out);
    ops->create_nat_table(out);

    /* 6. DPI queue rule */
    ops->add_dpi_queue(out);

    /* 7. State tracking rules */
    ops->add_state_rules(out);

    /* 8. TCP flag detection rules */
    ops->add_tcp_flag_rules(out);

    /* 9. DNS rules: localhost */
    ops->add_dns_localhost(out);

    /* 10. DNS rules: configured servers (rate limited) */
    for (int i = 0; i < cfg->dns_count; i++)
        ops->add_dns_server(out, cfg->dns[i], 1);

    /* 11. DNS rules: root servers */
    for (int i = 0; i < ROOT_SERVER_COUNT; i++)
        ops->add_dns_rootserver(out, root_servers[i]);

    /* 12. ICMP rules */
    ops->add_icmp_rules(out);

    /* 12b. ICMPv6 essential traffic rules */
    ops->add_icmpv6_rules(out);

    /* 12c. IPv6 transition mechanism filtering */
    ops->add_transition_filter(out, cfg->block_6to4, cfg->block_teredo,
                               cfg->block_isatap);

    /* 13. FORWARD chain: builtin jumps + localhost accept */
    ops->add_builtin_jumps(out, "FORWARD");
    /* FORWARD localhost accept (nft adds this, iptables uses -i lo) */
    fw_cmdlist_append(out, cfg->backend == BACKEND_NFT
        ? "/usr/sbin/nft \"add rule inet filter FORWARD iifname \\\"lo\\\" "
          "log prefix \\\"ACCEPTED FORWARD localhost : \\\" counter accept\""
        : "/sbin/iptables -A FORWARD -i lo -j ACCEPT");

    /* 14. FORWARD inter-zone jumps (non-VPN) */
    /* LAN → {LAN, WAN, DMZ} */
    add_forward_jumps(cfg, ops, out, ZONE_LAN, ZONE_LAN);
    add_forward_jumps(cfg, ops, out, ZONE_LAN, ZONE_WAN);
    add_forward_jumps(cfg, ops, out, ZONE_LAN, ZONE_DMZ);
    /* WAN → {LAN, DMZ, WAN} */
    add_forward_jumps(cfg, ops, out, ZONE_WAN, ZONE_LAN);
    add_forward_jumps(cfg, ops, out, ZONE_WAN, ZONE_DMZ);
    add_forward_jumps(cfg, ops, out, ZONE_WAN, ZONE_WAN);
    /* DMZ → {LAN, DMZ, WAN} */
    add_forward_jumps(cfg, ops, out, ZONE_DMZ, ZONE_LAN);
    add_forward_jumps(cfg, ops, out, ZONE_DMZ, ZONE_DMZ);
    add_forward_jumps(cfg, ops, out, ZONE_DMZ, ZONE_WAN);

    /* 15. INPUT chain: builtin jumps + per-zone jumps */
    ops->add_builtin_jumps(out, "INPUT");
    /* INPUT localhost */
    fw_cmdlist_append(out, cfg->backend == BACKEND_NFT
        ? "/usr/sbin/nft \"add rule inet filter INPUT iifname \\\"lo\\\" "
          "log prefix \\\"ACCEPT INPUT localhost : \\\" counter accept\""
        : "/sbin/iptables -A INPUT -i lo -j ACCEPT");

    for (int i = 0; i < cfg->lan_if_count; i++)
        ops->add_input_jump(out, cfg->lan_ifs[i], "lan2fw");
    for (int i = 0; i < cfg->wan_if_count; i++)
        ops->add_input_jump(out, cfg->wan_ifs[i], "wan2fw");
    for (int i = 0; i < cfg->dmz_if_count; i++)
        ops->add_input_jump(out, cfg->dmz_ifs[i], "dmz2fw");

    /* 16. OUTPUT chain: builtin jumps + per-zone jumps */
    ops->add_builtin_jumps(out, "OUTPUT");
    fw_cmdlist_append(out, cfg->backend == BACKEND_NFT
        ? "/usr/sbin/nft \"add rule inet filter OUTPUT oifname \\\"lo\\\" "
          "log prefix \\\"ACCEPTED OUTPUT localhost : \\\" counter accept\""
        : "/sbin/iptables -A OUTPUT -o lo -j ACCEPT");

    for (int i = 0; i < cfg->dmz_if_count; i++)
        ops->add_output_jump(out, cfg->dmz_ifs[i], "fw2dmz");
    for (int i = 0; i < cfg->lan_if_count; i++)
        ops->add_output_jump(out, cfg->lan_ifs[i], "fw2lan");
    for (int i = 0; i < cfg->wan_if_count; i++)
        ops->add_output_jump(out, cfg->wan_ifs[i], "fw2wan");

    /* 17. VPN chain attribution */
    const char *vpn_ifs[FW_MAX_INTERFACES];
    int vpn_count = fw_zone_interfaces(cfg, ZONE_VPN, vpn_ifs, FW_MAX_INTERFACES);

    /* LAN ↔ VPN */
    for (int l = 0; l < cfg->lan_if_count; l++)
        for (int v = 0; v < vpn_count; v++) {
            ops->add_forward_jump(out, cfg->lan_ifs[l], vpn_ifs[v], "lan2vpns");
            ops->add_forward_jump(out, vpn_ifs[v], cfg->lan_ifs[l], "vpns2lan");
        }
    /* DMZ ↔ VPN */
    for (int d = 0; d < cfg->dmz_if_count; d++)
        for (int v = 0; v < vpn_count; v++) {
            ops->add_forward_jump(out, cfg->dmz_ifs[d], vpn_ifs[v], "dmz2vpns");
            ops->add_forward_jump(out, vpn_ifs[v], cfg->dmz_ifs[d], "vpns2dmz");
        }
    /* WAN ↔ VPN */
    for (int w = 0; w < cfg->wan_if_count; w++)
        for (int v = 0; v < vpn_count; v++) {
            ops->add_forward_jump(out, cfg->wan_ifs[w], vpn_ifs[v], "wan2vpns");
            ops->add_forward_jump(out, vpn_ifs[v], cfg->wan_ifs[w], "vpns2wan");
        }
    /* VPN INPUT/OUTPUT */
    for (int v = 0; v < vpn_count; v++) {
        ops->add_input_jump(out, vpn_ifs[v], "vpns2fw");
        ops->add_output_jump(out, vpn_ifs[v], "fw2vpns");
    }
    /* VPN ↔ VPN */
    for (int v1 = 0; v1 < vpn_count; v1++)
        for (int v2 = 0; v2 < vpn_count; v2++)
            ops->add_forward_jump(out, vpn_ifs[v1], vpn_ifs[v2], "vpns2vpns");

    /* 18. Apply filter port rules for all 25 chains */
    for (int c = 0; c < FW_CHAIN_COUNT; c++) {
        const fw_chain_t *ch = &cfg->chains[c];
        for (int i = 0; i < ch->tcp_port_count; i++)
            ops->add_filter_port_rule(out, ch->name, PROTO_TCP, ch->tcp_ports[i]);
        for (int i = 0; i < ch->udp_port_count; i++)
            ops->add_filter_port_rule(out, ch->name, PROTO_UDP, ch->udp_ports[i]);
        for (int i = 0; i < ch->rule_count; i++)
            ops->add_filter_explicit_rule(out, ch->name, &ch->rules[i]);
    }

    /* 19. NAT: masquerade LAN ranges to WAN interfaces */
    for (int r = 0; r < cfg->lan_range_count; r++)
        for (int w = 0; w < cfg->wan_if_count; w++)
            ops->add_masquerade(out, cfg->lan_ranges[r], cfg->wan_ifs[w], "LAN_NAT");

    /* NAT: custom postrouting rules */
    for (int i = 0; i < cfg->nat_post_count; i++) {
        const fw_nat_post_t *np = &cfg->nat_post[i];
        if (np->type == NAT_SNAT)
            ops->add_snat(out, np->src, np->oif, np->to_source, np->comment);
        else
            ops->add_masquerade(out, np->src, np->oif, np->comment);
    }

    /* NAT: prerouting (DNAT) rules */
    for (int i = 0; i < cfg->nat_pre_count; i++)
        ops->add_dnat(out, &cfg->nat_pre[i]);

    /* 20. Final drop logging (nft only — iptables drops by policy) */
    ops->add_drop_log(out, "INPUT", "INPUT_DROP : ");
    ops->add_drop_log(out, "FORWARD", "FORWARD_DROP : ");
    ops->add_drop_log(out, "OUTPUT", "OUTPUT_DROP : ");

    return 0;
}

/* ── Compile stop ──────────────────────────────────────────────────── */

int fw_compile_stop(const fw_config_t *cfg, fw_cmdlist_t *out)
{
    fw_cmdlist_init(out);
    const fw_backend_ops_t *ops = fw_backend_get(cfg->backend);

    ops->setup_stop(out);

    /* Re-apply NAT masquerading for LAN ranges (stop keeps NAT active) */
    if (cfg->backend == BACKEND_NFT) {
        for (int r = 0; r < cfg->lan_range_count; r++)
            for (int w = 0; w < cfg->wan_if_count; w++)
                ops->add_masquerade(out, cfg->lan_ranges[r], cfg->wan_ifs[w], "LAN_NAT");
    }

    return 0;
}

/* ── Compile reset ─────────────────────────────────────────────────── */

int fw_compile_reset(const fw_config_t *cfg, fw_cmdlist_t *out)
{
    fw_cmdlist_init(out);
    const fw_backend_ops_t *ops = fw_backend_get(cfg->backend);
    ops->setup_reset(out);
    return 0;
}
