#include "firewallo/backend.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <string.h>

#define NFT "/usr/sbin/nft"

static void nft_cmd(fw_cmdlist_t *out, const char *rule)
{
    fw_cmdlist_append(out, "%s \"%s\"", NFT, rule);
}

/* ── Flush / Table / Chain ─────────────────────────────────────────── */

static void nft_flush_ruleset(fw_cmdlist_t *out)
{
    nft_cmd(out, "flush ruleset");
}

static void nft_create_filter_table(fw_cmdlist_t *out)
{
    nft_cmd(out, "add table inet filter");
}

static void nft_create_base_chain(fw_cmdlist_t *out, const char *chain,
                                   const char *hook, int priority, const char *policy)
{
    char rule[512];
    snprintf(rule, sizeof(rule),
             "add chain inet filter %s { type filter hook %s priority %d; policy %s; }",
             chain, hook, priority, policy);
    nft_cmd(out, rule);
}

static void nft_create_user_chain(fw_cmdlist_t *out, const char *table, const char *chain)
{
    char rule[256];
    snprintf(rule, sizeof(rule), "add chain inet %s %s", table, chain);
    nft_cmd(out, rule);
}

/* ── Loopback ──────────────────────────────────────────────────────── */

static void nft_add_loopback_accept(fw_cmdlist_t *out, const char *chain)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s iifname \\\"lo\\\" counter accept", chain);
    if (strcmp(chain, "INPUT") == 0)
        snprintf(rule, sizeof(rule),
                 "add rule inet filter INPUT iifname \\\"lo\\\" counter accept");
    else
        snprintf(rule, sizeof(rule),
                 "add rule inet filter OUTPUT oifname \\\"lo\\\" counter accept");
    nft_cmd(out, rule);
}

/* ── State tracking ────────────────────────────────────────────────── */

static void nft_add_state_rules(fw_cmdlist_t *out)
{
    nft_cmd(out, "add rule inet filter stato ct state related,established log prefix \\\"ACCEPT state related-established:\\\" counter accept");
    nft_cmd(out, "add rule inet filter stato ct state related log prefix \\\"ACCEPT state related :\\\" counter accept");
    nft_cmd(out, "add rule inet filter stato ct state established log prefix \\\"ACCEPT state established:\\\" counter accept");
}

/* ── TCP flag detection ────────────────────────────────────────────── */

static void nft_add_tcp_flag_rules(fw_cmdlist_t *out)
{
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags fin,psh,urg / fin,syn,rst,psh,ack,urg log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags fin,syn,rst,ack,urg / fin,syn,rst,psh,ack,urg log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags fin,syn,rst,psh,ack,urg / fin,syn,rst,psh,ack,urg log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags fin / fin,syn,rst,psh,ack,urg log prefix \\\"DROP PortScan:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags syn,rst / syn,rst log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags fin,syn / fin,syn log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
    nft_cmd(out, "add rule inet filter tcp_flags tcp flags 0x0 / fin,syn,rst,psh,ack,urg log prefix \\\"DROP PortScanX-mas:\\\" counter drop");
}

/* ── DNS ───────────────────────────────────────────────────────────── */

static void nft_add_dns_localhost(fw_cmdlist_t *out)
{
    nft_cmd(out, "add rule inet filter dnserv ip saddr 127.0.0.1 tcp dport 53 log prefix \\\"ACCEPT dnserv 127.0.0.1 :\\\" counter accept");
    nft_cmd(out, "add rule inet filter dnserv ip daddr 127.0.0.1 tcp dport 53 log prefix \\\"ACCEPT dnserv 127.0.0.1 :\\\" counter accept");
    nft_cmd(out, "add rule inet filter dnserv ip daddr 127.0.0.1 tcp sport 53 log prefix \\\"ACCEPT dnserv 127.0.0.1 :\\\" counter accept");
    nft_cmd(out, "add rule inet filter dnserv ip saddr 127.0.0.1 tcp sport 53 log prefix \\\"ACCEPT dnserv 127.0.0.1 :\\\" counter accept");
}

static void nft_add_dns_server(fw_cmdlist_t *out, const char *ip, int rate_limited)
{
    const char *limit = rate_limited ? "limit rate 10/minute " : "";
    char rule[512];
    const char *dirs[] = {"saddr", "daddr"};
    const char *protos[] = {"tcp", "udp"};
    const char *ports[] = {"dport", "sport"};

    for (int d = 0; d < 2; d++) {
        for (int p = 0; p < 2; p++) {
            for (int pt = 0; pt < 2; pt++) {
                snprintf(rule, sizeof(rule),
                         "add rule inet filter dnserv ip %s %s %s %s 53 "
                         "log prefix \\\"ACCEPT dnserv %s :\\\" %scounter accept",
                         dirs[d], ip, protos[p], ports[pt], ip, limit);
                nft_cmd(out, rule);
            }
        }
    }
}

static void nft_add_dns_rootserver(fw_cmdlist_t *out, const char *ip)
{
    nft_add_dns_server(out, ip, 0);
}

/* ── ICMP ──────────────────────────────────────────────────────────── */

static void nft_add_icmp_rules(fw_cmdlist_t *out)
{
    const char *types[] = {
        "destination-unreachable", "source-quench",
        "time-exceeded", "parameter-problem"
    };
    char rule[256];
    for (int i = 0; i < 4; i++) {
        snprintf(rule, sizeof(rule),
                 "add rule inet filter icmp_good icmp type %s "
                 "log prefix \\\"ACCEPT icmp_good :\\\" counter accept",
                 types[i]);
        nft_cmd(out, rule);
    }
    nft_cmd(out, "add rule inet filter icmp_good icmp type echo-request log prefix \\\"ACCEPT icmp_good :\\\" counter accept");
    nft_cmd(out, "add rule inet filter icmp_good icmp type echo-reply log prefix \\\"ACCEPT icmp_good :\\\" counter accept");
}

/* ── DPI queue ─────────────────────────────────────────────────────── */

static void nft_add_dpi_queue(fw_cmdlist_t *out)
{
    nft_cmd(out, "add rule inet filter dpi meta l4proto tcp queue num 0 bypass");
}

/* ── ICMPv6 ────────────────────────────────────────────────────────── */

static void nft_add_icmpv6_rules(fw_cmdlist_t *out)
{
    /* Neighbor Solicitation */
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type nd-neighbor-solicit "
            "log prefix \\\"ACCEPT icmpv6 NS :\\\" counter accept");
    /* Neighbor Advertisement */
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type nd-neighbor-advert "
            "log prefix \\\"ACCEPT icmpv6 NA :\\\" counter accept");
    /* Router Solicitation */
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type nd-router-solicit "
            "log prefix \\\"ACCEPT icmpv6 RS :\\\" counter accept");
    /* Router Advertisement */
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type nd-router-advert "
            "log prefix \\\"ACCEPT icmpv6 RA :\\\" counter accept");
    /* Echo request/reply for IPv6 */
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type echo-request "
            "log prefix \\\"ACCEPT icmpv6 echo-request :\\\" counter accept");
    nft_cmd(out, "add rule inet filter icmp_good icmpv6 type echo-reply "
            "log prefix \\\"ACCEPT icmpv6 echo-reply :\\\" counter accept");
}

/* ── IPv6 transition mechanism filtering ───────────────────────────── */

static void nft_add_transition_filter(fw_cmdlist_t *out, int block_6to4,
                                       int block_teredo, int block_isatap)
{
    /* 6to4: protocol 41, anycast prefix 192.88.99.0/24, IPv6 prefix 2002::/16 */
    if (block_6to4) {
        nft_cmd(out, "add rule inet filter FORWARD ip protocol 41 "
                "log prefix \\\"DROP 6to4 tunnel :\\\" counter drop");
        nft_cmd(out, "add rule inet filter INPUT ip protocol 41 "
                "log prefix \\\"DROP 6to4 tunnel :\\\" counter drop");
        nft_cmd(out, "add rule inet filter FORWARD ip6 daddr 2002::/16 "
                "log prefix \\\"DROP 6to4 prefix :\\\" counter drop");
    }

    /* Teredo: UDP port 3544 */
    if (block_teredo) {
        nft_cmd(out, "add rule inet filter FORWARD udp dport 3544 "
                "log prefix \\\"DROP Teredo :\\\" counter drop");
        nft_cmd(out, "add rule inet filter INPUT udp dport 3544 "
                "log prefix \\\"DROP Teredo :\\\" counter drop");
        nft_cmd(out, "add rule inet filter FORWARD ip6 daddr 2001::/32 "
                "log prefix \\\"DROP Teredo prefix :\\\" counter drop");
    }

    /* ISATAP: protocol 41 with ISATAP-specific addresses (0000:5efe:*) */
    if (block_isatap) {
        nft_cmd(out, "add rule inet filter FORWARD ip6 daddr ::5efe:0:0/96 "
                "log prefix \\\"DROP ISATAP :\\\" counter drop");
        nft_cmd(out, "add rule inet filter INPUT ip6 daddr ::5efe:0:0/96 "
                "log prefix \\\"DROP ISATAP :\\\" counter drop");
    }
}

/* ── Chain jumps ───────────────────────────────────────────────────── */

static void nft_add_builtin_jumps(fw_cmdlist_t *out, const char *builtin)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s counter jump stato", builtin);
    nft_cmd(out, rule);
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s counter jump dnserv", builtin);
    nft_cmd(out, rule);
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s counter jump icmp_good", builtin);
    nft_cmd(out, rule);
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s counter jump tcp_flags", builtin);
    nft_cmd(out, rule);
}

static void nft_add_forward_jump(fw_cmdlist_t *out, const char *iif,
                                  const char *oif, const char *chain)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter FORWARD iifname %s oifname %s counter jump %s",
             iif, oif, chain);
    nft_cmd(out, rule);
}

static void nft_add_input_jump(fw_cmdlist_t *out, const char *iif, const char *chain)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter INPUT iifname %s counter jump %s", iif, chain);
    nft_cmd(out, rule);
}

static void nft_add_output_jump(fw_cmdlist_t *out, const char *oif, const char *chain)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter OUTPUT oifname %s counter jump %s", oif, chain);
    nft_cmd(out, rule);
}

/* ── Filter rules ──────────────────────────────────────────────────── */

static void nft_add_filter_port_rule(fw_cmdlist_t *out, const char *chain,
                                      fw_proto_t proto, int port)
{
    const char *pstr = proto == PROTO_UDP ? "udp" : "tcp";
    char rule[512];
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s %s dport %d "
             "log prefix \\\"ACCEPTED %s %d %s : \\\" counter accept",
             chain, pstr, port, pstr, port, chain);
    nft_cmd(out, rule);
}

static void nft_add_filter_explicit_rule(fw_cmdlist_t *out, const char *chain,
                                          const fw_filter_rule_t *rule)
{
    const char *pstr = rule->protocol == PROTO_UDP ? "udp" : "tcp";
    const char *act = "accept";
    if (rule->action == ACTION_DROP) act = "drop";
    else if (rule->action == ACTION_REJECT) act = "reject";

    char buf[512];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "add rule inet filter %s", chain);

    if (rule->src_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " ip saddr %s", rule->src_addr);
    if (rule->dst_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " ip daddr %s", rule->dst_addr);

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, " %s", pstr);

    if (rule->src_port.start > 0) {
        if (rule->src_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " sport %d-%d", rule->src_port.start, rule->src_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " sport %d", rule->src_port.start);
    }

    if (rule->dst_port.start > 0) {
        if (rule->dst_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " dport %d-%d", rule->dst_port.start, rule->dst_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " dport %d", rule->dst_port.start);
    }

    /* Schedule constraints */
    if (rule->schedule.enabled) {
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " meta hour \\\"%02d:%02d\\\"-\\\"%02d:%02d\\\"",
                        rule->schedule.hour_start, rule->schedule.minute_start,
                        rule->schedule.hour_end, rule->schedule.minute_end);

        /* Build day list for meta day */
        static const char *day_names[] = {"Monday", "Tuesday", "Wednesday", "Thursday",
                                          "Friday", "Saturday", "Sunday"};
        char days_buf[256];
        fw_schedule_days_str(rule->schedule.days, days_buf, sizeof(days_buf), day_names, ", ");
        if (days_buf[0])
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " meta day { %s }", days_buf);
    }

    const char *comment = rule->comment[0] ? rule->comment : chain;
    snprintf(buf + pos, sizeof(buf) - (size_t)pos,
             " log prefix \\\"%s : \\\" counter %s", comment, act);
    nft_cmd(out, buf);
}

/* ── Drop logging ──────────────────────────────────────────────────── */

static void nft_add_drop_log(fw_cmdlist_t *out, const char *chain, const char *prefix)
{
    char rule[256];
    snprintf(rule, sizeof(rule),
             "add rule inet filter %s log prefix \\\"%s\\\" flags all", chain, prefix);
    nft_cmd(out, rule);
}

/* ── NAT ───────────────────────────────────────────────────────────── */

static void nft_create_nat_table(fw_cmdlist_t *out)
{
    nft_cmd(out, "add table inet nat");
    nft_cmd(out, "add chain inet nat PREROUTING { type nat hook prerouting priority -100; policy accept; }");
    nft_cmd(out, "add chain inet nat OUTPUT { type nat hook output priority 100; policy accept; }");
    nft_cmd(out, "add chain inet nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }");
}

static void nft_add_masquerade(fw_cmdlist_t *out, const char *src, const char *oif,
                                const char *comment)
{
    char rule[512];
    snprintf(rule, sizeof(rule),
             "add rule inet nat POSTROUTING oifname %s ip saddr %s "
             "log prefix \\\"NAT POSTROUTING %s ifout %s: \\\" counter masquerade",
             oif, src, src, oif);
    (void)comment;
    nft_cmd(out, rule);
}

static void nft_add_snat(fw_cmdlist_t *out, const char *src, const char *oif,
                          const char *to_source, const char *comment)
{
    char rule[512];
    snprintf(rule, sizeof(rule),
             "add rule inet nat POSTROUTING oifname %s ip saddr %s "
             "log prefix \\\"NAT SNAT %s: \\\" counter snat to %s",
             oif, src, comment, to_source);
    nft_cmd(out, rule);
}

static void nft_add_dnat(fw_cmdlist_t *out, const fw_nat_pre_t *rule)
{
    const char *pstr = rule->protocol == PROTO_UDP ? "udp" : "tcp";
    char buf[512];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "add rule inet nat PREROUTING");
    if (rule->iif[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " iif %s", rule->iif);
    if (rule->src[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " ip saddr %s", rule->src);

    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    " %s dport %d", pstr, rule->dport);
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    " log prefix \\\"NAT PREROUTING %s: \\\" counter dnat to %s:%d",
                    rule->comment, rule->to_dest_ip, rule->to_dest_port);
    nft_cmd(out, buf);
}

/* ── Mangle ────────────────────────────────────────────────────────── */

static void nft_create_mangle_table(fw_cmdlist_t *out)
{
    nft_cmd(out, "add table inet mangle");
    nft_cmd(out, "add chain inet mangle PREROUTING { type filter hook prerouting priority -150; policy accept; }");
    nft_cmd(out, "add chain inet mangle POSTROUTING { type filter hook postrouting priority 150; policy accept; }");
}

/* ── Rate limiting ─────────────────────────────────────────────────── */

static void nft_add_rate_limit(fw_cmdlist_t *out, const char *chain,
                                const fw_rate_limit_t *rl)
{
    if (!rl || !rl->enabled)
        return;

    char rule[512];

    /* Create a dynamic set for banned IPs with automatic timeout */
    snprintf(rule, sizeof(rule),
             "add set ip filter ratelimit_%s { type ipv4_addr; flags dynamic,timeout; timeout %ds; }",
             chain, rl->ban_seconds);
    nft_cmd(out, rule);

    /* Drop packets from IPs already in the ban set */
    snprintf(rule, sizeof(rule),
             "add rule ip filter %s ip saddr @ratelimit_%s "
             "log prefix \\\"RATELIMIT BAN %s : \\\" counter drop",
             chain, chain, chain);
    nft_cmd(out, rule);

    /* Use a meter keyed on ip saddr so rate limiting is per-source-IP.
     * Compute an equivalent rate+unit that respects period_seconds:
     *   - period <= 1s   -> rate/second
     *   - period <= 60s  -> (max * 60/period)/minute
     *   - otherwise      -> (max * 3600/period)/hour
     * This preserves the configured semantics instead of collapsing
     * arbitrary periods into a single unit. */
    const char *unit;
    int rate;
    if (rl->period_seconds <= 1) {
        rate = rl->max_connections;
        unit = "second";
    } else if (rl->period_seconds <= 60) {
        rate = rl->max_connections * 60 / rl->period_seconds;
        if (rate < 1) rate = 1;
        unit = "minute";
    } else {
        rate = rl->max_connections * 3600 / rl->period_seconds;
        if (rate < 1) rate = 1;
        unit = "hour";
    }

    snprintf(rule, sizeof(rule),
             "add rule ip filter %s ct state new "
             "meter ratelimit_meter_%s { ip saddr limit rate over %d/%s burst %d packets } "
             "add @ratelimit_%s { ip saddr } "
             "log prefix \\\"RATELIMIT ADD %s : \\\" counter drop",
             chain, chain, rate, unit,
             rl->max_connections, chain, chain);
    nft_cmd(out, rule);
}

/* ── Stop / Reset ──────────────────────────────────────────────────── */

static void nft_setup_stop(fw_cmdlist_t *out)
{
    nft_cmd(out, "flush ruleset");
    /* Re-create with accept policies */
    nft_cmd(out, "add table inet filter");
    nft_cmd(out, "add chain inet filter INPUT { type filter hook input priority 0; policy accept; }");
    nft_cmd(out, "add chain inet filter OUTPUT { type filter hook output priority 0; policy accept; }");
    nft_cmd(out, "add chain inet filter FORWARD { type filter hook forward priority 0; policy accept; }");
    /* Re-create NAT for masquerading */
    nft_cmd(out, "add table inet nat");
    nft_cmd(out, "add chain inet nat PREROUTING { type nat hook prerouting priority -100; policy accept; }");
    nft_cmd(out, "add chain inet nat OUTPUT { type nat hook output priority 100; policy accept; }");
    nft_cmd(out, "add chain inet nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }");
}

static void nft_setup_reset(fw_cmdlist_t *out)
{
    nft_cmd(out, "flush ruleset");
    nft_cmd(out, "add table inet filter");
    nft_cmd(out, "add chain inet filter INPUT { type filter hook input priority 0; policy accept; }");
    nft_cmd(out, "add chain inet filter OUTPUT { type filter hook output priority 0; policy accept; }");
    nft_cmd(out, "add chain inet filter FORWARD { type filter hook forward priority 0; policy accept; }");
}

/* ── Backend ops table ─────────────────────────────────────────────── */

const fw_backend_ops_t fw_backend_nft = {
    .flush_ruleset        = nft_flush_ruleset,
    .create_filter_table  = nft_create_filter_table,
    .create_base_chain    = nft_create_base_chain,
    .create_user_chain    = nft_create_user_chain,
    .add_loopback_accept  = nft_add_loopback_accept,
    .add_state_rules      = nft_add_state_rules,
    .add_tcp_flag_rules   = nft_add_tcp_flag_rules,
    .add_dns_localhost    = nft_add_dns_localhost,
    .add_dns_server       = nft_add_dns_server,
    .add_dns_rootserver   = nft_add_dns_rootserver,
    .add_icmp_rules       = nft_add_icmp_rules,
    .add_icmpv6_rules     = nft_add_icmpv6_rules,
    .add_transition_filter = nft_add_transition_filter,
    .add_dpi_queue        = nft_add_dpi_queue,
    .add_builtin_jumps    = nft_add_builtin_jumps,
    .add_forward_jump     = nft_add_forward_jump,
    .add_input_jump       = nft_add_input_jump,
    .add_output_jump      = nft_add_output_jump,
    .add_filter_port_rule = nft_add_filter_port_rule,
    .add_filter_explicit_rule = nft_add_filter_explicit_rule,
    .add_drop_log         = nft_add_drop_log,
    .create_nat_table     = nft_create_nat_table,
    .add_masquerade       = nft_add_masquerade,
    .add_snat             = nft_add_snat,
    .add_dnat             = nft_add_dnat,
    .create_mangle_table  = nft_create_mangle_table,
    .add_rate_limit       = nft_add_rate_limit,
    .setup_stop           = nft_setup_stop,
    .setup_reset          = nft_setup_reset,
};
