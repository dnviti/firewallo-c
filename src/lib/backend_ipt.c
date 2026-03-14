#include "firewallo/backend.h"
#include "firewallo/rule_compiler.h"
#include <stdio.h>
#include <string.h>

#define IPT "/sbin/iptables"

/* ── Flush / Table / Chain ─────────────────────────────────────────── */

static void ipt_flush_ruleset(fw_cmdlist_t *out)
{
    fw_cmdlist_append(out, "%s -F", IPT);
    fw_cmdlist_append(out, "%s -X", IPT);
    fw_cmdlist_append(out, "%s -t nat -F", IPT);
    fw_cmdlist_append(out, "%s -t nat -X", IPT);
    fw_cmdlist_append(out, "%s -t filter -F", IPT);
    fw_cmdlist_append(out, "%s -t filter -X", IPT);
    fw_cmdlist_append(out, "%s -t mangle -F", IPT);
    fw_cmdlist_append(out, "%s -t mangle -X", IPT);
}

static void ipt_create_filter_table(fw_cmdlist_t *out)
{
    (void)out; /* iptables filter table exists by default */
}

static void ipt_create_base_chain(fw_cmdlist_t *out, const char *chain,
                                   const char *hook, int priority, const char *policy)
{
    (void)hook;
    (void)priority;
    /* iptables uses -P to set policy on built-in chains */
    char pol_upper[16];
    if (strcmp(policy, "drop") == 0)
        snprintf(pol_upper, sizeof(pol_upper), "DROP");
    else
        snprintf(pol_upper, sizeof(pol_upper), "ACCEPT");

    fw_cmdlist_append(out, "%s -P %s %s", IPT, chain, pol_upper);
}

static void ipt_create_user_chain(fw_cmdlist_t *out, const char *table, const char *chain)
{
    (void)table;
    fw_cmdlist_append(out, "%s -N %s", IPT, chain);
}

/* ── Loopback ──────────────────────────────────────────────────────── */

static void ipt_add_loopback_accept(fw_cmdlist_t *out, const char *chain)
{
    if (strcmp(chain, "INPUT") == 0)
        fw_cmdlist_append(out, "%s -A INPUT -i lo -j ACCEPT", IPT);
    else
        fw_cmdlist_append(out, "%s -A OUTPUT -o lo -j ACCEPT", IPT);
}

/* ── State tracking ────────────────────────────────────────────────── */

static void ipt_add_state_rules(fw_cmdlist_t *out)
{
    fw_cmdlist_append(out, "%s -A stato -p all -m state --state ESTABLISHED,RELATED -j ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -A stato -p all -m state --state RELATED -j ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -A stato -p all -m state --state ESTABLISHED -j ACCEPT", IPT);
}

/* ── TCP flag detection ────────────────────────────────────────────── */

static void ipt_add_tcp_flag_rules(fw_cmdlist_t *out)
{
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL FIN,URG,PSH -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL ALL -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL ALL -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL FIN -j LOG --log-level warning --log-prefix \"PortScan:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL FIN -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags SYN,RST SYN,RST -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP", IPT);

    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL NONE -j LOG --log-level warning --log-prefix \"PortScanX-mas:\"", IPT);
    fw_cmdlist_append(out, "%s -A tcp_flags -p tcp --tcp-flags ALL NONE -j DROP", IPT);
}

/* ── DNS ───────────────────────────────────────────────────────────── */

static void ipt_add_dns_localhost(fw_cmdlist_t *out)
{
    fw_cmdlist_append(out, "%s -A dnserv -p tcp -s 127.0.0.1 --dport 53 -j ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -A dnserv -p udp -s 127.0.0.1 --dport 53 -j ACCEPT", IPT);
}

static void ipt_add_dns_server(fw_cmdlist_t *out, const char *ip, int rate_limited)
{
    const char *dirs[] = {"-s", "-d"};
    const char *protos[] = {"tcp", "udp"};
    const char *ports[] = {"--dport", "--sport"};

    for (int d = 0; d < 2; d++) {
        for (int p = 0; p < 2; p++) {
            for (int pt = 0; pt < 2; pt++) {
                if (rate_limited) {
                    fw_cmdlist_append(out,
                        "%s -A dnserv -p %s %s %s %s 53 "
                        "-m limit --limit 10/minute --limit-burst 10 "
                        "-j LOG --log-prefix \"ACCEPT dnserv %s : \"",
                        IPT, protos[p], dirs[d], ip, ports[pt], ip);
                }
                fw_cmdlist_append(out,
                    "%s -A dnserv -p %s %s %s %s 53 -j ACCEPT",
                    IPT, protos[p], dirs[d], ip, ports[pt]);
            }
        }
    }
}

static void ipt_add_dns_rootserver(fw_cmdlist_t *out, const char *ip)
{
    const char *dirs[] = {"-s", "-d"};
    const char *protos[] = {"tcp", "udp"};
    const char *ports[] = {"--dport", "--sport"};

    for (int d = 0; d < 2; d++) {
        for (int p = 0; p < 2; p++) {
            for (int pt = 0; pt < 2; pt++) {
                fw_cmdlist_append(out,
                    "%s -A dnserv -p %s %s %s %s 53 -j ACCEPT",
                    IPT, protos[p], dirs[d], ip, ports[pt]);
            }
        }
    }
}

/* ── ICMP ──────────────────────────────────────────────────────────── */

static void ipt_add_icmp_rules(fw_cmdlist_t *out)
{
    const char *types[] = {
        "destination-unreachable", "source-quench",
        "time-exceeded", "parameter-problem"
    };
    for (int i = 0; i < 4; i++)
        fw_cmdlist_append(out, "%s -A icmp_good -p icmp --icmp-type %s -j ACCEPT", IPT, types[i]);

    fw_cmdlist_append(out, "%s -A icmp_good -p icmp --icmp-type echo-request -j ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -A icmp_good -p icmp --icmp-type echo-reply -j ACCEPT", IPT);
}

/* ── DPI queue ─────────────────────────────────────────────────────── */

static void ipt_add_dpi_queue(fw_cmdlist_t *out)
{
    (void)out; /* DPI queue is nft-only in the original */
}

/* ── Chain jumps ───────────────────────────────────────────────────── */

static void ipt_add_builtin_jumps(fw_cmdlist_t *out, const char *builtin)
{
    fw_cmdlist_append(out, "%s -A %s -j stato", IPT, builtin);
    fw_cmdlist_append(out, "%s -A %s -j dnserv", IPT, builtin);
    fw_cmdlist_append(out, "%s -A %s -j icmp_good", IPT, builtin);
    fw_cmdlist_append(out, "%s -A %s -j tcp_flags", IPT, builtin);
}

static void ipt_add_forward_jump(fw_cmdlist_t *out, const char *iif,
                                  const char *oif, const char *chain)
{
    fw_cmdlist_append(out, "%s -A FORWARD -i %s -o %s -j %s", IPT, iif, oif, chain);
}

static void ipt_add_input_jump(fw_cmdlist_t *out, const char *iif, const char *chain)
{
    fw_cmdlist_append(out, "%s -A INPUT -i %s -j %s", IPT, iif, chain);
}

static void ipt_add_output_jump(fw_cmdlist_t *out, const char *oif, const char *chain)
{
    fw_cmdlist_append(out, "%s -A OUTPUT -o %s -j %s", IPT, oif, chain);
}

/* ── Filter rules ──────────────────────────────────────────────────── */

static void ipt_add_filter_port_rule(fw_cmdlist_t *out, const char *chain,
                                      fw_proto_t proto, int port)
{
    const char *pstr = proto == PROTO_UDP ? "udp" : "tcp";
    fw_cmdlist_append(out,
        "%s -t filter -A %s -p %s --dport %d "
        "-j LOG --log-level info --log-prefix \"ACCEPTED %s %d %s :\"",
        IPT, chain, pstr, port, pstr, port, chain);
    fw_cmdlist_append(out,
        "%s -t filter -A %s -p %s --dport %d -j ACCEPT",
        IPT, chain, pstr, port);
}

static void ipt_add_filter_explicit_rule(fw_cmdlist_t *out, const char *chain,
                                          const fw_filter_rule_t *rule)
{
    const char *pstr = rule->protocol == PROTO_UDP ? "udp" : "tcp";
    const char *act = "ACCEPT";
    if (rule->action == ACTION_DROP) act = "DROP";
    else if (rule->action == ACTION_REJECT) act = "REJECT";

    char buf[512];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "%s -t filter -A %s -p %s", IPT, chain, pstr);

    if (rule->src_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " -s %s", rule->src_addr);
    if (rule->dst_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                        " -d %s", rule->dst_addr);
    if (rule->dst_port.start > 0) {
        if (rule->dst_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --dport %d:%d", rule->dst_port.start, rule->dst_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --dport %d", rule->dst_port.start);
    }
    if (rule->src_port.start > 0) {
        if (rule->src_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --sport %d:%d", rule->src_port.start, rule->src_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --sport %d", rule->src_port.start);
    }

    /* LOG then ACTION (iptables needs two separate rules) */
    const char *comment = rule->comment[0] ? rule->comment : chain;
    fw_cmdlist_append(out, "%s -j LOG --log-level info --log-prefix \"%s :\"", buf, comment);

    /* Re-build without LOG, just the action */
    pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "%s -t filter -A %s -p %s", IPT, chain, pstr);
    if (rule->src_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, " -s %s", rule->src_addr);
    if (rule->dst_addr[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, " -d %s", rule->dst_addr);
    if (rule->dst_port.start > 0) {
        if (rule->dst_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --dport %d:%d", rule->dst_port.start, rule->dst_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --dport %d", rule->dst_port.start);
    }
    if (rule->src_port.start > 0) {
        if (rule->src_port.end > 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --sport %d:%d", rule->src_port.start, rule->src_port.end);
        else
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                            " --sport %d", rule->src_port.start);
    }
    fw_cmdlist_append(out, "%s -j %s", buf, act);
}

/* ── Drop logging ──────────────────────────────────────────────────── */

static void ipt_add_drop_log(fw_cmdlist_t *out, const char *chain, const char *prefix)
{
    (void)out; (void)prefix; (void)chain;
    /* iptables relies on policy DROP — drop is implicit by policy. */
}

/* ── NAT ───────────────────────────────────────────────────────────── */

static void ipt_create_nat_table(fw_cmdlist_t *out)
{
    (void)out; /* iptables nat table exists by default */
}

static void ipt_add_masquerade(fw_cmdlist_t *out, const char *src, const char *oif,
                                const char *comment)
{
    (void)comment;
    fw_cmdlist_append(out, "%s -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE",
                      IPT, src, oif);
}

static void ipt_add_snat(fw_cmdlist_t *out, const char *src, const char *oif,
                          const char *to_source, const char *comment)
{
    (void)comment;
    fw_cmdlist_append(out, "%s -t nat -A POSTROUTING -s %s -o %s -j SNAT --to-source %s",
                      IPT, src, oif, to_source);
}

static void ipt_add_dnat(fw_cmdlist_t *out, const fw_nat_pre_t *rule)
{
    const char *pstr = rule->protocol == PROTO_UDP ? "udp" : "tcp";
    char buf[512];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "%s -t nat -A PREROUTING", IPT);
    if (rule->iif[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, " -i %s", rule->iif);
    if (rule->src[0])
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, " -s %s", rule->src);

    snprintf(buf + pos, sizeof(buf) - (size_t)pos,
             " -p %s --dport %d -j DNAT --to-destination %s:%d",
             pstr, rule->dport, rule->to_dest_ip, rule->to_dest_port);

    fw_cmdlist_append(out, "%s", buf);
}

/* ── Mangle ────────────────────────────────────────────────────────── */

static void ipt_create_mangle_table(fw_cmdlist_t *out)
{
    (void)out; /* iptables mangle table exists by default */
}

/* ── Stop / Reset ──────────────────────────────────────────────────── */

static void ipt_setup_stop(fw_cmdlist_t *out)
{
    ipt_flush_ruleset(out);
    fw_cmdlist_append(out, "%s -P INPUT ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -P FORWARD ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -P OUTPUT ACCEPT", IPT);
}

static void ipt_setup_reset(fw_cmdlist_t *out)
{
    ipt_flush_ruleset(out);
    fw_cmdlist_append(out, "%s -P INPUT ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -P FORWARD ACCEPT", IPT);
    fw_cmdlist_append(out, "%s -P OUTPUT ACCEPT", IPT);
}

/* ── Backend ops table ─────────────────────────────────────────────── */

const fw_backend_ops_t fw_backend_ipt = {
    .flush_ruleset        = ipt_flush_ruleset,
    .create_filter_table  = ipt_create_filter_table,
    .create_base_chain    = ipt_create_base_chain,
    .create_user_chain    = ipt_create_user_chain,
    .add_loopback_accept  = ipt_add_loopback_accept,
    .add_state_rules      = ipt_add_state_rules,
    .add_tcp_flag_rules   = ipt_add_tcp_flag_rules,
    .add_dns_localhost    = ipt_add_dns_localhost,
    .add_dns_server       = ipt_add_dns_server,
    .add_dns_rootserver   = ipt_add_dns_rootserver,
    .add_icmp_rules       = ipt_add_icmp_rules,
    .add_dpi_queue        = ipt_add_dpi_queue,
    .add_builtin_jumps    = ipt_add_builtin_jumps,
    .add_forward_jump     = ipt_add_forward_jump,
    .add_input_jump       = ipt_add_input_jump,
    .add_output_jump      = ipt_add_output_jump,
    .add_filter_port_rule = ipt_add_filter_port_rule,
    .add_filter_explicit_rule = ipt_add_filter_explicit_rule,
    .add_drop_log         = ipt_add_drop_log,
    .create_nat_table     = ipt_create_nat_table,
    .add_masquerade       = ipt_add_masquerade,
    .add_snat             = ipt_add_snat,
    .add_dnat             = ipt_add_dnat,
    .create_mangle_table  = ipt_create_mangle_table,
    .setup_stop           = ipt_setup_stop,
    .setup_reset          = ipt_setup_reset,
};
