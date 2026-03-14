#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/backend.h"
#include "firewallo/zone.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
    } \
} while(0)

/* Search command list for a substring */
static int cmdlist_contains(const fw_cmdlist_t *list, const char *substr)
{
    for (int i = 0; i < list->count; i++) {
        if (strstr(list->cmds[i].command, substr))
            return 1;
    }
    return 0;
}

static void test_cmdlist_basic(void)
{
    printf("test_cmdlist_basic\n");
    fw_cmdlist_t list;
    fw_cmdlist_init(&list);

    fw_cmdlist_append(&list, "echo %s", "hello");
    fw_cmdlist_append(&list, "echo %d", 42);
    ASSERT(list.count == 2, "2 commands");
    ASSERT(strcmp(list.cmds[0].command, "echo hello") == 0, "cmd 0");
    ASSERT(strcmp(list.cmds[1].command, "echo 42") == 0, "cmd 1");

    fw_cmdlist_free(&list);
    ASSERT(list.count == 0, "freed");
}

static void test_zone_interfaces(void)
{
    printf("test_zone_interfaces\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config");

    const char *ifs[8];
    int count;

    count = fw_zone_interfaces(&cfg, ZONE_LAN, ifs, 8);
    ASSERT(count == 1, "1 LAN interface");
    ASSERT(strcmp(ifs[0], "eth0") == 0, "LAN is eth0");

    count = fw_zone_interfaces(&cfg, ZONE_WAN, ifs, 8);
    ASSERT(count == 1, "1 WAN interface");
    ASSERT(strcmp(ifs[0], "eth1") == 0, "WAN is eth1");

    count = fw_zone_interfaces(&cfg, ZONE_DMZ, ifs, 8);
    ASSERT(count == 0, "0 DMZ interfaces");

    count = fw_zone_interfaces(&cfg, ZONE_FW, ifs, 8);
    ASSERT(count == 0, "0 FW interfaces (firewall itself)");
}

static void test_compile_start_nft(void)
{
    printf("test_compile_start_nft\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config");
    ASSERT(cfg.backend == BACKEND_NFT, "backend is nft");

    fw_cmdlist_t out;
    ret = fw_compile_start(&cfg, &out);
    ASSERT(ret == 0, "compile start succeeds");
    ASSERT(out.count > 50, "generates many commands");

    /* Check key commands exist */
    ASSERT(cmdlist_contains(&out, "flush ruleset"), "has flush");
    ASSERT(cmdlist_contains(&out, "add table ip filter"), "has filter table");
    ASSERT(cmdlist_contains(&out, "policy drop"), "has drop policy");
    ASSERT(cmdlist_contains(&out, "add chain ip filter lan2wan"), "has lan2wan chain");
    ASSERT(cmdlist_contains(&out, "add chain ip filter stato"), "has stato chain");
    ASSERT(cmdlist_contains(&out, "add chain ip filter dnserv"), "has dnserv chain");
    ASSERT(cmdlist_contains(&out, "add chain ip filter icmp_good"), "has icmp chain");
    ASSERT(cmdlist_contains(&out, "add chain ip filter tcp_flags"), "has tcp_flags chain");

    /* State rules */
    ASSERT(cmdlist_contains(&out, "ct state related,established"), "has state rules");

    /* TCP flag rules */
    ASSERT(cmdlist_contains(&out, "PortScan"), "has port scan detection");

    /* DNS rules */
    ASSERT(cmdlist_contains(&out, "dnserv"), "has DNS rules");
    ASSERT(cmdlist_contains(&out, "8.8.8.8"), "has configured DNS");
    ASSERT(cmdlist_contains(&out, "198.41.0.4"), "has root server");

    /* ICMP rules */
    ASSERT(cmdlist_contains(&out, "icmp type echo-request"), "has ICMP echo");

    /* Filter port rules */
    ASSERT(cmdlist_contains(&out, "tcp dport 80"), "has port 80 rule");
    ASSERT(cmdlist_contains(&out, "tcp dport 443"), "has port 443 rule");
    ASSERT(cmdlist_contains(&out, "tcp dport 22"), "has port 22 rule");
    ASSERT(cmdlist_contains(&out, "udp dport 53"), "has udp 53 rule");

    /* NAT masquerade */
    ASSERT(cmdlist_contains(&out, "masquerade"), "has masquerade");
    ASSERT(cmdlist_contains(&out, "192.168.1.0/24"), "has LAN range in NAT");

    /* FORWARD jumps */
    ASSERT(cmdlist_contains(&out, "iifname eth0"), "has LAN input interface");
    ASSERT(cmdlist_contains(&out, "oifname eth1"), "has WAN output interface");
    ASSERT(cmdlist_contains(&out, "jump lan2wan"), "has lan2wan jump");

    /* Final drop log */
    ASSERT(cmdlist_contains(&out, "INPUT_DROP"), "has INPUT_DROP log");
    ASSERT(cmdlist_contains(&out, "FORWARD_DROP"), "has FORWARD_DROP log");
    ASSERT(cmdlist_contains(&out, "OUTPUT_DROP"), "has OUTPUT_DROP log");

    fw_cmdlist_free(&out);
}

static void test_compile_start_ipt(void)
{
    printf("test_compile_start_ipt\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config");
    cfg.backend = BACKEND_IPT;

    fw_cmdlist_t out;
    ret = fw_compile_start(&cfg, &out);
    ASSERT(ret == 0, "compile start succeeds");
    ASSERT(out.count > 50, "generates many commands");

    /* Check iptables commands */
    ASSERT(cmdlist_contains(&out, "/sbin/iptables -F"), "has iptables flush");
    ASSERT(cmdlist_contains(&out, "-P INPUT DROP"), "has INPUT DROP policy");
    ASSERT(cmdlist_contains(&out, "-P FORWARD DROP"), "has FORWARD DROP policy");
    ASSERT(cmdlist_contains(&out, "-N lan2wan"), "has lan2wan chain creation");
    ASSERT(cmdlist_contains(&out, "-N stato"), "has stato chain creation");

    /* State rules */
    ASSERT(cmdlist_contains(&out, "--state ESTABLISHED,RELATED"), "has state match");

    /* TCP flags */
    ASSERT(cmdlist_contains(&out, "--tcp-flags"), "has tcp flag rules");

    /* Filter port rules (iptables uses two rules: LOG + ACCEPT) */
    ASSERT(cmdlist_contains(&out, "--dport 80"), "has port 80");
    ASSERT(cmdlist_contains(&out, "--dport 443"), "has port 443");
    ASSERT(cmdlist_contains(&out, "-j ACCEPT"), "has ACCEPT action");
    ASSERT(cmdlist_contains(&out, "-j LOG"), "has LOG action");

    /* NAT */
    ASSERT(cmdlist_contains(&out, "-j MASQUERADE"), "has masquerade");

    /* Interface jumps */
    ASSERT(cmdlist_contains(&out, "-i eth0"), "has LAN input");
    ASSERT(cmdlist_contains(&out, "-o eth1"), "has WAN output");
    ASSERT(cmdlist_contains(&out, "-j lan2wan"), "has lan2wan jump");

    fw_cmdlist_free(&out);
}

static void test_compile_stop(void)
{
    printf("test_compile_stop\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config");

    fw_cmdlist_t out;
    ret = fw_compile_stop(&cfg, &out);
    ASSERT(ret == 0, "compile stop succeeds");
    ASSERT(out.count > 0, "generates commands");

    ASSERT(cmdlist_contains(&out, "flush ruleset"), "has flush");
    ASSERT(cmdlist_contains(&out, "policy accept"), "has accept policy");
    /* Stop re-applies NAT for LAN ranges */
    ASSERT(cmdlist_contains(&out, "masquerade"), "has masquerade in stop");

    fw_cmdlist_free(&out);
}

static void test_compile_reset(void)
{
    printf("test_compile_reset\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load config");

    fw_cmdlist_t out;
    ret = fw_compile_reset(&cfg, &out);
    ASSERT(ret == 0, "compile reset succeeds");
    ASSERT(out.count > 0, "generates commands");

    ASSERT(cmdlist_contains(&out, "flush ruleset"), "has flush");
    ASSERT(cmdlist_contains(&out, "policy accept"), "has accept policy");
    /* Reset does NOT re-apply NAT */
    ASSERT(!cmdlist_contains(&out, "masquerade"), "no masquerade in reset");

    fw_cmdlist_free(&out);
}

static void test_compile_full_config(void)
{
    printf("test_compile_full_config\n");
    fw_config_t cfg;
    char err[256];
    int ret = fw_config_load("etc/firewallo/firewallo.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load full config");

    fw_cmdlist_t out;
    ret = fw_compile_start(&cfg, &out);
    ASSERT(ret == 0, "compile start succeeds");
    ASSERT(out.count > 100, "full config generates many commands");

    /* With 3 LAN, 2 WAN, 2 DMZ, 4 VPN interfaces, we get lots of FORWARD jumps */
    ASSERT(cmdlist_contains(&out, "ens18"), "has ens18 (LAN)");
    ASSERT(cmdlist_contains(&out, "ens19"), "has ens19 (WAN)");
    ASSERT(cmdlist_contains(&out, "ens20"), "has ens20 (DMZ)");
    ASSERT(cmdlist_contains(&out, "tun0"), "has tun0 (VPN)");
    ASSERT(cmdlist_contains(&out, "wg0"), "has wg0 (VPN)");

    /* Check all 10 TCP ports for lan2wan are present */
    ASSERT(cmdlist_contains(&out, "tcp dport 20"), "lan2wan port 20");
    ASSERT(cmdlist_contains(&out, "tcp dport 995"), "lan2wan port 995");
    ASSERT(cmdlist_contains(&out, "udp dport 123"), "lan2wan udp 123");

    /* All 4 DNS servers */
    ASSERT(cmdlist_contains(&out, "8.8.8.8"), "DNS1");
    ASSERT(cmdlist_contains(&out, "192.168.69.1"), "DNS2");
    ASSERT(cmdlist_contains(&out, "212.216.112.112"), "DNS3");
    ASSERT(cmdlist_contains(&out, "151.99.125.1"), "DNS4");

    /* Both LAN ranges for NAT */
    ASSERT(cmdlist_contains(&out, "10.50.50.0/24"), "LAN range 1");
    ASSERT(cmdlist_contains(&out, "10.81.81.0/24"), "LAN range 2");

    printf("  Total commands generated: %d\n", out.count);
    fw_cmdlist_free(&out);
}

static void test_backend_get(void)
{
    printf("test_backend_get\n");
    const fw_backend_ops_t *nft = fw_backend_get(BACKEND_NFT);
    const fw_backend_ops_t *ipt = fw_backend_get(BACKEND_IPT);

    ASSERT(nft == &fw_backend_nft, "NFT backend returned");
    ASSERT(ipt == &fw_backend_ipt, "IPT backend returned");
    ASSERT(nft != ipt, "different backends");
}

int main(void)
{
    printf("=== Rule Compiler Tests ===\n\n");

    test_cmdlist_basic();
    test_zone_interfaces();
    test_backend_get();
    test_compile_start_nft();
    test_compile_start_ipt();
    test_compile_stop();
    test_compile_reset();
    test_compile_full_config();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
