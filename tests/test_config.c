#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
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

static void test_chain_index(void)
{
    printf("test_chain_index\n");
    ASSERT(fw_config_chain_index("fw2fw") == 0, "fw2fw is 0");
    ASSERT(fw_config_chain_index("lan2wan") == 7, "lan2wan is 7");
    ASSERT(fw_config_chain_index("vpns2vpns") == 24, "vpns2vpns is 24");
    ASSERT(fw_config_chain_index("invalid") == -1, "invalid is -1");
}

static void test_chain_name(void)
{
    printf("test_chain_name\n");
    ASSERT(strcmp(fw_config_chain_name(ZONE_FW, ZONE_FW), "fw2fw") == 0, "fw2fw");
    ASSERT(strcmp(fw_config_chain_name(ZONE_LAN, ZONE_WAN), "lan2wan") == 0, "lan2wan");
    ASSERT(strcmp(fw_config_chain_name(ZONE_DMZ, ZONE_VPN), "dmz2vpns") == 0, "dmz2vpns");
}

static void test_config_init(void)
{
    printf("test_config_init\n");
    fw_config_t cfg;
    fw_config_init(&cfg);

    ASSERT(strcmp(cfg.version, "2.0.0") == 0, "default version");
    ASSERT(cfg.language == LANG_EN, "default language EN");
    ASSERT(cfg.backend == BACKEND_NFT, "default backend NFT");
    ASSERT(cfg.ip_forward == 1, "default ip_forward on");
    ASSERT(cfg.lan_if_count == 0, "no interfaces by default");

    /* Check chain names are initialized */
    ASSERT(strcmp(cfg.chains[0].name, "fw2fw") == 0, "chain 0 name");
    ASSERT(strcmp(cfg.chains[7].name, "lan2wan") == 0, "chain 7 name");
}

static void test_load_minimal(void)
{
    printf("test_load_minimal\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    if (ret != 0) {
        printf("  Load error: %s\n", err);
    }
    ASSERT(ret == 0, "load succeeds");

    ASSERT(strcmp(cfg.version, "2.0.0") == 0, "version");
    ASSERT(cfg.language == LANG_EN, "language EN");
    ASSERT(cfg.backend == BACKEND_NFT, "backend NFT");

    /* Interfaces */
    ASSERT(cfg.lan_if_count == 1, "1 LAN interface");
    ASSERT(strcmp(cfg.lan_ifs[0], "eth0") == 0, "LAN is eth0");
    ASSERT(cfg.wan_if_count == 1, "1 WAN interface");
    ASSERT(strcmp(cfg.wan_ifs[0], "eth1") == 0, "WAN is eth1");
    ASSERT(cfg.dmz_if_count == 0, "no DMZ interfaces");
    ASSERT(cfg.vpn_if_count == 0, "no VPN interfaces");

    /* DNS */
    ASSERT(cfg.dns_count == 1, "1 DNS server");
    ASSERT(strcmp(cfg.dns[0], "8.8.8.8") == 0, "DNS is 8.8.8.8");

    /* Ranges */
    ASSERT(cfg.lan_range_count == 1, "1 LAN range");
    ASSERT(strcmp(cfg.lan_ranges[0], "192.168.1.0/24") == 0, "LAN range");

    /* Sysctl */
    ASSERT(cfg.ip_forward == 1, "ip_forward on");
    ASSERT(cfg.tcp_syncookies == 1, "tcp_syncookies on");
    ASSERT(cfg.accept_source_route == 0, "accept_source_route off");

    /* Filter chains */
    ASSERT(cfg.chains[2].tcp_port_count == 2, "fw2wan has 2 tcp ports");
    ASSERT(cfg.chains[2].tcp_ports[0] == 80, "fw2wan tcp port 0 is 80");
    ASSERT(cfg.chains[2].tcp_ports[1] == 443, "fw2wan tcp port 1 is 443");
    ASSERT(cfg.chains[2].udp_port_count == 1, "fw2wan has 1 udp port");
    ASSERT(cfg.chains[2].udp_ports[0] == 53, "fw2wan udp port 0 is 53");

    ASSERT(cfg.chains[5].tcp_port_count == 1, "lan2fw has 1 tcp port");
    ASSERT(cfg.chains[5].tcp_ports[0] == 22, "lan2fw tcp port 0 is 22");

    ASSERT(cfg.chains[7].tcp_port_count == 2, "lan2wan has 2 tcp ports");
}

static void test_load_full(void)
{
    printf("test_load_full\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("etc/firewallo/firewallo.json", &cfg, err, sizeof(err));
    if (ret != 0) {
        printf("  Load error: %s\n", err);
    }
    ASSERT(ret == 0, "load full config succeeds");

    /* Interfaces */
    ASSERT(cfg.lan_if_count == 3, "3 LAN interfaces");
    ASSERT(cfg.wan_if_count == 2, "2 WAN interfaces");
    ASSERT(cfg.dmz_if_count == 2, "2 DMZ interfaces");
    ASSERT(cfg.vpn_if_count == 4, "4 VPN interfaces");

    /* DNS */
    ASSERT(cfg.dns_count == 4, "4 DNS servers");

    /* Ranges */
    ASSERT(cfg.lan_range_count == 2, "2 LAN ranges");
    ASSERT(cfg.dmz_range_count == 1, "1 DMZ range");

    /* Filter chains — check lan2wan matches the original */
    int idx = fw_config_chain_index("lan2wan");
    ASSERT(idx >= 0, "lan2wan index found");
    ASSERT(cfg.chains[idx].tcp_port_count == 10, "lan2wan has 10 tcp ports");
    ASSERT(cfg.chains[idx].tcp_ports[0] == 20, "lan2wan tcp[0] is 20");
    ASSERT(cfg.chains[idx].tcp_ports[9] == 143, "lan2wan tcp[9] is 143");
    ASSERT(cfg.chains[idx].udp_port_count == 1, "lan2wan has 1 udp port");
    ASSERT(cfg.chains[idx].udp_ports[0] == 123, "lan2wan udp[0] is 123");

    /* Check fw2wan */
    idx = fw_config_chain_index("fw2wan");
    ASSERT(cfg.chains[idx].tcp_port_count == 5, "fw2wan has 5 tcp ports");

    /* Check dmz2fw */
    idx = fw_config_chain_index("dmz2fw");
    ASSERT(cfg.chains[idx].tcp_port_count == 1, "dmz2fw has 1 tcp port");
    ASSERT(cfg.chains[idx].tcp_ports[0] == 22, "dmz2fw tcp[0] is 22");
}

static void test_validate(void)
{
    printf("test_validate\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for validate");

    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "validate minimal passes");

    /* Corrupt an interface name and check validation fails */
    fw_strlcpy(cfg.lan_ifs[0], "0invalid", sizeof(cfg.lan_ifs[0]));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches bad interface");

    /* Restore and corrupt a DNS server */
    fw_strlcpy(cfg.lan_ifs[0], "eth0", sizeof(cfg.lan_ifs[0]));
    fw_strlcpy(cfg.dns[0], "999.999.999.999", sizeof(cfg.dns[0]));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches bad DNS");
}

static void test_save_and_reload(void)
{
    printf("test_save_and_reload\n");
    fw_config_t cfg1, cfg2;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg1, err, sizeof(err));
    ASSERT(ret == 0, "load original");

    /* Save to temp file */
    const char *tmpfile = "/tmp/firewallo_test_config.json";
    ret = fw_config_save(tmpfile, &cfg1);
    ASSERT(ret == 0, "save succeeds");

    /* Reload */
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload succeeds");

    /* Compare key fields */
    ASSERT(strcmp(cfg1.version, cfg2.version) == 0, "version matches");
    ASSERT(cfg1.language == cfg2.language, "language matches");
    ASSERT(cfg1.backend == cfg2.backend, "backend matches");
    ASSERT(cfg1.lan_if_count == cfg2.lan_if_count, "lan_if_count matches");
    ASSERT(cfg1.dns_count == cfg2.dns_count, "dns_count matches");
    ASSERT(cfg1.ip_forward == cfg2.ip_forward, "ip_forward matches");

    /* Compare filter chains */
    for (int i = 0; i < FW_CHAIN_COUNT; i++) {
        ASSERT(cfg1.chains[i].tcp_port_count == cfg2.chains[i].tcp_port_count,
               "tcp_port_count matches");
        ASSERT(cfg1.chains[i].udp_port_count == cfg2.chains[i].udp_port_count,
               "udp_port_count matches");
    }

    /* Clean up */
    remove(tmpfile);
}

static void test_set_interface(void)
{
    printf("test_set_interface\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-interface");

    const char *tmpfile = "/tmp/firewallo_test_setif.json";

    /* Add interface */
    ASSERT(cfg.lan_if_count == 1, "starts with 1 LAN");
    fw_strlcpy(cfg.lan_ifs[cfg.lan_if_count], "eth2", FW_MAX_IF_NAME);
    cfg.lan_if_count++;
    ASSERT(cfg.lan_if_count == 2, "now 2 LAN");
    ASSERT(strcmp(cfg.lan_ifs[1], "eth2") == 0, "eth2 added");

    /* Save and reload */
    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after add iface");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after add iface");
    ASSERT(cfg2.lan_if_count == 2, "reloaded 2 LAN");
    ASSERT(strcmp(cfg2.lan_ifs[1], "eth2") == 0, "reloaded eth2");

    /* Remove interface (shift) */
    for (int i = 0; i < cfg2.lan_if_count - 1; i++)
        fw_strlcpy(cfg2.lan_ifs[i], cfg2.lan_ifs[i + 1], FW_MAX_IF_NAME);
    cfg2.lan_if_count--;
    ASSERT(cfg2.lan_if_count == 1, "back to 1 LAN after remove");
    ASSERT(strcmp(cfg2.lan_ifs[0], "eth2") == 0, "eth2 is now first");

    remove(tmpfile);
}

static void test_set_dns(void)
{
    printf("test_set_dns\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-dns");

    const char *tmpfile = "/tmp/firewallo_test_setdns.json";

    /* Add DNS */
    ASSERT(cfg.dns_count == 1, "starts with 1 DNS");
    fw_strlcpy(cfg.dns[cfg.dns_count], "1.1.1.1", FW_MAX_ADDR);
    cfg.dns_count++;
    ASSERT(cfg.dns_count == 2, "now 2 DNS");

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after add dns");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after add dns");
    ASSERT(cfg2.dns_count == 2, "reloaded 2 DNS");
    ASSERT(strcmp(cfg2.dns[1], "1.1.1.1") == 0, "reloaded 1.1.1.1");

    /* Remove DNS (first entry) */
    for (int i = 0; i < cfg2.dns_count - 1; i++)
        fw_strlcpy(cfg2.dns[i], cfg2.dns[i + 1], FW_MAX_ADDR);
    cfg2.dns_count--;
    ASSERT(cfg2.dns_count == 1, "back to 1 DNS");
    ASSERT(strcmp(cfg2.dns[0], "1.1.1.1") == 0, "1.1.1.1 is now first");

    remove(tmpfile);
}

static void test_set_range(void)
{
    printf("test_set_range\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-range");

    const char *tmpfile = "/tmp/firewallo_test_setrange.json";

    ASSERT(cfg.lan_range_count == 1, "starts with 1 LAN range");
    fw_strlcpy(cfg.lan_ranges[cfg.lan_range_count], "10.0.0.0/8", FW_MAX_ADDR);
    cfg.lan_range_count++;

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after add range");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after add range");
    ASSERT(cfg2.lan_range_count == 2, "reloaded 2 LAN ranges");
    ASSERT(strcmp(cfg2.lan_ranges[1], "10.0.0.0/8") == 0, "reloaded 10.0.0.0/8");

    remove(tmpfile);
}

static void test_set_sysctl(void)
{
    printf("test_set_sysctl\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-sysctl");

    const char *tmpfile = "/tmp/firewallo_test_setsysctl.json";

    ASSERT(cfg.ip_forward == 1, "ip_forward starts on");
    cfg.ip_forward = 0;

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after sysctl change");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after sysctl change");
    ASSERT(cfg2.ip_forward == 0, "ip_forward is now off");

    remove(tmpfile);
}

static void test_set_chain_ports(void)
{
    printf("test_set_chain_ports\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-chain");

    const char *tmpfile = "/tmp/firewallo_test_setchain.json";

    int idx = fw_config_chain_index("fw2wan");
    ASSERT(idx >= 0, "fw2wan found");
    int orig_tcp = cfg.chains[idx].tcp_port_count;

    /* Add port 8080 */
    cfg.chains[idx].tcp_ports[cfg.chains[idx].tcp_port_count] = 8080;
    cfg.chains[idx].tcp_port_count++;
    ASSERT(cfg.chains[idx].tcp_port_count == orig_tcp + 1, "tcp count +1");

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after add port");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after add port");
    ASSERT(cfg2.chains[idx].tcp_port_count == orig_tcp + 1, "reloaded tcp count");
    ASSERT(cfg2.chains[idx].tcp_ports[orig_tcp] == 8080, "reloaded port 8080");

    /* Remove port 8080 (last element) */
    cfg2.chains[idx].tcp_port_count--;
    ASSERT(cfg2.chains[idx].tcp_port_count == orig_tcp, "back to original count");

    ret = fw_config_save(tmpfile, &cfg2);
    ASSERT(ret == 0, "save after remove port");

    fw_config_t cfg3;
    ret = fw_config_load(tmpfile, &cfg3, err, sizeof(err));
    ASSERT(ret == 0, "reload after remove port");
    ASSERT(cfg3.chains[idx].tcp_port_count == orig_tcp, "final tcp count matches");

    remove(tmpfile);
}

static void test_set_nat(void)
{
    printf("test_set_nat\n");
    fw_config_t cfg;
    char err[256] = {0};
    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for set-nat");

    const char *tmpfile = "/tmp/firewallo_test_setnat.json";

    int orig_post = cfg.nat_post_count;

    /* Add postrouting NAT rule */
    fw_nat_post_t *r = &cfg.nat_post[cfg.nat_post_count];
    memset(r, 0, sizeof(*r));
    fw_strlcpy(r->src, "192.168.1.0/24", sizeof(r->src));
    fw_strlcpy(r->oif, "eth1", sizeof(r->oif));
    r->type = NAT_MASQUERADE;
    fw_strlcpy(r->comment, "test masq", sizeof(r->comment));
    cfg.nat_post_count++;

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save after add nat");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload after add nat");
    ASSERT(cfg2.nat_post_count == orig_post + 1, "nat_post_count +1");
    ASSERT(strcmp(cfg2.nat_post[orig_post].src, "192.168.1.0/24") == 0, "nat src matches");
    ASSERT(strcmp(cfg2.nat_post[orig_post].oif, "eth1") == 0, "nat oif matches");

    /* Remove it */
    cfg2.nat_post_count--;
    ret = fw_config_save(tmpfile, &cfg2);
    ASSERT(ret == 0, "save after remove nat");

    fw_config_t cfg3;
    ret = fw_config_load(tmpfile, &cfg3, err, sizeof(err));
    ASSERT(ret == 0, "reload after remove nat");
    ASSERT(cfg3.nat_post_count == orig_post, "nat_post_count back to original");

    remove(tmpfile);
}

static void test_config_roundtrip_full(void)
{
    printf("test_config_roundtrip_full\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("etc/firewallo/firewallo.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load full config");

    const char *tmpfile = "/tmp/firewallo_test_roundtrip.json";

    /* Modify multiple sections */
    fw_strlcpy(cfg.lan_ifs[cfg.lan_if_count], "br0", FW_MAX_IF_NAME);
    cfg.lan_if_count++;
    fw_strlcpy(cfg.dns[cfg.dns_count], "9.9.9.9", FW_MAX_ADDR);
    cfg.dns_count++;
    cfg.tcp_syncookies = 0;

    int idx = fw_config_chain_index("lan2wan");
    ASSERT(idx >= 0, "lan2wan chain exists");
    cfg.chains[idx].tcp_ports[cfg.chains[idx].tcp_port_count] = 9090;
    cfg.chains[idx].tcp_port_count++;

    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "modified config validates");

    ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save modified full config");

    fw_config_t cfg2;
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload modified full config");

    ASSERT(cfg2.lan_if_count == cfg.lan_if_count, "lan_if_count matches");
    ASSERT(strcmp(cfg2.lan_ifs[cfg2.lan_if_count - 1], "br0") == 0, "br0 persisted");
    ASSERT(cfg2.dns_count == cfg.dns_count, "dns_count matches");
    ASSERT(strcmp(cfg2.dns[cfg2.dns_count - 1], "9.9.9.9") == 0, "9.9.9.9 persisted");
    ASSERT(cfg2.tcp_syncookies == 0, "tcp_syncookies persisted as 0");
    ASSERT(cfg2.chains[idx].tcp_ports[cfg2.chains[idx].tcp_port_count - 1] == 9090,
           "port 9090 persisted");

    remove(tmpfile);
}

static void test_validate_filter_rule_fields(void)
{
    printf("test_validate_filter_rule_fields\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for validate filter fields");

    /* Add a filter rule with invalid src_addr */
    int idx = fw_config_chain_index("lan2wan");
    ASSERT(idx >= 0, "lan2wan found");
    fw_filter_rule_t *r = &cfg.chains[idx].rules[cfg.chains[idx].rule_count];
    memset(r, 0, sizeof(*r));
    fw_strlcpy(r->src_addr, "999.999.999.999", sizeof(r->src_addr));
    r->action = ACTION_ACCEPT;
    cfg.chains[idx].rule_count++;

    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches invalid src_addr in filter rule");

    /* Fix src_addr, set invalid comment */
    fw_strlcpy(r->src_addr, "10.0.0.1", sizeof(r->src_addr));
    fw_strlcpy(r->comment, "bad;comment", sizeof(r->comment));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches invalid comment in filter rule");

    /* Fix comment, verify it passes */
    fw_strlcpy(r->comment, "good comment", sizeof(r->comment));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "validate passes with valid filter rule");

    /* Remove the added rule */
    cfg.chains[idx].rule_count--;
}

static void test_validate_mangle_mark(void)
{
    printf("test_validate_mangle_mark\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for validate mangle mark");

    /* Add a mangle prerouting rule with invalid mark */
    fw_mangle_rule_t *r = &cfg.mangle_pre[cfg.mangle_pre_count];
    memset(r, 0, sizeof(*r));
    fw_strlcpy(r->iif, "eth0", sizeof(r->iif));
    fw_strlcpy(r->mark, "invalid!mark", sizeof(r->mark));
    r->protocol = PROTO_TCP;
    cfg.mangle_pre_count++;

    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches invalid mangle mark");

    /* Fix mark to valid hex, should pass */
    fw_strlcpy(r->mark, "0xFF", sizeof(r->mark));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "validate passes with valid hex mark");

    /* Empty mark should also pass (optional) */
    r->mark[0] = '\0';
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "validate passes with empty mark");

    cfg.mangle_pre_count--;
}

static void test_validate_nat_comment(void)
{
    printf("test_validate_nat_comment\n");
    fw_config_t cfg;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/minimal.json", &cfg, err, sizeof(err));
    ASSERT(ret == 0, "load for validate nat comment");

    /* Add a NAT postrouting rule with invalid comment */
    fw_nat_post_t *r = &cfg.nat_post[cfg.nat_post_count];
    memset(r, 0, sizeof(*r));
    fw_strlcpy(r->src, "192.168.1.0/24", sizeof(r->src));
    fw_strlcpy(r->oif, "eth1", sizeof(r->oif));
    r->type = NAT_MASQUERADE;
    fw_strlcpy(r->comment, "drop;table", sizeof(r->comment));
    cfg.nat_post_count++;

    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == -1, "validate catches invalid NAT postrouting comment");

    /* Fix comment */
    fw_strlcpy(r->comment, "masquerade rule", sizeof(r->comment));
    ret = fw_config_validate(&cfg, err, sizeof(err));
    ASSERT(ret == 0, "validate passes with valid NAT postrouting comment");

    cfg.nat_post_count--;
}

static void test_alias_roundtrip(void)
{
    printf("test_alias_roundtrip\n");
    fw_config_t cfg1, cfg2;
    char err[256] = {0};

    int ret = fw_config_load("tests/fixtures/with_aliases.json", &cfg1, err, sizeof(err));
    if (ret != 0) {
        printf("  Load error: %s\n", err);
    }
    ASSERT(ret == 0, "load config with aliases");

    /* Verify aliases loaded correctly */
    ASSERT(cfg1.alias_count == 2, "2 aliases loaded");
    ASSERT(strcmp(cfg1.aliases[0].name, "web_servers") == 0, "alias 0 name");
    ASSERT(cfg1.aliases[0].type == 0 /* ALIAS_TYPE_IP */, "alias 0 type is IP");
    ASSERT(cfg1.aliases[0].entry_count == 3, "alias 0 has 3 entries");
    ASSERT(strcmp(cfg1.aliases[0].entries[0], "192.168.1.10") == 0, "alias 0 entry 0");
    ASSERT(strcmp(cfg1.aliases[0].entries[1], "192.168.1.11") == 0, "alias 0 entry 1");
    ASSERT(strcmp(cfg1.aliases[0].entries[2], "192.168.1.12") == 0, "alias 0 entry 2");
    ASSERT(strcmp(cfg1.aliases[0].comment, "Web server pool") == 0, "alias 0 comment");

    ASSERT(strcmp(cfg1.aliases[1].name, "web_ports") == 0, "alias 1 name");
    ASSERT(cfg1.aliases[1].type == 1 /* ALIAS_TYPE_PORT */, "alias 1 type is PORT");
    ASSERT(cfg1.aliases[1].entry_count == 3, "alias 1 has 3 entries");
    ASSERT(strcmp(cfg1.aliases[1].entries[0], "80") == 0, "alias 1 entry 0");
    ASSERT(strcmp(cfg1.aliases[1].entries[1], "443") == 0, "alias 1 entry 1");
    ASSERT(strcmp(cfg1.aliases[1].entries[2], "8080") == 0, "alias 1 entry 2");

    /* Verify alias reference in filter rule */
    int idx = fw_config_chain_index("lan2fw");
    ASSERT(idx >= 0, "lan2fw found");
    ASSERT(cfg1.chains[idx].rule_count == 1, "lan2fw has 1 rule");
    ASSERT(strcmp(cfg1.chains[idx].rules[0].src_addr, "$web_servers") == 0,
           "rule src_addr is alias ref");

    /* Validate the config */
    ret = fw_config_validate(&cfg1, err, sizeof(err));
    ASSERT(ret == 0, "config with aliases validates");

    /* Save and reload */
    const char *tmpfile = "/tmp/firewallo_test_alias_roundtrip.json";
    ret = fw_config_save(tmpfile, &cfg1);
    ASSERT(ret == 0, "save config with aliases");

    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    ASSERT(ret == 0, "reload config with aliases");

    /* Compare aliases after round-trip */
    ASSERT(cfg2.alias_count == cfg1.alias_count, "alias_count matches after roundtrip");
    for (int i = 0; i < cfg1.alias_count; i++) {
        ASSERT(strcmp(cfg2.aliases[i].name, cfg1.aliases[i].name) == 0,
               "alias name matches after roundtrip");
        ASSERT(cfg2.aliases[i].type == cfg1.aliases[i].type,
               "alias type matches after roundtrip");
        ASSERT(cfg2.aliases[i].entry_count == cfg1.aliases[i].entry_count,
               "alias entry_count matches after roundtrip");
        for (int e = 0; e < cfg1.aliases[i].entry_count; e++) {
            ASSERT(strcmp(cfg2.aliases[i].entries[e], cfg1.aliases[i].entries[e]) == 0,
                   "alias entry matches after roundtrip");
        }
        ASSERT(strcmp(cfg2.aliases[i].comment, cfg1.aliases[i].comment) == 0,
               "alias comment matches after roundtrip");
    }

    /* Verify filter rule alias reference survives round-trip */
    ASSERT(strcmp(cfg2.chains[idx].rules[0].src_addr, "$web_servers") == 0,
           "alias ref survives roundtrip");

    remove(tmpfile);
}

int main(void)
{
    printf("=== Config Tests ===\n\n");

    test_chain_index();
    test_chain_name();
    test_config_init();
    test_load_minimal();
    test_load_full();
    test_validate();
    test_save_and_reload();
    test_set_interface();
    test_set_dns();
    test_set_range();
    test_set_sysctl();
    test_set_chain_ports();
    test_set_nat();
    test_config_roundtrip_full();
    test_validate_filter_rule_fields();
    test_validate_mangle_mark();
    test_validate_nat_comment();
    test_alias_roundtrip();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
