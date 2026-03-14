#include "firewallo/validate.h"
#include <stdio.h>

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

static void test_ipv4(void)
{
    printf("test_ipv4\n");
    ASSERT(fw_validate_ipv4("192.168.1.1") == 1, "valid IP");
    ASSERT(fw_validate_ipv4("10.0.0.0") == 1, "valid 10.x");
    ASSERT(fw_validate_ipv4("255.255.255.255") == 1, "valid max");
    ASSERT(fw_validate_ipv4("0.0.0.0") == 1, "valid zero");
    ASSERT(fw_validate_ipv4("8.8.8.8") == 1, "valid dns");

    ASSERT(fw_validate_ipv4("") == 0, "empty");
    ASSERT(fw_validate_ipv4(NULL) == 0, "null");
    ASSERT(fw_validate_ipv4("256.1.1.1") == 0, "octet > 255");
    ASSERT(fw_validate_ipv4("1.2.3") == 0, "only 3 octets");
    ASSERT(fw_validate_ipv4("1.2.3.4.5") == 0, "5 octets");
    ASSERT(fw_validate_ipv4("a.b.c.d") == 0, "letters");
    ASSERT(fw_validate_ipv4("192.168.1") == 0, "missing octet");
    ASSERT(fw_validate_ipv4("192.168.1.") == 0, "trailing dot");
    ASSERT(fw_validate_ipv4(".168.1.1") == 0, "leading dot");
}

static void test_ipv4_cidr(void)
{
    printf("test_ipv4_cidr\n");
    ASSERT(fw_validate_ipv4_cidr("192.168.1.0/24") == 1, "valid /24");
    ASSERT(fw_validate_ipv4_cidr("10.0.0.0/8") == 1, "valid /8");
    ASSERT(fw_validate_ipv4_cidr("0.0.0.0/0") == 1, "valid /0");
    ASSERT(fw_validate_ipv4_cidr("192.168.1.1/32") == 1, "valid /32");

    ASSERT(fw_validate_ipv4_cidr("192.168.1.0") == 0, "no mask");
    ASSERT(fw_validate_ipv4_cidr("192.168.1.0/33") == 0, "mask > 32");
    ASSERT(fw_validate_ipv4_cidr("192.168.1.0/-1") == 0, "negative mask");
    ASSERT(fw_validate_ipv4_cidr("/24") == 0, "no IP");
    ASSERT(fw_validate_ipv4_cidr("") == 0, "empty");
    ASSERT(fw_validate_ipv4_cidr(NULL) == 0, "null");
}

static void test_port(void)
{
    printf("test_port\n");
    ASSERT(fw_validate_port(1) == 1, "min port");
    ASSERT(fw_validate_port(80) == 1, "http");
    ASSERT(fw_validate_port(443) == 1, "https");
    ASSERT(fw_validate_port(65535) == 1, "max port");

    ASSERT(fw_validate_port(0) == 0, "zero");
    ASSERT(fw_validate_port(-1) == 0, "negative");
    ASSERT(fw_validate_port(65536) == 0, "too high");
}

static void test_port_range(void)
{
    printf("test_port_range\n");
    ASSERT(fw_validate_port_range("80") == 1, "single port");
    ASSERT(fw_validate_port_range("1024:2000") == 1, "valid range");
    ASSERT(fw_validate_port_range("any") == 1, "any");
    ASSERT(fw_validate_port_range("1:65535") == 1, "full range");

    ASSERT(fw_validate_port_range("") == 0, "empty");
    ASSERT(fw_validate_port_range(NULL) == 0, "null");
    ASSERT(fw_validate_port_range("0") == 0, "zero port");
    ASSERT(fw_validate_port_range("65536") == 0, "too high");
    ASSERT(fw_validate_port_range("2000:1000") == 0, "reversed range");
    ASSERT(fw_validate_port_range("abc") == 0, "letters");
}

static void test_interface(void)
{
    printf("test_interface\n");
    ASSERT(fw_validate_interface("eth0") == 1, "eth0");
    ASSERT(fw_validate_interface("ens18") == 1, "ens18");
    ASSERT(fw_validate_interface("wg0") == 1, "wg0");
    ASSERT(fw_validate_interface("tun0") == 1, "tun0");
    ASSERT(fw_validate_interface("ipsec0") == 1, "ipsec0");
    ASSERT(fw_validate_interface("br-lan") == 1, "br-lan");

    ASSERT(fw_validate_interface("") == 0, "empty");
    ASSERT(fw_validate_interface(NULL) == 0, "null");
    ASSERT(fw_validate_interface("0eth") == 0, "starts with digit");
    ASSERT(fw_validate_interface("abcdefghijklmnop") == 0, "too long (16 chars)");
}

static void test_protocol(void)
{
    printf("test_protocol\n");
    ASSERT(fw_validate_protocol("tcp") == 1, "tcp");
    ASSERT(fw_validate_protocol("udp") == 1, "udp");

    ASSERT(fw_validate_protocol("TCP") == 0, "uppercase");
    ASSERT(fw_validate_protocol("icmp") == 0, "icmp");
    ASSERT(fw_validate_protocol("") == 0, "empty");
    ASSERT(fw_validate_protocol(NULL) == 0, "null");
}

static void test_action(void)
{
    printf("test_action\n");
    ASSERT(fw_validate_action("accept") == 1, "accept");
    ASSERT(fw_validate_action("drop") == 1, "drop");
    ASSERT(fw_validate_action("reject") == 1, "reject");

    ASSERT(fw_validate_action("ACCEPT") == 0, "uppercase");
    ASSERT(fw_validate_action("allow") == 0, "allow");
    ASSERT(fw_validate_action("") == 0, "empty");
    ASSERT(fw_validate_action(NULL) == 0, "null");
}

static void test_comment(void)
{
    printf("test_comment\n");
    ASSERT(fw_validate_comment("allow web traffic") == 1, "valid comment");
    ASSERT(fw_validate_comment("lan2wan_rule_1") == 1, "underscores");
    ASSERT(fw_validate_comment("my-rule") == 1, "hyphens");
    ASSERT(fw_validate_comment("") == 1, "empty ok");
    ASSERT(fw_validate_comment(NULL) == 1, "null ok");

    ASSERT(fw_validate_comment("rule; drop table") == 0, "semicolon");
    ASSERT(fw_validate_comment("rule`cmd`") == 0, "backtick");
}

int main(void)
{
    printf("=== Validator Tests ===\n\n");

    test_ipv4();
    test_ipv4_cidr();
    test_port();
    test_port_range();
    test_interface();
    test_protocol();
    test_action();
    test_comment();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
