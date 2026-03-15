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

static void test_ipv6(void)
{
    printf("test_ipv6\n");
    ASSERT(fw_validate_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == 1, "full IPv6");
    ASSERT(fw_validate_ipv6("2001:db8:85a3::8a2e:370:7334") == 1, "compressed IPv6");
    ASSERT(fw_validate_ipv6("::1") == 1, "loopback");
    ASSERT(fw_validate_ipv6("::") == 1, "all zeros");
    ASSERT(fw_validate_ipv6("fe80::1") == 1, "link-local");
    ASSERT(fw_validate_ipv6("ff02::1") == 1, "multicast");
    ASSERT(fw_validate_ipv6("2001:db8::") == 1, "trailing ::");
    ASSERT(fw_validate_ipv6("::ffff:192.0.2.1") == 0, "mapped IPv4 not supported");

    ASSERT(fw_validate_ipv6("") == 0, "empty");
    ASSERT(fw_validate_ipv6(NULL) == 0, "null");
    ASSERT(fw_validate_ipv6("2001:db8::85a3::7334") == 0, "double ::");
    ASSERT(fw_validate_ipv6("12345::1") == 0, "group > 4 digits");
    ASSERT(fw_validate_ipv6(":1") == 0, "single leading colon");
    ASSERT(fw_validate_ipv6("1:") == 0, "trailing single colon");
    ASSERT(fw_validate_ipv6("gggg::1") == 0, "invalid hex");
    ASSERT(fw_validate_ipv6("192.168.1.1") == 0, "IPv4 address");
}

static void test_ipv6_cidr(void)
{
    printf("test_ipv6_cidr\n");
    ASSERT(fw_validate_ipv6_cidr("2001:db8::/32") == 1, "valid /32");
    ASSERT(fw_validate_ipv6_cidr("::1/128") == 1, "valid /128");
    ASSERT(fw_validate_ipv6_cidr("::/0") == 1, "valid /0");
    ASSERT(fw_validate_ipv6_cidr("fe80::/10") == 1, "link-local /10");

    ASSERT(fw_validate_ipv6_cidr("2001:db8::") == 0, "no prefix");
    ASSERT(fw_validate_ipv6_cidr("2001:db8::/129") == 0, "prefix > 128");
    ASSERT(fw_validate_ipv6_cidr("2001:db8::/-1") == 0, "negative prefix");
    ASSERT(fw_validate_ipv6_cidr("/64") == 0, "no address");
    ASSERT(fw_validate_ipv6_cidr("") == 0, "empty");
    ASSERT(fw_validate_ipv6_cidr(NULL) == 0, "null");
}

static void test_ip_auto(void)
{
    printf("test_ip_auto\n");
    ASSERT(fw_validate_ip("192.168.1.1") == 1, "auto-detect IPv4");
    ASSERT(fw_validate_ip("2001:db8::1") == 1, "auto-detect IPv6");
    ASSERT(fw_validate_ip("::1") == 1, "auto-detect loopback v6");
    ASSERT(fw_validate_ip("") == 0, "auto-detect empty");
    ASSERT(fw_validate_ip(NULL) == 0, "auto-detect null");

    ASSERT(fw_validate_ip_cidr("192.168.1.0/24") == 1, "auto-detect IPv4 CIDR");
    ASSERT(fw_validate_ip_cidr("2001:db8::/32") == 1, "auto-detect IPv6 CIDR");
    ASSERT(fw_validate_ip_cidr("") == 0, "auto-detect CIDR empty");
    ASSERT(fw_validate_ip_cidr(NULL) == 0, "auto-detect CIDR null");
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

static void test_addr_field(void)
{
    printf("test_addr_field\n");
    /* NULL and empty are valid (optional field) */
    ASSERT(fw_validate_addr_field(NULL) == 1, "null ok");
    ASSERT(fw_validate_addr_field("") == 1, "empty ok");

    /* Valid IPv4 addresses */
    ASSERT(fw_validate_addr_field("192.168.1.1") == 1, "valid ipv4");
    ASSERT(fw_validate_addr_field("10.0.0.1") == 1, "valid 10.x");

    /* Valid CIDR */
    ASSERT(fw_validate_addr_field("192.168.1.0/24") == 1, "valid cidr");
    ASSERT(fw_validate_addr_field("10.0.0.0/8") == 1, "valid /8 cidr");

    /* Invalid */
    ASSERT(fw_validate_addr_field("999.999.999.999") == 0, "invalid ip");
    ASSERT(fw_validate_addr_field("abc") == 0, "letters");
    ASSERT(fw_validate_addr_field("192.168.1.0/33") == 0, "bad cidr mask");
    ASSERT(fw_validate_addr_field("192.168.1") == 0, "incomplete ip");
}

static void test_mark(void)
{
    printf("test_mark\n");
    /* NULL and empty are valid (optional field) */
    ASSERT(fw_validate_mark(NULL) == 1, "null ok");
    ASSERT(fw_validate_mark("") == 1, "empty ok");

    /* Valid decimal */
    ASSERT(fw_validate_mark("0") == 1, "zero");
    ASSERT(fw_validate_mark("1") == 1, "one");
    ASSERT(fw_validate_mark("42") == 1, "decimal 42");
    ASSERT(fw_validate_mark("65535") == 1, "large decimal");

    /* Valid hex */
    ASSERT(fw_validate_mark("0x1") == 1, "hex 0x1");
    ASSERT(fw_validate_mark("0xFF") == 1, "hex 0xFF");
    ASSERT(fw_validate_mark("0X10") == 1, "hex 0X10");
    ASSERT(fw_validate_mark("0xDEAD") == 1, "hex 0xDEAD");

    /* Invalid */
    ASSERT(fw_validate_mark("abc") == 0, "bare letters");
    ASSERT(fw_validate_mark("0x") == 0, "hex prefix only");
    ASSERT(fw_validate_mark("0xGG") == 0, "invalid hex digits");
    ASSERT(fw_validate_mark("-1") == 0, "negative");
    ASSERT(fw_validate_mark("12abc") == 0, "mixed decimal/letters");
}

int main(void)
{
    printf("=== Validator Tests ===\n\n");

    test_ipv4();
    test_ipv4_cidr();
    test_ipv6();
    test_ipv6_cidr();
    test_ip_auto();
    test_port();
    test_port_range();
    test_interface();
    test_protocol();
    test_action();
    test_comment();
    test_addr_field();
    test_mark();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
