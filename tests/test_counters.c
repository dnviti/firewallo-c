#include "firewallo/counters.h"
#include <stdio.h>
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

/* ── nftables parsing tests ─────────────────────────────────────────── */

static void test_nft_basic(void)
{
    printf("test_nft_basic\n");
    const char *nft_output =
        "table inet filter {\n"
        "  chain fw2fw {\n"
        "    type filter hook input priority 0;\n"
        "    tcp dport 22 counter packets 100 bytes 8000 accept\n"
        "    tcp dport 80 counter packets 250 bytes 32000 accept\n"
        "  }\n"
        "}\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_nft_counters(nft_output, &data);

    ASSERT(ret == 0, "nft parse returns 0");
    ASSERT(data.count == 2, "nft found 2 counters");
    ASSERT(strcmp(data.rules[0].chain, "fw2fw") == 0, "chain is fw2fw");
    ASSERT(data.rules[0].rule_index == 0, "first rule index is 0");
    ASSERT(data.rules[0].packets == 100, "first rule packets");
    ASSERT(data.rules[0].bytes == 8000, "first rule bytes");
    ASSERT(data.rules[1].rule_index == 1, "second rule index is 1");
    ASSERT(data.rules[1].packets == 250, "second rule packets");
    ASSERT(data.rules[1].bytes == 32000, "second rule bytes");
}

static void test_nft_multiple_chains(void)
{
    printf("test_nft_multiple_chains\n");
    const char *nft_output =
        "table inet filter {\n"
        "  chain fw2wan {\n"
        "    counter packets 10 bytes 500 accept\n"
        "  }\n"
        "  chain lan2wan {\n"
        "    counter packets 999 bytes 65536 accept\n"
        "    counter packets 0 bytes 0 drop\n"
        "  }\n"
        "}\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_nft_counters(nft_output, &data);

    ASSERT(ret == 0, "nft multi-chain returns 0");
    ASSERT(data.count == 3, "nft found 3 counters");
    ASSERT(strcmp(data.rules[0].chain, "fw2wan") == 0, "first chain fw2wan");
    ASSERT(strcmp(data.rules[1].chain, "lan2wan") == 0, "second chain lan2wan");
    ASSERT(data.rules[1].rule_index == 0, "lan2wan rule 0");
    ASSERT(strcmp(data.rules[2].chain, "lan2wan") == 0, "third chain lan2wan");
    ASSERT(data.rules[2].rule_index == 1, "lan2wan rule 1");
    ASSERT(data.rules[2].packets == 0, "zero packets");
    ASSERT(data.rules[2].bytes == 0, "zero bytes");
}

static void test_nft_empty(void)
{
    printf("test_nft_empty\n");
    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_nft_counters("", &data);

    ASSERT(ret == 0, "empty nft returns 0");
    ASSERT(data.count == 0, "empty nft has 0 counters");
}

static void test_nft_no_counters(void)
{
    printf("test_nft_no_counters\n");
    const char *nft_output =
        "table inet filter {\n"
        "  chain fw2fw {\n"
        "    tcp dport 22 accept\n"
        "  }\n"
        "}\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_nft_counters(nft_output, &data);

    ASSERT(ret == 0, "no-counter nft returns 0");
    ASSERT(data.count == 0, "no counters found");
}

/* ── iptables parsing tests ─────────────────────────────────────────── */

static void test_ipt_basic(void)
{
    printf("test_ipt_basic\n");
    const char *ipt_output =
        "Chain fw2fw (policy ACCEPT)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     100      8000 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "      50      4000 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_ipt_counters(ipt_output, &data);

    ASSERT(ret == 0, "ipt parse returns 0");
    ASSERT(data.count == 2, "ipt found 2 counters");
    ASSERT(strcmp(data.rules[0].chain, "fw2fw") == 0, "chain is fw2fw");
    ASSERT(data.rules[0].rule_index == 0, "first rule index is 0");
    ASSERT(data.rules[0].packets == 100, "first rule packets");
    ASSERT(data.rules[0].bytes == 8000, "first rule bytes");
    ASSERT(data.rules[1].rule_index == 1, "second rule index is 1");
    ASSERT(data.rules[1].packets == 50, "second rule packets");
    ASSERT(data.rules[1].bytes == 4000, "second rule bytes");
}

static void test_ipt_multiple_chains(void)
{
    printf("test_ipt_multiple_chains\n");
    const char *ipt_output =
        "Chain fw2wan (policy ACCEPT)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "      10       500 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "\n"
        "Chain lan2wan (policy DROP)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     999     65536 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "       0         0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0\n"
        "\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_ipt_counters(ipt_output, &data);

    ASSERT(ret == 0, "ipt multi-chain returns 0");
    ASSERT(data.count == 3, "ipt found 3 counters");
    ASSERT(strcmp(data.rules[0].chain, "fw2wan") == 0, "first chain fw2wan");
    ASSERT(data.rules[0].packets == 10, "fw2wan packets");
    ASSERT(strcmp(data.rules[1].chain, "lan2wan") == 0, "second chain lan2wan");
    ASSERT(data.rules[1].rule_index == 0, "lan2wan rule 0");
    ASSERT(data.rules[2].packets == 0, "zero packets");
}

static void test_ipt_empty(void)
{
    printf("test_ipt_empty\n");
    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_ipt_counters("", &data);

    ASSERT(ret == 0, "empty ipt returns 0");
    ASSERT(data.count == 0, "empty ipt has 0 counters");
}

static void test_nft_large_values(void)
{
    printf("test_nft_large_values\n");
    const char *nft_output =
        "table inet filter {\n"
        "  chain fw2fw {\n"
        "    counter packets 18446744073709551615 bytes 9999999999999 accept\n"
        "  }\n"
        "}\n";

    fw_counter_data_t data;
    memset(&data, 0, sizeof(data));
    int ret = fw_parse_nft_counters(nft_output, &data);

    ASSERT(ret == 0, "large value nft returns 0");
    ASSERT(data.count == 1, "found 1 counter");
    ASSERT(data.rules[0].packets == 18446744073709551615ULL, "max uint64 packets");
    ASSERT(data.rules[0].bytes == 9999999999999ULL, "large bytes");
}

int main(void)
{
    printf("=== Counter parsing tests ===\n\n");

    /* nftables tests */
    test_nft_basic();
    test_nft_multiple_chains();
    test_nft_empty();
    test_nft_no_counters();
    test_nft_large_values();

    /* iptables tests */
    test_ipt_basic();
    test_ipt_multiple_chains();
    test_ipt_empty();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_run == tests_passed ? 0 : 1;
}
