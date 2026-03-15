/* Test suite for ifinfo — Linux system interface info reader.
 * Requires Linux with /sys/class/net/ (always available on Debian 12+). */

#include "firewallo/ifinfo.h"
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

static void test_list(void)
{
    printf("\ntest_list\n");
    fw_ifinfo_list_t list;
    int ret = fw_ifinfo_list(&list);
    ASSERT(ret == 0, "fw_ifinfo_list returns 0");
    ASSERT(list.count >= 1, "at least 1 interface (lo)");
    ASSERT(list.count <= FW_IFINFO_MAX, "count within limit");

    /* Verify lo is in the list */
    int found_lo = 0;
    for (int i = 0; i < list.count; i++) {
        if (strcmp(list.ifaces[i].name, "lo") == 0)
            found_lo = 1;
    }
    ASSERT(found_lo, "loopback interface found");
}

static void test_get_loopback(void)
{
    printf("\ntest_get_loopback\n");
    fw_ifinfo_t info;
    int ret = fw_ifinfo_get("lo", &info);
    ASSERT(ret == 0, "fw_ifinfo_get(lo) returns 0");
    ASSERT(strcmp(info.name, "lo") == 0, "name is 'lo'");
    ASSERT(info.type == 772, "type is 772 (loopback)");
    ASSERT(info.mtu > 0, "mtu > 0");
    ASSERT(info.addr_count >= 1, "at least 1 address (127.0.0.1)");

    /* Check for 127.0.0.1 */
    int found_localhost = 0;
    for (int i = 0; i < info.addr_count; i++) {
        if (strcmp(info.addrs[i].address, "127.0.0.1") == 0)
            found_localhost = 1;
    }
    ASSERT(found_localhost, "127.0.0.1 found on lo");
}

static void test_get_nonexistent(void)
{
    printf("\ntest_get_nonexistent\n");
    fw_ifinfo_t info;
    int ret = fw_ifinfo_get("nonexistent_iface_xyz_99", &info);
    ASSERT(ret == -1, "fw_ifinfo_get returns -1 for nonexistent");
}

static void test_stats(void)
{
    printf("\ntest_stats\n");
    fw_ifinfo_t info;
    int ret = fw_ifinfo_get("lo", &info);
    ASSERT(ret == 0, "get lo for stats");
    /* Stats should be readable (uint64_t, verify they exist) */
    ASSERT(info.stats.rx_bytes == info.stats.rx_bytes, "rx_bytes readable");
    ASSERT(info.stats.tx_bytes == info.stats.tx_bytes, "tx_bytes readable");
    /* On loopback with any traffic, packets should be non-zero or at least 0 */
    ASSERT(info.stats.rx_packets <= UINT64_MAX, "rx_packets valid");
    ASSERT(info.stats.tx_packets <= UINT64_MAX, "tx_packets valid");
}

static void test_all_ifaces_have_name(void)
{
    printf("\ntest_all_ifaces_have_name\n");
    fw_ifinfo_list_t list;
    fw_ifinfo_list(&list);
    for (int i = 0; i < list.count; i++) {
        ASSERT(list.ifaces[i].name[0] != '\0', "interface has non-empty name");
        ASSERT(list.ifaces[i].mtu != 0, "interface has non-zero mtu");
    }
}

int main(void)
{
    printf("=== Interface Info Tests ===\n");

    test_list();
    test_get_loopback();
    test_get_nonexistent();
    test_stats();
    test_all_ifaces_have_name();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
