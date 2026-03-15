#include "firewallo/alias.h"
#include "firewallo/config.h"
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

static void test_alias_validate_name(void)
{
    printf("test_alias_validate_name\n");
    ASSERT(fw_alias_validate_name("web_servers") == 1, "valid name");
    ASSERT(fw_alias_validate_name("LAN") == 1, "uppercase");
    ASSERT(fw_alias_validate_name("group1") == 1, "with digits");
    ASSERT(fw_alias_validate_name("a") == 1, "single char");

    ASSERT(fw_alias_validate_name("") == 0, "empty");
    ASSERT(fw_alias_validate_name(NULL) == 0, "null");
    ASSERT(fw_alias_validate_name("1abc") == 0, "starts with digit");
    ASSERT(fw_alias_validate_name("a-b") == 0, "hyphen not allowed");
    ASSERT(fw_alias_validate_name("a b") == 0, "space not allowed");
    ASSERT(fw_alias_validate_name("$ref") == 0, "dollar not allowed");
}

static void test_alias_is_ref(void)
{
    printf("test_alias_is_ref\n");
    ASSERT(fw_alias_is_ref("$web_servers") == 1, "valid ref");
    ASSERT(fw_alias_is_ref("$x") == 1, "single char ref");

    ASSERT(fw_alias_is_ref("") == 0, "empty");
    ASSERT(fw_alias_is_ref(NULL) == 0, "null");
    ASSERT(fw_alias_is_ref("$") == 0, "dollar only");
    ASSERT(fw_alias_is_ref("web_servers") == 0, "no dollar");
}

static void test_alias_find(void)
{
    printf("test_alias_find\n");

    fw_config_t cfg;
    fw_config_init(&cfg);

    /* Add a test alias */
    strcpy(cfg.aliases[0].name, "web_servers");
    cfg.aliases[0].type = ALIAS_TYPE_IP;
    strcpy(cfg.aliases[0].entries[0], "192.168.1.10");
    strcpy(cfg.aliases[0].entries[1], "192.168.1.11");
    cfg.aliases[0].entry_count = 2;
    cfg.alias_count = 1;

    ASSERT(fw_alias_find(&cfg, "web_servers") != NULL, "found alias");
    ASSERT(fw_alias_find(&cfg, "nonexistent") == NULL, "not found");
    ASSERT(fw_alias_find(&cfg, NULL) == NULL, "null name");
    ASSERT(fw_alias_find(NULL, "web_servers") == NULL, "null config");
}

static void test_alias_resolve_ip(void)
{
    printf("test_alias_resolve_ip\n");

    fw_config_t cfg;
    fw_config_init(&cfg);

    strcpy(cfg.aliases[0].name, "servers");
    cfg.aliases[0].type = ALIAS_TYPE_IP;
    strcpy(cfg.aliases[0].entries[0], "10.0.0.1");
    strcpy(cfg.aliases[0].entries[1], "10.0.0.2");
    strcpy(cfg.aliases[0].entries[2], "10.0.0.3");
    cfg.aliases[0].entry_count = 3;
    cfg.alias_count = 1;

    char out[FW_MAX_ALIAS_ENTRIES][FW_MAX_ADDR];
    int n = fw_alias_resolve_ip(&cfg, "$servers", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == 3, "resolved 3 entries");
    ASSERT(strcmp(out[0], "10.0.0.1") == 0, "entry 0");
    ASSERT(strcmp(out[1], "10.0.0.2") == 0, "entry 1");
    ASSERT(strcmp(out[2], "10.0.0.3") == 0, "entry 2");

    /* Wrong type */
    strcpy(cfg.aliases[1].name, "ports");
    cfg.aliases[1].type = ALIAS_TYPE_PORT;
    strcpy(cfg.aliases[1].entries[0], "80");
    cfg.aliases[1].entry_count = 1;
    cfg.alias_count = 2;

    n = fw_alias_resolve_ip(&cfg, "$ports", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == -1, "wrong type returns -1");

    /* Not a reference */
    n = fw_alias_resolve_ip(&cfg, "10.0.0.1", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == -1, "not a ref returns -1");

    /* Unknown alias */
    n = fw_alias_resolve_ip(&cfg, "$unknown", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == -1, "unknown alias returns -1");
}

static void test_alias_resolve_port(void)
{
    printf("test_alias_resolve_port\n");

    fw_config_t cfg;
    fw_config_init(&cfg);

    strcpy(cfg.aliases[0].name, "web_ports");
    cfg.aliases[0].type = ALIAS_TYPE_PORT;
    strcpy(cfg.aliases[0].entries[0], "80");
    strcpy(cfg.aliases[0].entries[1], "443");
    cfg.aliases[0].entry_count = 2;
    cfg.alias_count = 1;

    char out[FW_MAX_ALIAS_ENTRIES][FW_MAX_ADDR];
    int n = fw_alias_resolve_port(&cfg, "$web_ports", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == 2, "resolved 2 entries");
    ASSERT(strcmp(out[0], "80") == 0, "port 80");
    ASSERT(strcmp(out[1], "443") == 0, "port 443");

    /* Wrong type (IP alias) */
    strcpy(cfg.aliases[1].name, "ips");
    cfg.aliases[1].type = ALIAS_TYPE_IP;
    strcpy(cfg.aliases[1].entries[0], "10.0.0.1");
    cfg.aliases[1].entry_count = 1;
    cfg.alias_count = 2;

    n = fw_alias_resolve_port(&cfg, "$ips", out, FW_MAX_ALIAS_ENTRIES);
    ASSERT(n == -1, "wrong type returns -1");
}

static void test_alias_validation(void)
{
    printf("test_alias_validation\n");

    fw_config_t cfg;
    fw_config_init(&cfg);
    char err[256];

    /* Add a LAN interface so validation passes */
    strcpy(cfg.lan_ifs[0], "eth0");
    cfg.lan_if_count = 1;

    /* Valid alias */
    strcpy(cfg.aliases[0].name, "servers");
    cfg.aliases[0].type = ALIAS_TYPE_IP;
    strcpy(cfg.aliases[0].entries[0], "192.168.1.10");
    cfg.aliases[0].entry_count = 1;
    cfg.alias_count = 1;

    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) == 0, "valid alias passes");

    /* Duplicate name */
    strcpy(cfg.aliases[1].name, "servers");
    cfg.aliases[1].type = ALIAS_TYPE_IP;
    strcpy(cfg.aliases[1].entries[0], "10.0.0.1");
    cfg.aliases[1].entry_count = 1;
    cfg.alias_count = 2;

    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "duplicate name fails");
    cfg.alias_count = 1;

    /* Empty entries */
    fw_alias_t saved = cfg.aliases[0];
    cfg.aliases[0].entry_count = 0;
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "empty entries fails");
    cfg.aliases[0] = saved;

    /* Invalid IP entry */
    strcpy(cfg.aliases[0].entries[0], "not_an_ip");
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "invalid IP entry fails");
    cfg.aliases[0] = saved;

    /* Valid port alias */
    strcpy(cfg.aliases[0].name, "web_ports");
    cfg.aliases[0].type = ALIAS_TYPE_PORT;
    strcpy(cfg.aliases[0].entries[0], "80");
    strcpy(cfg.aliases[0].entries[1], "443");
    cfg.aliases[0].entry_count = 2;
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) == 0, "valid port alias passes");

    /* Invalid port entry */
    strcpy(cfg.aliases[0].entries[0], "not_a_port");
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "invalid port entry fails");

    /* Port range rejected (only single numeric ports allowed) */
    strcpy(cfg.aliases[0].entries[0], "80");
    strcpy(cfg.aliases[0].entries[1], "1024:2048");
    cfg.aliases[0].entry_count = 2;
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "port range entry rejected");

    /* "any" rejected in port alias */
    strcpy(cfg.aliases[0].entries[0], "any");
    cfg.aliases[0].entry_count = 1;
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) != 0, "any entry rejected in port alias");

    /* Restore valid state */
    strcpy(cfg.aliases[0].entries[0], "80");
    cfg.aliases[0].entry_count = 1;
    ASSERT(fw_config_validate(&cfg, err, sizeof(err)) == 0, "single port entry passes");
}

int main(void)
{
    printf("=== Alias Tests ===\n\n");

    test_alias_validate_name();
    test_alias_is_ref();
    test_alias_find();
    test_alias_resolve_ip();
    test_alias_resolve_port();
    test_alias_validation();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
