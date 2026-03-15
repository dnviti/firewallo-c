#include "firewallo/webhook.h"
#include "firewallo/config.h"
#include "firewallo/util.h"
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

static void test_validate_url(void)
{
    printf("test_validate_url\n");

    /* Valid URLs */
    ASSERT(fw_webhook_validate_url("http://example.com/webhook") == 1,
           "http URL valid");
    ASSERT(fw_webhook_validate_url("https://hooks.slack.com/services/T00/B00/xxx") == 1,
           "https slack URL valid");
    ASSERT(fw_webhook_validate_url("http://localhost:8080/hook") == 1,
           "localhost with port valid");
    ASSERT(fw_webhook_validate_url("https://discord.com/api/webhooks/123/abc") == 1,
           "discord webhook valid");
    ASSERT(fw_webhook_validate_url("http://192.168.1.1:9000/notify") == 1,
           "IP with port valid");

    /* Invalid URLs */
    ASSERT(fw_webhook_validate_url(NULL) == 0, "NULL invalid");
    ASSERT(fw_webhook_validate_url("") == 0, "empty invalid");
    ASSERT(fw_webhook_validate_url("ftp://example.com") == 0, "ftp invalid");
    ASSERT(fw_webhook_validate_url("not-a-url") == 0, "no scheme invalid");
    ASSERT(fw_webhook_validate_url("http://") == 0, "no host invalid");
    ASSERT(fw_webhook_validate_url("https://") == 0, "https no host invalid");
}

static void test_validate_events(void)
{
    printf("test_validate_events\n");

    ASSERT(fw_webhook_validate_events(WH_EVENT_CONFIG_CHANGE) == 1,
           "single event valid");
    ASSERT(fw_webhook_validate_events(WH_EVENT_ALL) == 1,
           "all events valid");
    ASSERT(fw_webhook_validate_events(WH_EVENT_CONFIG_CHANGE | WH_EVENT_RULE_APPLY) == 1,
           "combined events valid");
    ASSERT(fw_webhook_validate_events(1) == 1, "min event valid");

    ASSERT(fw_webhook_validate_events(0) == 0, "zero events invalid");
    ASSERT(fw_webhook_validate_events(64) == 0, "out of range invalid");
    ASSERT(fw_webhook_validate_events(128) == 0, "large value invalid");
}

static void test_event_name(void)
{
    printf("test_event_name\n");

    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_CONFIG_CHANGE), "config_change") == 0,
           "config_change name");
    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_RULE_APPLY), "rule_apply") == 0,
           "rule_apply name");
    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_INTRUSION), "intrusion") == 0,
           "intrusion name");
    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_VPN_STATUS), "vpn_status") == 0,
           "vpn_status name");
    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_SURICATA), "suricata") == 0,
           "suricata name");
    ASSERT(strcmp(fw_webhook_event_name(WH_EVENT_SERVICE), "service") == 0,
           "service name");
}

static void test_webhook_config_roundtrip(void)
{
    printf("test_webhook_config_roundtrip\n");

    fw_config_t cfg;
    fw_config_init(&cfg);

    /* Set up minimal valid config */
    fw_strlcpy(cfg.lan_ifs[0], "eth0", FW_MAX_IF_NAME);
    cfg.lan_if_count = 1;

    /* Add webhooks */
    cfg.webhook_count = 2;

    fw_strlcpy(cfg.webhooks[0].url, "http://example.com/hook1", sizeof(cfg.webhooks[0].url));
    fw_strlcpy(cfg.webhooks[0].secret, "secret123", sizeof(cfg.webhooks[0].secret));
    cfg.webhooks[0].events = WH_EVENT_CONFIG_CHANGE | WH_EVENT_RULE_APPLY;
    cfg.webhooks[0].enabled = 1;
    cfg.webhooks[0].retry_count = 3;
    fw_strlcpy(cfg.webhooks[0].comment, "test hook 1", sizeof(cfg.webhooks[0].comment));

    fw_strlcpy(cfg.webhooks[1].url, "http://example.com/hook2", sizeof(cfg.webhooks[1].url));
    cfg.webhooks[1].events = WH_EVENT_ALL;
    cfg.webhooks[1].enabled = 0;
    cfg.webhooks[1].retry_count = 1;
    fw_strlcpy(cfg.webhooks[1].comment, "disabled hook", sizeof(cfg.webhooks[1].comment));

    /* Save */
    const char *tmpfile = "/tmp/firewallo_test_webhook.json";
    int ret = fw_config_save(tmpfile, &cfg);
    ASSERT(ret == 0, "save with webhooks succeeds");

    /* Reload */
    fw_config_t cfg2;
    char err[256] = {0};
    ret = fw_config_load(tmpfile, &cfg2, err, sizeof(err));
    if (ret != 0) printf("  Load error: %s\n", err);
    ASSERT(ret == 0, "reload with webhooks succeeds");

    /* Verify webhooks */
    ASSERT(cfg2.webhook_count == 2, "webhook_count is 2");

    ASSERT(strcmp(cfg2.webhooks[0].url, "http://example.com/hook1") == 0,
           "webhook 0 url matches");
    ASSERT(strcmp(cfg2.webhooks[0].secret, "secret123") == 0,
           "webhook 0 secret matches");
    ASSERT(cfg2.webhooks[0].events == (WH_EVENT_CONFIG_CHANGE | WH_EVENT_RULE_APPLY),
           "webhook 0 events match");
    ASSERT(cfg2.webhooks[0].enabled == 1, "webhook 0 enabled");
    ASSERT(cfg2.webhooks[0].retry_count == 3, "webhook 0 retry_count");
    ASSERT(strcmp(cfg2.webhooks[0].comment, "test hook 1") == 0,
           "webhook 0 comment matches");

    ASSERT(strcmp(cfg2.webhooks[1].url, "http://example.com/hook2") == 0,
           "webhook 1 url matches");
    ASSERT(cfg2.webhooks[1].events == (unsigned int)WH_EVENT_ALL,
           "webhook 1 events all");
    ASSERT(cfg2.webhooks[1].enabled == 0, "webhook 1 disabled");
    ASSERT(cfg2.webhooks[1].retry_count == 1, "webhook 1 retry_count");

    /* Validate */
    ret = fw_config_validate(&cfg2, err, sizeof(err));
    ASSERT(ret == 0, "config with webhooks validates");

    /* Test invalid webhook */
    fw_strlcpy(cfg2.webhooks[0].url, "ftp://bad", sizeof(cfg2.webhooks[0].url));
    ret = fw_config_validate(&cfg2, err, sizeof(err));
    ASSERT(ret == -1, "invalid webhook URL caught by validate");

    /* Restore and test invalid events */
    fw_strlcpy(cfg2.webhooks[0].url, "http://example.com/hook1", sizeof(cfg2.webhooks[0].url));
    cfg2.webhooks[0].events = 0;
    ret = fw_config_validate(&cfg2, err, sizeof(err));
    ASSERT(ret == -1, "zero events caught by validate");

    /* Restore and test invalid retry_count */
    cfg2.webhooks[0].events = WH_EVENT_ALL;
    cfg2.webhooks[0].retry_count = 99;
    ret = fw_config_validate(&cfg2, err, sizeof(err));
    ASSERT(ret == -1, "high retry_count caught by validate");

    remove(tmpfile);
}

static void test_webhook_send_no_match(void)
{
    printf("test_webhook_send_no_match\n");

    fw_config_t cfg;
    fw_config_init(&cfg);
    cfg.webhook_count = 0;

    /* Should return 0 (no matching webhooks, nothing to do) */
    int ret = fw_webhook_send(&cfg, WH_EVENT_CONFIG_CHANGE, "{\"test\":true}");
    ASSERT(ret == 0, "send with no webhooks returns 0");

    /* Add disabled webhook */
    cfg.webhook_count = 1;
    fw_strlcpy(cfg.webhooks[0].url, "http://example.com/hook", sizeof(cfg.webhooks[0].url));
    cfg.webhooks[0].events = WH_EVENT_ALL;
    cfg.webhooks[0].enabled = 0;
    cfg.webhooks[0].retry_count = 1;

    ret = fw_webhook_send(&cfg, WH_EVENT_CONFIG_CHANGE, "{\"test\":true}");
    ASSERT(ret == 0, "send with disabled webhook returns 0");

    /* Add enabled webhook but non-matching event */
    cfg.webhooks[0].enabled = 1;
    cfg.webhooks[0].events = WH_EVENT_SURICATA; /* only suricata */

    ret = fw_webhook_send(&cfg, WH_EVENT_CONFIG_CHANGE, "{\"test\":true}");
    ASSERT(ret == 0, "send with non-matching event returns 0");
}

int main(void)
{
    printf("=== Webhook Tests ===\n\n");

    test_validate_url();
    test_validate_events();
    test_event_name();
    test_webhook_config_roundtrip();
    test_webhook_send_no_match();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
