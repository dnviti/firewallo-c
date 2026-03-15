#include "firewallo/counters.h"
#include "firewallo/sysctl.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ── nftables counter parsing ──────────────────────────────────────── */

/*
 * Parse `nft list ruleset` output.  We look for lines like:
 *     chain <name> {
 * and within chains for "counter packets <N> bytes <N>".
 */
int fw_parse_nft_counters(const char *output, fw_counter_data_t *data)
{
    const char *p = output;
    char current_chain[16] = {0};
    int rule_idx = 0;

    while (*p) {
        /* Skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;

        /* Detect "chain <name> {" */
        if (strncmp(p, "chain ", 6) == 0) {
            const char *name_start = p + 6;
            const char *name_end = name_start;
            while (*name_end && *name_end != ' ' && *name_end != '{' && *name_end != '\n')
                name_end++;
            size_t len = (size_t)(name_end - name_start);
            if (len >= sizeof(current_chain))
                len = sizeof(current_chain) - 1;
            memcpy(current_chain, name_start, len);
            current_chain[len] = '\0';
            rule_idx = 0;
        }

        /* Detect "counter packets <N> bytes <N>" */
        if (current_chain[0]) {
            const char *cp = strstr(p, "counter packets ");
            /* Only match if counter appears on the current line */
            const char *eol = strchr(p, '\n');
            if (!eol) eol = p + strlen(p);

            if (cp && cp < eol) {
                uint64_t pkts = 0, bts = 0;
                const char *num = cp + 16; /* skip "counter packets " */
                pkts = strtoull(num, NULL, 10);

                const char *bp = strstr(num, "bytes ");
                if (bp && bp < eol) {
                    bts = strtoull(bp + 6, NULL, 10);
                }

                if (data->count < FW_MAX_COUNTERS) {
                    fw_rule_counter_t *rc = &data->rules[data->count];
                    fw_strlcpy(rc->chain, current_chain, sizeof(rc->chain));
                    rc->rule_index = rule_idx;
                    rc->packets = pkts;
                    rc->bytes = bts;
                    data->count++;
                }
                rule_idx++;
            }
        }

        /* Advance to next line */
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }

    return 0;
}

/* ── iptables counter parsing ──────────────────────────────────────── */

/*
 * Parse `iptables -L -v -n -x` output.  Format:
 *   Chain <name> (policy ...)
 *       pkts      bytes target ...
 *      <pkts>   <bytes> ...
 */
int fw_parse_ipt_counters(const char *output, fw_counter_data_t *data)
{
    const char *p = output;
    char current_chain[16] = {0};
    int rule_idx = 0;
    int in_header = 0; /* skip the header line after "Chain ..." */

    while (*p) {
        /* Skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;

        /* Detect "Chain <name>" */
        if (strncmp(p, "Chain ", 6) == 0) {
            const char *name_start = p + 6;
            const char *name_end = name_start;
            while (*name_end && *name_end != ' ' && *name_end != '\n')
                name_end++;
            size_t len = (size_t)(name_end - name_start);
            if (len >= sizeof(current_chain))
                len = sizeof(current_chain) - 1;
            memcpy(current_chain, name_start, len);
            current_chain[len] = '\0';
            rule_idx = 0;
            in_header = 1;
            /* Advance to next line */
            const char *nl = strchr(p, '\n');
            if (!nl) break;
            p = nl + 1;
            continue;
        }

        /* Skip column header line (starts with "pkts" after whitespace) */
        if (in_header) {
            in_header = 0;
            const char *nl = strchr(p, '\n');
            if (!nl) break;
            p = nl + 1;
            continue;
        }

        /* Skip empty lines */
        if (*p == '\n') {
            p++;
            continue;
        }

        /* Parse data line: first two numbers are pkts and bytes */
        if (current_chain[0]) {
            char *endptr;
            uint64_t pkts = strtoull(p, &endptr, 10);
            if (endptr != p) {
                /* Skip whitespace */
                while (*endptr == ' ' || *endptr == '\t') endptr++;
                char *endptr2;
                uint64_t bts = strtoull(endptr, &endptr2, 10);
                if (endptr2 != endptr && data->count < FW_MAX_COUNTERS) {
                    fw_rule_counter_t *rc = &data->rules[data->count];
                    fw_strlcpy(rc->chain, current_chain, sizeof(rc->chain));
                    rc->rule_index = rule_idx;
                    rc->packets = pkts;
                    rc->bytes = bts;
                    data->count++;
                }
                rule_idx++;
            }
        }

        /* Advance to next line */
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }

    return 0;
}

/* ── Public API ────────────────────────────────────────────────────── */

int fw_counters_collect(fw_backend_t backend, fw_counter_data_t *data)
{
    if (!data) return -1;

    memset(data, 0, sizeof(*data));
    data->collected_at = time(NULL);

    char *buf = malloc(262144); /* 256 KB for ruleset output */
    if (!buf) return -1;
    buf[0] = '\0';

    int ret;
    if (backend == BACKEND_NFT) {
        ret = fw_exec_capture("/usr/sbin/nft list ruleset 2>/dev/null", buf, 262144);
        if (ret != 0) { free(buf); return -1; }
        ret = fw_parse_nft_counters(buf, data);
    } else {
        ret = fw_exec_capture("/sbin/iptables -L -v -n -x 2>/dev/null", buf, 262144);
        if (ret != 0) { free(buf); return -1; }
        ret = fw_parse_ipt_counters(buf, data);
    }

    free(buf);
    return ret;
}

int fw_counters_reset(fw_backend_t backend)
{
    char buf[256] = {0};
    if (backend == BACKEND_NFT) {
        return fw_exec_capture("/usr/sbin/nft reset counters 2>/dev/null", buf, sizeof(buf));
    } else {
        return fw_exec_capture("/sbin/iptables -Z 2>/dev/null", buf, sizeof(buf));
    }
}
