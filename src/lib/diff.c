#include "firewallo/diff.h"
#include "firewallo/sysctl.h"
#include <stdio.h>
#include <string.h>

/* ── Capture current ruleset ──────────────────────────────────────── */

int fw_ruleset_current(const fw_config_t *cfg, char *buf, size_t len)
{
    if (!buf || len == 0)
        return -1;

    buf[0] = '\0';

    if (cfg->backend == BACKEND_NFT)
        return fw_exec_capture("/usr/sbin/nft list ruleset 2>/dev/null", buf, len);
    else
        return fw_exec_capture("/sbin/iptables-save 2>/dev/null", buf, len);
}

/* ── Helper: check if a line exists in a set of lines ─────────────── */

/* Find line in text (exact match). Returns 1 if found, 0 otherwise.
   Also marks the line as "used" in the used array at the matching index. */
static int find_line(const char *text, const char *line, size_t linelen,
                     int *used, int line_count)
{
    const char *p = text;
    int idx = 0;

    while (*p && idx < line_count) {
        const char *eol = strchr(p, '\n');
        size_t plen = eol ? (size_t)(eol - p) : strlen(p);

        if (!used[idx] && plen == linelen && memcmp(p, line, linelen) == 0) {
            used[idx] = 1;
            return 1;
        }

        idx++;
        p = eol ? eol + 1 : p + plen;
    }
    return 0;
}

/* Count lines in a string */
static int count_lines(const char *text)
{
    if (!text || !*text)
        return 0;

    int count = 0;
    const char *p = text;
    while (*p) {
        if (*p == '\n')
            count++;
        p++;
    }
    /* Count last line if not terminated by newline */
    if (p > text && *(p - 1) != '\n')
        count++;
    return count;
}

/* ── Line-by-line diff ────────────────────────────────────────────── */

int fw_ruleset_diff(const char *current, const char *proposed,
                    char *diff, size_t difflen)
{
    if (!diff || difflen == 0)
        return -1;

    diff[0] = '\0';
    size_t written = 0;

    /* Handle empty inputs */
    if ((!current || !*current) && (!proposed || !*proposed))
        return 0;

    /* Count lines for the used-tracking array */
    int prop_line_count = count_lines(proposed ? proposed : "");

    /* Stack-allocate for small counts, heap for large */
    int used_stack[512];
    int *used = used_stack;
    if (prop_line_count > 512) {
        /* For very large rulesets, zero out what we can */
        prop_line_count = 512;
        /* Truncate to avoid overflow — a reasonable limit */
    }
    memset(used, 0, sizeof(int) * (size_t)prop_line_count);

    /* Pass 1: Lines in current — check if they exist in proposed */
    if (current && *current) {
        const char *p = current;
        while (*p) {
            const char *eol = strchr(p, '\n');
            size_t linelen = eol ? (size_t)(eol - p) : strlen(p);

            if (linelen > 0) {
                int found = find_line(proposed ? proposed : "", p, linelen,
                                      used, prop_line_count);
                char prefix = found ? ' ' : '-';
                int n = snprintf(diff + written, difflen - written,
                                 "%c %.*s\n", prefix, (int)linelen, p);
                if (n > 0 && (size_t)n < difflen - written)
                    written += (size_t)n;
            }

            if (!eol) break;
            p = eol + 1;
        }
    }

    /* Pass 2: Lines in proposed that were not matched (additions) */
    if (proposed && *proposed) {
        const char *p = proposed;
        int idx = 0;
        while (*p && idx < prop_line_count) {
            const char *eol = strchr(p, '\n');
            size_t linelen = eol ? (size_t)(eol - p) : strlen(p);

            if (linelen > 0 && !used[idx]) {
                int n = snprintf(diff + written, difflen - written,
                                 "+ %.*s\n", (int)linelen, p);
                if (n > 0 && (size_t)n < difflen - written)
                    written += (size_t)n;
            }

            idx++;
            if (!eol) break;
            p = eol + 1;
        }
    }

    return 0;
}
