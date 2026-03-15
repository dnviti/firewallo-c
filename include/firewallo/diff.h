#ifndef FIREWALLO_DIFF_H
#define FIREWALLO_DIFF_H

#include <stddef.h>
#include "firewallo/types.h"

/* Capture the current active ruleset into buf in command-like format.
   Uses "nft list ruleset" for nft or "iptables -S" for ipt.
   Returns 0 on success (normalized via WEXITSTATUS), or -1 on failure. */
int fw_ruleset_current(const fw_config_t *cfg, char *buf, size_t len);

/* Compute a line-by-line diff between current and proposed rulesets.
   Lines prefixed with '+' are added, '-' are removed, ' ' are unchanged.
   Returns 0 on success. */
int fw_ruleset_diff(const char *current, const char *proposed,
                    char *diff, size_t difflen);

#endif /* FIREWALLO_DIFF_H */
