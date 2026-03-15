#ifndef FIREWALLO_COUNTERS_H
#define FIREWALLO_COUNTERS_H

#include "firewallo/types.h"
#include <stdint.h>
#include <time.h>

/* Maximum counters: FW_CHAIN_COUNT * FW_MAX_RULES = 25 * 256 = 6400 */
#define FW_MAX_COUNTERS (FW_CHAIN_COUNT * FW_MAX_RULES)

/* Per-rule counter entry */
typedef struct {
    char chain[16];
    int rule_index;
    uint64_t packets;
    uint64_t bytes;
} fw_rule_counter_t;

/* Collected counter data */
typedef struct {
    fw_rule_counter_t rules[FW_MAX_COUNTERS];
    int count;
    time_t collected_at;
} fw_counter_data_t;

/* Parse nftables ruleset output into counter data.
   Returns 0 on success. */
int fw_parse_nft_counters(const char *output, fw_counter_data_t *data);

/* Parse iptables -L -v -n -x output into counter data.
   Returns 0 on success. */
int fw_parse_ipt_counters(const char *output, fw_counter_data_t *data);

/* Collect counters from the active firewall backend.
   Returns 0 on success, -1 on error. */
int fw_counters_collect(fw_backend_t backend, fw_counter_data_t *data);

/* Reset counters in the active firewall backend.
   Returns 0 on success, -1 on error. */
int fw_counters_reset(fw_backend_t backend);

#endif /* FIREWALLO_COUNTERS_H */
