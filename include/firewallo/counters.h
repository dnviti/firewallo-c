#ifndef FIREWALLO_COUNTERS_H
#define FIREWALLO_COUNTERS_H

#include "firewallo/types.h"
#include <stdint.h>
#include <time.h>

/* Maximum counters: FW_CHAIN_COUNT * FW_MAX_RULES should fit */
#define FW_MAX_COUNTERS 512

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

/* Collect counters from the active firewall backend.
   Returns 0 on success, -1 on error. */
int fw_counters_collect(fw_backend_t backend, fw_counter_data_t *data);

/* Reset counters in the active firewall backend.
   Returns 0 on success, -1 on error. */
int fw_counters_reset(fw_backend_t backend);

#endif /* FIREWALLO_COUNTERS_H */
