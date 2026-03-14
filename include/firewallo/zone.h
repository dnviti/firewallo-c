#ifndef FIREWALLO_ZONE_H
#define FIREWALLO_ZONE_H

#include "firewallo/types.h"

/* Get the short name for a zone ("fw", "lan", "wan", "dmz", "vpns") */
const char *fw_zone_name(fw_zone_t zone);

/* Get zone enum from short name. Returns -1 if not found. */
int fw_zone_from_name(const char *name);

/* Get chain name for a source→destination zone pair (e.g. "lan2wan") */
const char *fw_zone_chain_name(fw_zone_t src, fw_zone_t dst);

/* Get all interfaces for a zone from config */
int fw_zone_interfaces(const fw_config_t *cfg, fw_zone_t zone,
                       const char *out[], int max);

/* Iterate all 25 chain combinations */
typedef void (*fw_chain_visitor_fn)(fw_zone_t src, fw_zone_t dst,
                                    const char *chain_name, void *userdata);
void fw_zone_foreach_chain(fw_chain_visitor_fn fn, void *userdata);

#endif /* FIREWALLO_ZONE_H */
