#ifndef FIREWALLO_ALIAS_H
#define FIREWALLO_ALIAS_H

#include "firewallo/types.h"

/* Find an alias by name in the config. Returns pointer or NULL. */
const fw_alias_t *fw_alias_find(const fw_config_t *cfg, const char *name);

/* Check if a string is an alias reference (starts with '$'). */
int fw_alias_is_ref(const char *s);

/* Resolve an alias reference for IP type. Writes resolved entries into
   out_entries (up to max_entries). Returns number of entries, or -1 on error. */
int fw_alias_resolve_ip(const fw_config_t *cfg, const char *ref,
                        char out_entries[][FW_MAX_ADDR], int max_entries);

/* Resolve an alias reference for port type. Writes resolved entries into
   out_entries (up to max_entries). Returns number of entries, or -1 on error. */
int fw_alias_resolve_port(const fw_config_t *cfg, const char *ref,
                          char out_entries[][FW_MAX_ADDR], int max_entries);

/* Validate an alias name (alphanumeric and underscore, starts with letter). */
int fw_alias_validate_name(const char *name);

/* Check if an alias is referenced by any filter rules (src_addr or dst_addr).
   Returns 1 if referenced, 0 if not. */
int fw_alias_is_referenced(const fw_config_t *cfg, const char *name);

#endif /* FIREWALLO_ALIAS_H */
