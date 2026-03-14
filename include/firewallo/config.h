#ifndef FIREWALLO_CONFIG_H
#define FIREWALLO_CONFIG_H

#include "firewallo/types.h"
#include <stddef.h>

/* Initialize config with defaults */
void fw_config_init(fw_config_t *cfg);

/* Load config from JSON file. Returns 0 on success, -1 on error. */
int fw_config_load(const char *path, fw_config_t *cfg, char *err, size_t errlen);

/* Save config to JSON file. Returns 0 on success. */
int fw_config_save(const char *path, const fw_config_t *cfg);

/* Validate a loaded config. Returns 0 if valid, -1 if invalid (error in err). */
int fw_config_validate(const fw_config_t *cfg, char *err, size_t errlen);

/* Get the index of a chain by name (e.g. "lan2wan"). Returns -1 if not found. */
int fw_config_chain_index(const char *name);

/* Get chain name for a zone pair */
const char *fw_config_chain_name(fw_zone_t src, fw_zone_t dst);

/* Default config file path */
#define FW_DEFAULT_CONFIG_PATH "/etc/firewallo/firewallo.json"

#endif /* FIREWALLO_CONFIG_H */
