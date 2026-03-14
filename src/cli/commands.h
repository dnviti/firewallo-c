#ifndef FIREWALLO_CLI_COMMANDS_H
#define FIREWALLO_CLI_COMMANDS_H

#include "firewallo/types.h"

int cmd_start(fw_config_t *cfg, int verbose);
int cmd_stop(fw_config_t *cfg, int verbose);
int cmd_restart(fw_config_t *cfg, const char *config_path, int verbose);
int cmd_reset(fw_config_t *cfg, int verbose);
int cmd_status(const fw_config_t *cfg);
int cmd_rules(const fw_config_t *cfg);
int cmd_validate(const fw_config_t *cfg);
int cmd_show_config(const fw_config_t *cfg);
int cmd_export(const fw_config_t *cfg, const char *config_path);
int cmd_restore(fw_config_t *cfg, const char *backup_path, const char *config_path);
int cmd_switch_backend(fw_config_t *cfg, const char *backend, const char *config_path);
int cmd_version(const fw_config_t *cfg);

/* Config editing commands (CFG-0001) */
int cmd_set_interface(fw_config_t *cfg, const char *zone, const char *action,
                      const char *iface, const char *config_path);
int cmd_set_dns(fw_config_t *cfg, const char *action, const char *ip,
                const char *config_path);
int cmd_set_range(fw_config_t *cfg, const char *zone, const char *action,
                  const char *cidr, const char *config_path);
int cmd_set_sysctl(fw_config_t *cfg, const char *key, const char *value,
                   const char *config_path);
int cmd_set_chain(fw_config_t *cfg, const char *chain, const char *proto,
                  const char *action, const char *port_str, const char *config_path);
int cmd_set_nat(fw_config_t *cfg, const char *direction, const char *action,
                const char *rule_json, const char *config_path);
int cmd_reload(fw_config_t *cfg, const char *config_path, int verbose);

#endif /* FIREWALLO_CLI_COMMANDS_H */
