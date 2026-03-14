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

#endif /* FIREWALLO_CLI_COMMANDS_H */
