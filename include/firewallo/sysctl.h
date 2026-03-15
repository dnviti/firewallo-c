#ifndef FIREWALLO_SYSCTL_H
#define FIREWALLO_SYSCTL_H

#include "firewallo/types.h"

/* Write a value to a /proc/sys path. Returns 0 on success. */
int fw_sysctl_set(const char *path, int value);

/* Apply all sysctl settings from config. Returns 0 on success. */
int fw_sysctl_apply(const fw_config_t *cfg);

/* Execute a shell command, return exit code. */
int fw_exec(const char *cmd);

/* Execute a command and capture stdout into buf.
   Returns the process exit code (0 on success) via WEXITSTATUS,
   or -1 if popen() fails or the process was killed by a signal. */
int fw_exec_capture(const char *cmd, char *buf, size_t buflen);

#endif /* FIREWALLO_SYSCTL_H */
