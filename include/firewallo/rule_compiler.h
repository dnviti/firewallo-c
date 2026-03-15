#ifndef FIREWALLO_RULE_COMPILER_H
#define FIREWALLO_RULE_COMPILER_H

#include "firewallo/types.h"
#include <stdarg.h>

/* A single command to be executed */
typedef struct {
    char command[1024];
} fw_cmd_t;

/* An ordered list of commands */
typedef struct {
    fw_cmd_t *cmds;
    int count;
    int capacity;
} fw_cmdlist_t;

/* Initialize a command list */
void fw_cmdlist_init(fw_cmdlist_t *list);

/* Append a formatted command to the list */
int fw_cmdlist_append(fw_cmdlist_t *list, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Execute all commands in the list. Returns 0 if all succeed.
   On failure, sets *fail_index to the index of the first failing command. */
int fw_cmdlist_exec(const fw_cmdlist_t *list, int *fail_index);

/* Serialize command list to a human-readable string.
   Each command is written on its own line, prefixed with its index.
   Returns the number of bytes written (excluding NUL), or -1 on error. */
int fw_cmdlist_dump(const fw_cmdlist_t *list, char *buf, size_t buflen);

/* Free the command list */
void fw_cmdlist_free(fw_cmdlist_t *list);

/* Compile the full start sequence */
int fw_compile_start(const fw_config_t *cfg, fw_cmdlist_t *out);

/* Compile the stop sequence */
int fw_compile_stop(const fw_config_t *cfg, fw_cmdlist_t *out);

/* Compile the reset sequence */
int fw_compile_reset(const fw_config_t *cfg, fw_cmdlist_t *out);

#endif /* FIREWALLO_RULE_COMPILER_H */
