#include "firewallo/alias.h"
#include "firewallo/validate.h"
#include "firewallo/util.h"
#include <string.h>
#include <ctype.h>

const fw_alias_t *fw_alias_find(const fw_config_t *cfg, const char *name)
{
    if (!cfg || !name)
        return NULL;

    for (int i = 0; i < cfg->alias_count; i++) {
        if (strcmp(cfg->aliases[i].name, name) == 0)
            return &cfg->aliases[i];
    }
    return NULL;
}

int fw_alias_is_ref(const char *s)
{
    return s && s[0] == '$' && s[1] != '\0';
}

int fw_alias_resolve_ip(const fw_config_t *cfg, const char *ref,
                        char out_entries[][FW_MAX_ADDR], int max_entries)
{
    if (!fw_alias_is_ref(ref))
        return -1;

    const char *name = ref + 1; /* skip '$' */
    const fw_alias_t *alias = fw_alias_find(cfg, name);
    if (!alias)
        return -1;

    if (alias->type != ALIAS_TYPE_IP)
        return -1;

    int count = alias->entry_count;
    if (count > max_entries)
        count = max_entries;

    for (int i = 0; i < count; i++)
        fw_strlcpy(out_entries[i], alias->entries[i], FW_MAX_ADDR);

    return count;
}

int fw_alias_resolve_port(const fw_config_t *cfg, const char *ref,
                          char out_entries[][FW_MAX_ADDR], int max_entries)
{
    if (!fw_alias_is_ref(ref))
        return -1;

    const char *name = ref + 1; /* skip '$' */
    const fw_alias_t *alias = fw_alias_find(cfg, name);
    if (!alias)
        return -1;

    if (alias->type != ALIAS_TYPE_PORT)
        return -1;

    int count = alias->entry_count;
    if (count > max_entries)
        count = max_entries;

    for (int i = 0; i < count; i++)
        fw_strlcpy(out_entries[i], alias->entries[i], FW_MAX_ADDR);

    return count;
}

int fw_alias_validate_name(const char *name)
{
    if (!name || !*name)
        return 0;

    size_t len = strlen(name);
    if (len >= FW_MAX_ALIAS_NAME)
        return 0;

    /* Must start with a letter */
    if (!isalpha((unsigned char)name[0]))
        return 0;

    /* Allow alphanumeric and underscore */
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!isalnum((unsigned char)c) && c != '_')
            return 0;
    }

    return 1;
}
