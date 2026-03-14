#include "firewallo/zone.h"
#include "firewallo/config.h"
#include <string.h>

static const char *zone_names[ZONE_COUNT] = {"fw", "lan", "wan", "dmz", "vpns"};

const char *fw_zone_name(fw_zone_t zone)
{
    if (zone >= 0 && zone < ZONE_COUNT)
        return zone_names[zone];
    return NULL;
}

int fw_zone_from_name(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < ZONE_COUNT; i++) {
        if (strcmp(zone_names[i], name) == 0)
            return i;
    }
    return -1;
}

const char *fw_zone_chain_name(fw_zone_t src, fw_zone_t dst)
{
    return fw_config_chain_name(src, dst);
}

int fw_zone_interfaces(const fw_config_t *cfg, fw_zone_t zone,
                       const char *out[], int max)
{
    int count = 0;
    switch (zone) {
    case ZONE_LAN:
        for (int i = 0; i < cfg->lan_if_count && count < max; i++)
            out[count++] = cfg->lan_ifs[i];
        break;
    case ZONE_WAN:
        for (int i = 0; i < cfg->wan_if_count && count < max; i++)
            out[count++] = cfg->wan_ifs[i];
        break;
    case ZONE_DMZ:
        for (int i = 0; i < cfg->dmz_if_count && count < max; i++)
            out[count++] = cfg->dmz_ifs[i];
        break;
    case ZONE_VPN:
        for (int i = 0; i < cfg->vpn_if_count && count < max; i++)
            out[count++] = cfg->vpn_ifs[i];
        break;
    case ZONE_FW:
    default:
        break; /* FW zone has no interfaces (it's the firewall itself) */
    }
    return count;
}

void fw_zone_foreach_chain(fw_chain_visitor_fn fn, void *userdata)
{
    for (int s = 0; s < ZONE_COUNT; s++) {
        for (int d = 0; d < ZONE_COUNT; d++) {
            const char *name = fw_config_chain_name((fw_zone_t)s, (fw_zone_t)d);
            if (name)
                fn((fw_zone_t)s, (fw_zone_t)d, name, userdata);
        }
    }
}
