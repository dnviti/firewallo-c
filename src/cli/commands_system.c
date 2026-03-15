#include "commands.h"
#include "firewallo/ifinfo.h"
#include <stdio.h>
#include <string.h>

/* ── System interfaces ────────────────────────────────────────────── */

int cmd_list_system_interfaces(void)
{
    fw_ifinfo_list_t list;
    if (fw_ifinfo_list(&list) != 0) {
        fprintf(stderr, "Error: cannot read system interfaces\n");
        return 1;
    }

    printf("%-16s %-8s %-18s %6s %10s  %s\n",
           "NAME", "STATE", "MAC", "MTU", "SPEED", "IP ADDRESSES");
    printf("%-16s %-8s %-18s %6s %10s  %s\n",
           "----", "-----", "---", "---", "-----", "------------");

    for (int i = 0; i < list.count; i++) {
        const fw_ifinfo_t *iface = &list.ifaces[i];
        char speed_str[16];
        if (iface->speed > 0)
            snprintf(speed_str, sizeof(speed_str), "%dMbps", iface->speed);
        else
            snprintf(speed_str, sizeof(speed_str), "-");

        /* Build IP addresses string */
        char ips[256] = {0};
        int pos = 0;
        for (int j = 0; j < iface->addr_count && pos < 240; j++) {
            if (j > 0) pos += snprintf(ips + pos, sizeof(ips) - (size_t)pos, ", ");
            pos += snprintf(ips + pos, sizeof(ips) - (size_t)pos, "%s", iface->addrs[j].address);
        }
        if (ips[0] == '\0') snprintf(ips, sizeof(ips), "-");

        printf("%-16s %-8s %-18s %6d %10s  %s\n",
               iface->name, iface->state, iface->mac,
               iface->mtu, speed_str, ips);
    }

    return 0;
}
