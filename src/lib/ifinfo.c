#include "firewallo/ifinfo.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SYSFS_NET "/sys/class/net"

/* ── Internal helpers ─────────────────────────────────────────────── */

static int read_sysfs_string(const char *path, char *buf, size_t buflen)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)buflen, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
    return 0;
}

static int read_sysfs_int(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int val = -1;
    if (fscanf(f, "%d", &val) != 1) val = -1;
    fclose(f);
    return val;
}

static uint64_t read_sysfs_u64(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    uint64_t val = 0;
    if (fscanf(f, "%" SCNu64, &val) != 1) val = 0;
    fclose(f);
    return val;
}

/* Read all sysfs attributes for one interface */
static int read_one_iface(const char *name, fw_ifinfo_t *info)
{
    char path[256];
    memset(info, 0, sizeof(*info));
    snprintf(info->name, sizeof(info->name), "%s", name);

    /* operstate */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/operstate", name);
    if (read_sysfs_string(path, info->state, sizeof(info->state)) != 0)
        snprintf(info->state, sizeof(info->state), "unknown");

    /* MAC address */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/address", name);
    if (read_sysfs_string(path, info->mac, sizeof(info->mac)) != 0)
        info->mac[0] = '\0';

    /* MTU */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/mtu", name);
    info->mtu = read_sysfs_int(path);

    /* Speed (may fail for virtual interfaces) */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/speed", name);
    info->speed = read_sysfs_int(path);

    /* Type */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/type", name);
    info->type = read_sysfs_int(path);

    /* Statistics */
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/rx_bytes", name);
    info->stats.rx_bytes = read_sysfs_u64(path);
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/tx_bytes", name);
    info->stats.tx_bytes = read_sysfs_u64(path);
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/rx_packets", name);
    info->stats.rx_packets = read_sysfs_u64(path);
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/tx_packets", name);
    info->stats.tx_packets = read_sysfs_u64(path);
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/rx_errors", name);
    info->stats.rx_errors = read_sysfs_u64(path);
    snprintf(path, sizeof(path), SYSFS_NET "/%s/statistics/tx_errors", name);
    info->stats.tx_errors = read_sysfs_u64(path);

    return 0;
}

/* Collect IP addresses for a named interface using getifaddrs() */
static void collect_addrs(fw_ifinfo_t *info)
{
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) return;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name)
            continue;
        if (strcmp(ifa->ifa_name, info->name) != 0)
            continue;
        if (info->addr_count >= FW_IFINFO_MAX_ADDRS)
            break;

        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;

        fw_ifaddr_t *a = &info->addrs[info->addr_count];
        a->family = family;

        if (family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sin->sin_addr, a->address, sizeof(a->address));
            if (ifa->ifa_netmask) {
                struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
                inet_ntop(AF_INET, &mask->sin_addr, a->netmask, sizeof(a->netmask));
            }
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, a->address, sizeof(a->address));
            if (ifa->ifa_netmask) {
                struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
                inet_ntop(AF_INET6, &mask6->sin6_addr, a->netmask, sizeof(a->netmask));
            }
        }

        info->addr_count++;
    }

    freeifaddrs(ifap);
}

/* ── Public API ───────────────────────────────────────────────────── */

int fw_ifinfo_list(fw_ifinfo_list_t *out)
{
    memset(out, 0, sizeof(*out));

    DIR *dir = opendir(SYSFS_NET);
    if (!dir) {
        fw_log(LOG_WARN, "cannot open %s", SYSFS_NET);
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL && out->count < FW_IFINFO_MAX) {
        if (ent->d_name[0] == '.')
            continue;
        read_one_iface(ent->d_name, &out->ifaces[out->count]);
        collect_addrs(&out->ifaces[out->count]);
        out->count++;
    }

    closedir(dir);
    return 0;
}

int fw_ifinfo_get(const char *name, fw_ifinfo_t *out)
{
    char path[256];
    snprintf(path, sizeof(path), SYSFS_NET "/%s", name);

    DIR *dir = opendir(path);
    if (!dir) return -1;
    closedir(dir);

    read_one_iface(name, out);
    collect_addrs(out);
    return 0;
}
