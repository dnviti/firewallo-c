#ifndef FIREWALLO_IFINFO_H
#define FIREWALLO_IFINFO_H

#include <stddef.h>
#include <stdint.h>

/* Limits */
#define FW_IFINFO_MAX        32   /* max interfaces to enumerate */
#define FW_IFINFO_MAX_ADDRS   8   /* max IP addresses per interface */
#define FW_IF_NAME_SIZE      32
#define FW_IF_ADDR_SIZE      64   /* big enough for IPv6 */
#define FW_IF_MAC_SIZE       18   /* "aa:bb:cc:dd:ee:ff\0" */
#define FW_IF_STATE_SIZE     16   /* "up", "down", "unknown" */

/* Known interface hardware types (from linux/if_arp.h values) */
#define FW_IFTYPE_ETHERNET    1
#define FW_IFTYPE_LOOPBACK  772

/* IP address entry */
typedef struct {
    char address[FW_IF_ADDR_SIZE];
    char netmask[FW_IF_ADDR_SIZE];
    int  family;   /* AF_INET=2 or AF_INET6=10 */
} fw_ifaddr_t;

/* Per-interface traffic statistics */
typedef struct {
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
} fw_ifstats_t;

/* Full interface info */
typedef struct {
    char          name[FW_IF_NAME_SIZE];
    char          state[FW_IF_STATE_SIZE];
    char          mac[FW_IF_MAC_SIZE];
    int           mtu;
    int           speed;        /* Mbps, -1 if unavailable */
    int           type;         /* sysfs type number */
    fw_ifstats_t  stats;
    fw_ifaddr_t   addrs[FW_IFINFO_MAX_ADDRS];
    int           addr_count;
} fw_ifinfo_t;

/* Result set */
typedef struct {
    fw_ifinfo_t  ifaces[FW_IFINFO_MAX];
    int          count;
} fw_ifinfo_list_t;

/* Enumerate all system interfaces. Returns 0 on success, -1 on error. */
int fw_ifinfo_list(fw_ifinfo_list_t *out);

/* Get info for a single interface by name. Returns 0 on success, -1 if not found. */
int fw_ifinfo_get(const char *name, fw_ifinfo_t *out);

#endif /* FIREWALLO_IFINFO_H */
