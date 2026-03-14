#ifndef FIREWALLO_VALIDATE_H
#define FIREWALLO_VALIDATE_H

/* All validators return 1 if valid, 0 if invalid */

/* Validate IPv4 address (e.g. "192.168.1.1") */
int fw_validate_ipv4(const char *ip);

/* Validate IPv4 with CIDR mask (e.g. "192.168.1.0/24") */
int fw_validate_ipv4_cidr(const char *cidr);

/* Validate port number (1-65535) */
int fw_validate_port(int port);

/* Validate port range string (e.g. "1024" or "1024:2000" or "any") */
int fw_validate_port_range(const char *range);

/* Validate network interface name (e.g. "eth0", "ens18", "wg0") */
int fw_validate_interface(const char *ifname);

/* Validate protocol string ("tcp" or "udp") */
int fw_validate_protocol(const char *proto);

/* Validate action string ("accept", "drop", "reject") */
int fw_validate_action(const char *action);

/* Validate comment (alphanumeric, underscore, hyphen, space) */
int fw_validate_comment(const char *comment);

#endif /* FIREWALLO_VALIDATE_H */
