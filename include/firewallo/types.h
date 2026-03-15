#ifndef FIREWALLO_TYPES_H
#define FIREWALLO_TYPES_H

#include <stddef.h>

/* Maximum limits */
#define FW_MAX_INTERFACES    8
#define FW_MAX_IF_NAME      32
#define FW_MAX_DNS           8
#define FW_MAX_ADDR         64
#define FW_MAX_RANGES       16
#define FW_MAX_PORTS       256
#define FW_MAX_RULES       256
#define FW_MAX_NAT          64
#define FW_MAX_MANGLE       64
#define FW_MAX_ROUTES       32
#define FW_MAX_COMMENT     128
#define FW_MAX_VERSION      32
#define FW_MAX_PROTOCOLS    64
#define FW_CHAIN_COUNT      25

/* Zones */
typedef enum {
    ZONE_FW = 0,
    ZONE_LAN,
    ZONE_WAN,
    ZONE_DMZ,
    ZONE_VPN,
    ZONE_COUNT  /* = 5 */
} fw_zone_t;

/* Backends */
typedef enum {
    BACKEND_NFT = 0,
    BACKEND_IPT
} fw_backend_t;

/* Actions */
typedef enum {
    ACTION_ACCEPT = 0,
    ACTION_DROP,
    ACTION_REJECT
} fw_action_t;

/* Protocols */
typedef enum {
    PROTO_TCP = 0,
    PROTO_UDP
} fw_proto_t;

/* NAT types */
typedef enum {
    NAT_MASQUERADE = 0,
    NAT_SNAT,
    NAT_DNAT
} fw_nat_type_t;

/* Languages */
typedef enum {
    LANG_EN = 0,
    LANG_IT
} fw_lang_t;

/* Port: single or range. start=0 means "any". end=0 means single port. */
typedef struct {
    int start;
    int end;
} fw_port_t;

/* Explicit filter rule (beyond simple port opens) */
typedef struct {
    char src_addr[FW_MAX_ADDR];
    char dst_addr[FW_MAX_ADDR];
    fw_proto_t protocol;
    fw_port_t src_port;
    fw_port_t dst_port;
    fw_action_t action;
    char comment[FW_MAX_COMMENT];
} fw_filter_rule_t;

/* Rate limit configuration for brute-force protection */
typedef struct {
    int max_connections;
    int period_seconds;
    int ban_seconds;
    int enabled;
} fw_rate_limit_t;

/* A filter chain (one of 25) */
typedef struct {
    char name[16];
    int tcp_ports[FW_MAX_PORTS];
    int tcp_port_count;
    int udp_ports[FW_MAX_PORTS];
    int udp_port_count;
    fw_filter_rule_t rules[FW_MAX_RULES];
    int rule_count;
    fw_rate_limit_t rate_limit;
} fw_chain_t;

/* NAT postrouting rule (MASQUERADE / SNAT) */
typedef struct {
    char src[FW_MAX_ADDR];
    char oif[FW_MAX_IF_NAME];
    fw_nat_type_t type;
    fw_port_t dport;
    char to_source[FW_MAX_ADDR];
    char comment[FW_MAX_COMMENT];
} fw_nat_post_t;

/* NAT prerouting rule (DNAT) */
typedef struct {
    char src[FW_MAX_ADDR];
    char iif[FW_MAX_IF_NAME];
    fw_proto_t protocol;
    int dport;
    char to_dest_ip[FW_MAX_ADDR];
    int to_dest_port;
    char comment[FW_MAX_COMMENT];
} fw_nat_pre_t;

/* Mangle rule */
typedef struct {
    char iif[FW_MAX_IF_NAME];
    char src_addr[FW_MAX_ADDR];
    char dst_addr[FW_MAX_ADDR];
    fw_proto_t protocol;
    int dport;
    char mark[16];
    char comment[FW_MAX_COMMENT];
} fw_mangle_rule_t;

/* Route entry */
typedef struct {
    char destination[FW_MAX_ADDR];
    char gateway[FW_MAX_ADDR];
    char interface[FW_MAX_IF_NAME];
    char comment[FW_MAX_COMMENT];
} fw_route_t;

/* DPI rule */
typedef struct {
    char src_addr[FW_MAX_ADDR];
    char dst_addr[FW_MAX_ADDR];
    fw_proto_t protocol;
    fw_port_t src_port;
    fw_port_t dst_port;
    char comment[FW_MAX_COMMENT];
} fw_dpi_rule_t;

/* Master configuration */
typedef struct {
    char version[FW_MAX_VERSION];
    fw_lang_t language;
    fw_backend_t backend;

    /* Interfaces */
    char lan_ifs[FW_MAX_INTERFACES][FW_MAX_IF_NAME];
    int lan_if_count;
    char wan_ifs[FW_MAX_INTERFACES][FW_MAX_IF_NAME];
    int wan_if_count;
    char dmz_ifs[FW_MAX_INTERFACES][FW_MAX_IF_NAME];
    int dmz_if_count;
    char vpn_ifs[FW_MAX_INTERFACES][FW_MAX_IF_NAME];
    int vpn_if_count;

    /* DNS */
    char dns[FW_MAX_DNS][FW_MAX_ADDR];
    int dns_count;

    /* Ranges */
    char lan_ranges[FW_MAX_RANGES][FW_MAX_ADDR];
    int lan_range_count;
    char dmz_ranges[FW_MAX_RANGES][FW_MAX_ADDR];
    int dmz_range_count;

    /* Sysctl */
    int ip_forward;
    int ip_dynaddr;
    int tcp_syncookies;
    int accept_source_route;

    /* 25 filter chains */
    fw_chain_t chains[FW_CHAIN_COUNT];

    /* NAT */
    fw_nat_post_t nat_post[FW_MAX_NAT];
    int nat_post_count;
    fw_nat_pre_t nat_pre[FW_MAX_NAT];
    int nat_pre_count;

    /* Mangle */
    fw_mangle_rule_t mangle_pre[FW_MAX_MANGLE];
    int mangle_pre_count;
    fw_mangle_rule_t mangle_post[FW_MAX_MANGLE];
    int mangle_post_count;

    /* Routes */
    fw_route_t routes[FW_MAX_ROUTES];
    int route_count;

    /* DPI */
    int dpi_enabled;
    fw_dpi_rule_t dpi_rules[FW_MAX_RULES];
    int dpi_rule_count;

    /* Suricata */
    int suricata_enabled;
    char suricata_blocked[FW_MAX_PROTOCOLS][FW_MAX_ADDR];
    int suricata_blocked_count;
} fw_config_t;

#endif /* FIREWALLO_TYPES_H */
