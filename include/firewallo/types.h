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
#define FW_MAX_ALIASES      64
#define FW_MAX_ALIAS_ENTRIES 128
#define FW_MAX_ALIAS_NAME    32
#define FW_MAX_VERSION      32
#define FW_MAX_PROTOCOLS    64
#define FW_CHAIN_COUNT      25
#define FW_MAX_WEBHOOKS      8
#define FW_MAX_WEBHOOK_URL 512
#define FW_MAX_WEBHOOK_SECRET 128
#define FW_MAX_WEBHOOK_RETRY    5

/* Alias types */
typedef enum { ALIAS_TYPE_IP = 0, ALIAS_TYPE_PORT } fw_alias_type_t;

typedef struct {
    char name[FW_MAX_ALIAS_NAME];
    fw_alias_type_t type;
    char entries[FW_MAX_ALIAS_ENTRIES][FW_MAX_ADDR];
    int entry_count;
    char comment[FW_MAX_COMMENT];
} fw_alias_t;

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

/* Time-based schedule for rules */
typedef struct {
    int enabled;
    int hour_start;
    int minute_start;
    int hour_end;
    int minute_end;
    unsigned char days; /* bitmask: bit0=Mon, bit1=Tue, ..., bit6=Sun */
} fw_schedule_t;

/* Explicit filter rule (beyond simple port opens) */
typedef struct {
    char src_addr[FW_MAX_ADDR];
    char dst_addr[FW_MAX_ADDR];
    fw_proto_t protocol;
    fw_port_t src_port;
    fw_port_t dst_port;
    fw_action_t action;
    char comment[FW_MAX_COMMENT];
    fw_schedule_t schedule;
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

/* Webhook event types (bitmask) */
typedef enum {
    WH_EVENT_CONFIG_CHANGE = 1,
    WH_EVENT_RULE_APPLY    = 2,
    WH_EVENT_INTRUSION     = 4,
    WH_EVENT_VPN_STATUS    = 8,
    WH_EVENT_SURICATA      = 16,
    WH_EVENT_SERVICE       = 32,
    WH_EVENT_ALL           = 63
} fw_webhook_event_t;

/* Webhook endpoint */
typedef struct {
    char url[FW_MAX_WEBHOOK_URL];
    char secret[FW_MAX_WEBHOOK_SECRET];
    unsigned int events;
    int enabled;
    int retry_count;
    char comment[FW_MAX_COMMENT];
} fw_webhook_t;

/* VPN protocol types */
typedef enum {
    VPN_WIREGUARD = 0,
    VPN_OPENVPN,
    VPN_IPSEC
} fw_vpn_proto_t;

/* VPN mode */
typedef enum {
    VPN_MODE_SERVER = 0,
    VPN_MODE_CLIENT,
    VPN_MODE_SITE2SITE
} fw_vpn_mode_t;

#define FW_MAX_VPN_TUNNELS 16
#define FW_MAX_VPN_PEERS   32
#define FW_MAX_VPN_KEY     64
#define FW_MAX_VPN_PATH   256

/* VPN tunnel configuration */
typedef struct {
    char name[FW_MAX_IF_NAME];
    fw_vpn_proto_t protocol;
    fw_vpn_mode_t mode;
    char listen_port[8];
    char endpoint[FW_MAX_COMMENT];         /* remote host:port for client/s2s */
    char local_network[FW_MAX_ADDR];       /* e.g. "10.0.0.0/24" */
    char remote_network[FW_MAX_ADDR];      /* for site2site */
    char interface[FW_MAX_IF_NAME];        /* linked system interface */
    char comment[FW_MAX_COMMENT];
    /* WireGuard */
    char wg_private_key[FW_MAX_VPN_KEY];
    char wg_public_key[FW_MAX_VPN_KEY];
    char wg_preshared_key[FW_MAX_VPN_KEY];
    /* OpenVPN */
    char ovpn_ca_path[FW_MAX_VPN_PATH];
    char ovpn_cert_path[FW_MAX_VPN_PATH];
    char ovpn_key_path[FW_MAX_VPN_PATH];
    char ovpn_dh_path[FW_MAX_VPN_PATH];
    char ovpn_cipher[FW_MAX_IF_NAME];
    /* IPSec */
    char ipsec_auth_method[FW_MAX_IF_NAME]; /* "psk" or "cert" */
    char ipsec_psk[FW_MAX_COMMENT];
    char ipsec_local_id[FW_MAX_ADDR];
    char ipsec_remote_id[FW_MAX_ADDR];
} fw_vpn_tunnel_t;

/* VPN peer (WireGuard) */
typedef struct {
    char name[FW_MAX_IF_NAME];
    char tunnel[FW_MAX_IF_NAME];           /* parent tunnel name */
    char public_key[FW_MAX_VPN_KEY];
    char preshared_key[FW_MAX_VPN_KEY];
    char allowed_ips[FW_MAX_COMMENT];
    char endpoint[FW_MAX_COMMENT];
    int  keepalive;
    char comment[FW_MAX_COMMENT];
} fw_vpn_peer_t;

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

    /* IPv6 transition mechanism filtering */
    int block_6to4;
    int block_teredo;
    int block_isatap;

    /* Webhooks */
    fw_webhook_t webhooks[FW_MAX_WEBHOOKS];
    int webhook_count;

    /* Aliases (named address/port groups) */
    fw_alias_t aliases[FW_MAX_ALIASES];
    int alias_count;

    /* VPN tunnels and peers */
    fw_vpn_tunnel_t vpn_tunnels[FW_MAX_VPN_TUNNELS];
    int vpn_tunnel_count;
    fw_vpn_peer_t vpn_peers[FW_MAX_VPN_PEERS];
    int vpn_peer_count;
} fw_config_t;

#endif /* FIREWALLO_TYPES_H */
