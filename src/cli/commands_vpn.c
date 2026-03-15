#include "commands.h"
#include "firewallo/vpn.h"
#include <stdio.h>
#include <string.h>

/* ── VPN helpers ──────────────────────────────────────────────────── */

static const char *vpn_proto_str(fw_vpn_proto_t p)
{
    switch (p) {
    case VPN_OPENVPN: return "OpenVPN";
    case VPN_IPSEC:   return "IPSec";
    default:          return "WireGuard";
    }
}

static const char *vpn_mode_str(fw_vpn_mode_t m)
{
    switch (m) {
    case VPN_MODE_CLIENT:    return "Client";
    case VPN_MODE_SITE2SITE: return "Site2Site";
    default:                 return "Server";
    }
}

/* ── VPN list ─────────────────────────────────────────────────────── */

int cmd_vpn_list(const fw_config_t *cfg)
{
    printf("VPN Tunnels (%d configured):\n\n", cfg->vpn_tunnel_count);
    if (cfg->vpn_tunnel_count == 0) {
        printf("  No VPN tunnels configured.\n");
        return 0;
    }

    printf("  %-16s %-12s %-10s %-8s %-20s %s\n",
           "NAME", "PROTOCOL", "MODE", "STATUS", "ENDPOINT", "NETWORK");
    printf("  %-16s %-12s %-10s %-8s %-20s %s\n",
           "----", "--------", "----", "------", "--------", "-------");

    for (int i = 0; i < cfg->vpn_tunnel_count; i++) {
        const fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[i];
        int active = fw_vpn_is_active(t);
        printf("  %-16s %-12s %-10s %-8s %-20s %s\n",
               t->name, vpn_proto_str(t->protocol), vpn_mode_str(t->mode),
               active == 1 ? "UP" : "DOWN",
               t->endpoint[0] ? t->endpoint : "-",
               t->local_network[0] ? t->local_network : "-");
    }
    return 0;
}

/* ── VPN status ───────────────────────────────────────────────────── */

int cmd_vpn_status(const fw_config_t *cfg, const char *name)
{
    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) {
        fprintf(stderr, "Tunnel not found: %s\n", name);
        return 1;
    }
    const fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[idx];
    int active = fw_vpn_is_active(t);

    printf("Tunnel: %s\n", t->name);
    printf("Protocol: %s\n", vpn_proto_str(t->protocol));
    printf("Mode: %s\n", vpn_mode_str(t->mode));
    printf("Status: %s\n", active == 1 ? "UP" : "DOWN");
    printf("Interface: %s\n", t->interface[0] ? t->interface : t->name);
    printf("Listen Port: %s\n", t->listen_port[0] ? t->listen_port : "-");
    printf("Endpoint: %s\n", t->endpoint[0] ? t->endpoint : "-");
    printf("Local Network: %s\n", t->local_network[0] ? t->local_network : "-");
    printf("Remote Network: %s\n", t->remote_network[0] ? t->remote_network : "-");

    int peer_count = 0;
    for (int i = 0; i < cfg->vpn_peer_count; i++) {
        if (strcmp(cfg->vpn_peers[i].tunnel, t->name) == 0)
            peer_count++;
    }
    printf("Peers: %d\n", peer_count);

    return 0;
}

/* ── VPN start ────────────────────────────────────────────────────── */

int cmd_vpn_start(fw_config_t *cfg, const char *name)
{
    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) {
        fprintf(stderr, "Tunnel not found: %s\n", name);
        return 1;
    }
    fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[idx];

    int ret = -1;
    if (t->protocol == VPN_WIREGUARD)
        ret = fw_vpn_write_wg_config(t, cfg->vpn_peers, cfg->vpn_peer_count);
    else if (t->protocol == VPN_OPENVPN)
        ret = fw_vpn_write_ovpn_config(t);
    else if (t->protocol == VPN_IPSEC)
        ret = fw_vpn_write_ipsec_config(t);

    if (ret != 0) {
        fprintf(stderr, "Failed to write VPN config for %s\n", name);
        return 1;
    }

    ret = fw_vpn_start(t);
    if (ret != 0) {
        fprintf(stderr, "Failed to start VPN tunnel %s\n", name);
        return 1;
    }
    printf("VPN tunnel %s started\n", name);
    return 0;
}

/* ── VPN stop ─────────────────────────────────────────────────────── */

int cmd_vpn_stop(fw_config_t *cfg, const char *name)
{
    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) {
        fprintf(stderr, "Tunnel not found: %s\n", name);
        return 1;
    }
    int ret = fw_vpn_stop(&cfg->vpn_tunnels[idx]);
    if (ret != 0) {
        fprintf(stderr, "Failed to stop VPN tunnel %s\n", name);
        return 1;
    }
    printf("VPN tunnel %s stopped\n", name);
    return 0;
}

/* ── VPN peers ────────────────────────────────────────────────────── */

int cmd_vpn_peers(const fw_config_t *cfg, const char *tunnel_name)
{
    printf("Peers for tunnel '%s':\n\n", tunnel_name);
    int found = 0;
    printf("  %-16s %-44s %-20s %s\n", "NAME", "PUBLIC KEY", "ALLOWED IPS", "ENDPOINT");
    printf("  %-16s %-44s %-20s %s\n", "----", "----------", "-----------", "--------");
    for (int i = 0; i < cfg->vpn_peer_count; i++) {
        const fw_vpn_peer_t *p = &cfg->vpn_peers[i];
        if (strcmp(p->tunnel, tunnel_name) != 0) continue;
        found++;
        char pk_short[FW_MAX_VPN_KEY + 4];
        if (strlen(p->public_key) > 40)
            snprintf(pk_short, sizeof(pk_short), "%.40s...", p->public_key);
        else
            snprintf(pk_short, sizeof(pk_short), "%s", p->public_key);
        printf("  %-16s %-44s %-20s %s\n",
               p->name, pk_short,
               p->allowed_ips[0] ? p->allowed_ips : "-",
               p->endpoint[0] ? p->endpoint : "-");
    }
    if (!found) printf("  No peers configured for this tunnel.\n");
    return 0;
}
