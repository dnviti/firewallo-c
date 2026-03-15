/*
 * vpn.c — VPN tunnel management (WireGuard, OpenVPN, IPSec/StrongSwan)
 *
 * Part of firewallo — pure C17 + POSIX, no external libraries.
 */

#include "firewallo/vpn.h"
#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Helpers ─────────────────────────────────────────────────────────── */

/* Strip trailing newline/whitespace from a string in place. */
static void strip_trailing(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                       s[len - 1] == ' '  || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

/* ── Key generation ──────────────────────────────────────────────────── */

int fw_vpn_generate_wg_keys(char *privkey, size_t privlen,
                             char *pubkey, size_t publen)
{
    if (!privkey || !pubkey || privlen == 0 || publen == 0)
        return -1;

    /* Generate private key */
    int ret = fw_exec_capture("wg genkey 2>/dev/null", privkey, privlen);
    if (ret != 0) {
        fw_log(LOG_WARN, "vpn: wg genkey failed (is wireguard-tools installed?)");
        return -1;
    }
    strip_trailing(privkey);

    if (strlen(privkey) == 0) {
        fw_log(LOG_WARN, "vpn: wg genkey returned empty output");
        return -1;
    }

    /* Derive public key from private key */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo '%s' | wg pubkey 2>/dev/null", privkey);

    ret = fw_exec_capture(cmd, pubkey, publen);
    if (ret != 0) {
        fw_log(LOG_WARN, "vpn: wg pubkey failed");
        return -1;
    }
    strip_trailing(pubkey);

    fw_log(LOG_INFO, "vpn: generated WireGuard keypair");
    return 0;
}

/* ── WireGuard config ────────────────────────────────────────────────── */

int fw_vpn_write_wg_config(const fw_vpn_tunnel_t *tunnel,
                            const fw_vpn_peer_t *peers, int peer_count)
{
    if (!tunnel) return -1;

    char path[512];
    snprintf(path, sizeof(path), "/etc/wireguard/%s.conf", tunnel->name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fw_log(LOG_WARN, "vpn: cannot open %s for writing", path);
        return -1;
    }

    /* [Interface] section */
    fprintf(f, "[Interface]\n");
    fprintf(f, "PrivateKey = %s\n", tunnel->wg_private_key);
    if (tunnel->local_network[0])
        fprintf(f, "Address = %s\n", tunnel->local_network);
    if (tunnel->listen_port[0])
        fprintf(f, "ListenPort = %s\n", tunnel->listen_port);
    fprintf(f, "\n");

    /* [Peer] sections — only peers belonging to this tunnel */
    for (int i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].tunnel, tunnel->name) != 0)
            continue;

        fprintf(f, "[Peer]\n");
        fprintf(f, "PublicKey = %s\n", peers[i].public_key);
        if (peers[i].allowed_ips[0])
            fprintf(f, "AllowedIPs = %s\n", peers[i].allowed_ips);
        if (peers[i].preshared_key[0])
            fprintf(f, "PresharedKey = %s\n", peers[i].preshared_key);
        if (peers[i].endpoint[0])
            fprintf(f, "Endpoint = %s\n", peers[i].endpoint);
        if (peers[i].keepalive > 0)
            fprintf(f, "PersistentKeepalive = %d\n", peers[i].keepalive);
        fprintf(f, "\n");
    }

    fclose(f);
    chmod(path, 0600);

    fw_log(LOG_INFO, "vpn: wrote WireGuard config %s", path);
    return 0;
}

/* ── OpenVPN config ──────────────────────────────────────────────────── */

int fw_vpn_write_ovpn_config(const fw_vpn_tunnel_t *tunnel)
{
    if (!tunnel) return -1;

    char path[512];
    if (tunnel->mode == VPN_MODE_CLIENT) {
        snprintf(path, sizeof(path), "/etc/openvpn/client/%s.conf",
                 tunnel->name);
    } else {
        snprintf(path, sizeof(path), "/etc/openvpn/server/%s.conf",
                 tunnel->name);
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        fw_log(LOG_WARN, "vpn: cannot open %s for writing", path);
        return -1;
    }

    if (tunnel->mode == VPN_MODE_CLIENT) {
        /* Client configuration */
        fprintf(f, "client\n");
        fprintf(f, "dev tun\n");
        fprintf(f, "proto udp\n");
        if (tunnel->endpoint[0])
            fprintf(f, "remote %s\n", tunnel->endpoint);
        fprintf(f, "resolv-retry infinite\n");
        fprintf(f, "nobind\n");
        fprintf(f, "persist-key\n");
        fprintf(f, "persist-tun\n");
    } else {
        /* Server configuration */
        fprintf(f, "mode server\n");
        fprintf(f, "tls-server\n");
        fprintf(f, "dev tun\n");
        fprintf(f, "proto udp\n");
        if (tunnel->listen_port[0])
            fprintf(f, "port %s\n", tunnel->listen_port);
        if (tunnel->local_network[0])
            fprintf(f, "server %s\n", tunnel->local_network);
        fprintf(f, "persist-key\n");
        fprintf(f, "persist-tun\n");
        fprintf(f, "keepalive 10 120\n");
    }

    /* Certificates and keys */
    if (tunnel->ovpn_ca_path[0])
        fprintf(f, "ca %s\n", tunnel->ovpn_ca_path);
    if (tunnel->ovpn_cert_path[0])
        fprintf(f, "cert %s\n", tunnel->ovpn_cert_path);
    if (tunnel->ovpn_key_path[0])
        fprintf(f, "key %s\n", tunnel->ovpn_key_path);
    if (tunnel->ovpn_dh_path[0] && tunnel->mode != VPN_MODE_CLIENT)
        fprintf(f, "dh %s\n", tunnel->ovpn_dh_path);

    /* Cipher */
    if (tunnel->ovpn_cipher[0])
        fprintf(f, "cipher %s\n", tunnel->ovpn_cipher);

    fprintf(f, "verb 3\n");

    fclose(f);
    chmod(path, 0600);

    fw_log(LOG_INFO, "vpn: wrote OpenVPN config %s", path);
    return 0;
}

/* ── IPSec / StrongSwan config ───────────────────────────────────────── */

int fw_vpn_write_ipsec_config(const fw_vpn_tunnel_t *tunnel)
{
    if (!tunnel) return -1;

    char path[512];
    snprintf(path, sizeof(path), "/etc/ipsec.d/%s.conf", tunnel->name);

    FILE *f = fopen(path, "w");
    if (!f) {
        fw_log(LOG_WARN, "vpn: cannot open %s for writing", path);
        return -1;
    }

    /* swanctl style configuration */
    fprintf(f, "connections {\n");
    fprintf(f, "    %s {\n", tunnel->name);

    /* Local side */
    fprintf(f, "        local {\n");
    if (strcmp(tunnel->ipsec_auth_method, "psk") == 0) {
        fprintf(f, "            auth = psk\n");
    } else {
        fprintf(f, "            auth = pubkey\n");
    }
    if (tunnel->ipsec_local_id[0])
        fprintf(f, "            id = %s\n", tunnel->ipsec_local_id);
    fprintf(f, "        }\n");

    /* Remote side */
    fprintf(f, "        remote {\n");
    if (strcmp(tunnel->ipsec_auth_method, "psk") == 0) {
        fprintf(f, "            auth = psk\n");
    } else {
        fprintf(f, "            auth = pubkey\n");
    }
    if (tunnel->ipsec_remote_id[0])
        fprintf(f, "            id = %s\n", tunnel->ipsec_remote_id);
    fprintf(f, "        }\n");

    /* Children (traffic selectors) */
    fprintf(f, "        children {\n");
    fprintf(f, "            %s {\n", tunnel->name);
    if (tunnel->local_network[0])
        fprintf(f, "                local_ts = %s\n", tunnel->local_network);
    if (tunnel->remote_network[0])
        fprintf(f, "                remote_ts = %s\n", tunnel->remote_network);
    fprintf(f, "                start_action = trap\n");
    fprintf(f, "            }\n");
    fprintf(f, "        }\n");

    fprintf(f, "        version = 2\n");
    if (tunnel->endpoint[0])
        fprintf(f, "        remote_addrs = %s\n", tunnel->endpoint);
    fprintf(f, "    }\n");
    fprintf(f, "}\n");

    /* Secrets section for PSK */
    if (strcmp(tunnel->ipsec_auth_method, "psk") == 0 &&
        tunnel->ipsec_psk[0]) {
        fprintf(f, "\nsecrets {\n");
        fprintf(f, "    ike-%s {\n", tunnel->name);
        if (tunnel->ipsec_remote_id[0])
            fprintf(f, "        id = %s\n", tunnel->ipsec_remote_id);
        fprintf(f, "        secret = \"%s\"\n", tunnel->ipsec_psk);
        fprintf(f, "    }\n");
        fprintf(f, "}\n");
    }

    fclose(f);
    chmod(path, 0600);

    fw_log(LOG_INFO, "vpn: wrote IPSec config %s", path);
    return 0;
}

/* ── Service control ─────────────────────────────────────────────────── */

int fw_vpn_start(const fw_vpn_tunnel_t *tunnel)
{
    if (!tunnel) return -1;

    char cmd[256];

    switch (tunnel->protocol) {
    case VPN_WIREGUARD:
        snprintf(cmd, sizeof(cmd),
                 "systemctl start wg-quick@%s", tunnel->name);
        break;
    case VPN_OPENVPN:
        if (tunnel->mode == VPN_MODE_CLIENT) {
            snprintf(cmd, sizeof(cmd),
                     "systemctl start openvpn-client@%s", tunnel->name);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "systemctl start openvpn-server@%s", tunnel->name);
        }
        break;
    case VPN_IPSEC:
        snprintf(cmd, sizeof(cmd), "systemctl start strongswan");
        break;
    default:
        fw_log(LOG_WARN, "vpn: unknown protocol for tunnel '%s'",
               tunnel->name);
        return -1;
    }

    fw_log(LOG_INFO, "vpn: starting tunnel '%s'", tunnel->name);
    return fw_exec(cmd);
}

int fw_vpn_stop(const fw_vpn_tunnel_t *tunnel)
{
    if (!tunnel) return -1;

    char cmd[256];

    switch (tunnel->protocol) {
    case VPN_WIREGUARD:
        snprintf(cmd, sizeof(cmd),
                 "systemctl stop wg-quick@%s", tunnel->name);
        break;
    case VPN_OPENVPN:
        if (tunnel->mode == VPN_MODE_CLIENT) {
            snprintf(cmd, sizeof(cmd),
                     "systemctl stop openvpn-client@%s", tunnel->name);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "systemctl stop openvpn-server@%s", tunnel->name);
        }
        break;
    case VPN_IPSEC:
        snprintf(cmd, sizeof(cmd), "systemctl stop strongswan");
        break;
    default:
        fw_log(LOG_WARN, "vpn: unknown protocol for tunnel '%s'",
               tunnel->name);
        return -1;
    }

    fw_log(LOG_INFO, "vpn: stopping tunnel '%s'", tunnel->name);
    return fw_exec(cmd);
}

/* ── Status check ────────────────────────────────────────────────────── */

int fw_vpn_is_active(const fw_vpn_tunnel_t *tunnel)
{
    if (!tunnel) return -1;

    /* Check if the network interface exists */
    char sysfs_path[256];
    snprintf(sysfs_path, sizeof(sysfs_path),
             "/sys/class/net/%s", tunnel->interface);

    if (access(sysfs_path, F_OK) != 0)
        return 0;   /* interface does not exist — tunnel is down */

    /* Check systemd service status */
    char cmd[256];

    switch (tunnel->protocol) {
    case VPN_WIREGUARD:
        snprintf(cmd, sizeof(cmd),
                 "systemctl is-active --quiet wg-quick@%s", tunnel->name);
        break;
    case VPN_OPENVPN:
        if (tunnel->mode == VPN_MODE_CLIENT) {
            snprintf(cmd, sizeof(cmd),
                     "systemctl is-active --quiet openvpn-client@%s",
                     tunnel->name);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "systemctl is-active --quiet openvpn-server@%s",
                     tunnel->name);
        }
        break;
    case VPN_IPSEC:
        snprintf(cmd, sizeof(cmd),
                 "systemctl is-active --quiet strongswan");
        break;
    default:
        return -1;
    }

    int ret = fw_exec(cmd);
    return (ret == 0) ? 1 : 0;
}

/* ── WireGuard client config generation ──────────────────────────────── */

char *fw_vpn_generate_wg_client_config(const fw_vpn_tunnel_t *tunnel,
                                        const fw_vpn_peer_t *peer)
{
    if (!tunnel || !peer) return NULL;

    /* Allocate a generous buffer for the config string */
    size_t bufsize = 2048;
    char *buf = malloc(bufsize);
    if (!buf) return NULL;

    int n = snprintf(buf, bufsize,
        "[Interface]\n"
        "PrivateKey = <client-private-key>\n"
        "Address = %s\n"
        "DNS = 1.1.1.1\n"
        "\n"
        "[Peer]\n"
        "PublicKey = %s\n",
        peer->allowed_ips,
        tunnel->wg_public_key);

    if (n < 0 || (size_t)n >= bufsize) {
        free(buf);
        return NULL;
    }

    if (tunnel->wg_preshared_key[0]) {
        int w = snprintf(buf + n, bufsize - (size_t)n,
            "PresharedKey = %s\n", tunnel->wg_preshared_key);
        if (w < 0 || (size_t)w >= bufsize - (size_t)n) {
            free(buf);
            return NULL;
        }
        n += w;
    }

    /* Endpoint is the server address + listen port */
    if (tunnel->endpoint[0]) {
        int w = snprintf(buf + n, bufsize - (size_t)n,
            "Endpoint = %s\n", tunnel->endpoint);
        if (w < 0 || (size_t)w >= bufsize - (size_t)n) {
            free(buf);
            return NULL;
        }
        n += w;
    } else if (tunnel->listen_port[0]) {
        int w = snprintf(buf + n, bufsize - (size_t)n,
            "Endpoint = <server-ip>:%s\n", tunnel->listen_port);
        if (w < 0 || (size_t)w >= bufsize - (size_t)n) {
            free(buf);
            return NULL;
        }
        n += w;
    }

    {
        int w = snprintf(buf + n, bufsize - (size_t)n,
            "AllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = 25\n");
        if (w < 0 || (size_t)w >= bufsize - (size_t)n) {
            free(buf);
            return NULL;
        }
    }

    fw_log(LOG_INFO, "vpn: generated WireGuard client config for peer '%s'",
           peer->name);
    return buf;
}

/* ── Lookup helpers ──────────────────────────────────────────────────── */

int fw_vpn_find_tunnel(const fw_config_t *cfg, const char *name)
{
    if (!cfg || !name) return -1;

    for (int i = 0; i < cfg->vpn_tunnel_count; i++) {
        if (strcmp(cfg->vpn_tunnels[i].name, name) == 0)
            return i;
    }
    return -1;
}

int fw_vpn_find_peer(const fw_config_t *cfg, const char *name)
{
    if (!cfg || !name) return -1;

    for (int i = 0; i < cfg->vpn_peer_count; i++) {
        if (strcmp(cfg->vpn_peers[i].name, name) == 0)
            return i;
    }
    return -1;
}
