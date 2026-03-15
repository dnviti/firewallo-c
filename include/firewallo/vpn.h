#ifndef FIREWALLO_VPN_H
#define FIREWALLO_VPN_H

#include "firewallo/types.h"

/* ── Validation ──────────────────────────────────────────────────── */

/* Validate a tunnel name for safe use in shell commands and file paths.
 * Returns 1 if valid (alphanumeric + -._), 0 if invalid. */
int fw_vpn_validate_tunnel_name(const char *name);

/* ── VPN config generation ────────────────────────────────────────── */

/* Generate a WireGuard keypair. Writes base64 keys into buffers. Returns 0 on success. */
int fw_vpn_generate_wg_keys(char *privkey, size_t privlen,
                             char *pubkey, size_t publen);

/* Write WireGuard config to /etc/wireguard/{name}.conf. Returns 0 on success. */
int fw_vpn_write_wg_config(const fw_vpn_tunnel_t *tunnel,
                            const fw_vpn_peer_t *peers, int peer_count);

/* Write OpenVPN server/client config. Returns 0 on success. */
int fw_vpn_write_ovpn_config(const fw_vpn_tunnel_t *tunnel);

/* Write StrongSwan IPSec config. Returns 0 on success. */
int fw_vpn_write_ipsec_config(const fw_vpn_tunnel_t *tunnel);

/* ── Service control ──────────────────────────────────────────────── */

/* Start a VPN tunnel's system service. Returns 0 on success. */
int fw_vpn_start(const fw_vpn_tunnel_t *tunnel);

/* Stop a VPN tunnel's system service. Returns 0 on success. */
int fw_vpn_stop(const fw_vpn_tunnel_t *tunnel);

/* Check if a VPN tunnel is currently active. Returns 1 if up, 0 if down, -1 on error. */
int fw_vpn_is_active(const fw_vpn_tunnel_t *tunnel);

/* ── WireGuard peer management ────────────────────────────────────── */

/* Generate a client config string for a WireGuard peer. Caller must free() the returned string. */
char *fw_vpn_generate_wg_client_config(const fw_vpn_tunnel_t *tunnel,
                                        const fw_vpn_peer_t *peer);

/* ── Tunnel lookup helpers ────────────────────────────────────────── */

/* Find tunnel index by name in config. Returns -1 if not found. */
int fw_vpn_find_tunnel(const fw_config_t *cfg, const char *name);

/* Find peer index by name in config. Returns -1 if not found. */
int fw_vpn_find_peer(const fw_config_t *cfg, const char *name);

#endif /* FIREWALLO_VPN_H */
