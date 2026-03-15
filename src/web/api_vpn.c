#include "firewallo/api_common.h"
#include "firewallo/vpn.h"
#include "firewallo/validate.h"
#include "firewallo/config.h"
#include "firewallo/json.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── Helpers ──────────────────────────────────────────────────────── */

static const char *vpn_proto_str(fw_vpn_proto_t p)
{
    switch (p) {
    case VPN_WIREGUARD: return "wireguard";
    case VPN_OPENVPN:   return "openvpn";
    case VPN_IPSEC:     return "ipsec";
    }
    return "unknown";
}

static fw_vpn_proto_t vpn_proto_from_str(const char *s)
{
    if (!s) return VPN_WIREGUARD;
    if (fw_strcasecmp(s, "openvpn") == 0)   return VPN_OPENVPN;
    if (fw_strcasecmp(s, "ipsec") == 0)     return VPN_IPSEC;
    return VPN_WIREGUARD;
}

static const char *vpn_mode_str(fw_vpn_mode_t m)
{
    switch (m) {
    case VPN_MODE_SERVER:   return "server";
    case VPN_MODE_CLIENT:   return "client";
    case VPN_MODE_SITE2SITE: return "site2site";
    }
    return "unknown";
}

static fw_vpn_mode_t vpn_mode_from_str(const char *s)
{
    if (!s) return VPN_MODE_SERVER;
    if (fw_strcasecmp(s, "client") == 0)    return VPN_MODE_CLIENT;
    if (fw_strcasecmp(s, "site2site") == 0) return VPN_MODE_SITE2SITE;
    return VPN_MODE_SERVER;
}

/* Copy a JSON string field into a fixed-size char buffer */
static void json_str_to_buf(const json_value_t *obj, const char *key,
                            char *dst, size_t dst_size)
{
    const char *v = json_string_value(json_object_get(obj, key));
    if (v) fw_strlcpy(dst, v, dst_size);
}

/* Build a JSON object from a tunnel struct */
static json_value_t *tunnel_to_json(const fw_vpn_tunnel_t *t, int active)
{
    json_value_t *obj = json_new_object();
    json_object_set(obj, "name",           json_new_string(t->name));
    json_object_set(obj, "protocol",       json_new_string(vpn_proto_str(t->protocol)));
    json_object_set(obj, "mode",           json_new_string(vpn_mode_str(t->mode)));
    json_object_set(obj, "listen_port",    json_new_string(t->listen_port));
    json_object_set(obj, "endpoint",       json_new_string(t->endpoint));
    json_object_set(obj, "local_network",  json_new_string(t->local_network));
    json_object_set(obj, "remote_network", json_new_string(t->remote_network));
    json_object_set(obj, "interface",      json_new_string(t->interface));
    json_object_set(obj, "comment",        json_new_string(t->comment));
    json_object_set(obj, "active",         json_new_bool(active));

    /* Protocol-specific fields */
    if (t->protocol == VPN_WIREGUARD) {
        json_object_set(obj, "wg_public_key",    json_new_string(t->wg_public_key));
        json_object_set(obj, "wg_preshared_key", json_new_string(t->wg_preshared_key));
    } else if (t->protocol == VPN_OPENVPN) {
        json_object_set(obj, "ovpn_ca_path",   json_new_string(t->ovpn_ca_path));
        json_object_set(obj, "ovpn_cert_path", json_new_string(t->ovpn_cert_path));
        json_object_set(obj, "ovpn_key_path",  json_new_string(t->ovpn_key_path));
        json_object_set(obj, "ovpn_dh_path",   json_new_string(t->ovpn_dh_path));
        json_object_set(obj, "ovpn_cipher",    json_new_string(t->ovpn_cipher));
    } else if (t->protocol == VPN_IPSEC) {
        json_object_set(obj, "ipsec_auth_method", json_new_string(t->ipsec_auth_method));
        json_object_set(obj, "ipsec_psk",         json_new_string(t->ipsec_psk));
        json_object_set(obj, "ipsec_local_id",    json_new_string(t->ipsec_local_id));
        json_object_set(obj, "ipsec_remote_id",   json_new_string(t->ipsec_remote_id));
    }

    return obj;
}

/* Parse common tunnel fields from a JSON body into a tunnel struct */
static void tunnel_from_json(const json_value_t *body, fw_vpn_tunnel_t *t)
{
    json_str_to_buf(body, "name",           t->name,           sizeof(t->name));
    json_str_to_buf(body, "listen_port",    t->listen_port,    sizeof(t->listen_port));
    json_str_to_buf(body, "endpoint",       t->endpoint,       sizeof(t->endpoint));
    json_str_to_buf(body, "local_network",  t->local_network,  sizeof(t->local_network));
    json_str_to_buf(body, "remote_network", t->remote_network, sizeof(t->remote_network));
    json_str_to_buf(body, "interface",      t->interface,      sizeof(t->interface));
    json_str_to_buf(body, "comment",        t->comment,        sizeof(t->comment));

    const char *proto = json_string_value(json_object_get(body, "protocol"));
    if (proto) t->protocol = vpn_proto_from_str(proto);

    const char *mode = json_string_value(json_object_get(body, "mode"));
    if (mode) t->mode = vpn_mode_from_str(mode);

    /* WireGuard fields */
    json_str_to_buf(body, "wg_private_key",   t->wg_private_key,   sizeof(t->wg_private_key));
    json_str_to_buf(body, "wg_public_key",    t->wg_public_key,    sizeof(t->wg_public_key));
    json_str_to_buf(body, "wg_preshared_key", t->wg_preshared_key, sizeof(t->wg_preshared_key));

    /* OpenVPN fields */
    json_str_to_buf(body, "ovpn_ca_path",   t->ovpn_ca_path,   sizeof(t->ovpn_ca_path));
    json_str_to_buf(body, "ovpn_cert_path", t->ovpn_cert_path, sizeof(t->ovpn_cert_path));
    json_str_to_buf(body, "ovpn_key_path",  t->ovpn_key_path,  sizeof(t->ovpn_key_path));
    json_str_to_buf(body, "ovpn_dh_path",   t->ovpn_dh_path,   sizeof(t->ovpn_dh_path));
    json_str_to_buf(body, "ovpn_cipher",    t->ovpn_cipher,    sizeof(t->ovpn_cipher));

    /* IPSec fields */
    json_str_to_buf(body, "ipsec_auth_method", t->ipsec_auth_method, sizeof(t->ipsec_auth_method));
    json_str_to_buf(body, "ipsec_psk",         t->ipsec_psk,         sizeof(t->ipsec_psk));
    json_str_to_buf(body, "ipsec_local_id",    t->ipsec_local_id,    sizeof(t->ipsec_local_id));
    json_str_to_buf(body, "ipsec_remote_id",   t->ipsec_remote_id,   sizeof(t->ipsec_remote_id));
}

/* Write the config file for a tunnel based on its protocol */
static int tunnel_write_config(const fw_vpn_tunnel_t *tunnel,
                               const fw_vpn_peer_t *peers, int peer_count)
{
    switch (tunnel->protocol) {
    case VPN_WIREGUARD: return fw_vpn_write_wg_config(tunnel, peers, peer_count);
    case VPN_OPENVPN:   return fw_vpn_write_ovpn_config(tunnel);
    case VPN_IPSEC:     return fw_vpn_write_ipsec_config(tunnel);
    }
    return -1;
}

/* Collect peers belonging to a specific tunnel */
static int collect_tunnel_peers(const fw_config_t *cfg, const char *tunnel_name,
                                const fw_vpn_peer_t **out, int max)
{
    int count = 0;
    for (int i = 0; i < cfg->vpn_peer_count && count < max; i++) {
        if (strcmp(cfg->vpn_peers[i].tunnel, tunnel_name) == 0)
            out[count++] = &cfg->vpn_peers[i];
    }
    return count;
}

/* Delete the generated config file for a tunnel */
static void tunnel_delete_config(const fw_vpn_tunnel_t *tunnel)
{
    char path[512];
    if (tunnel->protocol == VPN_WIREGUARD) {
        snprintf(path, sizeof(path), "/etc/wireguard/%s.conf", tunnel->name);
        unlink(path);
    }
    /* OpenVPN and IPSec config paths could vary; best-effort removal */
}

/* ── GET vpn/tunnels ──────────────────────────────────────────────── */

static void api_get_tunnels(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *arr = json_new_array();

    for (int i = 0; i < cfg->vpn_tunnel_count; i++) {
        int active = fw_vpn_is_active(&cfg->vpn_tunnels[i]);
        json_value_t *obj = tunnel_to_json(&cfg->vpn_tunnels[i], active > 0);
        json_array_append(arr, obj);
    }

    api_ok_json(resp, arr);
}

/* ── POST vpn/tunnels ─────────────────────────────────────────────── */

static void api_create_tunnel(httpd_t *srv, const http_request_t *req,
                              http_response_t *resp)
{
    fw_config_t *cfg = srv->config;

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    const char *name = json_string_value(json_object_get(body, "name"));
    if (!name || fw_str_empty(name)) {
        json_free(body);
        api_error(resp, 400, "Missing tunnel name");
        return;
    }

    if (!fw_vpn_validate_tunnel_name(name)) {
        json_free(body);
        api_error(resp, 400, "Invalid tunnel name (alphanumeric, hyphen, dot, underscore only)");
        return;
    }

    /* Validate interface name if provided */
    const char *iface = json_string_value(json_object_get(body, "interface"));
    if (iface && iface[0] && !fw_validate_interface(iface)) {
        json_free(body);
        api_error(resp, 400, "Invalid interface name");
        return;
    }

    if (cfg->vpn_tunnel_count >= FW_MAX_VPN_TUNNELS) {
        json_free(body);
        api_error(resp, 400, "Maximum tunnel count reached");
        return;
    }

    if (fw_vpn_find_tunnel(cfg, name) >= 0) {
        json_free(body);
        api_error(resp, 409, "Tunnel already exists");
        return;
    }

    fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[cfg->vpn_tunnel_count];
    memset(t, 0, sizeof(*t));
    tunnel_from_json(body, t);
    json_free(body);

    cfg->vpn_tunnel_count++;

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Tunnel created");
}

/* ── PUT vpn/tunnels/{name} ───────────────────────────────────────── */

static void api_update_tunnel(httpd_t *srv, const http_request_t *req,
                              http_response_t *resp, const char *name)
{
    fw_config_t *cfg = srv->config;

    if (!fw_vpn_validate_tunnel_name(name)) {
        api_error(resp, 400, "Invalid tunnel name");
        return;
    }

    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Tunnel not found"); return; }

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    /* Validate interface name if provided in update */
    const char *iface = json_string_value(json_object_get(body, "interface"));
    if (iface && iface[0] && !fw_validate_interface(iface)) {
        json_free(body);
        api_error(resp, 400, "Invalid interface name");
        return;
    }

    tunnel_from_json(body, &cfg->vpn_tunnels[idx]);
    json_free(body);

    /* Preserve original name so the lookup key does not change */
    fw_strlcpy(cfg->vpn_tunnels[idx].name, name,
               sizeof(cfg->vpn_tunnels[idx].name));

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Tunnel updated");
}

/* ── DELETE vpn/tunnels/{name} ────────────────────────────────────── */

static void api_delete_tunnel(httpd_t *srv, http_response_t *resp,
                              const char *name)
{
    fw_config_t *cfg = srv->config;

    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Tunnel not found"); return; }

    /* Stop if currently active */
    if (fw_vpn_is_active(&cfg->vpn_tunnels[idx]) > 0)
        fw_vpn_stop(&cfg->vpn_tunnels[idx]);

    /* Delete config file */
    tunnel_delete_config(&cfg->vpn_tunnels[idx]);

    /* Remove from array by shifting */
    for (int i = idx; i < cfg->vpn_tunnel_count - 1; i++)
        cfg->vpn_tunnels[i] = cfg->vpn_tunnels[i + 1];
    cfg->vpn_tunnel_count--;

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Tunnel deleted");
}

/* ── POST vpn/tunnels/{name}/start ────────────────────────────────── */

static void api_start_tunnel(httpd_t *srv, http_response_t *resp,
                             const char *name)
{
    fw_config_t *cfg = srv->config;

    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Tunnel not found"); return; }

    fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[idx];

    /* Collect peers for this tunnel (needed for WireGuard config) */
    const fw_vpn_peer_t *peers[FW_MAX_VPN_PEERS];
    int peer_count = collect_tunnel_peers(cfg, name, peers, FW_MAX_VPN_PEERS);

    /* Build a contiguous peer array for the write function */
    fw_vpn_peer_t peer_buf[FW_MAX_VPN_PEERS];
    for (int i = 0; i < peer_count; i++)
        peer_buf[i] = *peers[i];

    if (tunnel_write_config(t, peer_buf, peer_count) != 0) {
        api_error(resp, 500, "Failed to write VPN config file");
        return;
    }

    if (fw_vpn_start(t) != 0) {
        api_error(resp, 500, "Failed to start VPN service");
        return;
    }

    api_ok_msg(resp, "Tunnel started");
}

/* ── POST vpn/tunnels/{name}/stop ─────────────────────────────────── */

static void api_stop_tunnel(httpd_t *srv, http_response_t *resp,
                            const char *name)
{
    fw_config_t *cfg = srv->config;

    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Tunnel not found"); return; }

    if (fw_vpn_stop(&cfg->vpn_tunnels[idx]) != 0) {
        api_error(resp, 500, "Failed to stop VPN service");
        return;
    }

    api_ok_msg(resp, "Tunnel stopped");
}

/* ── GET vpn/tunnels/{name}/status ────────────────────────────────── */

static void api_tunnel_status(httpd_t *srv, http_response_t *resp,
                              const char *name)
{
    fw_config_t *cfg = srv->config;

    int idx = fw_vpn_find_tunnel(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Tunnel not found"); return; }

    fw_vpn_tunnel_t *t = &cfg->vpn_tunnels[idx];
    int active = fw_vpn_is_active(t);

    json_value_t *data = json_new_object();
    json_object_set(data, "name",     json_new_string(t->name));
    json_object_set(data, "protocol", json_new_string(vpn_proto_str(t->protocol)));
    json_object_set(data, "mode",     json_new_string(vpn_mode_str(t->mode)));
    json_object_set(data, "active",   json_new_bool(active > 0));

    api_ok_json(resp, data);
}

/* ── GET vpn/peers ────────────────────────────────────────────────── */

static void api_get_peers(httpd_t *srv, http_response_t *resp)
{
    fw_config_t *cfg = srv->config;
    json_value_t *arr = json_new_array();

    for (int i = 0; i < cfg->vpn_peer_count; i++) {
        fw_vpn_peer_t *p = &cfg->vpn_peers[i];
        json_value_t *obj = json_new_object();
        json_object_set(obj, "name",          json_new_string(p->name));
        json_object_set(obj, "tunnel",        json_new_string(p->tunnel));
        json_object_set(obj, "public_key",    json_new_string(p->public_key));
        json_object_set(obj, "preshared_key", json_new_string(p->preshared_key));
        json_object_set(obj, "allowed_ips",   json_new_string(p->allowed_ips));
        json_object_set(obj, "endpoint",      json_new_string(p->endpoint));
        json_object_set(obj, "keepalive",     json_new_number(p->keepalive));
        json_object_set(obj, "comment",       json_new_string(p->comment));
        json_array_append(arr, obj);
    }

    api_ok_json(resp, arr);
}

/* ── POST vpn/peers ───────────────────────────────────────────────── */

static void api_create_peer(httpd_t *srv, const http_request_t *req,
                            http_response_t *resp)
{
    fw_config_t *cfg = srv->config;

    if (!req->body) { api_error(resp, 400, "Empty body"); return; }

    char err[256];
    json_value_t *body = json_parse(req->body, err, sizeof(err));
    if (!body) { api_error(resp, 400, "Invalid JSON"); return; }

    const char *name = json_string_value(json_object_get(body, "name"));
    if (!name || fw_str_empty(name)) {
        json_free(body);
        api_error(resp, 400, "Missing peer name");
        return;
    }

    if (!fw_vpn_validate_tunnel_name(name)) {
        json_free(body);
        api_error(resp, 400, "Invalid peer name (alphanumeric, hyphen, dot, underscore only)");
        return;
    }

    /* Validate the tunnel reference if provided */
    const char *tunnel_ref = json_string_value(json_object_get(body, "tunnel"));
    if (tunnel_ref && tunnel_ref[0] && !fw_vpn_validate_tunnel_name(tunnel_ref)) {
        json_free(body);
        api_error(resp, 400, "Invalid tunnel reference name");
        return;
    }

    if (cfg->vpn_peer_count >= FW_MAX_VPN_PEERS) {
        json_free(body);
        api_error(resp, 400, "Maximum peer count reached");
        return;
    }

    if (fw_vpn_find_peer(cfg, name) >= 0) {
        json_free(body);
        api_error(resp, 409, "Peer already exists");
        return;
    }

    fw_vpn_peer_t *p = &cfg->vpn_peers[cfg->vpn_peer_count];
    memset(p, 0, sizeof(*p));

    json_str_to_buf(body, "name",          p->name,          sizeof(p->name));
    json_str_to_buf(body, "tunnel",        p->tunnel,        sizeof(p->tunnel));
    json_str_to_buf(body, "public_key",    p->public_key,    sizeof(p->public_key));
    json_str_to_buf(body, "preshared_key", p->preshared_key, sizeof(p->preshared_key));
    json_str_to_buf(body, "allowed_ips",   p->allowed_ips,   sizeof(p->allowed_ips));
    json_str_to_buf(body, "endpoint",      p->endpoint,      sizeof(p->endpoint));
    json_str_to_buf(body, "comment",       p->comment,       sizeof(p->comment));

    json_value_t *ka = json_object_get(body, "keepalive");
    if (ka && ka->type == JSON_NUMBER)
        p->keepalive = (int)json_number_value(ka);

    json_free(body);

    cfg->vpn_peer_count++;

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Peer created");
}

/* ── DELETE vpn/peers/{name} ──────────────────────────────────────── */

static void api_delete_peer(httpd_t *srv, http_response_t *resp,
                            const char *name)
{
    fw_config_t *cfg = srv->config;

    int idx = fw_vpn_find_peer(cfg, name);
    if (idx < 0) { api_error(resp, 404, "Peer not found"); return; }

    /* Remove from array by shifting */
    for (int i = idx; i < cfg->vpn_peer_count - 1; i++)
        cfg->vpn_peers[i] = cfg->vpn_peers[i + 1];
    cfg->vpn_peer_count--;

    if (api_save_config(srv, resp) != 0) return;
    api_ok_msg(resp, "Peer deleted");
}

/* ── GET vpn/peers/{name}/config ──────────────────────────────────── */

static void api_get_peer_config(httpd_t *srv, http_response_t *resp,
                                const char *name)
{
    fw_config_t *cfg = srv->config;

    int pidx = fw_vpn_find_peer(cfg, name);
    if (pidx < 0) { api_error(resp, 404, "Peer not found"); return; }

    fw_vpn_peer_t *peer = &cfg->vpn_peers[pidx];

    int tidx = fw_vpn_find_tunnel(cfg, peer->tunnel);
    if (tidx < 0) { api_error(resp, 404, "Parent tunnel not found"); return; }

    fw_vpn_tunnel_t *tunnel = &cfg->vpn_tunnels[tidx];

    if (tunnel->protocol != VPN_WIREGUARD) {
        api_error(resp, 400, "Client config is only supported for WireGuard tunnels");
        return;
    }

    char *config_text = fw_vpn_generate_wg_client_config(tunnel, peer);
    if (!config_text) {
        api_error(resp, 500, "Failed to generate client config");
        return;
    }

    json_value_t *data = json_new_object();
    json_object_set(data, "config", json_new_string(config_text));
    free(config_text);

    api_ok_json(resp, data);
}

/* ── POST vpn/generate-keys ───────────────────────────────────────── */

static void api_generate_keys(http_response_t *resp)
{
    char privkey[FW_MAX_VPN_KEY];
    char pubkey[FW_MAX_VPN_KEY];

    if (fw_vpn_generate_wg_keys(privkey, sizeof(privkey),
                                 pubkey, sizeof(pubkey)) != 0) {
        api_error(resp, 500, "Failed to generate WireGuard keys");
        return;
    }

    json_value_t *data = json_new_object();
    json_object_set(data, "private_key", json_new_string(privkey));
    json_object_set(data, "public_key",  json_new_string(pubkey));

    api_ok_json(resp, data);
}

/* ── VPN domain dispatcher ────────────────────────────────────────── */

int api_handle_vpn(httpd_t *srv, const http_request_t *req,
                   http_response_t *resp, const char *path, const char *method)
{
    const char *sub;

    /* POST vpn/generate-keys */
    if (strcmp(path, "vpn/generate-keys") == 0 && strcmp(method, "POST") == 0) {
        api_generate_keys(resp);
        return 1;
    }

    /* vpn/peers sub-routes */
    if ((sub = api_path_after(path, "vpn/peers/")) != NULL) {
        char peer_name[FW_MAX_IF_NAME];
        const char *slash = strchr(sub, '/');

        if (slash) {
            /* sub is "name/config" — extract name */
            size_t name_len = (size_t)(slash - sub);
            if (name_len >= sizeof(peer_name)) name_len = sizeof(peer_name) - 1;
            memcpy(peer_name, sub, name_len);
            peer_name[name_len] = '\0';
            const char *resource = slash + 1;

            if (strcmp(resource, "config") == 0 && strcmp(method, "GET") == 0) {
                api_get_peer_config(srv, resp, peer_name);
                return 1;
            }
            return 0;
        }

        /* DELETE vpn/peers/{name} */
        if (strcmp(method, "DELETE") == 0) {
            api_delete_peer(srv, resp, sub);
            return 1;
        }
        return 0;
    }

    /* GET/POST vpn/peers */
    if (strcmp(path, "vpn/peers") == 0) {
        if (strcmp(method, "GET") == 0) {
            api_get_peers(srv, resp);
            return 1;
        }
        if (strcmp(method, "POST") == 0) {
            api_create_peer(srv, req, resp);
            return 1;
        }
        return 0;
    }

    /* vpn/tunnels sub-routes */
    if ((sub = api_path_after(path, "vpn/tunnels/")) != NULL) {
        /* Check for action suffix: start, stop, status */
        const char *action = NULL;
        char tunnel_name[FW_MAX_IF_NAME];

        /* Try to find a '/' separator for actions like {name}/start */
        const char *slash = strchr(sub, '/');
        if (slash) {
            size_t name_len = (size_t)(slash - sub);
            if (name_len >= sizeof(tunnel_name)) name_len = sizeof(tunnel_name) - 1;
            memcpy(tunnel_name, sub, name_len);
            tunnel_name[name_len] = '\0';
            action = slash + 1;
        } else {
            fw_strlcpy(tunnel_name, sub, sizeof(tunnel_name));
        }

        if (action) {
            if (strcmp(action, "start") == 0 && strcmp(method, "POST") == 0) {
                api_start_tunnel(srv, resp, tunnel_name);
                return 1;
            }
            if (strcmp(action, "stop") == 0 && strcmp(method, "POST") == 0) {
                api_stop_tunnel(srv, resp, tunnel_name);
                return 1;
            }
            if (strcmp(action, "status") == 0 && strcmp(method, "GET") == 0) {
                api_tunnel_status(srv, resp, tunnel_name);
                return 1;
            }
            return 0;
        }

        /* PUT vpn/tunnels/{name} */
        if (strcmp(method, "PUT") == 0) {
            api_update_tunnel(srv, req, resp, tunnel_name);
            return 1;
        }
        /* DELETE vpn/tunnels/{name} */
        if (strcmp(method, "DELETE") == 0) {
            api_delete_tunnel(srv, resp, tunnel_name);
            return 1;
        }
        return 0;
    }

    /* GET/POST vpn/tunnels */
    if (strcmp(path, "vpn/tunnels") == 0) {
        if (strcmp(method, "GET") == 0) {
            api_get_tunnels(srv, resp);
            return 1;
        }
        if (strcmp(method, "POST") == 0) {
            api_create_tunnel(srv, req, resp);
            return 1;
        }
        return 0;
    }

    return 0; /* not handled */
}
