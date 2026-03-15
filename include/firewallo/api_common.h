#ifndef FIREWALLO_API_COMMON_H
#define FIREWALLO_API_COMMON_H

#include "firewallo/httpd.h"
#include "firewallo/json.h"

/* Shared API response helpers used by all api_*.c modules */

void api_error(http_response_t *resp, int status, const char *msg);
void api_ok_json(http_response_t *resp, json_value_t *data);
void api_ok_msg(http_response_t *resp, const char *msg);

/* Save config to disk; sends error response on failure. Returns 0 on success. */
int api_save_config(httpd_t *srv, http_response_t *resp);

/* Extract path segment after prefix. Returns pointer into path string or NULL. */
const char *api_path_after(const char *path, const char *prefix);

/* Read a sysctl integer value from /proc/sys/. Returns -1 on failure. */
int api_read_sysctl(const char *path);

/* ── Per-domain handler functions (called from api_handle dispatcher) ── */

/* Config domain: version, config GET/PUT, interfaces, dns, backend, validate */
int api_handle_config(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method);

/* Filter domain: filter overview, chain detail, port add/delete */
int api_handle_filter(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method);

/* Firewall domain: firewall actions/status/rules, NAT */
int api_handle_firewall(httpd_t *srv, const http_request_t *req,
                        http_response_t *resp, const char *path, const char *method);

/* System domain: system interfaces, live OS data */
int api_handle_system(httpd_t *srv, const http_request_t *req,
                      http_response_t *resp, const char *path, const char *method);

/* VPN domain: tunnel and peer management */
int api_handle_vpn(httpd_t *srv, const http_request_t *req,
                   http_response_t *resp, const char *path, const char *method);

#endif /* FIREWALLO_API_COMMON_H */
