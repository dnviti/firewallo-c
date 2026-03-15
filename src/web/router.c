#include "firewallo/router.h"
#include "firewallo/api.h"
#include "firewallo/auth.h"
#include "firewallo/static_serve.h"
#include "firewallo/log.h"
#include "firewallo/util.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <string.h>

/*
 * Extract the host portion from a URL or Host header value.
 * For "http://example.com:8080/path", extracts "example.com:8080".
 * For "example.com:8080", returns as-is.
 * Result is written to dst (up to dst_size bytes).
 */
static void extract_host(const char *src, char *dst, size_t dst_size)
{
    if (dst_size == 0) return;
    dst[0] = '\0';

    if (!src || src[0] == '\0') return;

    /* Skip scheme (http:// or https://) if present */
    const char *host = src;
    const char *scheme_end = strstr(src, "://");
    if (scheme_end)
        host = scheme_end + 3;

    /* Copy up to the first '/' (path start) or end of string */
    size_t i = 0;
    while (host[i] != '\0' && host[i] != '/' && i < dst_size - 1) {
        dst[i] = host[i];
        i++;
    }
    dst[i] = '\0';
}

/*
 * CSRF same-origin check for state-changing methods.
 * Returns 0 if the request is allowed, -1 if it should be rejected.
 *
 * Logic:
 * - Only applies to POST, PUT, DELETE methods
 * - If no Origin header (and no Referer), allow (non-browser client)
 * - If Origin/Referer is present, its host must match the Host header
 */
static int csrf_check(const http_request_t *req)
{
    /* Only check state-changing methods */
    if (strcmp(req->method, "POST") != 0 &&
        strcmp(req->method, "PUT") != 0 &&
        strcmp(req->method, "DELETE") != 0)
        return 0;

    /* No Origin/Referer => non-browser client, allow */
    if (req->origin[0] == '\0')
        return 0;

    /* No Host header => can't verify, reject */
    if (req->host[0] == '\0') {
        fw_log(LOG_WARN, "CSRF: rejecting %s %s — no Host header to verify against",
               req->method, req->path);
        return -1;
    }

    /* Extract host portion from Origin (strips scheme and path) */
    char origin_host[256];
    extract_host(req->origin, origin_host, sizeof(origin_host));

    /* Compare origin host with Host header */
    if (strcasecmp(origin_host, req->host) != 0) {
        fw_log(LOG_WARN, "CSRF: rejecting %s %s — origin '%s' does not match host '%s'",
               req->method, req->path, origin_host, req->host);
        return -1;
    }

    return 0;
}

int router_dispatch(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    /* API routes — require authentication */
    if (strncmp(req->path, "/api/v1/", 8) == 0) {
        if (!auth_check_bearer(req->authorization, srv->api_token)) {
            fw_log(LOG_WARN, "auth: rejected unauthenticated request to %s", req->path);
            char *err = strdup("{\"error\":true,\"message\":\"Unauthorized: valid Bearer token required\"}");
            if (!err) {
                http_response_set_json(resp, 401,
                    (char *)"{\"error\":true,\"message\":\"Unauthorized\"}");
                resp->body_owned = 0;
            } else {
                http_response_set_json(resp, 401, err);
            }
            return 0;
        }
        /* CSRF protection: reject cross-origin state-changing requests */
        if (csrf_check(req) != 0) {
            char *err = strdup("{\"error\":true,\"message\":\"Cross-origin request rejected\"}");
            if (!err) {
                http_response_set_json(resp, 403,
                    (char *)"{\"error\":true,\"message\":\"Cross-origin request rejected\"}");
                resp->body_owned = 0;
            } else {
                http_response_set_json(resp, 403, err);
            }
            return 0;
        }
        return api_handle(srv, req, resp);
    }

    /* Static files (GET only) */
    if (strcmp(req->method, "GET") != 0) {
        char *err = strdup("{\"error\":true,\"message\":\"Method not allowed\"}");
        if (!err) {
            http_response_set_json(resp, 405,
                (char *)"{\"error\":true,\"message\":\"Method not allowed\"}");
            resp->body_owned = 0;
        } else {
            http_response_set_json(resp, 405, err);
        }
        return 0;
    }

    if (static_serve_file(srv->real_webroot, srv->webroot, req->path, resp) != 0) {
        resp->status = 404;
        fw_strlcpy(resp->status_text, "Not Found", sizeof(resp->status_text));
        fw_strlcpy(resp->content_type, "text/html; charset=utf-8", sizeof(resp->content_type));
        const char *body = "<h1>404 Not Found</h1>";
        char *b = strdup(body);
        if (!b) {
            http_response_set_body(resp, (char *)body, strlen(body), 0);
        } else {
            http_response_set_body(resp, b, strlen(b), 1);
        }
    }

    return 0;
}
