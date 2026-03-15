#include "firewallo/httpd.h"
#include "firewallo/router.h"
#include "firewallo/log.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

/* ── Fork-per-connection constants ───────────────────────────────── */

#define HTTPD_MAX_CHILDREN      16   /* Max concurrent child processes */
#define HTTPD_READ_TIMEOUT_MS   2000 /* Per-read poll timeout (ms)     */
#define HTTPD_CONN_TIMEOUT_SEC  10   /* Max total connection time (s)  */

static volatile sig_atomic_t g_active_children = 0;
static volatile sig_atomic_t g_sigchld_fired = 0;

static void sigchld_handler(int sig)
{
    (void)sig;
    g_sigchld_fired = 1;
}

/* Reap finished children and update counter (call with SIGCHLD blocked) */
static void reap_children(void)
{
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (g_active_children > 0)
            g_active_children--;
    }
    g_sigchld_fired = 0;
}

/* ── Response helpers ──────────────────────────────────────────────── */

void http_response_init(http_response_t *resp)
{
    memset(resp, 0, sizeof(*resp));
    resp->status = 200;
    fw_strlcpy(resp->status_text, "OK", sizeof(resp->status_text));
    fw_strlcpy(resp->content_type, "text/plain", sizeof(resp->content_type));
}

void http_response_free(http_response_t *resp)
{
    if (resp->body_owned && resp->body)
        free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}

void http_response_set_body(http_response_t *resp, char *body, size_t len, int owned)
{
    if (resp->body_owned && resp->body)
        free(resp->body);
    resp->body = body;
    resp->body_len = len;
    resp->body_owned = owned;
}

void http_response_set_json(http_response_t *resp, int status, char *json)
{
    resp->status = status;
    switch (status) {
    case 200: fw_strlcpy(resp->status_text, "OK", sizeof(resp->status_text)); break;
    case 201: fw_strlcpy(resp->status_text, "Created", sizeof(resp->status_text)); break;
    case 204: fw_strlcpy(resp->status_text, "No Content", sizeof(resp->status_text)); break;
    case 400: fw_strlcpy(resp->status_text, "Bad Request", sizeof(resp->status_text)); break;
    case 401: fw_strlcpy(resp->status_text, "Unauthorized", sizeof(resp->status_text)); break;
    case 403: fw_strlcpy(resp->status_text, "Forbidden", sizeof(resp->status_text)); break;
    case 404: fw_strlcpy(resp->status_text, "Not Found", sizeof(resp->status_text)); break;
    case 405: fw_strlcpy(resp->status_text, "Method Not Allowed", sizeof(resp->status_text)); break;
    case 500: fw_strlcpy(resp->status_text, "Internal Server Error", sizeof(resp->status_text)); break;
    default:  fw_strlcpy(resp->status_text, "OK", sizeof(resp->status_text)); break;
    }
    fw_strlcpy(resp->content_type, "application/json; charset=utf-8", sizeof(resp->content_type));
    http_response_set_body(resp, json, strlen(json), 1);
}

/* ── Request parsing ───────────────────────────────────────────────── */

static int parse_request(const char *raw, size_t raw_len, http_request_t *req)
{
    memset(req, 0, sizeof(*req));

    /* Find end of request line */
    const char *line_end = strstr(raw, "\r\n");
    if (!line_end)
        return -1;

    /* Parse method */
    const char *p = raw;
    const char *space = strchr(p, ' ');
    if (!space || space > line_end)
        return -1;

    size_t mlen = (size_t)(space - p);
    if (mlen >= sizeof(req->method))
        return -1;
    memcpy(req->method, p, mlen);
    req->method[mlen] = '\0';

    /* Parse path */
    p = space + 1;
    space = strchr(p, ' ');
    if (!space || space > line_end)
        return -1;

    size_t pathlen = (size_t)(space - p);
    if (pathlen >= sizeof(req->path))
        pathlen = sizeof(req->path) - 1;

    /* Split path and query string */
    const char *qmark = memchr(p, '?', pathlen);
    if (qmark) {
        size_t plen = (size_t)(qmark - p);
        memcpy(req->path, p, plen);
        req->path[plen] = '\0';

        size_t qlen = pathlen - plen - 1;
        if (qlen >= sizeof(req->query))
            qlen = sizeof(req->query) - 1;
        memcpy(req->query, qmark + 1, qlen);
        req->query[qlen] = '\0';
    } else {
        memcpy(req->path, p, pathlen);
        req->path[pathlen] = '\0';
    }

    /* Parse headers */
    const char *headers_start = line_end + 2;
    const char *header_end = strstr(headers_start, "\r\n\r\n");
    if (!header_end)
        return -1;

    /* Extract Content-Length and Content-Type */
    const char *h = headers_start;
    while (h < header_end) {
        const char *nl = strstr(h, "\r\n");
        if (!nl) break;

        if (strncasecmp(h, "Content-Length:", 15) == 0) {
            req->content_length = (size_t)atol(h + 15);
        } else if (strncasecmp(h, "Content-Type:", 13) == 0) {
            const char *val = h + 13;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->content_type))
                vlen = sizeof(req->content_type) - 1;
            memcpy(req->content_type, val, vlen);
            req->content_type[vlen] = '\0';
        } else if (strncasecmp(h, "Authorization:", 14) == 0) {
            const char *val = h + 14;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->authorization))
                vlen = sizeof(req->authorization) - 1;
            memcpy(req->authorization, val, vlen);
            req->authorization[vlen] = '\0';
        } else if (strncasecmp(h, "Host:", 5) == 0) {
            const char *val = h + 5;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->host))
                vlen = sizeof(req->host) - 1;
            memcpy(req->host, val, vlen);
            req->host[vlen] = '\0';
        } else if (strncasecmp(h, "Origin:", 7) == 0) {
            const char *val = h + 7;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->origin))
                vlen = sizeof(req->origin) - 1;
            memcpy(req->origin, val, vlen);
            req->origin[vlen] = '\0';
        } else if (strncasecmp(h, "Referer:", 8) == 0 && req->origin[0] == '\0') {
            /* Use Referer as fallback if Origin was not set */
            const char *val = h + 8;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->origin))
                vlen = sizeof(req->origin) - 1;
            memcpy(req->origin, val, vlen);
            req->origin[vlen] = '\0';
        } else if (strncasecmp(h, "X-Requested-With:", 17) == 0) {
            const char *val = h + 17;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(nl - val);
            if (vlen >= sizeof(req->x_requested_with))
                vlen = sizeof(req->x_requested_with) - 1;
            memcpy(req->x_requested_with, val, vlen);
            req->x_requested_with[vlen] = '\0';
        }
        h = nl + 2;
    }

    /* Body — enforce size limit */
    if (req->content_length > HTTP_MAX_BODY)
        return -1;

    const char *body_start = header_end + 4;
    size_t body_available = raw_len - (size_t)(body_start - raw);
    if (req->content_length > 0 && body_available > 0) {
        size_t blen = body_available < req->content_length ? body_available : req->content_length;
        req->body = malloc(blen + 1);
        if (req->body) {
            memcpy(req->body, body_start, blen);
            req->body[blen] = '\0';
            req->body_len = blen;
        }
    }

    return 0;
}

/* ── Send response ─────────────────────────────────────────────────── */

static void send_response(int fd, const http_response_t *resp, int auth_enabled)
{
    char header[2048];
    /* When auth is enabled, do not expose a wildcard CORS origin with
       Authorization in allowed headers — the API is same-origin and the
       wildcard would let any website make authenticated cross-origin calls. */
    const char *cors_headers = auth_enabled
        ? ""
        : "Access-Control-Allow-Origin: *\r\n"
          "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
          "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";

    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'\r\n"
        "%s"
        "\r\n",
        resp->status, resp->status_text,
        resp->content_type,
        resp->body_len,
        cors_headers);

    /* Send header */
    ssize_t sent = 0;
    while (sent < hlen) {
        ssize_t n = write(fd, header + sent, (size_t)(hlen - sent));
        if (n <= 0) return;
        sent += n;
    }

    /* Send body */
    if (resp->body && resp->body_len > 0) {
        sent = 0;
        while ((size_t)sent < resp->body_len) {
            ssize_t n = write(fd, resp->body + sent, resp->body_len - (size_t)sent);
            if (n <= 0) return;
            sent += n;
        }
    }
}

/* ── Handle connection ─────────────────────────────────────────────── */

static void handle_connection(httpd_t *srv, int client_fd)
{
    char buf[HTTP_MAX_BODY + HTTP_MAX_HEADERS];
    ssize_t total = 0;

    /* Read request with poll timeout */
    struct pollfd pfd = {.fd = client_fd, .events = POLLIN};
    while ((size_t)total < sizeof(buf) - 1) {
        int ready = poll(&pfd, 1, HTTPD_READ_TIMEOUT_MS);
        if (ready <= 0) break;

        ssize_t n = read(client_fd, buf + total, sizeof(buf) - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        /* Check if we have the full request */
        char *header_end = strstr(buf, "\r\n\r\n");
        if (header_end) {
            /* Check if we need to read more body */
            const char *cl = strcasestr(buf, "Content-Length:");
            if (cl) {
                size_t content_len = (size_t)atol(cl + 15);
                size_t body_start = (size_t)(header_end + 4 - buf);
                size_t body_have = (size_t)total - body_start;
                if (body_have >= content_len)
                    break;
            } else {
                break;
            }
        }
    }

    if (total <= 0) {
        close(client_fd);
        return;
    }

    /* Parse request */
    http_request_t req;
    http_response_t resp;
    http_response_init(&resp);

    if (parse_request(buf, (size_t)total, &req) != 0) {
        resp.status = 400;
        fw_strlcpy(resp.status_text, "Bad Request", sizeof(resp.status_text));
        char *err = strdup("{\"error\":true,\"message\":\"Bad request\"}");
        if (!err) {
            http_response_set_json(&resp, 400,
                (char *)"{\"error\":true,\"message\":\"Bad request\"}");
            resp.body_owned = 0;
        } else {
            http_response_set_json(&resp, 400, err);
        }
    } else if (strcmp(req.method, "OPTIONS") == 0) {
        /* CORS preflight */
        resp.status = 204;
        fw_strlcpy(resp.status_text, "No Content", sizeof(resp.status_text));
    } else {
        /* Route the request */
        router_dispatch(srv, &req, &resp);
    }

    fw_log(LOG_DEBUG, "%s %s -> %d", req.method, req.path, resp.status);

    send_response(client_fd, &resp, srv->api_token[0] != '\0');

    /* Cleanup */
    http_response_free(&resp);
    free(req.body);
    close(client_fd);
}

/*
 * ── TLS / Transport Security Notice ────────────────────────────────
 *
 * This HTTP server does NOT support TLS.  All traffic is transmitted in
 * cleartext.  In production deployments the server MUST be placed behind
 * a TLS-terminating reverse proxy such as nginx, Caddy, or HAProxy.
 *
 * Example (nginx):
 *   server {
 *       listen 443 ssl;
 *       ssl_certificate     /etc/ssl/certs/firewallo.pem;
 *       ssl_certificate_key /etc/ssl/private/firewallo.key;
 *       location / { proxy_pass http://127.0.0.1:8080; }
 *   }
 *
 * Bind the server to 127.0.0.1 (-b 127.0.0.1) so it is only reachable
 * through the reverse proxy and not directly from the network.
 *
 * Adding native TLS would require an external library (OpenSSL, mbedTLS)
 * which conflicts with the project's "no external dependencies" policy.
 * ─────────────────────────────────────────────────────────────────── */

/* ── Server init ───────────────────────────────────────────────────── */

int httpd_init(httpd_t *srv, const char *bind_addr, int port,
               const char *webroot, const char *config_path,
               fw_config_t *config)
{
    memset(srv, 0, sizeof(*srv));
    srv->port = port;
    srv->bind_addr = bind_addr;
    srv->webroot = webroot;
    srv->config_path = config_path;
    srv->config = config;
    srv->running = 1;

    /* Canonicalize webroot once at init to avoid per-request realpath() */
    if (!realpath(webroot, srv->real_webroot)) {
        perror("realpath(webroot)");
        return -1;
    }

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->listen_fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (bind_addr && strcmp(bind_addr, "0.0.0.0") != 0)
        inet_pton(AF_INET, bind_addr, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv->listen_fd);
        return -1;
    }

    if (listen(srv->listen_fd, 16) < 0) {
        perror("listen");
        close(srv->listen_fd);
        return -1;
    }

    return 0;
}

/* ── Server main loop (fork-per-connection) ───────────────────────── */

int httpd_run(httpd_t *srv)
{
    fw_log(LOG_INFO, "firewallo-web listening on %s:%d",
           srv->bind_addr ? srv->bind_addr : "0.0.0.0", srv->port);

    /* SEC-011: Single consolidated TLS / bind-address startup warning */
    const char *addr = srv->bind_addr ? srv->bind_addr : "0.0.0.0";
    int exposed = (strcmp(addr, "0.0.0.0") == 0);
    fw_log(LOG_WARN,
           "Listening on %s:%d over plain HTTP (no TLS).%s "
           "Place behind a TLS reverse proxy (nginx/Caddy/HAProxy) for production.",
           addr, srv->port,
           exposed ? " Server is reachable from all interfaces in cleartext." : "");

    /* Install SIGCHLD handler to set reap flag */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction");
        return -1;
    }

    /* Prepare signal mask for critical sections */
    sigset_t block_chld, prev_mask;
    sigemptyset(&block_chld);
    sigaddset(&block_chld, SIGCHLD);

    struct pollfd pfd = {.fd = srv->listen_fd, .events = POLLIN};

    while (srv->running) {
        int ready = poll(&pfd, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                /* Reap outside critical section is fine here —
                   we'll reap again inside the critical section below */
                continue;
            }
            perror("poll");
            break;
        }

        /* Block SIGCHLD for reaping + capacity check + fork + increment */
        sigprocmask(SIG_BLOCK, &block_chld, &prev_mask);

        /* Reap any finished children */
        if (g_sigchld_fired)
            reap_children();

        if (ready == 0) {
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(srv->listen_fd,
                               (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        /* Reject new connections when at capacity */
        if (g_active_children >= HTTPD_MAX_CHILDREN) {
            fw_log(LOG_WARN, "Max children (%d) reached, rejecting connection",
                   HTTPD_MAX_CHILDREN);
            close(client_fd);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            continue;
        }

        if (pid == 0) {
            /* ── Child process ────────────────────────────────── */
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            close(srv->listen_fd);

            /* Hard limit on total connection time */
            alarm(HTTPD_CONN_TIMEOUT_SEC);

            handle_connection(srv, client_fd);
            _exit(0);
        }

        /* ── Parent process ───────────────────────────────────── */
        g_active_children++;
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        close(client_fd);
    }

    close(srv->listen_fd);

    /* Wait for remaining children before exit */
    for (;;) {
        pid_t w = waitpid(-1, NULL, 0);
        if (w > 0)
            continue;
        if (w < 0 && errno == EINTR)
            continue;
        /* ECHILD or other error — no more children */
        break;
    }

    return 0;
}

void httpd_stop(httpd_t *srv)
{
    srv->running = 0;
}
