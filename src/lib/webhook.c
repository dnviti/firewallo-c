#include "firewallo/webhook.h"
#include "firewallo/log.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

/* ── Event name mapping ───────────────────────────────────────────── */

const char *fw_webhook_event_name(fw_webhook_event_t event)
{
    switch (event) {
    case WH_EVENT_CONFIG_CHANGE: return "config_change";
    case WH_EVENT_RULE_APPLY:    return "rule_apply";
    case WH_EVENT_INTRUSION:     return "intrusion";
    case WH_EVENT_VPN_STATUS:    return "vpn_status";
    case WH_EVENT_SURICATA:      return "suricata";
    case WH_EVENT_SERVICE:       return "service";
    default:                     return "unknown";
    }
}

/* ── URL validation ───────────────────────────────────────────────── */

int fw_webhook_validate_url(const char *url)
{
    if (!url || !*url)
        return 0;

    /* Must start with http:// or https:// */
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)
        return 0;

    /* Must have a host after the scheme */
    const char *after_scheme = url;
    if (strncmp(url, "https://", 8) == 0)
        after_scheme = url + 8;
    else
        after_scheme = url + 7;

    /* Must have at least one char for hostname */
    if (!*after_scheme)
        return 0;

    /* Check that hostname portion is reasonable */
    const char *host_end = strchr(after_scheme, '/');
    if (!host_end)
        host_end = after_scheme + strlen(after_scheme);

    /* Check for port in host */
    const char *colon = strchr(after_scheme, ':');
    const char *hostname_end = (colon && colon < host_end) ? colon : host_end;

    size_t hlen = (size_t)(hostname_end - after_scheme);
    if (hlen == 0 || hlen > 253)
        return 0;

    /* Overall length check */
    if (strlen(url) >= FW_MAX_WEBHOOK_URL)
        return 0;

    return 1;
}

/* ── Event mask validation ────────────────────────────────────────── */

int fw_webhook_validate_events(unsigned int events)
{
    return events >= 1 && events <= (unsigned int)WH_EVENT_ALL;
}

/* ── URL parsing helper ───────────────────────────────────────────── */

typedef struct {
    int use_tls;
    char host[256];
    char port[8];
    char path[512];
} parsed_url_t;

static int parse_url(const char *url, parsed_url_t *out)
{
    memset(out, 0, sizeof(*out));

    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) {
        out->use_tls = 1;
        p += 8;
        fw_strlcpy(out->port, "443", sizeof(out->port));
    } else if (strncmp(p, "http://", 7) == 0) {
        out->use_tls = 0;
        p += 7;
        fw_strlcpy(out->port, "80", sizeof(out->port));
    } else {
        return -1;
    }

    /* Find end of host (first / or end of string) */
    const char *slash = strchr(p, '/');
    const char *host_end = slash ? slash : p + strlen(p);

    /* Check for port */
    const char *colon = strchr(p, ':');
    if (colon && colon < host_end) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= sizeof(out->host)) return -1;
        memcpy(out->host, p, hlen);
        out->host[hlen] = '\0';

        const char *port_start = colon + 1;
        size_t plen = (size_t)(host_end - port_start);
        if (plen >= sizeof(out->port)) return -1;
        memcpy(out->port, port_start, plen);
        out->port[plen] = '\0';
    } else {
        size_t hlen = (size_t)(host_end - p);
        if (hlen >= sizeof(out->host)) return -1;
        memcpy(out->host, p, hlen);
        out->host[hlen] = '\0';
    }

    /* Path */
    if (slash)
        fw_strlcpy(out->path, slash, sizeof(out->path));
    else
        fw_strlcpy(out->path, "/", sizeof(out->path));

    return 0;
}

/* ── HTTP POST via plain socket (no TLS) ──────────────────────────── */

static int http_post(const parsed_url_t *url, const char *body,
                     size_t body_len, const char *secret)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(url->host, url->port, &hints, &res);
    if (gai != 0) {
        fw_log(LOG_WARN, "webhook: getaddrinfo(%s): %s", url->host, gai_strerror(gai));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Set a connect timeout via alarm */
    struct sigaction sa_old;
    struct sigaction sa_new;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &sa_new, &sa_old);
    alarm(10);

    int ret = connect(fd, res->ai_addr, res->ai_addrlen);
    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);
    freeaddrinfo(res);

    if (ret != 0) {
        close(fd);
        return -1;
    }

    /* Build HTTP request */
    char header[2048];
    int hlen = snprintf(header, sizeof(header),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: firewallo-webhook/1.0\r\n"
        "Connection: close\r\n"
        "%s%s%s"
        "\r\n",
        url->path,
        url->host,
        body_len,
        secret[0] ? "X-Webhook-Secret: " : "",
        secret[0] ? secret : "",
        secret[0] ? "\r\n" : "");

    if (hlen < 0 || (size_t)hlen >= sizeof(header)) {
        close(fd);
        return -1;
    }

    /* Send header */
    ssize_t w = write(fd, header, (size_t)hlen);
    if (w < 0) { close(fd); return -1; }

    /* Send body */
    w = write(fd, body, body_len);
    if (w < 0) { close(fd); return -1; }

    /* Read response status line */
    char resp_buf[512];
    ssize_t r = read(fd, resp_buf, sizeof(resp_buf) - 1);
    close(fd);

    if (r <= 0)
        return -1;

    resp_buf[r] = '\0';

    /* Parse HTTP status code */
    /* "HTTP/1.1 200 OK\r\n..." */
    const char *sp = strchr(resp_buf, ' ');
    if (!sp) return -1;

    int status = atoi(sp + 1);
    return status;
}

/* ── Send with retry ──────────────────────────────────────────────── */

static int send_with_retry(const fw_webhook_t *wh, const char *body, size_t body_len)
{
    parsed_url_t url;
    if (parse_url(wh->url, &url) != 0) {
        fw_log(LOG_WARN, "webhook: invalid URL: %s", wh->url);
        return -1;
    }

    if (url.use_tls) {
        /* TLS not supported in pure POSIX - log warning and attempt plain */
        fw_log(LOG_WARN, "webhook: TLS not supported, attempting plain HTTP to %s:%s",
               url.host, url.port);
    }

    int max_retries = wh->retry_count > 0 ? wh->retry_count : 1;
    if (max_retries > 5) max_retries = 5;

    for (int attempt = 0; attempt < max_retries; attempt++) {
        if (attempt > 0) {
            /* Exponential backoff: 1s, 2s, 4s, 8s */
            unsigned int delay = 1u << (unsigned int)(attempt - 1);
            sleep(delay);
        }

        int status = http_post(&url, body, body_len, wh->secret);
        if (status >= 200 && status < 300) {
            fw_log(LOG_INFO, "webhook: delivered to %s (status %d)", wh->url, status);
            return status;
        }

        fw_log(LOG_WARN, "webhook: attempt %d/%d to %s failed (status %d)",
               attempt + 1, max_retries, wh->url, status);
    }

    fw_log(LOG_ERROR, "webhook: all retries exhausted for %s", wh->url);
    return -1;
}

/* ── Public: send to matching webhooks ────────────────────────────── */

int fw_webhook_send(const fw_config_t *cfg, fw_webhook_event_t event,
                    const char *payload)
{
    if (!cfg || !payload)
        return -1;

    /* Count matching webhooks */
    int match_count = 0;
    for (int i = 0; i < cfg->webhook_count; i++) {
        const fw_webhook_t *wh = &cfg->webhooks[i];
        if (wh->enabled && (wh->events & (unsigned int)event))
            match_count++;
    }

    if (match_count == 0)
        return 0; /* No matching webhooks, nothing to do */

    /* Build JSON envelope */
    char envelope[8192];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    int elen = snprintf(envelope, sizeof(envelope),
        "{\"event\":\"%s\",\"timestamp\":\"%s\",\"source\":\"firewallo\",\"data\":%s}",
        fw_webhook_event_name(event), ts, payload);

    if (elen < 0 || (size_t)elen >= sizeof(envelope))
        return -1;

    /* Fork a child to deliver webhooks non-blocking */
    pid_t pid = fork();
    if (pid < 0) {
        fw_log(LOG_ERROR, "webhook: fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid > 0) {
        /* Parent: don't wait, let child run in background.
         * Reap with SIGCHLD handler or waitpid WNOHANG elsewhere. */
        return 0;
    }

    /* Child process: deliver to all matching webhooks */
    for (int i = 0; i < cfg->webhook_count; i++) {
        const fw_webhook_t *wh = &cfg->webhooks[i];
        if (!wh->enabled || !(wh->events & (unsigned int)event))
            continue;

        send_with_retry(wh, envelope, (size_t)elen);
    }

    _exit(0);
    return 0; /* unreachable, for compiler */
}

/* ── Public: test single webhook ──────────────────────────────────── */

int fw_webhook_test(const fw_webhook_t *wh)
{
    if (!wh || !wh->url[0])
        return -1;

    const char *test_payload =
        "{\"event\":\"test\",\"timestamp\":\"2025-01-01T00:00:00Z\","
        "\"source\":\"firewallo\",\"data\":{\"message\":\"Webhook test notification\"}}";

    return send_with_retry(wh, test_payload, strlen(test_payload));
}
