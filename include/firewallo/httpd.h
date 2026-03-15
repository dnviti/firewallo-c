#ifndef FIREWALLO_HTTPD_H
#define FIREWALLO_HTTPD_H

#include "firewallo/types.h"
#include "firewallo/auth.h"
#include <stddef.h>

#define HTTP_MAX_HEADERS 2048
#define HTTP_MAX_PATH    512
#define HTTP_MAX_QUERY   256
#define HTTP_MAX_BODY    65536

/* Parsed HTTP request */
typedef struct {
    char method[8];
    char path[HTTP_MAX_PATH];
    char query[HTTP_MAX_QUERY];
    char content_type[128];
    char authorization[AUTH_TOKEN_MAX + 16]; /* "Bearer <token>" */
    size_t content_length;
    char *body;
    size_t body_len;
} http_request_t;

/* HTTP response to build */
typedef struct {
    int status;
    char status_text[64];
    char content_type[128];
    char *body;
    size_t body_len;
    int body_owned; /* 1 if body was malloc'd and should be freed */
} http_response_t;

/* Server context */
typedef struct {
    int listen_fd;
    int port;
    const char *bind_addr;
    const char *webroot;
    const char *config_path;
    fw_config_t *config;
    char api_token[AUTH_TOKEN_MAX]; /* loaded API token (empty = auth disabled) */
    volatile int running;
} httpd_t;

/* Initialize server. Returns 0 on success. */
int httpd_init(httpd_t *srv, const char *bind_addr, int port,
               const char *webroot, const char *config_path,
               fw_config_t *config);

/* Run the server main loop (blocks). */
int httpd_run(httpd_t *srv);

/* Signal the server to stop. */
void httpd_stop(httpd_t *srv);

/* Response helpers */
void http_response_init(http_response_t *resp);
void http_response_free(http_response_t *resp);
void http_response_set_body(http_response_t *resp, char *body, size_t len, int owned);
void http_response_set_json(http_response_t *resp, int status, char *json);

#endif /* FIREWALLO_HTTPD_H */
