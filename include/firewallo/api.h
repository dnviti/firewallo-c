#ifndef FIREWALLO_API_H
#define FIREWALLO_API_H

#include "firewallo/httpd.h"

/* Handle an API request under /api/v1/. Returns 0. */
int api_handle(httpd_t *srv, const http_request_t *req, http_response_t *resp);

/* Handle monitor API requests under /api/v1/monitor/. Returns 0. */
int api_handle_monitor(httpd_t *srv, const http_request_t *req,
                       http_response_t *resp, const char *sub);

#endif /* FIREWALLO_API_H */
