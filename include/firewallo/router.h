#ifndef FIREWALLO_ROUTER_H
#define FIREWALLO_ROUTER_H

#include "firewallo/httpd.h"

/* Route a request. Populates resp. Returns 0. */
int router_dispatch(httpd_t *srv, const http_request_t *req, http_response_t *resp);

#endif /* FIREWALLO_ROUTER_H */
