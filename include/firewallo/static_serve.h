#ifndef FIREWALLO_STATIC_SERVE_H
#define FIREWALLO_STATIC_SERVE_H

#include "firewallo/httpd.h"

/* Serve a static file from webroot. real_webroot must be the canonicalized
 * (realpath'd) webroot, resolved once at server init.
 * Returns 0 on success, -1 if not found. */
int static_serve_file(const char *real_webroot, const char *webroot,
                      const char *path, http_response_t *resp);

#endif /* FIREWALLO_STATIC_SERVE_H */
