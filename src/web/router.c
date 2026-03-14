#include "firewallo/router.h"
#include "firewallo/api.h"
#include "firewallo/static_serve.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <string.h>

int router_dispatch(httpd_t *srv, const http_request_t *req, http_response_t *resp)
{
    /* API routes */
    if (strncmp(req->path, "/api/v1/", 8) == 0) {
        return api_handle(srv, req, resp);
    }

    /* Static files (GET only) */
    if (strcmp(req->method, "GET") != 0) {
        char *err = strdup("{\"error\":true,\"message\":\"Method not allowed\"}");
        http_response_set_json(resp, 405, err);
        return 0;
    }

    if (static_serve_file(srv->webroot, req->path, resp) != 0) {
        resp->status = 404;
        fw_strlcpy(resp->status_text, "Not Found", sizeof(resp->status_text));
        fw_strlcpy(resp->content_type, "text/html; charset=utf-8", sizeof(resp->content_type));
        const char *body = "<h1>404 Not Found</h1>";
        char *b = strdup(body);
        http_response_set_body(resp, b, strlen(b), 1);
    }

    return 0;
}
