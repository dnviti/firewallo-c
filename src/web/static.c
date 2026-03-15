#include "firewallo/static_serve.h"
#include "firewallo/mime.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int static_serve_file(const char *webroot, const char *path, http_response_t *resp)
{
    /* Default to index.html */
    const char *file_path = path;
    if (strcmp(path, "/") == 0)
        file_path = "/index.html";

    /* Build candidate path */
    char candidate[PATH_MAX];
    snprintf(candidate, sizeof(candidate), "%s%s", webroot, file_path);

    /* Resolve webroot to an absolute canonical path */
    char real_webroot[PATH_MAX];
    if (!realpath(webroot, real_webroot))
        return -1;
    size_t webroot_len = strlen(real_webroot);

    /* Resolve requested file to an absolute canonical path */
    char fullpath[PATH_MAX];
    if (!realpath(candidate, fullpath))
        return -1;

    /* Prevent directory traversal: resolved path must be within webroot */
    if (strncmp(fullpath, real_webroot, webroot_len) != 0 ||
        (fullpath[webroot_len] != '/' && fullpath[webroot_len] != '\0'))
        return -1;

    /* Read file */
    size_t len;
    char *content = fw_read_file(fullpath, &len);
    if (!content)
        return -1;

    resp->status = 200;
    fw_strlcpy(resp->status_text, "OK", sizeof(resp->status_text));
    fw_strlcpy(resp->content_type, mime_type_for(fullpath), sizeof(resp->content_type));
    http_response_set_body(resp, content, len, 1);

    return 0;
}
