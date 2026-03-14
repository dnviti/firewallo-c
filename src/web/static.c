#include "firewallo/static_serve.h"
#include "firewallo/mime.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int static_serve_file(const char *webroot, const char *path, http_response_t *resp)
{
    /* Prevent directory traversal */
    if (strstr(path, ".."))
        return -1;

    /* Default to index.html */
    const char *file_path = path;
    if (strcmp(path, "/") == 0)
        file_path = "/index.html";

    /* Build full path */
    char fullpath[1024];
    snprintf(fullpath, sizeof(fullpath), "%s%s", webroot, file_path);

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
