#include "firewallo/static_serve.h"
#include "firewallo/mime.h"
#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int static_serve_file(const char *real_webroot, const char *webroot,
                      const char *path, http_response_t *resp)
{
    /* Default to index.html */
    const char *file_path = path;
    if (strcmp(path, "/") == 0)
        file_path = "/index.html";

    /* Build candidate path; reject if the result would be truncated */
    char candidate[PATH_MAX];
    int ret = snprintf(candidate, sizeof(candidate), "%s%s", webroot, file_path);
    if (ret < 0 || (size_t)ret >= sizeof(candidate))
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

    /*
     * TOCTOU note: there is an inherent race between the realpath() check
     * above and the open() below — a symlink could theoretically be swapped
     * in between the two calls.  We mitigate this by opening with O_NOFOLLOW
     * immediately after the check, which rejects last-component symlinks and
     * reduces the attack window.  Full elimination would require openat()
     * traversal with O_NOFOLLOW on every path component or mounting the
     * webroot read-only, which is outside the scope of this server.
     */
    int fd = open(fullpath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;

    /* Use fdopen so we read from the already-opened descriptor */
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        return -1;
    }

    size_t len = (size_t)st.st_size;
    char *content = malloc(len + 1);
    if (!content) {
        fclose(f);
        return -1;
    }

    size_t nread = fread(content, 1, len, f);
    fclose(f); /* closes underlying fd too */
    content[nread] = '\0';

    resp->status = 200;
    fw_strlcpy(resp->status_text, "OK", sizeof(resp->status_text));
    fw_strlcpy(resp->content_type, mime_type_for(fullpath), sizeof(resp->content_type));
    http_response_set_body(resp, content, nread, 1);

    return 0;
}
