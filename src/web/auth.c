#include "firewallo/auth.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

/* Strip leading and trailing whitespace in-place */
static void strip_whitespace(char *s)
{
    /* leading */
    char *start = s;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    /* trailing */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';
}

int auth_load_token(const char *token_path, char *token_buf, size_t buf_size)
{
    if (!token_path || !token_buf || buf_size == 0)
        return -1;

    token_buf[0] = '\0';

    /* Check file permissions — warn if too open */
    struct stat st;
    if (stat(token_path, &st) != 0) {
        fw_log(LOG_ERROR, "auth: cannot stat token file: %s", token_path);
        return -1;
    }
    if ((st.st_mode & 0077) != 0) {
        fw_log(LOG_WARN, "auth: token file %s has insecure permissions "
               "(mode %04o, expected 0600)", token_path, st.st_mode & 0777);
    }

    FILE *fp = fopen(token_path, "r");
    if (!fp) {
        fw_log(LOG_ERROR, "auth: cannot open token file: %s", token_path);
        return -1;
    }

    if (!fgets(token_buf, (int)buf_size, fp)) {
        fclose(fp);
        fw_log(LOG_ERROR, "auth: token file is empty: %s", token_path);
        return -1;
    }
    fclose(fp);

    strip_whitespace(token_buf);

    if (strlen(token_buf) == 0) {
        fw_log(LOG_ERROR, "auth: token file contains only whitespace: %s", token_path);
        return -1;
    }

    fw_log(LOG_INFO, "auth: API token loaded from %s", token_path);
    return 0;
}

int auth_check_bearer(const char *auth_header, const char *stored_token)
{
    /* If no token is configured, auth is disabled — allow all */
    if (!stored_token || stored_token[0] == '\0')
        return 1;

    if (!auth_header || auth_header[0] == '\0')
        return 0;

    /* Expect "Bearer <token>" */
    const char *prefix = "Bearer ";
    size_t prefix_len = 7;

    if (strncmp(auth_header, prefix, prefix_len) != 0)
        return 0;

    const char *provided = auth_header + prefix_len;

    /* Constant-time comparison to prevent timing attacks */
    size_t stored_len = strlen(stored_token);
    size_t provided_len = strlen(provided);

    /* Compare all bytes regardless of mismatch to avoid timing leak */
    unsigned char result = (stored_len != provided_len) ? 1 : 0;
    size_t cmp_len = stored_len < provided_len ? stored_len : provided_len;
    for (size_t i = 0; i < cmp_len; i++)
        result |= (unsigned char)((unsigned char)stored_token[i] ^ (unsigned char)provided[i]);

    return result == 0 ? 1 : 0;
}

int auth_generate_token(const char *token_path)
{
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    const int token_len = 48;
    char token[49];

    /* Try /dev/urandom first for cryptographic randomness */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fw_log(LOG_ERROR, "auth: cannot open /dev/urandom");
        return -1;
    }

    unsigned char randbuf[48];
    ssize_t n = read(fd, randbuf, sizeof(randbuf));
    close(fd);

    if (n != (ssize_t)sizeof(randbuf)) {
        fw_log(LOG_ERROR, "auth: failed to read random bytes");
        return -1;
    }

    for (int i = 0; i < token_len; i++)
        token[i] = charset[randbuf[i] % (sizeof(charset) - 1)];
    token[token_len] = '\0';

    /* Write token to file with restrictive permissions */
    fd = open(token_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fw_log(LOG_ERROR, "auth: cannot create token file: %s", token_path);
        return -1;
    }

    size_t len = (size_t)token_len;
    char buf[50];
    memcpy(buf, token, len);
    buf[len] = '\n';

    ssize_t written = write(fd, buf, len + 1);
    close(fd);

    if (written != (ssize_t)(len + 1)) {
        fw_log(LOG_ERROR, "auth: failed to write token file");
        return -1;
    }

    fw_log(LOG_INFO, "auth: generated new API token at %s", token_path);
    printf("API token generated: %s\n", token);
    printf("Token file: %s\n", token_path);
    return 0;
}
