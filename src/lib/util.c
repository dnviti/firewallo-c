#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

size_t fw_strlcpy(char *dst, const char *src, size_t size)
{
    size_t srclen = strlen(src);
    if (size > 0) {
        size_t copylen = srclen < size - 1 ? srclen : size - 1;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}

char *fw_read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }

    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }

    rewind(f);

    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(buf, 1, (size_t)len, f);
    fclose(f);

    buf[read] = '\0';
    if (out_len)
        *out_len = read;

    return buf;
}

int fw_write_file(const char *path, const char *data, size_t len)
{
    /* Write to a temporary file, then rename for atomicity */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (!f)
        return -1;

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len) {
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }

    return 0;
}

int fw_strcasecmp(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb)
            return ca - cb;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int fw_str_empty(const char *s)
{
    return s == NULL || s[0] == '\0';
}
