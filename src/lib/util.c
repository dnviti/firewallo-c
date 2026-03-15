#include "firewallo/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

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
    /*
     * Write to a mkstemp-created temp file in the same directory, then
     * rename for atomicity.  This avoids predictable temp-file names
     * (e.g. "%s.tmp") that are vulnerable to symlink attacks in
     * world-writable directories such as /tmp.
     */

    /* Build template in the same directory as the target path */
    char tmp[512];
    const char *last_slash = strrchr(path, '/');
    if (last_slash) {
        size_t dir_len = (size_t)(last_slash - path + 1);
        if (dir_len + sizeof(".fw_XXXXXX") > sizeof(tmp))
            return -1;
        memcpy(tmp, path, dir_len);
        memcpy(tmp + dir_len, ".fw_XXXXXX", sizeof(".fw_XXXXXX"));
    } else {
        /* No directory component — use current directory */
        memcpy(tmp, ".fw_XXXXXX", sizeof(".fw_XXXXXX"));
    }

    int fd = mkstemp(tmp);  /* creates with mode 0600, O_EXCL semantics */
    if (fd < 0)
        return -1;

    /* Preserve target file permissions when possible */
    struct stat st;
    if (stat(path, &st) == 0)
        fchmod(fd, st.st_mode & 0777);

    const char *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);
        if (written < 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        p += written;
        remaining -= (size_t)written;
    }
    close(fd);

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

size_t fw_schedule_days_str(unsigned char days, char *buf, size_t len,
                            const char *names[], const char *sep)
{
    if (len == 0) return 0;
    buf[0] = '\0';

    size_t pos = 0;
    size_t sep_len = strlen(sep);
    int first = 1;

    for (int d = 0; d < 7; d++) {
        if (!(days & (1 << d))) continue;

        size_t name_len = strlen(names[d]);

        if (!first) {
            if (pos + sep_len >= len) break;
            memcpy(buf + pos, sep, sep_len);
            pos += sep_len;
        }

        if (pos + name_len >= len) break;
        memcpy(buf + pos, names[d], name_len);
        pos += name_len;
        first = 0;
    }

    buf[pos] = '\0';
    return pos;
}
