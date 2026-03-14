#ifndef FIREWALLO_UTIL_H
#define FIREWALLO_UTIL_H

#include <stddef.h>

/* Safe string copy — always null-terminates, returns bytes written (excluding NUL) */
size_t fw_strlcpy(char *dst, const char *src, size_t size);

/* Read entire file into malloc'd buffer. Caller must free(). Returns NULL on error. */
char *fw_read_file(const char *path, size_t *out_len);

/* Write buffer to file atomically (write to tmp, rename). Returns 0 on success. */
int fw_write_file(const char *path, const char *data, size_t len);

/* Case-insensitive string compare */
int fw_strcasecmp(const char *a, const char *b);

/* Check if string is empty or NULL */
int fw_str_empty(const char *s);

#endif /* FIREWALLO_UTIL_H */
