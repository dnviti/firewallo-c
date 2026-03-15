#ifndef FIREWALLO_UTIL_H
#define FIREWALLO_UTIL_H

#include <stddef.h>
#include <string.h>

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

/*
 * Build a comma-separated (or custom separator) string of day names from a
 * bitmask (bit 0 = Monday … bit 6 = Sunday).
 *
 * names  – array of 7 day-name strings (e.g. {"Mon","Tue",…} or
 *          {"Monday","Tuesday",…})
 * sep    – separator between names (e.g. "," or ", ")
 * days   – bitmask of active days
 * buf    – output buffer
 * len    – size of output buffer
 *
 * Returns the number of characters written (excluding NUL), or 0 if no days
 * are set.
 */
size_t fw_schedule_days_str(unsigned char days, char *buf, size_t len,
                            const char *names[], const char *sep);

#endif /* FIREWALLO_UTIL_H */
