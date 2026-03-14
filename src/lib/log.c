#include "firewallo/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

static FILE *log_file = NULL;
static fw_log_level_t log_min_level = LOG_INFO;

static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};

void fw_log_init(const char *logfile_path, fw_log_level_t min_level)
{
    log_min_level = min_level;

    if (logfile_path) {
        log_file = fopen(logfile_path, "a");
        /* If we can't open the log file, we'll just use stderr */
    }
}

void fw_log(fw_log_level_t level, const char *fmt, ...)
{
    if (level < log_min_level)
        return;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    va_list ap;

    /* Write to stderr */
    fprintf(stderr, "[%s] %s: ", timebuf, level_names[level]);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    /* Write to log file if open */
    if (log_file) {
        fprintf(log_file, "[%s] %s: ", timebuf, level_names[level]);
        va_start(ap, fmt);
        vfprintf(log_file, fmt, ap);
        va_end(ap);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

void fw_log_close(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
