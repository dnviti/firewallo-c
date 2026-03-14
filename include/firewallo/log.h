#ifndef FIREWALLO_LOG_H
#define FIREWALLO_LOG_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} fw_log_level_t;

/* Initialize logging. logfile may be NULL for stderr only. */
void fw_log_init(const char *logfile_path, fw_log_level_t min_level);

/* Log a message */
void fw_log(fw_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Close log file if open */
void fw_log_close(void);

#endif /* FIREWALLO_LOG_H */
