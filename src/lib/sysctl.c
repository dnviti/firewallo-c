#include "firewallo/sysctl.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int fw_sysctl_set(const char *path, int value)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        fw_log(LOG_WARN, "cannot write to %s", path);
        return -1;
    }
    fprintf(f, "%d\n", value);
    fclose(f);
    fw_log(LOG_DEBUG, "sysctl %s = %d", path, value);
    return 0;
}

int fw_sysctl_apply(const fw_config_t *cfg)
{
    int ret = 0;

    if (cfg->ip_forward)
        ret |= fw_sysctl_set("/proc/sys/net/ipv4/ip_forward", 1);

    if (cfg->ip_dynaddr)
        ret |= fw_sysctl_set("/proc/sys/net/ipv4/ip_dynaddr", 1);

    if (cfg->tcp_syncookies)
        ret |= fw_sysctl_set("/proc/sys/net/ipv4/tcp_syncookies", 1);

    fw_sysctl_set("/proc/sys/net/ipv4/conf/all/accept_source_route",
                  cfg->accept_source_route ? 1 : 0);

    return ret;
}

int fw_exec(const char *cmd)
{
    fw_log(LOG_DEBUG, "exec: %s", cmd);
    int ret = system(cmd);
    if (ret != 0)
        fw_log(LOG_WARN, "command failed (exit %d): %s", ret, cmd);
    return ret;
}

int fw_exec_capture(const char *cmd, char *buf, size_t buflen)
{
    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;

    size_t total = 0;
    while (total < buflen - 1) {
        size_t n = fread(buf + total, 1, buflen - 1 - total, p);
        if (n == 0) break;
        total += n;
    }
    buf[total] = '\0';

    int status = pclose(p);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}
