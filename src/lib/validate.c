#include "firewallo/validate.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

int fw_validate_ipv4(const char *ip)
{
    if (!ip || !*ip)
        return 0;

    int octets = 0;
    int val = 0;
    int digits = 0;

    for (const char *p = ip; ; p++) {
        if (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            digits++;
            if (digits > 3 || val > 255)
                return 0;
        } else if (*p == '.' || *p == '\0') {
            if (digits == 0)
                return 0;
            octets++;
            if (*p == '\0')
                break;
            if (octets >= 4)
                return 0;
            val = 0;
            digits = 0;
        } else {
            return 0;
        }
    }

    return octets == 4;
}

int fw_validate_ipv4_cidr(const char *cidr)
{
    if (!cidr || !*cidr)
        return 0;

    /* Find the slash */
    const char *slash = strchr(cidr, '/');
    if (!slash)
        return 0;

    /* Validate the IP part */
    size_t iplen = (size_t)(slash - cidr);
    if (iplen == 0 || iplen > 15)
        return 0;

    char ipbuf[16];
    memcpy(ipbuf, cidr, iplen);
    ipbuf[iplen] = '\0';

    if (!fw_validate_ipv4(ipbuf))
        return 0;

    /* Validate the mask (0-32) */
    const char *mask_str = slash + 1;
    if (!*mask_str)
        return 0;

    char *end;
    long mask = strtol(mask_str, &end, 10);
    if (*end != '\0' || mask < 0 || mask > 32)
        return 0;

    return 1;
}

int fw_validate_port(int port)
{
    return port >= 1 && port <= 65535;
}

int fw_validate_port_range(const char *range)
{
    if (!range || !*range)
        return 0;

    /* "any" is valid */
    if (strcmp(range, "any") == 0)
        return 1;

    /* Check for range format: "start:end" */
    const char *colon = strchr(range, ':');
    if (colon) {
        char start_str[8], end_str[8];
        size_t slen = (size_t)(colon - range);
        if (slen == 0 || slen > 5)
            return 0;

        memcpy(start_str, range, slen);
        start_str[slen] = '\0';

        const char *estr = colon + 1;
        size_t elen = strlen(estr);
        if (elen == 0 || elen > 5)
            return 0;
        memcpy(end_str, estr, elen + 1);

        int start = atoi(start_str);
        int end = atoi(end_str);
        return fw_validate_port(start) && fw_validate_port(end) && start <= end;
    }

    /* Single port */
    for (const char *p = range; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    int port = atoi(range);
    return fw_validate_port(port);
}

int fw_validate_interface(const char *ifname)
{
    if (!ifname || !*ifname)
        return 0;

    size_t len = strlen(ifname);
    if (len > 15) /* IFNAMSIZ - 1 */
        return 0;

    /* Must start with a letter */
    if (!isalpha((unsigned char)ifname[0]))
        return 0;

    /* Allow alphanumeric, hyphen, dot */
    for (size_t i = 0; i < len; i++) {
        char c = ifname[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '.' && c != '_')
            return 0;
    }

    return 1;
}

int fw_validate_protocol(const char *proto)
{
    if (!proto)
        return 0;
    return strcmp(proto, "tcp") == 0 || strcmp(proto, "udp") == 0;
}

int fw_validate_action(const char *action)
{
    if (!action)
        return 0;
    return strcmp(action, "accept") == 0 ||
           strcmp(action, "drop") == 0 ||
           strcmp(action, "reject") == 0;
}

int fw_validate_comment(const char *comment)
{
    if (!comment)
        return 1; /* NULL is OK (optional) */
    if (!*comment)
        return 1; /* Empty is OK */

    for (const char *p = comment; *p; p++) {
        char c = *p;
        if (!isalnum((unsigned char)c) && c != '_' && c != '-' && c != ' ' && c != '.')
            return 0;
    }
    return 1;
}

int fw_validate_addr_field(const char *addr)
{
    if (!addr || !*addr)
        return 1; /* Empty/NULL is OK (optional field) */
    if (fw_validate_ipv4(addr))
        return 1;
    if (fw_validate_ipv4_cidr(addr))
        return 1;
    return 0;
}

int fw_validate_mark(const char *mark)
{
    if (!mark || !*mark)
        return 0;

    const char *p = mark;

    /* Allow "0x" or "0X" prefix for hex */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        if (!*p)
            return 0;
        for (; *p; p++) {
            if (!isxdigit((unsigned char)*p))
                return 0;
        }
        return 1;
    }

    /* Otherwise must be decimal digits */
    for (; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}
