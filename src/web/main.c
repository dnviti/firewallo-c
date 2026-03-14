#include "firewallo/httpd.h"
#include "firewallo/config.h"
#include "firewallo/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

static httpd_t server;

static void sigint_handler(int sig)
{
    (void)sig;
    httpd_stop(&server);
}

static void print_usage(void)
{
    printf(
        "Usage: firewallo-web [options]\n"
        "\n"
        "Options:\n"
        "  -p, --port <port>      Listen port (default: 8080)\n"
        "  -b, --bind <addr>      Bind address (default: 0.0.0.0)\n"
        "  -w, --webroot <path>   Static files directory (default: /usr/local/share/firewallo/web)\n"
        "  -c, --config <path>    Config file (default: /etc/firewallo/firewallo.json)\n"
        "  -h, --help             Show this help\n"
    );
}

int main(int argc, char *argv[])
{
    int port = 8080;
    const char *bind_addr = "0.0.0.0";
    const char *webroot = "/usr/local/share/firewallo/web";
    const char *config_path = "/etc/firewallo/firewallo.json";

    static struct option long_opts[] = {
        {"port",    required_argument, NULL, 'p'},
        {"bind",    required_argument, NULL, 'b'},
        {"webroot", required_argument, NULL, 'w'},
        {"config",  required_argument, NULL, 'c'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:b:w:c:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 'b': bind_addr = optarg; break;
        case 'w': webroot = optarg; break;
        case 'c': config_path = optarg; break;
        case 'h': print_usage(); return 0;
        default:  print_usage(); return 1;
        }
    }

    /* Load config */
    fw_config_t cfg;
    char err[256];
    if (fw_config_load(config_path, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 1;
    }

    fw_log_init(NULL, LOG_INFO);
    fw_log(LOG_INFO, "firewallo-web %s", cfg.version);

    /* Setup signal handling */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Init and run server */
    if (httpd_init(&server, bind_addr, port, webroot, config_path, &cfg) != 0) {
        fprintf(stderr, "Failed to start server on port %d\n", port);
        return 1;
    }

    httpd_run(&server);

    fw_log(LOG_INFO, "Server stopped");
    fw_log_close();
    return 0;
}
