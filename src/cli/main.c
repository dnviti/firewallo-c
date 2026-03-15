#include "commands.h"
#include "firewallo/config.h"
#include "firewallo/rule_compiler.h"
#include "firewallo/rollback.h"
#include "firewallo/log.h"
#include "firewallo/i18n.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static void print_usage(void)
{
    printf(
        "Usage: firewallo <command> [options]\n"
        "\n"
        "Commands:\n"
        "  start           Start the firewall\n"
        "  stop            Stop the firewall (flush rules, keep NAT)\n"
        "  restart         Stop then start\n"
        "  reload          Re-read config from disk and reapply rules\n"
        "  reset           Flush all rules, set accept policy\n"
        "  status          Show firewall status\n"
        "  rules           Display active ruleset\n"
        "  preview         Compile config and show commands + diff without executing\n"
        "  validate        Validate the configuration file\n"
        "  show-config     Pretty-print the JSON configuration\n"
        "  export          Export configuration backup\n"
        "  restore <file>  Restore configuration from backup\n"
        "  switch <nft|ipt> Switch backend between nftables and iptables\n"
        "  confirm         Confirm pending config (cancel rollback timer)\n"
        "  version         Show version\n"
        "\n"
        "Config editing:\n"
        "  set-interface <zone> <add|remove> <iface>\n"
        "  set-dns <add|remove> <ip>\n"
        "  set-range <zone> <add|remove> <cidr>\n"
        "  set-sysctl <key> <0|1>\n"
        "  set-chain <chain> <tcp|udp> <add|remove> <port>\n"
        "  set-nat <post|pre> <add|remove> <rule-json>\n"
        "  set-ratelimit <chain> <max> <period> <ban>\n"
        "\n"
        "Options:\n"
        "  -c, --config <path>  Config file (default: /etc/firewallo/firewallo.json)\n"
        "  -v, --verbose        Verbose output (show all commands)\n"
        "  -n, --dry-run        Show commands without executing\n"
        "  -t, --rollback-timeout <N>  Auto-rollback after N seconds (opt-in, disabled by default)\n"
        "  -h, --help           Show this help\n"
    );
}

int main(int argc, char *argv[])
{
    const char *config_path = FW_DEFAULT_CONFIG_PATH;
    int verbose = 0;
    int dry_run = 0;
    int rollback_timeout = 0; /* 0 means no rollback timer */

    static struct option long_opts[] = {
        {"config",           required_argument, NULL, 'c'},
        {"verbose",          no_argument,       NULL, 'v'},
        {"dry-run",          no_argument,       NULL, 'n'},
        {"rollback-timeout", required_argument, NULL, 't'},
        {"help",             no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:vnt:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'n':
            dry_run = 1;
            verbose = 1;
            break;
        case 't':
            rollback_timeout = atoi(optarg);
            if (rollback_timeout <= 0) {
                fprintf(stderr, "Rollback timeout must be a positive integer\n");
                return 1;
            }
            break;
        case 'h':
            print_usage();
            return 0;
        default:
            print_usage();
            return 1;
        }
    }

    if (optind >= argc) {
        print_usage();
        return 1;
    }

    const char *command = argv[optind];

    /* Load configuration */
    fw_config_t cfg;
    char err[256] = {0};

    if (fw_config_load(config_path, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 1;
    }

    /* Initialize subsystems */
    fw_i18n_init(cfg.language);
    fw_log_init(NULL, verbose ? LOG_DEBUG : LOG_INFO);

    /* Check root for commands that need it */
    if (geteuid() != 0 && !dry_run) {
        if (strcmp(command, "start") == 0 || strcmp(command, "stop") == 0 ||
            strcmp(command, "restart") == 0 || strcmp(command, "reset") == 0 ||
            strcmp(command, "reload") == 0) {
            fprintf(stderr, "%s\n", _("error_root"));
            return 1;
        }
    }

    /* Dry-run: compile start and print commands */
    if (dry_run) {
        fw_cmdlist_t cmds;
        if (strcmp(command, "stop") == 0)
            fw_compile_stop(&cfg, &cmds);
        else if (strcmp(command, "reset") == 0)
            fw_compile_reset(&cfg, &cmds);
        else
            fw_compile_start(&cfg, &cmds);

        printf("# Dry run: %d commands for '%s'\n", cmds.count, command);
        for (int i = 0; i < cmds.count; i++)
            printf("%s\n", cmds.cmds[i].command);

        fw_cmdlist_free(&cmds);
        return 0;
    }

    /* Dispatch command */
    int ret = 0;
    if (strcmp(command, "start") == 0) {
        if (rollback_timeout > 0)
            ret = cmd_start_with_rollback(&cfg, config_path, verbose, rollback_timeout);
        else
            ret = cmd_start(&cfg, verbose);
    } else if (strcmp(command, "stop") == 0)
        ret = cmd_stop(&cfg, verbose);
    else if (strcmp(command, "restart") == 0)
        ret = cmd_restart(&cfg, config_path, verbose);
    else if (strcmp(command, "reset") == 0)
        ret = cmd_reset(&cfg, verbose);
    else if (strcmp(command, "status") == 0)
        ret = cmd_status(&cfg);
    else if (strcmp(command, "rules") == 0)
        ret = cmd_rules(&cfg);
    else if (strcmp(command, "preview") == 0)
        ret = cmd_preview(&cfg, config_path);
    else if (strcmp(command, "validate") == 0)
        ret = cmd_validate(&cfg);
    else if (strcmp(command, "show-config") == 0)
        ret = cmd_show_config(&cfg);
    else if (strcmp(command, "export") == 0)
        ret = cmd_export(&cfg, config_path);
    else if (strcmp(command, "restore") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: firewallo restore <backup-file>\n");
            return 1;
        }
        ret = cmd_restore(&cfg, argv[optind + 1], config_path);
    } else if (strcmp(command, "switch") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: firewallo switch <nft|ipt>\n");
            return 1;
        }
        ret = cmd_switch_backend(&cfg, argv[optind + 1], config_path);
    } else if (strcmp(command, "reload") == 0) {
        if (rollback_timeout > 0)
            ret = cmd_reload_with_rollback(&cfg, config_path, verbose, rollback_timeout);
        else
            ret = cmd_reload(&cfg, config_path, verbose);
    } else if (strcmp(command, "confirm") == 0)
        ret = cmd_confirm();
    else if (strcmp(command, "set-interface") == 0) {
        if (optind + 3 >= argc) {
            fprintf(stderr, "Usage: firewallo set-interface <zone> <add|remove> <iface>\n");
            return 1;
        }
        ret = cmd_set_interface(&cfg, argv[optind + 1], argv[optind + 2],
                                argv[optind + 3], config_path);
    } else if (strcmp(command, "set-dns") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: firewallo set-dns <add|remove> <ip>\n");
            return 1;
        }
        ret = cmd_set_dns(&cfg, argv[optind + 1], argv[optind + 2], config_path);
    } else if (strcmp(command, "set-range") == 0) {
        if (optind + 3 >= argc) {
            fprintf(stderr, "Usage: firewallo set-range <zone> <add|remove> <cidr>\n");
            return 1;
        }
        ret = cmd_set_range(&cfg, argv[optind + 1], argv[optind + 2],
                            argv[optind + 3], config_path);
    } else if (strcmp(command, "set-sysctl") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: firewallo set-sysctl <key> <0|1>\n");
            return 1;
        }
        ret = cmd_set_sysctl(&cfg, argv[optind + 1], argv[optind + 2], config_path);
    } else if (strcmp(command, "set-chain") == 0) {
        if (optind + 4 >= argc) {
            fprintf(stderr, "Usage: firewallo set-chain <chain> <tcp|udp> <add|remove> <port>\n");
            return 1;
        }
        ret = cmd_set_chain(&cfg, argv[optind + 1], argv[optind + 2],
                            argv[optind + 3], argv[optind + 4], config_path);
    } else if (strcmp(command, "set-nat") == 0) {
        if (optind + 3 >= argc) {
            fprintf(stderr, "Usage: firewallo set-nat <post|pre> <add|remove> <rule-json>\n");
            return 1;
        }
        ret = cmd_set_nat(&cfg, argv[optind + 1], argv[optind + 2],
                          argv[optind + 3], config_path);
    } else if (strcmp(command, "set-ratelimit") == 0) {
        if (optind + 4 >= argc) {
            fprintf(stderr, "Usage: firewallo set-ratelimit <chain> <max> <period> <ban>\n");
            return 1;
        }
        ret = cmd_set_ratelimit(&cfg, argv[optind + 1], argv[optind + 2],
                                argv[optind + 3], argv[optind + 4], config_path);
    } else if (strcmp(command, "version") == 0)
        ret = cmd_version(&cfg);
    else {
        fprintf(stderr, "Unknown command: %s\n\n", command);
        print_usage();
        ret = 1;
    }

    fw_log_close();
    return ret;
}
