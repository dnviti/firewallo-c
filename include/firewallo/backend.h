#ifndef FIREWALLO_BACKEND_H
#define FIREWALLO_BACKEND_H

#include "firewallo/types.h"
#include "firewallo/rule_compiler.h"

/* Backend operations — each backend (nft/ipt) implements all of these */
typedef struct {
    /* Flush and table/chain setup */
    void (*flush_ruleset)(fw_cmdlist_t *out);
    void (*create_filter_table)(fw_cmdlist_t *out);
    void (*create_base_chain)(fw_cmdlist_t *out, const char *chain,
                              const char *hook, int priority, const char *policy);
    void (*create_user_chain)(fw_cmdlist_t *out, const char *table, const char *chain);

    /* Loopback */
    void (*add_loopback_accept)(fw_cmdlist_t *out, const char *chain);

    /* State tracking */
    void (*add_state_rules)(fw_cmdlist_t *out);

    /* TCP flag detection */
    void (*add_tcp_flag_rules)(fw_cmdlist_t *out);

    /* DNS rules */
    void (*add_dns_localhost)(fw_cmdlist_t *out);
    void (*add_dns_server)(fw_cmdlist_t *out, const char *ip, int rate_limited);
    void (*add_dns_rootserver)(fw_cmdlist_t *out, const char *ip);

    /* ICMP */
    void (*add_icmp_rules)(fw_cmdlist_t *out);

    /* DPI queue */
    void (*add_dpi_queue)(fw_cmdlist_t *out);

    /* Chain jumps */
    void (*add_builtin_jumps)(fw_cmdlist_t *out, const char *builtin);
    void (*add_forward_jump)(fw_cmdlist_t *out, const char *iif,
                             const char *oif, const char *chain);
    void (*add_input_jump)(fw_cmdlist_t *out, const char *iif, const char *chain);
    void (*add_output_jump)(fw_cmdlist_t *out, const char *oif, const char *chain);

    /* Filter rules */
    void (*add_filter_port_rule)(fw_cmdlist_t *out, const char *chain,
                                 fw_proto_t proto, int port);
    void (*add_filter_explicit_rule)(fw_cmdlist_t *out, const char *chain,
                                     const fw_filter_rule_t *rule);

    /* Final drop logging */
    void (*add_drop_log)(fw_cmdlist_t *out, const char *chain, const char *prefix);

    /* NAT table setup */
    void (*create_nat_table)(fw_cmdlist_t *out);
    void (*add_masquerade)(fw_cmdlist_t *out, const char *src, const char *oif,
                           const char *comment);
    void (*add_snat)(fw_cmdlist_t *out, const char *src, const char *oif,
                     const char *to_source, const char *comment);
    void (*add_dnat)(fw_cmdlist_t *out, const fw_nat_pre_t *rule);

    /* Mangle table setup */
    void (*create_mangle_table)(fw_cmdlist_t *out);

    /* Stop/Reset */
    void (*setup_stop)(fw_cmdlist_t *out);
    void (*setup_reset)(fw_cmdlist_t *out);
} fw_backend_ops_t;

/* Get the backend operations table */
const fw_backend_ops_t *fw_backend_get(fw_backend_t type);

/* Declared in backend_nft.c and backend_ipt.c */
extern const fw_backend_ops_t fw_backend_nft;
extern const fw_backend_ops_t fw_backend_ipt;

#endif /* FIREWALLO_BACKEND_H */
