#ifndef FIREWALLO_I18N_H
#define FIREWALLO_I18N_H

#include "firewallo/types.h"

/* Initialize i18n with the given language */
void fw_i18n_init(fw_lang_t lang);

/* Get translated string by message ID */
const char *fw_i18n_get(const char *msg_id);

/* Shorthand macro */
#define _(id) fw_i18n_get(id)

#endif /* FIREWALLO_I18N_H */
