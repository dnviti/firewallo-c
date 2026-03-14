#include "firewallo/i18n.h"
#include <string.h>

typedef struct {
    const char *id;
    const char *en;
    const char *it;
} msg_entry_t;

static const msg_entry_t messages[] = {
    {"starting_firewall",  "Starting firewall...",           "Avvio del firewall..."},
    {"stopping_firewall",  "Stopping firewall...",           "Arresto del firewall..."},
    {"restarting_firewall", "Restarting firewall...",        "Riavvio del firewall..."},
    {"resetting_firewall", "Resetting firewall...",          "Reset del firewall..."},
    {"firewall_started",   "Firewall started successfully.", "Firewall avviato con successo."},
    {"firewall_stopped",   "Firewall stopped.",              "Firewall arrestato."},
    {"firewall_reset",     "Firewall reset to accept all.",  "Firewall reimpostato ad accettare tutto."},
    {"config_loaded",      "Configuration loaded.",          "Configurazione caricata."},
    {"config_saved",       "Configuration saved.",           "Configurazione salvata."},
    {"config_valid",       "Configuration is valid.",        "La configurazione e' valida."},
    {"config_invalid",     "Configuration error:",           "Errore di configurazione:"},
    {"export_done",        "Configuration exported to:",     "Configurazione esportata in:"},
    {"restore_done",       "Configuration restored from:",   "Configurazione ripristinata da:"},
    {"backend_switched",   "Backend switched to:",           "Backend cambiato in:"},
    {"status_running",     "Firewall is running.",           "Il firewall e' attivo."},
    {"status_stopped",     "Firewall is stopped.",           "Il firewall e' fermo."},
    {"error_root",         "Error: must run as root.",       "Errore: eseguire come root."},
    {"error_load",         "Error loading configuration:",   "Errore nel caricamento della configurazione:"},
    {"error_start",        "Error starting firewall:",       "Errore nell'avvio del firewall:"},
    {"cmd_failed",         "Command failed at index:",       "Comando fallito all'indice:"},
    {NULL, NULL, NULL}
};

static fw_lang_t current_lang = LANG_EN;

void fw_i18n_init(fw_lang_t lang)
{
    current_lang = lang;
}

const char *fw_i18n_get(const char *msg_id)
{
    if (!msg_id)
        return "";
    for (const msg_entry_t *m = messages; m->id; m++) {
        if (strcmp(m->id, msg_id) == 0)
            return current_lang == LANG_IT ? m->it : m->en;
    }
    return msg_id; /* Fallback: return the ID itself */
}
