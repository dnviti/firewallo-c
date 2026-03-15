#ifndef FIREWALLO_WEBHOOK_H
#define FIREWALLO_WEBHOOK_H

#include "firewallo/types.h"

/* Event name strings */
const char *fw_webhook_event_name(fw_webhook_event_t event);

/* Validate a webhook URL (must start with http:// or https://).
 * Returns 1 if valid, 0 if invalid. */
int fw_webhook_validate_url(const char *url);

/* Validate a webhook event bitmask (must be 1..WH_EVENT_ALL).
 * Returns 1 if valid, 0 if invalid. */
int fw_webhook_validate_events(unsigned int events);

/* Validate a webhook secret (reject control characters).
 * Returns 1 if valid, 0 if invalid. NULL is considered valid. */
int fw_webhook_validate_secret(const char *secret);

/* Send a notification to all matching webhooks for the given event.
 * The payload is a JSON string. Delivery is non-blocking (fork).
 * Returns 0 on success (fork succeeded), -1 on error. */
int fw_webhook_send(const fw_config_t *cfg, fw_webhook_event_t event,
                    const char *payload);

/* Send a test notification to a single webhook (by pointer).
 * Blocking call (does not fork). Returns HTTP status or -1 on error. */
int fw_webhook_test(const fw_webhook_t *wh);

#endif /* FIREWALLO_WEBHOOK_H */
