#ifndef FIREWALLO_AUTH_H
#define FIREWALLO_AUTH_H

#include <stddef.h>

#define AUTH_TOKEN_MAX 256

/**
 * Load API token from file. The file should contain a single line with
 * the token (leading/trailing whitespace is stripped).
 * Returns 0 on success, -1 on error.
 * If token_path is NULL, authentication is disabled (all requests pass).
 */
int auth_load_token(const char *token_path, char *token_buf, size_t buf_size);

/**
 * Check whether the given Authorization header value matches the loaded token.
 * Expected format: "Bearer <token>"
 * Returns 1 if authorized, 0 if not.
 * If stored_token is NULL or empty, all requests are authorized (auth disabled).
 */
int auth_check_bearer(const char *auth_header, const char *stored_token);

/**
 * Generate a random API token and write it to the given file path
 * with mode 0600. Returns 0 on success, -1 on error.
 */
int auth_generate_token(const char *token_path);

#endif /* FIREWALLO_AUTH_H */
