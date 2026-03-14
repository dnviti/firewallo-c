#ifndef FIREWALLO_JSON_H
#define FIREWALLO_JSON_H

#include <stddef.h>

/* JSON value types */
typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    union {
        int boolean;
        double number;
        char *string;
        struct {
            json_value_t **items;
            int count;
            int capacity;
        } array;
        struct {
            char **keys;
            json_value_t **values;
            int count;
            int capacity;
        } object;
    } u;
};

/* Parse JSON text into a value tree. Returns NULL on error, writes message to err_buf. */
json_value_t *json_parse(const char *text, char *err_buf, size_t err_len);

/* Free a value tree recursively */
void json_free(json_value_t *val);

/* Serialize a value tree to a JSON string. Caller must free(). pretty=1 for indented. */
char *json_serialize(const json_value_t *val, int pretty);

/* Object accessors — return NULL if key not found or wrong type */
json_value_t *json_object_get(const json_value_t *obj, const char *key);
int json_object_count(const json_value_t *obj);

/* Array accessors */
json_value_t *json_array_get(const json_value_t *arr, int index);
int json_array_count(const json_value_t *arr);

/* Value accessors — return defaults if wrong type */
const char *json_string_value(const json_value_t *val);
double json_number_value(const json_value_t *val);
int json_bool_value(const json_value_t *val);
int json_is_null(const json_value_t *val);

/* Builder functions for constructing JSON trees */
json_value_t *json_new_object(void);
json_value_t *json_new_array(void);
json_value_t *json_new_string(const char *s);
json_value_t *json_new_number(double n);
json_value_t *json_new_bool(int b);
json_value_t *json_new_null(void);

/* Add key-value pair to object. Takes ownership of val. Returns 0 on success. */
int json_object_set(json_value_t *obj, const char *key, json_value_t *val);

/* Append value to array. Takes ownership of val. Returns 0 on success. */
int json_array_append(json_value_t *arr, json_value_t *val);

#endif /* FIREWALLO_JSON_H */
