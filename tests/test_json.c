#include "firewallo/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
    } else { \
        tests_passed++; \
    } \
} while(0)

static void test_parse_null(void)
{
    printf("test_parse_null\n");
    char err[256];
    json_value_t *v = json_parse("null", err, sizeof(err));
    ASSERT(v != NULL, "parse null");
    ASSERT(v->type == JSON_NULL, "type is null");
    ASSERT(json_is_null(v), "json_is_null");
    json_free(v);
}

static void test_parse_bool(void)
{
    printf("test_parse_bool\n");
    char err[256];

    json_value_t *t = json_parse("true", err, sizeof(err));
    ASSERT(t != NULL, "parse true");
    ASSERT(t->type == JSON_BOOL, "type is bool");
    ASSERT(json_bool_value(t) == 1, "value is 1");
    json_free(t);

    json_value_t *f = json_parse("false", err, sizeof(err));
    ASSERT(f != NULL, "parse false");
    ASSERT(json_bool_value(f) == 0, "value is 0");
    json_free(f);
}

static void test_parse_number(void)
{
    printf("test_parse_number\n");
    char err[256];

    json_value_t *v = json_parse("42", err, sizeof(err));
    ASSERT(v != NULL, "parse 42");
    ASSERT(v->type == JSON_NUMBER, "type is number");
    ASSERT(json_number_value(v) == 42.0, "value is 42");
    json_free(v);

    v = json_parse("-3.14", err, sizeof(err));
    ASSERT(v != NULL, "parse -3.14");
    ASSERT(json_number_value(v) > -3.15 && json_number_value(v) < -3.13, "value is -3.14");
    json_free(v);

    v = json_parse("1e3", err, sizeof(err));
    ASSERT(v != NULL, "parse 1e3");
    ASSERT(json_number_value(v) == 1000.0, "value is 1000");
    json_free(v);
}

static void test_parse_string(void)
{
    printf("test_parse_string\n");
    char err[256];

    json_value_t *v = json_parse("\"hello\"", err, sizeof(err));
    ASSERT(v != NULL, "parse string");
    ASSERT(v->type == JSON_STRING, "type is string");
    ASSERT(strcmp(json_string_value(v), "hello") == 0, "value is hello");
    json_free(v);

    v = json_parse("\"line\\nbreak\"", err, sizeof(err));
    ASSERT(v != NULL, "parse escaped string");
    ASSERT(strcmp(json_string_value(v), "line\nbreak") == 0, "value has newline");
    json_free(v);

    v = json_parse("\"\"", err, sizeof(err));
    ASSERT(v != NULL, "parse empty string");
    ASSERT(strcmp(json_string_value(v), "") == 0, "value is empty");
    json_free(v);
}

static void test_parse_array(void)
{
    printf("test_parse_array\n");
    char err[256];

    json_value_t *v = json_parse("[1, 2, 3]", err, sizeof(err));
    ASSERT(v != NULL, "parse array");
    ASSERT(v->type == JSON_ARRAY, "type is array");
    ASSERT(json_array_count(v) == 3, "count is 3");
    ASSERT(json_number_value(json_array_get(v, 0)) == 1.0, "item 0 is 1");
    ASSERT(json_number_value(json_array_get(v, 2)) == 3.0, "item 2 is 3");
    json_free(v);

    v = json_parse("[]", err, sizeof(err));
    ASSERT(v != NULL, "parse empty array");
    ASSERT(json_array_count(v) == 0, "count is 0");
    json_free(v);

    v = json_parse("[\"a\", true, null, 42]", err, sizeof(err));
    ASSERT(v != NULL, "parse mixed array");
    ASSERT(json_array_count(v) == 4, "count is 4");
    ASSERT(strcmp(json_string_value(json_array_get(v, 0)), "a") == 0, "item 0 is a");
    ASSERT(json_bool_value(json_array_get(v, 1)) == 1, "item 1 is true");
    ASSERT(json_is_null(json_array_get(v, 2)), "item 2 is null");
    ASSERT(json_number_value(json_array_get(v, 3)) == 42.0, "item 3 is 42");
    json_free(v);
}

static void test_parse_object(void)
{
    printf("test_parse_object\n");
    char err[256];

    json_value_t *v = json_parse("{\"name\": \"test\", \"value\": 42}", err, sizeof(err));
    ASSERT(v != NULL, "parse object");
    ASSERT(v->type == JSON_OBJECT, "type is object");
    ASSERT(json_object_count(v) == 2, "count is 2");
    ASSERT(strcmp(json_string_value(json_object_get(v, "name")), "test") == 0, "name is test");
    ASSERT(json_number_value(json_object_get(v, "value")) == 42.0, "value is 42");
    ASSERT(json_object_get(v, "missing") == NULL, "missing key returns NULL");
    json_free(v);

    v = json_parse("{}", err, sizeof(err));
    ASSERT(v != NULL, "parse empty object");
    ASSERT(json_object_count(v) == 0, "count is 0");
    json_free(v);
}

static void test_parse_nested(void)
{
    printf("test_parse_nested\n");
    char err[256];

    const char *json = "{\"interfaces\": {\"lan\": [\"eth0\", \"eth1\"]}, \"ports\": [80, 443]}";
    json_value_t *v = json_parse(json, err, sizeof(err));
    ASSERT(v != NULL, "parse nested");

    json_value_t *ifs = json_object_get(v, "interfaces");
    ASSERT(ifs != NULL, "interfaces exists");
    ASSERT(ifs->type == JSON_OBJECT, "interfaces is object");

    json_value_t *lan = json_object_get(ifs, "lan");
    ASSERT(lan != NULL, "lan exists");
    ASSERT(json_array_count(lan) == 2, "lan has 2 items");
    ASSERT(strcmp(json_string_value(json_array_get(lan, 0)), "eth0") == 0, "lan[0] is eth0");

    json_value_t *ports = json_object_get(v, "ports");
    ASSERT(json_array_count(ports) == 2, "ports has 2 items");
    ASSERT(json_number_value(json_array_get(ports, 0)) == 80.0, "ports[0] is 80");

    json_free(v);
}

static void test_parse_error(void)
{
    printf("test_parse_error\n");
    char err[256] = {0};

    json_value_t *v = json_parse("{invalid}", err, sizeof(err));
    ASSERT(v == NULL, "parse error returns NULL");
    ASSERT(err[0] != '\0', "error message set");
}

static void test_serialize(void)
{
    printf("test_serialize\n");

    json_value_t *obj = json_new_object();
    json_object_set(obj, "name", json_new_string("test"));
    json_object_set(obj, "count", json_new_number(42));
    json_object_set(obj, "active", json_new_bool(1));
    json_object_set(obj, "data", json_new_null());

    json_value_t *arr = json_new_array();
    json_array_append(arr, json_new_number(1));
    json_array_append(arr, json_new_number(2));
    json_object_set(obj, "items", arr);

    char *json = json_serialize(obj, 0);
    ASSERT(json != NULL, "serialize not null");
    ASSERT(strstr(json, "\"name\":\"test\"") != NULL, "contains name");
    ASSERT(strstr(json, "\"count\":42") != NULL, "contains count");
    ASSERT(strstr(json, "\"active\":true") != NULL, "contains active");
    ASSERT(strstr(json, "\"data\":null") != NULL, "contains data");

    free(json);
    json_free(obj);
}

static void test_roundtrip(void)
{
    printf("test_roundtrip\n");
    char err[256];

    const char *original = "{\"version\":\"2.0.0\",\"backend\":\"nft\",\"ports\":[80,443,8080]}";
    json_value_t *v = json_parse(original, err, sizeof(err));
    ASSERT(v != NULL, "parse original");

    char *serialized = json_serialize(v, 0);
    ASSERT(serialized != NULL, "serialize");

    json_value_t *v2 = json_parse(serialized, err, sizeof(err));
    ASSERT(v2 != NULL, "re-parse serialized");

    ASSERT(strcmp(json_string_value(json_object_get(v2, "version")), "2.0.0") == 0,
           "roundtrip version");
    ASSERT(json_array_count(json_object_get(v2, "ports")) == 3,
           "roundtrip ports count");

    free(serialized);
    json_free(v);
    json_free(v2);
}

int main(void)
{
    printf("=== JSON Parser Tests ===\n\n");

    test_parse_null();
    test_parse_bool();
    test_parse_number();
    test_parse_string();
    test_parse_array();
    test_parse_object();
    test_parse_nested();
    test_parse_error();
    test_serialize();
    test_roundtrip();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
