#include "firewallo/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* ── Internal parser state ──────────────────────────────────────────── */

typedef struct {
    const char *text;
    size_t pos;
    size_t len;
    char err[256];
} parser_t;

static void parser_error(parser_t *p, const char *msg)
{
    if (p->err[0] == '\0')
        snprintf(p->err, sizeof(p->err), "JSON parse error at position %zu: %s", p->pos, msg);
}

static void skip_whitespace(parser_t *p)
{
    while (p->pos < p->len) {
        char c = p->text[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            p->pos++;
        else
            break;
    }
}

static char peek(parser_t *p)
{
    skip_whitespace(p);
    if (p->pos >= p->len)
        return '\0';
    return p->text[p->pos];
}

static char advance(parser_t *p)
{
    if (p->pos >= p->len)
        return '\0';
    return p->text[p->pos++];
}

/* Forward declaration */
static json_value_t *parse_value(parser_t *p);

/* ── Parse string ──────────────────────────────────────────────────── */

static char *parse_string_raw(parser_t *p)
{
    skip_whitespace(p);
    if (advance(p) != '"') {
        parser_error(p, "expected '\"'");
        return NULL;
    }

    /* First pass: compute length */
    size_t start = p->pos;
    size_t slen = 0;
    while (p->pos < p->len && p->text[p->pos] != '"') {
        if (p->text[p->pos] == '\\') {
            p->pos++;
            if (p->pos >= p->len) {
                parser_error(p, "unterminated string escape");
                return NULL;
            }
            char esc = p->text[p->pos];
            if (esc == 'u') {
                p->pos += 4; /* skip 4 hex digits */
                slen += 4;   /* worst case UTF-8 */
            } else {
                p->pos++;
                slen++;
            }
        } else {
            p->pos++;
            slen++;
        }
    }
    if (p->pos >= p->len) {
        parser_error(p, "unterminated string");
        return NULL;
    }
    p->pos++; /* skip closing quote */

    /* Second pass: extract */
    char *buf = malloc(slen + 1);
    if (!buf)
        return NULL;

    size_t si = start;
    size_t di = 0;
    while (si < p->pos - 1) {
        if (p->text[si] == '\\') {
            si++;
            switch (p->text[si]) {
            case '"':  buf[di++] = '"';  break;
            case '\\': buf[di++] = '\\'; break;
            case '/':  buf[di++] = '/';  break;
            case 'b':  buf[di++] = '\b'; break;
            case 'f':  buf[di++] = '\f'; break;
            case 'n':  buf[di++] = '\n'; break;
            case 'r':  buf[di++] = '\r'; break;
            case 't':  buf[di++] = '\t'; break;
            case 'u':
                /* Simple: store as \uXXXX literal for now (ASCII subset sufficient) */
                si++;
                for (int k = 0; k < 4 && si < p->pos - 1; k++)
                    buf[di++] = p->text[si++];
                continue;
            default:
                buf[di++] = p->text[si];
                break;
            }
            si++;
        } else {
            buf[di++] = p->text[si++];
        }
    }
    buf[di] = '\0';
    return buf;
}

/* ── Parse number ──────────────────────────────────────────────────── */

static json_value_t *parse_number(parser_t *p)
{
    skip_whitespace(p);
    size_t start = p->pos;

    if (p->text[p->pos] == '-')
        p->pos++;

    if (p->pos >= p->len || !isdigit((unsigned char)p->text[p->pos])) {
        parser_error(p, "invalid number");
        return NULL;
    }

    while (p->pos < p->len && isdigit((unsigned char)p->text[p->pos]))
        p->pos++;

    if (p->pos < p->len && p->text[p->pos] == '.') {
        p->pos++;
        while (p->pos < p->len && isdigit((unsigned char)p->text[p->pos]))
            p->pos++;
    }

    if (p->pos < p->len && (p->text[p->pos] == 'e' || p->text[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < p->len && (p->text[p->pos] == '+' || p->text[p->pos] == '-'))
            p->pos++;
        while (p->pos < p->len && isdigit((unsigned char)p->text[p->pos]))
            p->pos++;
    }

    char tmp[64];
    size_t nlen = p->pos - start;
    if (nlen >= sizeof(tmp))
        nlen = sizeof(tmp) - 1;
    memcpy(tmp, p->text + start, nlen);
    tmp[nlen] = '\0';

    json_value_t *v = json_new_number(strtod(tmp, NULL));
    return v;
}

/* ── Parse object ──────────────────────────────────────────────────── */

static json_value_t *parse_object(parser_t *p)
{
    skip_whitespace(p);
    if (advance(p) != '{') {
        parser_error(p, "expected '{'");
        return NULL;
    }

    json_value_t *obj = json_new_object();
    if (!obj)
        return NULL;

    skip_whitespace(p);
    if (peek(p) == '}') {
        p->pos++;
        return obj;
    }

    for (;;) {
        char *key = parse_string_raw(p);
        if (!key) {
            json_free(obj);
            return NULL;
        }

        skip_whitespace(p);
        if (advance(p) != ':') {
            free(key);
            json_free(obj);
            parser_error(p, "expected ':'");
            return NULL;
        }

        json_value_t *val = parse_value(p);
        if (!val) {
            free(key);
            json_free(obj);
            return NULL;
        }

        json_object_set(obj, key, val);
        free(key);

        skip_whitespace(p);
        char c = peek(p);
        if (c == ',') {
            p->pos++;
            continue;
        }
        if (c == '}') {
            p->pos++;
            break;
        }

        parser_error(p, "expected ',' or '}' in object");
        json_free(obj);
        return NULL;
    }

    return obj;
}

/* ── Parse array ───────────────────────────────────────────────────── */

static json_value_t *parse_array(parser_t *p)
{
    skip_whitespace(p);
    if (advance(p) != '[') {
        parser_error(p, "expected '['");
        return NULL;
    }

    json_value_t *arr = json_new_array();
    if (!arr)
        return NULL;

    skip_whitespace(p);
    if (peek(p) == ']') {
        p->pos++;
        return arr;
    }

    for (;;) {
        json_value_t *val = parse_value(p);
        if (!val) {
            json_free(arr);
            return NULL;
        }
        json_array_append(arr, val);

        skip_whitespace(p);
        char c = peek(p);
        if (c == ',') {
            p->pos++;
            continue;
        }
        if (c == ']') {
            p->pos++;
            break;
        }

        parser_error(p, "expected ',' or ']' in array");
        json_free(arr);
        return NULL;
    }

    return arr;
}

/* ── Parse value (dispatch) ────────────────────────────────────────── */

static json_value_t *parse_value(parser_t *p)
{
    skip_whitespace(p);
    if (p->pos >= p->len) {
        parser_error(p, "unexpected end of input");
        return NULL;
    }

    char c = p->text[p->pos];

    if (c == '"') {
        char *s = parse_string_raw(p);
        if (!s)
            return NULL;
        json_value_t *v = json_new_string(s);
        free(s);
        return v;
    }
    if (c == '{')
        return parse_object(p);
    if (c == '[')
        return parse_array(p);
    if (c == '-' || isdigit((unsigned char)c))
        return parse_number(p);

    /* true */
    if (p->len - p->pos >= 4 && strncmp(p->text + p->pos, "true", 4) == 0) {
        p->pos += 4;
        return json_new_bool(1);
    }
    /* false */
    if (p->len - p->pos >= 5 && strncmp(p->text + p->pos, "false", 5) == 0) {
        p->pos += 5;
        return json_new_bool(0);
    }
    /* null */
    if (p->len - p->pos >= 4 && strncmp(p->text + p->pos, "null", 4) == 0) {
        p->pos += 4;
        return json_new_null();
    }

    parser_error(p, "unexpected character");
    return NULL;
}

/* ── Public parse API ──────────────────────────────────────────────── */

json_value_t *json_parse(const char *text, char *err_buf, size_t err_len)
{
    parser_t p;
    p.text = text;
    p.pos = 0;
    p.len = strlen(text);
    p.err[0] = '\0';

    json_value_t *val = parse_value(&p);
    if (!val && err_buf && err_len > 0)
        snprintf(err_buf, err_len, "%s", p.err);

    return val;
}

/* ── Free ──────────────────────────────────────────────────────────── */

void json_free(json_value_t *val)
{
    if (!val)
        return;

    switch (val->type) {
    case JSON_STRING:
        free(val->u.string);
        break;
    case JSON_ARRAY:
        for (int i = 0; i < val->u.array.count; i++)
            json_free(val->u.array.items[i]);
        free(val->u.array.items);
        break;
    case JSON_OBJECT:
        for (int i = 0; i < val->u.object.count; i++) {
            free(val->u.object.keys[i]);
            json_free(val->u.object.values[i]);
        }
        free(val->u.object.keys);
        free(val->u.object.values);
        break;
    default:
        break;
    }

    free(val);
}

/* ── Serializer ────────────────────────────────────────────────────── */

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    int pretty;
    int depth;
} serializer_t;

static void ser_grow(serializer_t *s, size_t need)
{
    while (s->len + need >= s->cap) {
        s->cap = s->cap < 256 ? 256 : s->cap * 2;
        s->buf = realloc(s->buf, s->cap);
    }
}

static void ser_append(serializer_t *s, const char *str, size_t slen)
{
    ser_grow(s, slen + 1);
    memcpy(s->buf + s->len, str, slen);
    s->len += slen;
    s->buf[s->len] = '\0';
}

static void ser_char(serializer_t *s, char c)
{
    ser_grow(s, 2);
    s->buf[s->len++] = c;
    s->buf[s->len] = '\0';
}

static void ser_indent(serializer_t *s)
{
    if (!s->pretty)
        return;
    for (int i = 0; i < s->depth; i++)
        ser_append(s, "  ", 2);
}

static void ser_newline(serializer_t *s)
{
    if (s->pretty)
        ser_char(s, '\n');
}

static void ser_string(serializer_t *s, const char *str)
{
    ser_char(s, '"');
    for (const char *p = str; *p; p++) {
        switch (*p) {
        case '"':  ser_append(s, "\\\"", 2); break;
        case '\\': ser_append(s, "\\\\", 2); break;
        case '\b': ser_append(s, "\\b", 2);  break;
        case '\f': ser_append(s, "\\f", 2);  break;
        case '\n': ser_append(s, "\\n", 2);  break;
        case '\r': ser_append(s, "\\r", 2);  break;
        case '\t': ser_append(s, "\\t", 2);  break;
        default:
            if ((unsigned char)*p < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*p);
                ser_append(s, esc, 6);
            } else {
                ser_char(s, *p);
            }
            break;
        }
    }
    ser_char(s, '"');
}

static void ser_value(serializer_t *s, const json_value_t *v);

static void ser_object(serializer_t *s, const json_value_t *v)
{
    ser_char(s, '{');
    if (v->u.object.count > 0) {
        ser_newline(s);
        s->depth++;
        for (int i = 0; i < v->u.object.count; i++) {
            ser_indent(s);
            ser_string(s, v->u.object.keys[i]);
            ser_char(s, ':');
            if (s->pretty)
                ser_char(s, ' ');
            ser_value(s, v->u.object.values[i]);
            if (i < v->u.object.count - 1)
                ser_char(s, ',');
            ser_newline(s);
        }
        s->depth--;
        ser_indent(s);
    }
    ser_char(s, '}');
}

static void ser_array(serializer_t *s, const json_value_t *v)
{
    ser_char(s, '[');
    if (v->u.array.count > 0) {
        /* Compact arrays of scalars (numbers, strings) on one line */
        int all_scalar = 1;
        for (int i = 0; i < v->u.array.count; i++) {
            json_type_t t = v->u.array.items[i]->type;
            if (t == JSON_OBJECT || t == JSON_ARRAY) {
                all_scalar = 0;
                break;
            }
        }

        if (all_scalar && s->pretty) {
            for (int i = 0; i < v->u.array.count; i++) {
                if (i > 0) {
                    ser_char(s, ',');
                    ser_char(s, ' ');
                }
                ser_value(s, v->u.array.items[i]);
            }
        } else {
            ser_newline(s);
            s->depth++;
            for (int i = 0; i < v->u.array.count; i++) {
                ser_indent(s);
                ser_value(s, v->u.array.items[i]);
                if (i < v->u.array.count - 1)
                    ser_char(s, ',');
                ser_newline(s);
            }
            s->depth--;
            ser_indent(s);
        }
    }
    ser_char(s, ']');
}

static void ser_value(serializer_t *s, const json_value_t *v)
{
    if (!v) {
        ser_append(s, "null", 4);
        return;
    }

    switch (v->type) {
    case JSON_NULL:
        ser_append(s, "null", 4);
        break;
    case JSON_BOOL:
        if (v->u.boolean)
            ser_append(s, "true", 4);
        else
            ser_append(s, "false", 5);
        break;
    case JSON_NUMBER: {
        char num[64];
        double d = v->u.number;
        if (d == (double)(long long)d && fabs(d) < 1e15)
            snprintf(num, sizeof(num), "%lld", (long long)d);
        else
            snprintf(num, sizeof(num), "%.17g", d);
        ser_append(s, num, strlen(num));
        break;
    }
    case JSON_STRING:
        ser_string(s, v->u.string);
        break;
    case JSON_ARRAY:
        ser_array(s, v);
        break;
    case JSON_OBJECT:
        ser_object(s, v);
        break;
    }
}

char *json_serialize(const json_value_t *val, int pretty)
{
    serializer_t s = {0};
    s.pretty = pretty;
    ser_value(&s, val);
    ser_newline(&s);
    return s.buf;
}

/* ── Accessors ─────────────────────────────────────────────────────── */

json_value_t *json_object_get(const json_value_t *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJECT)
        return NULL;
    for (int i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.keys[i], key) == 0)
            return obj->u.object.values[i];
    }
    return NULL;
}

int json_object_count(const json_value_t *obj)
{
    if (!obj || obj->type != JSON_OBJECT)
        return 0;
    return obj->u.object.count;
}

json_value_t *json_array_get(const json_value_t *arr, int index)
{
    if (!arr || arr->type != JSON_ARRAY)
        return NULL;
    if (index < 0 || index >= arr->u.array.count)
        return NULL;
    return arr->u.array.items[index];
}

int json_array_count(const json_value_t *arr)
{
    if (!arr || arr->type != JSON_ARRAY)
        return 0;
    return arr->u.array.count;
}

const char *json_string_value(const json_value_t *val)
{
    if (!val || val->type != JSON_STRING)
        return NULL;
    return val->u.string;
}

double json_number_value(const json_value_t *val)
{
    if (!val || val->type != JSON_NUMBER)
        return 0.0;
    return val->u.number;
}

int json_bool_value(const json_value_t *val)
{
    if (!val || val->type != JSON_BOOL)
        return 0;
    return val->u.boolean;
}

int json_is_null(const json_value_t *val)
{
    return !val || val->type == JSON_NULL;
}

/* ── Builders ──────────────────────────────────────────────────────── */

json_value_t *json_new_object(void)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v)
        v->type = JSON_OBJECT;
    return v;
}

json_value_t *json_new_array(void)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v)
        v->type = JSON_ARRAY;
    return v;
}

json_value_t *json_new_string(const char *s)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v) {
        v->type = JSON_STRING;
        v->u.string = strdup(s ? s : "");
    }
    return v;
}

json_value_t *json_new_number(double n)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v) {
        v->type = JSON_NUMBER;
        v->u.number = n;
    }
    return v;
}

json_value_t *json_new_bool(int b)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v) {
        v->type = JSON_BOOL;
        v->u.boolean = b ? 1 : 0;
    }
    return v;
}

json_value_t *json_new_null(void)
{
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (v)
        v->type = JSON_NULL;
    return v;
}

int json_object_set(json_value_t *obj, const char *key, json_value_t *val)
{
    if (!obj || obj->type != JSON_OBJECT || !key)
        return -1;

    /* Overwrite if key exists */
    for (int i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.keys[i], key) == 0) {
            json_free(obj->u.object.values[i]);
            obj->u.object.values[i] = val;
            return 0;
        }
    }

    /* Grow if needed */
    if (obj->u.object.count >= obj->u.object.capacity) {
        int newcap = obj->u.object.capacity < 8 ? 8 : obj->u.object.capacity * 2;
        char **nk = realloc(obj->u.object.keys, sizeof(char *) * (size_t)newcap);
        json_value_t **nv = realloc(obj->u.object.values, sizeof(json_value_t *) * (size_t)newcap);
        if (!nk || !nv)
            return -1;
        obj->u.object.keys = nk;
        obj->u.object.values = nv;
        obj->u.object.capacity = newcap;
    }

    obj->u.object.keys[obj->u.object.count] = strdup(key);
    obj->u.object.values[obj->u.object.count] = val;
    obj->u.object.count++;
    return 0;
}

int json_array_append(json_value_t *arr, json_value_t *val)
{
    if (!arr || arr->type != JSON_ARRAY)
        return -1;

    if (arr->u.array.count >= arr->u.array.capacity) {
        int newcap = arr->u.array.capacity < 8 ? 8 : arr->u.array.capacity * 2;
        json_value_t **ni = realloc(arr->u.array.items, sizeof(json_value_t *) * (size_t)newcap);
        if (!ni)
            return -1;
        arr->u.array.items = ni;
        arr->u.array.capacity = newcap;
    }

    arr->u.array.items[arr->u.array.count++] = val;
    return 0;
}
