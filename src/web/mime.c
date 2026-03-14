#include "firewallo/mime.h"
#include <string.h>

static const struct {
    const char *ext;
    const char *mime;
} mime_table[] = {
    {".html", "text/html; charset=utf-8"},
    {".htm",  "text/html; charset=utf-8"},
    {".css",  "text/css; charset=utf-8"},
    {".js",   "application/javascript; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".png",  "image/png"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif",  "image/gif"},
    {".svg",  "image/svg+xml"},
    {".ico",  "image/x-icon"},
    {".txt",  "text/plain; charset=utf-8"},
    {".xml",  "application/xml"},
    {".woff", "font/woff"},
    {".woff2","font/woff2"},
    {".ttf",  "font/ttf"},
    {NULL, NULL}
};

const char *mime_type_for(const char *filename)
{
    if (!filename)
        return "application/octet-stream";

    const char *dot = strrchr(filename, '.');
    if (!dot)
        return "application/octet-stream";

    for (int i = 0; mime_table[i].ext; i++) {
        if (strcmp(dot, mime_table[i].ext) == 0)
            return mime_table[i].mime;
    }

    return "application/octet-stream";
}
