#ifndef FIREWALLO_MIME_H
#define FIREWALLO_MIME_H

/* Return MIME type for a file extension. Returns "application/octet-stream" if unknown. */
const char *mime_type_for(const char *filename);

#endif /* FIREWALLO_MIME_H */
