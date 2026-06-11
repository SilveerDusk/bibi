#include "io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Upper bound on a single input so a hostile stream cannot exhaust memory. */
#define IO_MAX_INPUT (64u * 1024u * 1024u)

/* Read an open stream to EOF into a growable malloc'd buffer. */
static unsigned char *slurp(FILE *f, uint32_t *len)
{
    size_t cap = 4096, used = 0;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        size_t got;
        if (used == cap) {
            unsigned char *grown;
            if (cap > IO_MAX_INPUT) { free(buf); return NULL; }
            cap *= 2;
            grown = (unsigned char *)realloc(buf, cap);
            if (!grown) { free(buf); return NULL; }
            buf = grown;
        }
        got = fread(buf + used, 1, cap - used, f);
        used += got;
        if (got == 0) {
            if (ferror(f)) { free(buf); return NULL; }
            break;              /* EOF */
        }
        if (used > IO_MAX_INPUT) { free(buf); return NULL; }
    }

    *len = (uint32_t)used;
    return buf;                 /* may be 0 bytes; still a valid non-NULL buffer */
}

unsigned char *io_read_input(const Request *req, uint32_t *len)
{
    if (req->infile) {
        FILE *f = fopen(req->infile, "rb");
        unsigned char *buf;
        if (!f) return NULL;            /* -i unreadable => invalid */
        buf = slurp(f, len);
        fclose(f);
        return buf;
    }

    if (req->have_text) {
        size_t n = strlen(req->text);
        unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
        if (!buf) return NULL;
        if (n) memcpy(buf, req->text, n);
        *len = (uint32_t)n;
        return buf;
    }

    return slurp(stdin, len);
}

int io_write_output(const Request *req, const unsigned char *buf, uint32_t len)
{
    if (req->outfile) {
        FILE *f = fopen(req->outfile, "wb");
        int ok;
        if (!f) return -1;
        ok = (len == 0) || (fwrite(buf, 1, len, f) == len);
        if (fclose(f) != 0) ok = 0;
        return ok ? 0 : -1;
    }

    if (len && fwrite(buf, 1, len, stdout) != len) return -1;
    if (fflush(stdout) != 0) return -1;
    return 0;
}
