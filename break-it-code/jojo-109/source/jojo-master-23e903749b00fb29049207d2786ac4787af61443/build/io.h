#ifndef STOR_IO_H
#define STOR_IO_H

#include <stdint.h>

#include "args.h"

/*
 * Resolve the write input according to precedence:
 *   1. -i infile   (whole file)
 *   2. inline text (the bare positional)
 *   3. stdin       (read until EOF)
 *
 * Returns a freshly malloc'd buffer (caller frees) and sets *len. Returns NULL
 * on failure (e.g. -i points at an unreadable file) -> caller emits "invalid".
 * An empty input is a valid result: a non-NULL buffer with *len == 0.
 */
unsigned char *io_read_input(const Request *req, uint32_t *len);

/*
 * Emit `len` bytes either to -o outfile (created/overwritten) or, if no -o was
 * given, to stdout verbatim with no added trailing newline. Returns 0 on
 * success, non-zero on failure.
 */
int io_write_output(const Request *req, const unsigned char *buf, uint32_t len);

#endif /* STOR_IO_H */
