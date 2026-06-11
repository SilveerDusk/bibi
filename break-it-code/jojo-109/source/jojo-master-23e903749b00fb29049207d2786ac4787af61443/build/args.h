#ifndef STOR_ARGS_H
#define STOR_ARGS_H

/* Command selected on the command line. CMD_NONE means none was given. */
typedef enum {
    CMD_NONE = 0,
    CMD_REGISTER,
    CMD_CREATE,
    CMD_WRITE,
    CMD_READ
} Cmd;

/*
 * A fully parsed and validated command-line request.
 *
 * All string pointers alias into argv (which lives for the whole process), so
 * the Request itself owns no heap memory and never needs to be freed.
 */
typedef struct {
    Cmd         cmd;
    const char *user;    /* -u */
    const char *key;     /* -k */
    const char *file;    /* -f */
    const char *infile;  /* -i */
    const char *outfile; /* -o */
    const char *text;    /* lone non-flag positional: inline write content */
    int         have_text;
} Request;

/*
 * Parse argv into *req, applying "last occurrence wins" for repeated flags and
 * validating the flag combination against the selected command.
 *
 * Returns 1 on success, 0 if the arguments are missing/contradictory/unknown
 * (the caller should then emit the "invalid"/255 error contract).
 */
int args_parse(int argc, char **argv, Request *req);

#endif /* STOR_ARGS_H */
