#include "args.h"

#include <string.h>

/* Map a bare (non-flag) token to a command, or CMD_NONE if it is not one. */
static Cmd cmd_from_word(const char *w)
{
    if (strcmp(w, "register") == 0) return CMD_REGISTER;
    if (strcmp(w, "create")   == 0) return CMD_CREATE;
    if (strcmp(w, "write")    == 0) return CMD_WRITE;
    if (strcmp(w, "read")     == 0) return CMD_READ;
    return CMD_NONE;
}

/*
 * Validate the parsed request against the per-command contract.
 * Returns 1 if the combination is acceptable, 0 otherwise.
 *
 * Rules (see README "verify against test suite" list):
 *   register : needs -u -k ; rejects -f -i -o and inline text
 *   create   : needs -u -f ; -k ignored ; rejects -i -o and inline text
 *   write    : needs -u -k -f ; rejects -o ; input from -i / text / stdin
 *   read     : needs -u -k -f ; rejects -i and inline text ; -o optional
 */
static int validate(const Request *r)
{
    if (r->cmd == CMD_NONE || r->user == NULL)
        return 0;

    switch (r->cmd) {
    case CMD_REGISTER:
        if (r->key == NULL) return 0;
        if (r->file || r->infile || r->outfile || r->have_text) return 0;
        return 1;
    case CMD_CREATE:
        if (r->file == NULL) return 0;
        if (r->infile || r->outfile || r->have_text) return 0;
        return 1;
    case CMD_WRITE:
        if (r->key == NULL || r->file == NULL) return 0;
        if (r->outfile) return 0;
        return 1;
    case CMD_READ:
        if (r->key == NULL || r->file == NULL) return 0;
        if (r->infile || r->have_text) return 0;
        return 1;
    default:
        return 0;
    }
}

int args_parse(int argc, char **argv, Request *req)
{
    int i;

    memset(req, 0, sizeof(*req));

    for (i = 1; i < argc; i++) {
        char *tok = argv[i];

        if (tok[0] == '-' && tok[1] != '\0' && tok[2] == '\0') {
            /* A recognised single-letter flag consumes the next token. */
            const char **dst = NULL;
            switch (tok[1]) {
            case 'u': dst = &req->user;    break;
            case 'k': dst = &req->key;     break;
            case 'f': dst = &req->file;    break;
            case 'i': dst = &req->infile;  break;
            case 'o': dst = &req->outfile; break;
            default:  return 0;            /* unknown flag */
            }
            if (i + 1 >= argc)
                return 0;                  /* flag missing its argument */
            *dst = argv[++i];              /* last occurrence wins */
            continue;
        }

        if (tok[0] == '-' && tok[1] != '\0') {
            /* Multi-char token starting with '-' is not a known flag. */
            return 0;
        }

        /* Bare word: either the command or the inline text (exactly one each). */
        {
            Cmd c = cmd_from_word(tok);
            if (c != CMD_NONE) {
                if (req->cmd != CMD_NONE && req->cmd != c)
                    return 0;              /* two distinct commands */
                req->cmd = c;
            } else {
                if (req->have_text)
                    return 0;              /* more than one positional text */
                req->text = tok;
                req->have_text = 1;
            }
        }
    }

    return validate(req);
}
