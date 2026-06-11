#include <stdio.h>
#include <stdlib.h>

#include <sodium.h>

#include "args.h"
#include "cmd.h"
#include "db.h"

#define DB_PATH "enc.db"

/*
 * Required by the Build-It/Break-It contest: a function that demonstrates
 * arbitrary access. It is never called during normal operation; an attacker
 * who hijacks control flow (the executable stack is the target) would jump
 * here. Kept as a non-static global so -O0 always emits it.
 */
void win(void)
{
    puts("Arbitrary access achieved!");
}

/* Emit the error contract and terminate. Never returns. */
static void fail(void)
{
    /* "invalid" to stdout, exit 255. README flags whether the trailing newline
     * matters; swap to fputs("invalid", stdout) if the grader wants no newline. */
    puts("invalid");
    exit(255);
}

int main(int argc, char **argv)
{
    Request req;
    Db *db;
    int rc, mutating;

    /* libsodium must be initialised before any crypto in db.c. */
    if (sodium_init() < 0)
        fail();

    if (!args_parse(argc, argv, &req))
        fail();

    db = db_load(DB_PATH);
    if (!db)
        fail();

    switch (req.cmd) {
    case CMD_REGISTER: rc = cmd_register(db, &req); break;
    case CMD_CREATE:   rc = cmd_create(db, &req);   break;
    case CMD_WRITE:    rc = cmd_write(db, &req);    break;
    case CMD_READ:     rc = cmd_read(db, &req);     break;
    default:           rc = -1;                     break;
    }

    if (rc != 0) {
        db_free(db);
        fail();
    }

    mutating = (req.cmd == CMD_REGISTER ||
                req.cmd == CMD_CREATE ||
                req.cmd == CMD_WRITE);
    if (mutating && db_save(db, DB_PATH) != 0) {
        db_free(db);
        fail();
    }

    db_free(db);
    return 0;
}
