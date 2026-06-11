#include "cmd.h"

#include <stdlib.h>

#include "io.h"

int cmd_register(Db *db, const Request *req)
{
    if (db_find_user(db, req->user))
        return -1;                          /* already registered */
    return db_add_user(db, req->user, req->key);
}

int cmd_create(Db *db, const Request *req)
{
    if (!db_find_user(db, req->user))
        return -1;                          /* user must exist first */
    if (db_find_file(db, req->user, req->file))
        return -1;                          /* duplicate file */
    return db_add_file(db, req->user, req->file);
}

int cmd_write(Db *db, const Request *req)
{
    User *u = db_find_user(db, req->user);
    File *f;
    unsigned char *input;
    uint32_t len = 0;
    int rc;

    if (!u)
        return -1;
    f = db_find_file(db, req->user, req->file);
    if (!f)
        return -1;

    input = io_read_input(req, &len);
    if (!input)
        return -1;

    /* db_write_content authenticates the key, then encrypts under the owner's
     * derived key before storing. */
    rc = db_write_content(f, u, req->key, input, len);
    free(input);
    return rc;
}

int cmd_read(Db *db, const Request *req)
{
    User *u = db_find_user(db, req->user);
    File *f;
    unsigned char *plain = NULL;
    uint32_t len = 0;
    int rc;

    if (!u)
        return -1;
    f = db_find_file(db, req->user, req->file);
    if (!f)
        return -1;

    /* db_read_content authenticates the key, then decrypts the stored blob. */
    if (db_read_content(f, u, req->key, &plain, &len) != 0)
        return -1;

    rc = io_write_output(req, plain, len);
    free(plain);
    return rc;
}
