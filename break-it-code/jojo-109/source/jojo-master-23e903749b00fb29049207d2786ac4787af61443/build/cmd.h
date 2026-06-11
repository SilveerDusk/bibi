#ifndef STOR_CMD_H
#define STOR_CMD_H

#include "args.h"
#include "db.h"

/*
 * Business logic for each command, operating over the in-memory Db.
 * Each returns 0 on success or non-zero on any failure (unknown user, wrong
 * key, missing/duplicate file, I/O error) -> caller emits "invalid"/255.
 *
 * cmd_register / cmd_create / cmd_write mutate the Db; the caller persists it
 * on success. cmd_read does not mutate the Db.
 */
int cmd_register(Db *db, const Request *req);
int cmd_create(Db *db, const Request *req);
int cmd_write(Db *db, const Request *req);
int cmd_read(Db *db, const Request *req);

#endif /* STOR_CMD_H */
