#ifndef STOR_DB_H
#define STOR_DB_H

#include <stdint.h>

/*
 * In-memory model of the store plus (de)serialization to a single on-disk
 * file (enc.db). The on-disk encoding is PRIVATE to db.c.
 *
 * Security model (libsodium):
 *   - A user's command-line key is a PASSWORD. We never store it. At register
 *     time we draw a random salt and derive a 256-bit key with Argon2id
 *     (crypto_pwhash); a small "verifier" token sealed under that key lets us
 *     reject wrong passwords on later operations (even on empty files).
 *   - File content is stored as nonce||secretbox(K, plaintext): XSalsa20 +
 *     Poly1305 authenticated encryption keyed by the OWNER's derived key K.
 *     This gives confidentiality AND integrity per record: content cannot be
 *     tampered with, forged, or moved to another user without that user's
 *     password. There is no global secret, so there is no global db MAC -- the
 *     per-record AE is what defeats structural forgery.
 *
 * Nothing outside db.c knows the crypto layout: callers pass the password
 * string in and get plaintext back; the derived key never leaves this module.
 */

typedef struct {
    char          *name;
    unsigned char *salt;        /* random KDF salt (crypto_pwhash_SALTBYTES) */
    uint32_t       salt_len;
    unsigned char *verifier;    /* vnonce || secretbox(K, token) */
    uint32_t       verifier_len;
    uint32_t       opslimit;    /* Argon2id params used for THIS user, so a */
    uint32_t       memlimit;    /* future tuning never breaks old records.  */
} User;

typedef struct {
    char          *owner;
    char          *name;
    unsigned char *content;     /* empty (len 0) OR nonce||ciphertext */
    uint32_t       content_len;
} File;

typedef struct {
    User    *users;
    uint32_t nuser;
    File    *files;
    uint32_t nfile;
} Db;

/*
 * Load the store from `path`. A missing file is NOT an error: it yields an
 * empty Db (first run). Returns NULL only on allocation failure or a corrupt
 * file. The returned Db must be released with db_free().
 */
Db *db_load(const char *path);

/* Persist the Db to `path` atomically (temp file + rename). 0 on success. */
int db_save(const Db *db, const char *path);

/* Release a Db and everything it owns. Safe on NULL. */
void db_free(Db *db);

/* Lookups return a pointer into the Db (do not free), or NULL if absent. */
User *db_find_user(Db *db, const char *name);
File *db_find_file(Db *db, const char *owner, const char *name);

/*
 * Register a user: derive crypto material from `key` (the password). Returns 0
 * on success, non-zero on allocation/crypto failure. Caller checks for an
 * existing user first.
 */
int db_add_user(Db *db, const char *name, const char *key);

/* Create an empty file owned by `owner`. Returns 0 on success. */
int db_add_file(Db *db, const char *owner, const char *name);

/*
 * Authenticate `key` against user `u`, then encrypt `pt` (len bytes) and store
 * it as the content of file `f`. Returns 0 on success, non-zero on a wrong
 * password or any crypto/allocation failure.
 */
int db_write_content(File *f, const User *u, const char *key,
                     const unsigned char *pt, uint32_t len);

/*
 * Authenticate `key` against user `u`, then decrypt the content of file `f`
 * into a freshly malloc'd buffer (*pt_out, caller frees) of length *len_out.
 * Returns 0 on success, non-zero on a wrong password, tampered ciphertext, or
 * allocation failure. An empty file yields a valid 0-length result.
 */
int db_read_content(const File *f, const User *u, const char *key,
                    unsigned char **pt_out, uint32_t *len_out);

#endif /* STOR_DB_H */
