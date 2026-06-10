/*
 * stor.c — BiBiFi secure encrypted file store.
 *
 * Cryptographic primitives (all via libsodium):
 *   - Key derivation : Argon2id  (crypto_pwhash)
 *   - Authenticated encryption : XChaCha20-Poly1305  (crypto_aead_xchacha20poly1305_ietf)
 *   - Secure memory  : sodium_memzero, sodium_memcmp
 *   - CSPRNG         : randombytes_buf
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 *   actions: register | create | write | read
 *
 * Rules:
 *   - On ANY error: print exactly "invalid" to stdout and exit 255.
 *   - On success: exit 0.
 *   - State persisted in "enc.db" (current directory).
 *   - The win() function MUST remain — do not remove it.
 *   - Must link against malloc-2.7.2.c (dlmalloc).
 *   - Build flags: -O0 -g -m32 -fno-stack-protector + execstack.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sodium.h>

/* ================================================================
 * Constants
 * ================================================================ */

#define DB_FILE          "enc.db"
#define DB_TMP_FILE      "enc.db.tmp"
#define DB_MAGIC         "STOR"
#define DB_MAGIC_LEN     4
#define DB_VERSION       1

/* Libsodium sizes */
#define ENC_KEY_LEN      crypto_aead_xchacha20poly1305_ietf_KEYBYTES   /* 32 */
#define NONCE_LEN        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  /* 24 */
#define TAG_LEN          crypto_aead_xchacha20poly1305_ietf_ABYTES     /* 16 */
#define SALT_LEN         crypto_pwhash_SALTBYTES                        /* 16 */

/* Derived-key layout: first 32 bytes = encryption key, next 32 = verify token */
#define VERIFY_LEN       32
#define DERIVED_LEN      (ENC_KEY_LEN + VERIFY_LEN)                    /* 64 */

/* Safety limits — reject obviously malicious input */
#define MAX_STR_LEN      4096
#define MAX_CONTENT_LEN  (500UL * 1024 * 1024)   /* 500 MiB */
#define MAX_DB_SIZE      (600UL * 1024 * 1024)   /* 600 MiB */
#define MAX_RECORDS      100000

/* ================================================================
 * Required function — do NOT remove
 * ================================================================ */

void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* Print "invalid" and return 255 — every error path uses this. */
static int invalid(void) {
    printf("invalid");
    return 255;
}

/* ================================================================
 * Data structures
 * ================================================================ */

typedef struct {
    uint32_t      username_len;
    char         *username;          /* heap-allocated, NUL-terminated      */
    unsigned char salt[SALT_LEN];    /* random per-user, for Argon2id       */
    unsigned char verify[VERIFY_LEN];/* derived verify token (constant-time)*/
} UserRecord;

typedef struct {
    uint32_t      owner_len;
    char         *owner;             /* heap-allocated, NUL-terminated */
    uint32_t      filename_len;
    char         *filename;          /* heap-allocated, NUL-terminated */
    unsigned char nonce[NONCE_LEN];  /* random per-write                */
    uint32_t      ciphertext_len;    /* 0 = created but never written   */
    unsigned char *ciphertext;       /* AEAD ciphertext (content + tag) */
} FileRecord;

typedef struct {
    uint32_t    num_users;
    UserRecord *users;
    uint32_t    num_files;
    FileRecord *files;
} Database;

/* ================================================================
 * Read buffer — safe deserialization with bounds checking
 * ================================================================ */

typedef struct {
    const unsigned char *data;
    size_t size;
    size_t pos;
} ReadBuf;

/* Read exactly `len` bytes.  Returns 0 on success, -1 if out-of-bounds. */
static int rbuf_read(ReadBuf *b, void *out, size_t len) {
    if (len == 0) return 0;
    /* Overflow check */
    if (b->pos + len < b->pos) return -1;
    if (b->pos + len > b->size) return -1;
    memcpy(out, b->data + b->pos, len);
    b->pos += len;
    return 0;
}

static int rbuf_read_u32(ReadBuf *b, uint32_t *out) {
    return rbuf_read(b, out, sizeof(uint32_t));
}

/* ================================================================
 * Write buffer — safe serialization with dynamic growth
 * ================================================================ */

typedef struct {
    unsigned char *data;
    size_t size;
    size_t cap;
} WriteBuf;

static int wbuf_init(WriteBuf *wb, size_t initial) {
    wb->data = malloc(initial);
    if (!wb->data) return -1;
    wb->size = 0;
    wb->cap  = initial;
    return 0;
}

static int wbuf_write(WriteBuf *wb, const void *src, size_t len) {
    if (len == 0) return 0;
    /* Overflow check */
    if (wb->size + len < wb->size) return -1;
    while (wb->size + len > wb->cap) {
        if (wb->cap > ((size_t)-1) / 2) return -1;
        size_t new_cap = wb->cap * 2;
        unsigned char *tmp = realloc(wb->data, new_cap);
        if (!tmp) return -1;
        wb->data = tmp;
        wb->cap  = new_cap;
    }
    memcpy(wb->data + wb->size, src, len);
    wb->size += len;
    return 0;
}

static int wbuf_write_u32(WriteBuf *wb, uint32_t val) {
    return wbuf_write(wb, &val, sizeof(uint32_t));
}

static void wbuf_free(WriteBuf *wb) {
    if (wb->data) {
        sodium_memzero(wb->data, wb->size);
        free(wb->data);
    }
    wb->data = NULL;
    wb->size = 0;
    wb->cap  = 0;
}

/* ================================================================
 * Database helpers
 * ================================================================ */

static void db_init(Database *db) {
    memset(db, 0, sizeof(Database));
}

static void db_free(Database *db) {
    uint32_t i;
    if (db->users) {
        for (i = 0; i < db->num_users; i++) {
            if (db->users[i].username) free(db->users[i].username);
            sodium_memzero(db->users[i].salt, SALT_LEN);
            sodium_memzero(db->users[i].verify, VERIFY_LEN);
        }
        free(db->users);
    }
    if (db->files) {
        for (i = 0; i < db->num_files; i++) {
            if (db->files[i].owner)    free(db->files[i].owner);
            if (db->files[i].filename) free(db->files[i].filename);
            if (db->files[i].ciphertext) {
                sodium_memzero(db->files[i].ciphertext,
                               db->files[i].ciphertext_len);
                free(db->files[i].ciphertext);
            }
        }
        free(db->files);
    }
    memset(db, 0, sizeof(Database));
}

/* ================================================================
 * enc.db  —  Load (deserialize)
 *
 * Format (all uint32_t are native-endian, i.e. little-endian on x86):
 *
 *   [4]  magic "STOR"
 *   [4]  version (1)
 *   [4]  num_users
 *   [4]  num_files
 *   --- per user ---
 *     [4]  username_len
 *     [N]  username
 *     [16] salt
 *     [32] verify_token
 *   --- per file ---
 *     [4]  owner_len
 *     [N]  owner
 *     [4]  filename_len
 *     [N]  filename
 *     [24] nonce
 *     [4]  ciphertext_len
 *     [M]  ciphertext
 *
 * Returns 0 on success (including "file not found" → empty DB).
 * Returns -1 on any parse/read error.
 * ================================================================ */

static int db_load(Database *db) {
    FILE *fp;
    long fsize;
    size_t size;
    unsigned char *data = NULL;
    uint32_t i;

    db_init(db);

    fp = fopen(DB_FILE, "rb");
    if (!fp) {
        /* No database yet → start with empty state */
        if (errno == ENOENT) return 0;
        return -1;
    }

    /* Read whole file into memory */
    if (fseek(fp, 0, SEEK_END) != 0)        { fclose(fp); return -1; }
    fsize = ftell(fp);
    if (fsize < 0)                           { fclose(fp); return -1; }
    if ((unsigned long)fsize > MAX_DB_SIZE)  { fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0)         { fclose(fp); return -1; }

    size = (size_t)fsize;
    if (size == 0)                           { fclose(fp); return 0; }

    data = malloc(size);
    if (!data)                               { fclose(fp); return -1; }
    if (fread(data, 1, size, fp) != size)    { free(data); fclose(fp); return -1; }
    fclose(fp);

    /* ---- Parse ---- */
    ReadBuf rb = { data, size, 0 };
    char magic[DB_MAGIC_LEN];
    uint32_t version;

    if (rbuf_read(&rb, magic, DB_MAGIC_LEN) != 0)           goto fail;
    if (memcmp(magic, DB_MAGIC, DB_MAGIC_LEN) != 0)         goto fail;
    if (rbuf_read_u32(&rb, &version) != 0)                   goto fail;
    if (version != DB_VERSION)                                goto fail;
    if (rbuf_read_u32(&rb, &db->num_users) != 0)            goto fail;
    if (db->num_users > MAX_RECORDS)                          goto fail;
    if (rbuf_read_u32(&rb, &db->num_files) != 0)            goto fail;
    if (db->num_files > MAX_RECORDS)                          goto fail;

    /* ---- User records ---- */
    if (db->num_users > 0) {
        db->users = calloc(db->num_users, sizeof(UserRecord));
        if (!db->users) goto fail;

        for (i = 0; i < db->num_users; i++) {
            UserRecord *u = &db->users[i];

            if (rbuf_read_u32(&rb, &u->username_len) != 0)  goto fail;
            if (u->username_len == 0 || u->username_len > MAX_STR_LEN) goto fail;

            u->username = malloc((size_t)u->username_len + 1);
            if (!u->username)                                goto fail;
            if (rbuf_read(&rb, u->username, u->username_len) != 0) goto fail;
            u->username[u->username_len] = '\0';

            /* Validate: username must not contain embedded NUL bytes */
            if (strlen(u->username) != u->username_len)      goto fail;

            if (rbuf_read(&rb, u->salt, SALT_LEN) != 0)     goto fail;
            if (rbuf_read(&rb, u->verify, VERIFY_LEN) != 0) goto fail;
        }
    }

    /* ---- File records ---- */
    if (db->num_files > 0) {
        db->files = calloc(db->num_files, sizeof(FileRecord));
        if (!db->files) goto fail;

        for (i = 0; i < db->num_files; i++) {
            FileRecord *f = &db->files[i];

            if (rbuf_read_u32(&rb, &f->owner_len) != 0)     goto fail;
            if (f->owner_len == 0 || f->owner_len > MAX_STR_LEN) goto fail;

            f->owner = malloc((size_t)f->owner_len + 1);
            if (!f->owner)                                    goto fail;
            if (rbuf_read(&rb, f->owner, f->owner_len) != 0) goto fail;
            f->owner[f->owner_len] = '\0';
            if (strlen(f->owner) != f->owner_len)            goto fail;

            if (rbuf_read_u32(&rb, &f->filename_len) != 0)  goto fail;
            if (f->filename_len == 0 || f->filename_len > MAX_STR_LEN) goto fail;

            f->filename = malloc((size_t)f->filename_len + 1);
            if (!f->filename)                                 goto fail;
            if (rbuf_read(&rb, f->filename, f->filename_len) != 0) goto fail;
            f->filename[f->filename_len] = '\0';
            if (strlen(f->filename) != f->filename_len)      goto fail;

            if (rbuf_read(&rb, f->nonce, NONCE_LEN) != 0)   goto fail;

            if (rbuf_read_u32(&rb, &f->ciphertext_len) != 0) goto fail;
            /* ciphertext_len == 0 is valid (created, never written) */
            if (f->ciphertext_len > MAX_CONTENT_LEN + TAG_LEN) goto fail;

            if (f->ciphertext_len > 0) {
                f->ciphertext = malloc(f->ciphertext_len);
                if (!f->ciphertext)                           goto fail;
                if (rbuf_read(&rb, f->ciphertext, f->ciphertext_len) != 0)
                    goto fail;
            }
        }
    }

    free(data);
    return 0;

fail:
    db_free(db);
    db_init(db);
    free(data);
    return -1;
}

/* ================================================================
 * enc.db  —  Save (serialize)
 *
 * Writes to a temp file then renames for atomicity.
 * Returns 0 on success, -1 on error.
 * ================================================================ */

static int db_save(const Database *db) {
    WriteBuf wb;
    uint32_t i;
    FILE *fp;

    if (wbuf_init(&wb, 4096) != 0) return -1;

    /* Header */
    if (wbuf_write(&wb, DB_MAGIC, DB_MAGIC_LEN) != 0)  goto fail;
    if (wbuf_write_u32(&wb, DB_VERSION) != 0)           goto fail;
    if (wbuf_write_u32(&wb, db->num_users) != 0)        goto fail;
    if (wbuf_write_u32(&wb, db->num_files) != 0)        goto fail;

    /* User records */
    for (i = 0; i < db->num_users; i++) {
        const UserRecord *u = &db->users[i];
        if (wbuf_write_u32(&wb, u->username_len) != 0)  goto fail;
        if (wbuf_write(&wb, u->username, u->username_len) != 0) goto fail;
        if (wbuf_write(&wb, u->salt, SALT_LEN) != 0)    goto fail;
        if (wbuf_write(&wb, u->verify, VERIFY_LEN) != 0) goto fail;
    }

    /* File records */
    for (i = 0; i < db->num_files; i++) {
        const FileRecord *f = &db->files[i];
        if (wbuf_write_u32(&wb, f->owner_len) != 0)     goto fail;
        if (wbuf_write(&wb, f->owner, f->owner_len) != 0) goto fail;
        if (wbuf_write_u32(&wb, f->filename_len) != 0)  goto fail;
        if (wbuf_write(&wb, f->filename, f->filename_len) != 0) goto fail;
        if (wbuf_write(&wb, f->nonce, NONCE_LEN) != 0)  goto fail;
        if (wbuf_write_u32(&wb, f->ciphertext_len) != 0) goto fail;
        if (f->ciphertext_len > 0) {
            if (wbuf_write(&wb, f->ciphertext, f->ciphertext_len) != 0)
                goto fail;
        }
    }

    /* Atomic write: tmp file → rename */
    fp = fopen(DB_TMP_FILE, "wb");
    if (!fp) goto fail;

    if (fwrite(wb.data, 1, wb.size, fp) != wb.size) {
        fclose(fp);
        remove(DB_TMP_FILE);
        goto fail;
    }
    if (fflush(fp) != 0) {
        fclose(fp);
        remove(DB_TMP_FILE);
        goto fail;
    }
    if (fclose(fp) != 0) {
        remove(DB_TMP_FILE);
        goto fail;
    }
    if (rename(DB_TMP_FILE, DB_FILE) != 0) {
        remove(DB_TMP_FILE);
        goto fail;
    }

    wbuf_free(&wb);
    return 0;

fail:
    wbuf_free(&wb);
    return -1;
}

/* ================================================================
 * Lookup helpers
 * ================================================================ */

static UserRecord *db_find_user(const Database *db, const char *username) {
    uint32_t i;
    for (i = 0; i < db->num_users; i++) {
        if (strcmp(db->users[i].username, username) == 0)
            return &db->users[i];
    }
    return NULL;
}

static FileRecord *db_find_file(const Database *db,
                                 const char *owner,
                                 const char *filename) {
    uint32_t i;
    for (i = 0; i < db->num_files; i++) {
        if (strcmp(db->files[i].owner, owner) == 0 &&
            strcmp(db->files[i].filename, filename) == 0)
            return &db->files[i];
    }
    return NULL;
}

/* ================================================================
 * Cryptography
 * ================================================================ */

/*
 * Derive a 64-byte value from password + salt using Argon2id.
 *   bytes  0..31 → encryption key  (for AEAD)
 *   bytes 32..63 → verify token    (stored in user record)
 *
 * By deriving both from a single pwhash call, authentication
 * and key derivation cost only one Argon2id invocation.
 */
static int derive_key(const char *password, size_t password_len,
                      const unsigned char *salt,
                      unsigned char *enc_key_out,
                      unsigned char *verify_out) {
    unsigned char derived[DERIVED_LEN];

    if (crypto_pwhash(derived, DERIVED_LEN,
                      password, password_len,
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_memzero(derived, DERIVED_LEN);
        return -1;
    }

    memcpy(enc_key_out, derived, ENC_KEY_LEN);
    memcpy(verify_out, derived + ENC_KEY_LEN, VERIFY_LEN);
    sodium_memzero(derived, DERIVED_LEN);
    return 0;
}

/*
 * Authenticate: verify the user's password and obtain the encryption key.
 * Returns 0 on success (key written to enc_key_out), -1 on failure.
 */
static int authenticate(const Database *db,
                         const char *username, const char *password,
                         unsigned char *enc_key_out) {
    unsigned char enc_key[ENC_KEY_LEN];
    unsigned char verify[VERIFY_LEN];

    UserRecord *u = db_find_user(db, username);
    if (!u) return -1;

    if (derive_key(password, strlen(password), u->salt,
                   enc_key, verify) != 0) {
        return -1;
    }

    /* Constant-time comparison — prevents timing side-channel */
    if (sodium_memcmp(verify, u->verify, VERIFY_LEN) != 0) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        sodium_memzero(verify,  VERIFY_LEN);
        return -1;
    }

    memcpy(enc_key_out, enc_key, ENC_KEY_LEN);
    sodium_memzero(enc_key, ENC_KEY_LEN);
    sodium_memzero(verify,  VERIFY_LEN);
    return 0;
}

/*
 * Build AEAD associated data: owner || '\0' || filename
 *
 * The NUL separator removes ambiguity (e.g. "ab"+"cd" vs "a"+"bcd").
 * Binding AD to the ciphertext means swapping records between
 * different owner/filename pairs will cause decryption to fail.
 */
static unsigned char *build_ad(const char *owner, uint32_t owner_len,
                                const char *filename, uint32_t filename_len,
                                size_t *ad_len_out) {
    size_t ad_len = (size_t)owner_len + 1 + (size_t)filename_len;
    unsigned char *ad = malloc(ad_len);
    if (!ad) return NULL;

    memcpy(ad, owner, owner_len);
    ad[owner_len] = '\0';
    memcpy(ad + owner_len + 1, filename, filename_len);
    *ad_len_out = ad_len;
    return ad;
}

/* ================================================================
 * Command implementations
 * ================================================================ */

/*
 * register — create a new user account.
 *   - Requires: -u and -k
 *   - Rejects duplicate usernames.
 *   - Generates random salt, derives key, stores verify token.
 */
static int do_register(Database *db,
                        const char *user, const char *key) {
    UserRecord *new_users;
    UserRecord *u;
    unsigned char enc_key[ENC_KEY_LEN];

    /* Reject duplicate */
    if (db_find_user(db, user) != NULL) return -1;

    /* Capacity check */
    if (db->num_users >= MAX_RECORDS) return -1;

    /* Grow users array */
    new_users = realloc(db->users,
                        (size_t)(db->num_users + 1) * sizeof(UserRecord));
    if (!new_users) return -1;
    db->users = new_users;

    u = &db->users[db->num_users];
    memset(u, 0, sizeof(UserRecord));

    /* Username */
    u->username_len = (uint32_t)strlen(user);
    u->username = malloc((size_t)u->username_len + 1);
    if (!u->username) return -1;
    memcpy(u->username, user, (size_t)u->username_len + 1);

    /* Random salt */
    randombytes_buf(u->salt, SALT_LEN);

    /* Key derivation */
    if (derive_key(key, strlen(key), u->salt, enc_key, u->verify) != 0) {
        free(u->username);
        u->username = NULL;
        return -1;
    }

    sodium_memzero(enc_key, ENC_KEY_LEN);
    db->num_users++;
    return 0;
}

/*
 * create — create an empty file owned by a user.
 *   - Requires: -u and -f
 *   - Does NOT require -k.
 *   - If the file already exists for this user: no-op (exit 0).
 *   - User must be registered.
 */
static int do_create(Database *db,
                      const char *user, const char *filename) {
    FileRecord *new_files;
    FileRecord *f;

    /* User must exist */
    if (db_find_user(db, user) == NULL) return -1;

    /* Already exists → no-op */
    if (db_find_file(db, user, filename) != NULL) return 0;

    /* Capacity check */
    if (db->num_files >= MAX_RECORDS) return -1;

    /* Grow files array */
    new_files = realloc(db->files,
                        (size_t)(db->num_files + 1) * sizeof(FileRecord));
    if (!new_files) return -1;
    db->files = new_files;

    f = &db->files[db->num_files];
    memset(f, 0, sizeof(FileRecord));

    /* Owner */
    f->owner_len = (uint32_t)strlen(user);
    f->owner = malloc((size_t)f->owner_len + 1);
    if (!f->owner) return -1;
    memcpy(f->owner, user, (size_t)f->owner_len + 1);

    /* Filename */
    f->filename_len = (uint32_t)strlen(filename);
    f->filename = malloc((size_t)f->filename_len + 1);
    if (!f->filename) {
        free(f->owner);
        f->owner = NULL;
        return -1;
    }
    memcpy(f->filename, filename, (size_t)f->filename_len + 1);

    /* Created with no content — ciphertext_len stays 0 */
    db->num_files++;
    return 0;
}

/*
 * write — encrypt and store content in a file.
 *   - Requires: -u, -k, -f
 *   - Content comes from -i file, positional arg, or empty string.
 *   - Authenticates the user's key before writing.
 *   - Encrypts with XChaCha20-Poly1305 AEAD.
 *   - Associated data = owner||'\0'||filename  (binds ciphertext to record).
 */
static int do_write(Database *db,
                     const char *user, const char *key,
                     const char *filename,
                     const unsigned char *content, size_t content_len) {
    unsigned char enc_key[ENC_KEY_LEN];
    FileRecord *f;
    unsigned char *ad = NULL;
    size_t ad_len;
    unsigned char *ct = NULL;
    unsigned long long ct_len;
    size_t ct_buf_len;

    /* Authenticate */
    if (authenticate(db, user, key, enc_key) != 0)
        return -1;

    /* Find file — must have been created first */
    f = db_find_file(db, user, filename);
    if (!f) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Build associated data */
    ad = build_ad(f->owner, f->owner_len, f->filename, f->filename_len,
                  &ad_len);
    if (!ad) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Fresh random nonce for every write */
    randombytes_buf(f->nonce, NONCE_LEN);

    /* Allocate ciphertext buffer  (plaintext + TAG_LEN) */
    ct_buf_len = content_len + TAG_LEN;
    ct = malloc(ct_buf_len > 0 ? ct_buf_len : 1);
    if (!ct) {
        free(ad);
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* AEAD encrypt */
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len,
            content, (unsigned long long)content_len,
            ad, (unsigned long long)ad_len,
            NULL,       /* nsec — unused by this construction */
            f->nonce,
            enc_key) != 0) {
        free(ct);
        free(ad);
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Replace old ciphertext */
    if (f->ciphertext) {
        sodium_memzero(f->ciphertext, f->ciphertext_len);
        free(f->ciphertext);
    }
    f->ciphertext     = ct;
    f->ciphertext_len = (uint32_t)ct_len;

    free(ad);
    sodium_memzero(enc_key, ENC_KEY_LEN);
    return 0;
}

/*
 * read — decrypt and output a file's content.
 *   - Requires: -u, -k, -f
 *   - Output goes to -o file or stdout.
 *   - Authenticates the user's key, then AEAD-decrypts.
 */
static int do_read(Database *db,
                    const char *user, const char *key,
                    const char *filename, const char *outfile) {
    unsigned char enc_key[ENC_KEY_LEN];
    FileRecord *f;
    unsigned char *ad = NULL;
    size_t ad_len;
    unsigned char *pt = NULL;
    unsigned long long pt_len;
    FILE *fp;

    /* Authenticate */
    if (authenticate(db, user, key, enc_key) != 0)
        return -1;

    /* Find file */
    f = db_find_file(db, user, filename);
    if (!f) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Empty file (created but never written) → output nothing */
    if (f->ciphertext_len == 0) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        if (outfile) {
            fp = fopen(outfile, "wb");
            if (!fp) return -1;
            fclose(fp);
        }
        /* stdout: nothing to write */
        return 0;
    }

    /* Sanity: ciphertext must be at least TAG_LEN */
    if (f->ciphertext_len < TAG_LEN) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Build associated data (must match what was used at encrypt time) */
    ad = build_ad(f->owner, f->owner_len, f->filename, f->filename_len,
                  &ad_len);
    if (!ad) {
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* Allocate plaintext buffer */
    pt = malloc(f->ciphertext_len);   /* at most ciphertext_len bytes */
    if (!pt) {
        free(ad);
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* AEAD decrypt — fails if ciphertext was tampered with */
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &pt_len,
            NULL,       /* nsec */
            f->ciphertext, (unsigned long long)f->ciphertext_len,
            ad, (unsigned long long)ad_len,
            f->nonce,
            enc_key) != 0) {
        /* Authentication failed — tampered data or wrong key */
        sodium_memzero(pt, f->ciphertext_len);
        free(pt);
        free(ad);
        sodium_memzero(enc_key, ENC_KEY_LEN);
        return -1;
    }

    /* ---- Output ---- */
    if (outfile) {
        fp = fopen(outfile, "wb");
        if (!fp) {
            sodium_memzero(pt, pt_len);
            free(pt);
            free(ad);
            sodium_memzero(enc_key, ENC_KEY_LEN);
            return -1;
        }
        if (pt_len > 0 && fwrite(pt, 1, (size_t)pt_len, fp) != (size_t)pt_len) {
            fclose(fp);
            sodium_memzero(pt, pt_len);
            free(pt);
            free(ad);
            sodium_memzero(enc_key, ENC_KEY_LEN);
            return -1;
        }
        fclose(fp);
    } else {
        /* stdout */
        if (pt_len > 0) {
            fwrite(pt, 1, (size_t)pt_len, stdout);
        }
    }

    sodium_memzero(pt, pt_len);
    free(pt);
    free(ad);
    sodium_memzero(enc_key, ENC_KEY_LEN);
    return 0;
}

/* ================================================================
 * Input reading (for the write command)
 *
 * Priority: -i file  >  positional arg  >  empty string
 * ================================================================ */

static int read_content(const char *infile, const char *text,
                         unsigned char **out, size_t *out_len) {
    FILE *fp;
    long fsize;
    size_t size;
    unsigned char *data;
    size_t len;

    if (infile) {
        fp = fopen(infile, "rb");
        if (!fp) return -1;

        if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
        fsize = ftell(fp);
        if (fsize < 0)                      { fclose(fp); return -1; }
        if ((size_t)fsize > MAX_CONTENT_LEN) { fclose(fp); return -1; }
        if (fseek(fp, 0, SEEK_SET) != 0)     { fclose(fp); return -1; }

        size = (size_t)fsize;
        if (size == 0) {
            fclose(fp);
            *out     = NULL;
            *out_len = 0;
            return 0;
        }

        data = malloc(size);
        if (!data) { fclose(fp); return -1; }

        if (fread(data, 1, size, fp) != size) {
            free(data);
            fclose(fp);
            return -1;
        }
        fclose(fp);

        *out     = data;
        *out_len = size;
        return 0;
    }

    if (text) {
        len = strlen(text);
        if (len > MAX_CONTENT_LEN) return -1;

        if (len == 0) {
            *out     = NULL;
            *out_len = 0;
            return 0;
        }

        data = malloc(len);
        if (!data) return -1;
        memcpy(data, text, len);

        *out     = data;
        *out_len = len;
        return 0;
    }

    /* No source → empty content */
    *out     = NULL;
    *out_len = 0;
    return 0;
}

/* ================================================================
 * main
 * ================================================================ */

int main(int argc, char **argv) {
    char *user    = NULL;
    char *key     = NULL;
    char *file    = NULL;
    char *infile  = NULL;
    char *outfile = NULL;
    int c;
    const char *action;
    const char *content_arg;
    Database db;
    int result;

    /* Initialize libsodium */
    if (sodium_init() < 0)
        return invalid();

    /* ---- Parse arguments ---- */
    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  return invalid();
        }
    }

    /* Validate: -u is always required, action is always required */
    if (!user)                        return invalid();
    if (strlen(user) == 0)            return invalid();
    if (strlen(user) > MAX_STR_LEN)   return invalid();
    if (optind >= argc)               return invalid();

    action      = argv[optind];
    content_arg = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    /* ---- Load database ---- */
    if (db_load(&db) != 0)
        return invalid();

    result = -1;

    /* ---- Dispatch ---- */
    if (strcmp(action, "register") == 0) {
        /* register: requires -u and -k */
        if (!key || strlen(key) == 0) {
            db_free(&db);
            return invalid();
        }

        result = do_register(&db, user, key);
        if (result == 0) {
            if (db_save(&db) != 0) {
                db_free(&db);
                return invalid();
            }
        }

    } else if (strcmp(action, "create") == 0) {
        /* create: requires -u and -f; does NOT require -k */
        if (!file || strlen(file) == 0 || strlen(file) > MAX_STR_LEN) {
            db_free(&db);
            return invalid();
        }

        result = do_create(&db, user, file);
        if (result == 0) {
            if (db_save(&db) != 0) {
                db_free(&db);
                return invalid();
            }
        }

    } else if (strcmp(action, "write") == 0) {
        /* write: requires -u, -k, -f */
        unsigned char *content_data = NULL;
        size_t content_len = 0;

        if (!key  || strlen(key)  == 0 ||
            !file || strlen(file) == 0 || strlen(file) > MAX_STR_LEN) {
            db_free(&db);
            return invalid();
        }

        if (read_content(infile, content_arg, &content_data, &content_len) != 0) {
            db_free(&db);
            return invalid();
        }

        result = do_write(&db, user, key, file,
                           content_data ? content_data : (const unsigned char *)"",
                           content_len);

        if (content_data) {
            sodium_memzero(content_data, content_len);
            free(content_data);
        }

        if (result == 0) {
            if (db_save(&db) != 0) {
                db_free(&db);
                return invalid();
            }
        }

    } else if (strcmp(action, "read") == 0) {
        /* read: requires -u, -k, -f */
        if (!key  || strlen(key)  == 0 ||
            !file || strlen(file) == 0 || strlen(file) > MAX_STR_LEN) {
            db_free(&db);
            return invalid();
        }

        result = do_read(&db, user, key, file, outfile);

    } else {
        /* Unknown action */
        db_free(&db);
        return invalid();
    }

    db_free(&db);

    if (result != 0)
        return invalid();

    return 0;
}
