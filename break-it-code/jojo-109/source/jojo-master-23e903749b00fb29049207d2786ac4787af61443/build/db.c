#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

/*
 * On-disk format (little-endian, fixed-width), PRIVATE to this file:
 *
 *   magic   : 4 bytes  "STOR"
 *   version : uint32   = 2
 *   nuser   : uint32
 *     per user : { field name } { field salt } u32 ops u32 mem { field verifier }
 *   nfile   : uint32
 *     per file : { field owner } { field name } { field content }
 *
 * A "field" is { uint32 len, len bytes }. content is empty OR nonce||ciphertext.
 * uint32 lengths (never size_t) keep the layout identical on the 32-bit target.
 */

static const char  DB_MAGIC[4] = { 'S', 'T', 'O', 'R' };
#define DB_VERSION 2u

/* Cap a single field/record so a corrupt header cannot trigger a huge malloc. */
#define DB_MAX_FIELD (64u * 1024u * 1024u)

/* ---- crypto parameters (libsodium) ---- */

#define KDF_SALT_BYTES   crypto_pwhash_SALTBYTES       /* 16 */
#define DERIVED_KEYBYTES crypto_secretbox_KEYBYTES     /* 32 */
#define NONCE_BYTES      crypto_secretbox_NONCEBYTES   /* 24 */
#define MAC_BYTES        crypto_secretbox_MACBYTES      /* 16 */

#define VERIFIER_TOKEN_BYTES 16u
/* exactly 16 bytes (15 chars + terminating NUL fills the array) */
static const unsigned char VERIFIER_TOKEN[VERIFIER_TOKEN_BYTES] = "stor-verify-v2!";
#define VERIFIER_LEN (NONCE_BYTES + MAC_BYTES + VERIFIER_TOKEN_BYTES)

/* libsodium must be initialised once before any crypto call. Safe to call
 * repeatedly (returns 1 if already initialised). */
static int crypto_ready(void)
{
    return sodium_init() >= 0 ? 0 : -1;
}

/* Argon2id: password (+ user salt/params) -> 32-byte symmetric key. 0 on ok. */
static int derive_key(unsigned char K[DERIVED_KEYBYTES], const char *password,
                      const unsigned char *salt, uint32_t ops, uint32_t mem)
{
    return crypto_pwhash(K, DERIVED_KEYBYTES,
                         password, strlen(password),
                         salt,
                         (unsigned long long)ops, (size_t)mem,
                         crypto_pwhash_ALG_DEFAULT);
}

/*
 * Derive K from the supplied password and verify it against the user's stored
 * verifier. On success returns 0 with K populated (caller must wipe it). On a
 * wrong password / malformed verifier returns -1 with K wiped.
 */
static int auth_derive(const User *u, const char *key,
                       unsigned char K[DERIVED_KEYBYTES])
{
    unsigned char token[VERIFIER_TOKEN_BYTES];

    if (crypto_ready() != 0) return -1;
    if (u->salt_len != KDF_SALT_BYTES || u->verifier_len != VERIFIER_LEN)
        return -1;
    if (derive_key(K, key, u->salt, u->opslimit, u->memlimit) != 0) {
        sodium_memzero(K, DERIVED_KEYBYTES);
        return -1;
    }
    /* verifier = nonce(NONCE_BYTES) || secretbox(K, token) */
    if (crypto_secretbox_open_easy(token, u->verifier + NONCE_BYTES,
                                   MAC_BYTES + VERIFIER_TOKEN_BYTES,
                                   u->verifier, K) != 0) {
        sodium_memzero(K, DERIVED_KEYBYTES);
        return -1;                  /* wrong password */
    }
    sodium_memzero(token, sizeof token);
    return 0;
}

/* ---- small heap helpers (all via dlmalloc's malloc/free) ---- */

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static unsigned char *dup_bytes(const unsigned char *b, uint32_t n)
{
    unsigned char *p = (unsigned char *)malloc(n ? n : 1);
    if (p && n) memcpy(p, b, n);
    return p;
}

/* ---- buffered little-endian writers ---- */

static int put_u32(FILE *f, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    return fwrite(b, 1, 4, f) == 4 ? 0 : -1;
}

static int put_field(FILE *f, const unsigned char *buf, uint32_t len)
{
    if (put_u32(f, len) != 0) return -1;
    if (len && fwrite(buf, 1, len, f) != len) return -1;
    return 0;
}

/* ---- little-endian readers over an in-memory image ---- */

typedef struct { const unsigned char *p; size_t left; } Reader;

static int get_u32(Reader *r, uint32_t *out)
{
    if (r->left < 4) return -1;
    *out = (uint32_t)r->p[0] | ((uint32_t)r->p[1] << 8) |
           ((uint32_t)r->p[2] << 16) | ((uint32_t)r->p[3] << 24);
    r->p += 4; r->left -= 4;
    return 0;
}

/* Read a length-prefixed field into a freshly malloc'd, NUL-terminated buffer.
 * *out_len (optional) receives the byte length excluding the NUL. */
static unsigned char *get_field(Reader *r, uint32_t *out_len)
{
    uint32_t len;
    unsigned char *buf;
    if (get_u32(r, &len) != 0) return NULL;
    if (len > DB_MAX_FIELD || len > r->left) return NULL;
    buf = (unsigned char *)malloc((size_t)len + 1);
    if (!buf) return NULL;
    if (len) memcpy(buf, r->p, len);
    buf[len] = '\0';
    r->p += len; r->left -= len;
    if (out_len) *out_len = len;
    return buf;
}

/* ---- lifecycle ---- */

static Db *db_new(void)
{
    Db *db = (Db *)calloc(1, sizeof(Db));
    return db;
}

void db_free(Db *db)
{
    uint32_t i;
    if (!db) return;
    for (i = 0; i < db->nuser; i++) {
        free(db->users[i].name);
        free(db->users[i].salt);
        free(db->users[i].verifier);
    }
    free(db->users);
    for (i = 0; i < db->nfile; i++) {
        free(db->files[i].owner);
        free(db->files[i].name);
        free(db->files[i].content);
    }
    free(db->files);
    free(db);
}

Db *db_load(const char *path)
{
    FILE *f;
    long size;
    unsigned char *image = NULL;
    Reader r;
    uint32_t version, n, i;
    Db *db;

    db = db_new();
    if (!db) return NULL;

    f = fopen(path, "rb");
    if (!f)
        return db;                 /* missing file => empty store (first run) */

    if (fseek(f, 0, SEEK_END) != 0) goto fail;
    size = ftell(f);
    if (size < 0) goto fail;
    if (fseek(f, 0, SEEK_SET) != 0) goto fail;

    image = (unsigned char *)malloc((size_t)size ? (size_t)size : 1);
    if (!image) goto fail;
    if (size && fread(image, 1, (size_t)size, f) != (size_t)size) goto fail;
    fclose(f);
    f = NULL;

    r.p = image; r.left = (size_t)size;

    if (r.left < 4 || memcmp(r.p, DB_MAGIC, 4) != 0) goto fail;
    r.p += 4; r.left -= 4;
    if (get_u32(&r, &version) != 0 || version != DB_VERSION) goto fail;

    /* users */
    if (get_u32(&r, &n) != 0) goto fail;
    if (n) {
        db->users = (User *)calloc(n, sizeof(User));
        if (!db->users) goto fail;
    }
    for (i = 0; i < n; i++) {
        User *u = &db->users[i];
        u->name = (char *)get_field(&r, NULL);
        if (!u->name) goto fail;
        db->nuser = i + 1;          /* track partial so db_free cleans up */
        u->salt = get_field(&r, &u->salt_len);
        if (!u->salt) goto fail;
        if (get_u32(&r, &u->opslimit) != 0) goto fail;
        if (get_u32(&r, &u->memlimit) != 0) goto fail;
        u->verifier = get_field(&r, &u->verifier_len);
        if (!u->verifier) goto fail;
        if (u->salt_len != KDF_SALT_BYTES || u->verifier_len != VERIFIER_LEN)
            goto fail;              /* corrupt/forged user record */
    }

    /* files */
    if (get_u32(&r, &n) != 0) goto fail;
    if (n) {
        db->files = (File *)calloc(n, sizeof(File));
        if (!db->files) goto fail;
    }
    for (i = 0; i < n; i++) {
        db->files[i].owner = (char *)get_field(&r, NULL);
        if (!db->files[i].owner) goto fail;
        db->nfile = i + 1;
        db->files[i].name = (char *)get_field(&r, NULL);
        if (!db->files[i].name) goto fail;
        db->files[i].content = get_field(&r, &db->files[i].content_len);
        if (!db->files[i].content) goto fail;
    }

    free(image);
    return db;

fail:
    if (f) fclose(f);
    free(image);
    db_free(db);
    return NULL;
}

int db_save(const Db *db, const char *path)
{
    char tmp[1024];
    FILE *f;
    uint32_t i;
    int n;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;

    f = fopen(tmp, "wb");
    if (!f) return -1;

    if (fwrite(DB_MAGIC, 1, 4, f) != 4) goto fail;
    if (put_u32(f, DB_VERSION) != 0) goto fail;

    if (put_u32(f, db->nuser) != 0) goto fail;
    for (i = 0; i < db->nuser; i++) {
        const User *u = &db->users[i];
        if (put_field(f, (const unsigned char *)u->name,
                      (uint32_t)strlen(u->name)) != 0) goto fail;
        if (put_field(f, u->salt, u->salt_len) != 0) goto fail;
        if (put_u32(f, u->opslimit) != 0) goto fail;
        if (put_u32(f, u->memlimit) != 0) goto fail;
        if (put_field(f, u->verifier, u->verifier_len) != 0) goto fail;
    }

    if (put_u32(f, db->nfile) != 0) goto fail;
    for (i = 0; i < db->nfile; i++) {
        if (put_field(f, (const unsigned char *)db->files[i].owner,
                      (uint32_t)strlen(db->files[i].owner)) != 0) goto fail;
        if (put_field(f, (const unsigned char *)db->files[i].name,
                      (uint32_t)strlen(db->files[i].name)) != 0) goto fail;
        if (put_field(f, db->files[i].content, db->files[i].content_len) != 0) goto fail;
    }

    if (fflush(f) != 0) goto fail;
    if (fclose(f) != 0) { f = NULL; goto fail; }

    if (rename(tmp, path) != 0) { remove(tmp); return -1; }
    return 0;

fail:
    if (f) fclose(f);
    remove(tmp);
    return -1;
}

/* ---- lookups ---- */

User *db_find_user(Db *db, const char *name)
{
    uint32_t i;
    for (i = 0; i < db->nuser; i++)
        if (strcmp(db->users[i].name, name) == 0)
            return &db->users[i];
    return NULL;
}

File *db_find_file(Db *db, const char *owner, const char *name)
{
    uint32_t i;
    for (i = 0; i < db->nfile; i++)
        if (strcmp(db->files[i].owner, owner) == 0 &&
            strcmp(db->files[i].name, name) == 0)
            return &db->files[i];
    return NULL;
}

/* ---- mutators ---- */

int db_add_user(Db *db, const char *name, const char *key)
{
    User *grown, *u;
    unsigned char K[DERIVED_KEYBYTES];
    unsigned char salt[KDF_SALT_BYTES];
    unsigned char verifier[VERIFIER_LEN];
    uint32_t ops = (uint32_t)crypto_pwhash_OPSLIMIT_INTERACTIVE;
    uint32_t mem = (uint32_t)crypto_pwhash_MEMLIMIT_INTERACTIVE;

    if (crypto_ready() != 0) return -1;

    randombytes_buf(salt, sizeof salt);
    if (derive_key(K, key, salt, ops, mem) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    /* verifier = nonce || secretbox(K, token) */
    randombytes_buf(verifier, NONCE_BYTES);
    if (crypto_secretbox_easy(verifier + NONCE_BYTES, VERIFIER_TOKEN,
                              VERIFIER_TOKEN_BYTES, verifier, K) != 0) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    sodium_memzero(K, sizeof K);

    grown = (User *)realloc(db->users, (db->nuser + 1) * sizeof(User));
    if (!grown) return -1;
    db->users = grown;

    u = &db->users[db->nuser];
    memset(u, 0, sizeof *u);
    u->name     = dup_str(name);
    u->salt     = dup_bytes(salt, sizeof salt);
    u->verifier = dup_bytes(verifier, sizeof verifier);
    if (!u->name || !u->salt || !u->verifier) {
        free(u->name); free(u->salt); free(u->verifier);
        return -1;
    }
    u->salt_len     = sizeof salt;
    u->verifier_len = sizeof verifier;
    u->opslimit     = ops;
    u->memlimit     = mem;
    db->nuser++;
    return 0;
}

int db_add_file(Db *db, const char *owner, const char *name)
{
    File *grown = (File *)realloc(db->files, (db->nfile + 1) * sizeof(File));
    if (!grown) return -1;
    db->files = grown;

    db->files[db->nfile].owner       = dup_str(owner);
    db->files[db->nfile].name        = dup_str(name);
    db->files[db->nfile].content     = dup_bytes((const unsigned char *)"", 0);
    db->files[db->nfile].content_len = 0;
    if (!db->files[db->nfile].owner || !db->files[db->nfile].name ||
        !db->files[db->nfile].content) {
        free(db->files[db->nfile].owner);
        free(db->files[db->nfile].name);
        free(db->files[db->nfile].content);
        return -1;
    }
    db->nfile++;
    return 0;
}

int db_write_content(File *f, const User *u, const char *key,
                     const unsigned char *pt, uint32_t len)
{
    unsigned char K[DERIVED_KEYBYTES];
    unsigned char *stored;
    uint32_t stored_len;

    if (auth_derive(u, key, K) != 0)
        return -1;                          /* wrong password */

    /* stored = nonce(NONCE_BYTES) || secretbox(K, pt)  (ct = len + MAC_BYTES) */
    if (len > DB_MAX_FIELD - (NONCE_BYTES + MAC_BYTES)) {
        sodium_memzero(K, sizeof K);
        return -1;
    }
    stored_len = NONCE_BYTES + len + MAC_BYTES;
    stored = (unsigned char *)malloc(stored_len);
    if (!stored) { sodium_memzero(K, sizeof K); return -1; }

    randombytes_buf(stored, NONCE_BYTES);
    if (crypto_secretbox_easy(stored + NONCE_BYTES, pt, len, stored, K) != 0) {
        sodium_memzero(K, sizeof K);
        free(stored);
        return -1;
    }
    sodium_memzero(K, sizeof K);

    free(f->content);
    f->content = stored;
    f->content_len = stored_len;
    return 0;
}

int db_read_content(const File *f, const User *u, const char *key,
                    unsigned char **pt_out, uint32_t *len_out)
{
    unsigned char K[DERIVED_KEYBYTES];
    unsigned char *pt;
    uint32_t ctlen, ptlen;

    if (auth_derive(u, key, K) != 0)
        return -1;                          /* wrong password */

    /* Empty (created, never written): key verified, return 0-length plaintext. */
    if (f->content_len == 0) {
        sodium_memzero(K, sizeof K);
        pt = (unsigned char *)malloc(1);
        if (!pt) return -1;
        *pt_out = pt;
        *len_out = 0;
        return 0;
    }

    if (f->content_len < NONCE_BYTES + MAC_BYTES) {
        sodium_memzero(K, sizeof K);
        return -1;                          /* truncated/corrupt */
    }
    ctlen = f->content_len - NONCE_BYTES;
    ptlen = ctlen - MAC_BYTES;
    pt = (unsigned char *)malloc(ptlen ? ptlen : 1);
    if (!pt) { sodium_memzero(K, sizeof K); return -1; }

    if (crypto_secretbox_open_easy(pt, f->content + NONCE_BYTES, ctlen,
                                   f->content, K) != 0) {
        sodium_memzero(K, sizeof K);
        free(pt);
        return -1;                          /* tampered or wrong key */
    }
    sodium_memzero(K, sizeof K);

    *pt_out = pt;
    *len_out = ptlen;
    return 0;
}
