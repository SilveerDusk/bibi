/*
 * stor.c — BiBiFi secure encrypted file store.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 *   actions: register | create | write | read
 *
 * Behavior:
 *   - On ANY error / incomplete / contradictory args: print "invalid", exit 255.
 *   - On success: exit 0.
 *   - All state persisted to "enc.db" in the working directory.
 *
 * Security model (per spec):
 *   - Confidentiality: file contents in enc.db are AEAD-encrypted under a key
 *     derived from the user's secret (Argon2id). Without the secret, contents
 *     cannot be recovered.
 *   - Integrity / forgery detection: any tampering with a user's record is
 *     detected when that user later supplies the correct secret:
 *       * content tamper -> AEAD tag check fails
 *       * filename/owner tamper -> AAD mismatch -> AEAD fails
 *       * salt tamper -> wrong derived key -> AEAD fails
 *       * verifier tamper -> Argon2 verify fails
 *       * structural tamper -> bounds-checked parse fails
 *   - register cannot verify identity, so re-registering an existing user is
 *     rejected (prevents account hijack/wipe by someone without the key).
 *
 * Crypto: libsodium only (Argon2id KDF + XChaCha20-Poly1305-IETF AEAD).
 *
 * Build: -O0 -g -m32 -fno-stack-protector, linked with malloc-2.7.2.c (dlmalloc)
 *        and -lsodium; stack made executable via execstack (contest rules).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sodium.h>

/* ---- Required: do not remove. Never called during normal operation. ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* ----------------------------------------------------------------------- */
/* Limits — bound every user-controlled count/length/allocation.           */
/* ----------------------------------------------------------------------- */
#define DB_PATH       "enc.db"
#define DB_TMP_PATH   "enc.db.tmp"
#define DB_MAGIC      "STORDB01"
#define DB_MAGIC_LEN  8

#define MAX_NAME      4096u            /* username / filename length cap     */
#define MAX_KEY       (1u << 20)       /* secret key length cap (1 MiB)      */
#define MAX_CONTENT   (256u * 1024u * 1024u) /* per-file content cap (256MB) */
#define MAX_RECORDS   1000000u         /* user/file count cap                */
#define MAX_DB_SIZE   (512u * 1024u * 1024u) /* enc.db size cap             */

#define SALTLEN       crypto_pwhash_SALTBYTES
#define KEYLEN        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCELEN      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define ABYTES        crypto_aead_xchacha20poly1305_ietf_ABYTES

/* ----------------------------------------------------------------------- */
/* In-memory database model.                                               */
/* ----------------------------------------------------------------------- */
typedef struct {
    unsigned char *name;          /* username bytes (not NUL-terminated)    */
    size_t         name_len;
    unsigned char  salt[SALTLEN];
    char          *verifier;      /* crypto_pwhash_str string (NUL-term)    */
    size_t         verifier_len;  /* strlen(verifier)                       */
} User;

typedef struct {
    unsigned char *owner;
    size_t         owner_len;
    unsigned char *name;
    size_t         name_len;
    int            has_content;   /* 0 = created but never written          */
    unsigned char  nonce[NONCELEN];
    unsigned char *ct;            /* ciphertext + tag                       */
    size_t         ct_len;
} FileRec;

typedef struct {
    User    *users;
    size_t   nusers;
    FileRec *files;
    size_t   nfiles;
} DB;

/* ----------------------------------------------------------------------- */
/* Single error chokepoint: print "invalid" and exit 255 (flush first).    */
/* ----------------------------------------------------------------------- */
static void die_invalid(void) {
    fputs("invalid", stdout);
    fflush(stdout);
    exit(255);
}

/* Bounded malloc helper: returns NULL on zero or overflow-prone request is
 * the caller's job to check; here we just wrap malloc and on failure we
 * treat it as a graceful out-of-memory error (-> invalid). */
static void *xmalloc_or_die(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die_invalid();
    return p;
}

/* ----------------------------------------------------------------------- */
/* Read an entire file into a freshly allocated buffer. Returns 0 on        */
/* success (*out / *out_len set), -1 on any error. Caller frees *out.       */
/* Enforces a maximum size; oversized files are an error (graceful).        */
/* ----------------------------------------------------------------------- */
static int read_entire_file(const char *path, unsigned char **out,
                            size_t *out_len, size_t max) {
    FILE *f = NULL;
    unsigned char *buf = NULL;
    struct stat st;
    long sz;
    size_t got;

    *out = NULL;
    *out_len = 0;

    if (stat(path, &st) != 0) return -1;
    /* Only regular files are accepted for -i to avoid FIFO/device hangs. */
    if (!S_ISREG(st.st_mode)) return -1;
    if ((unsigned long)st.st_size > (unsigned long)max) return -1;

    f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) goto err;
    sz = ftell(f);
    if (sz < 0) goto err;
    if ((unsigned long)sz > (unsigned long)max) goto err;
    if (fseek(f, 0, SEEK_SET) != 0) goto err;

    buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) goto err;

    got = fread(buf, 1, (size_t)sz, f);
    if (got != (size_t)sz) goto err;

    if (fclose(f) != 0) { f = NULL; goto err; }

    *out = buf;
    *out_len = (size_t)sz;
    return 0;

err:
    if (buf) free(buf);
    if (f) fclose(f);
    return -1;
}

/* Refuse output paths that would clobber stor's own database.  We open the
 * output before truncating, then compare inodes so ./enc.db, symlinks, and
 * hardlinks are all caught. */
static int is_reserved_db_name(const char *path) {
    while (path[0] == '.' && path[1] == '/') path += 2;
    return strcmp(path, DB_PATH) == 0 || strcmp(path, DB_TMP_PATH) == 0;
}

static int fd_targets_db(int fd) {
    struct stat out_st;
    struct stat db_st;

    if (fstat(fd, &out_st) != 0) return 1;
    if (stat(DB_PATH, &db_st) != 0) return 0;
    return out_st.st_dev == db_st.st_dev && out_st.st_ino == db_st.st_ino;
}

/* ----------------------------------------------------------------------- */
/* Bounds-checked cursor for parsing the binary DB.                        */
/* ----------------------------------------------------------------------- */
typedef struct {
    const unsigned char *p;
    size_t remaining;
} Cursor;

static int cur_read(Cursor *c, void *dst, size_t n) {
    if (n > c->remaining) return -1;
    memcpy(dst, c->p, n);
    c->p += n;
    c->remaining -= n;
    return 0;
}

static int cur_skip_check(Cursor *c, size_t n) {
    return (n > c->remaining) ? -1 : 0;
}

static int cur_read_u32(Cursor *c, uint32_t *v) {
    unsigned char b[4];
    if (cur_read(c, b, 4) != 0) return -1;
    *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
         ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    return 0;
}

/* Read a u32-length-prefixed blob into a newly allocated buffer. */
static int cur_read_blob(Cursor *c, unsigned char **out, size_t *out_len,
                         size_t max) {
    uint32_t len;
    unsigned char *buf;

    *out = NULL;
    *out_len = 0;
    if (cur_read_u32(c, &len) != 0) return -1;
    if (len > max) return -1;
    if (cur_skip_check(c, len) != 0) return -1;

    buf = malloc((size_t)len ? (size_t)len : 1);
    if (!buf) return -1;
    if (len) memcpy(buf, c->p, len);
    c->p += len;
    c->remaining -= len;

    *out = buf;
    *out_len = len;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* DB lifecycle.                                                           */
/* ----------------------------------------------------------------------- */
static void db_init(DB *db) {
    db->users = NULL;
    db->nusers = 0;
    db->files = NULL;
    db->nfiles = 0;
}

static void db_free(DB *db) {
    size_t i;
    if (db->users) {
        for (i = 0; i < db->nusers; i++) {
            free(db->users[i].name);
            if (db->users[i].verifier) {
                sodium_memzero(db->users[i].verifier,
                               db->users[i].verifier_len);
                free(db->users[i].verifier);
            }
        }
        free(db->users);
    }
    if (db->files) {
        for (i = 0; i < db->nfiles; i++) {
            free(db->files[i].owner);
            free(db->files[i].name);
            free(db->files[i].ct);
        }
        free(db->files);
    }
    db_init(db);
}

/* ----------------------------------------------------------------------- */
/* Duplicate-record detection (forgery detection for a tampered enc.db).   */
/* Our own writer never emits duplicate usernames or duplicate (owner,name) */
/* file records, so any duplicate means the DB was modified outside stor.   */
/* Done with qsort over an index array: O(n log n), bounded by MAX_RECORDS, */
/* so it cannot be turned into a denial-of-service.                         */
/* ----------------------------------------------------------------------- */
static const DB *g_dup_db; /* single-threaded: comparator context */

static int blob_cmp(const unsigned char *a, size_t alen,
                    const unsigned char *b, size_t blen) {
    size_t n = (alen < blen) ? alen : blen;
    int r = n ? memcmp(a, b, n) : 0;
    if (r) return r;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int cmp_user_idx(const void *pa, const void *pb) {
    size_t ia = *(const size_t *)pa, ib = *(const size_t *)pb;
    const User *ua = &g_dup_db->users[ia];
    const User *ub = &g_dup_db->users[ib];
    return blob_cmp(ua->name, ua->name_len, ub->name, ub->name_len);
}

static int cmp_file_idx(const void *pa, const void *pb) {
    size_t ia = *(const size_t *)pa, ib = *(const size_t *)pb;
    const FileRec *fa = &g_dup_db->files[ia];
    const FileRec *fb = &g_dup_db->files[ib];
    int r = blob_cmp(fa->owner, fa->owner_len, fb->owner, fb->owner_len);
    if (r) return r;
    return blob_cmp(fa->name, fa->name_len, fb->name, fb->name_len);
}

/* Returns 0 if no duplicates, 1 if a duplicate exists, -1 on alloc failure. */
static int has_duplicates(const DB *db, size_t n, int is_files) {
    size_t *idx;
    size_t i;
    int dup = 0;

    if (n < 2) return 0;
    if (n > SIZE_MAX / sizeof(size_t)) return -1; /* overflow guard */
    idx = malloc(n * sizeof(size_t));
    if (!idx) return -1;
    for (i = 0; i < n; i++) idx[i] = i;

    g_dup_db = db;
    qsort(idx, n, sizeof(size_t), is_files ? cmp_file_idx : cmp_user_idx);

    for (i = 1; i < n; i++) {
        int eq = is_files ? (cmp_file_idx(&idx[i - 1], &idx[i]) == 0)
                          : (cmp_user_idx(&idx[i - 1], &idx[i]) == 0);
        if (eq) { dup = 1; break; }
    }
    free(idx);
    return dup;
}

/* Parse the on-disk DB. Returns 0 on success, -1 on any malformed input
 * (treated by the caller as a tamper/corruption -> invalid). */
static int db_parse(const unsigned char *data, size_t len, DB *db) {
    Cursor c;
    unsigned char magic[DB_MAGIC_LEN];
    uint32_t ucount, fcount, i;

    db_init(db);

    c.p = data;
    c.remaining = len;

    if (cur_read(&c, magic, DB_MAGIC_LEN) != 0) goto fail;
    if (memcmp(magic, DB_MAGIC, DB_MAGIC_LEN) != 0) goto fail;

    /* Users */
    if (cur_read_u32(&c, &ucount) != 0) goto fail;
    if (ucount > MAX_RECORDS || ucount > c.remaining) goto fail;
    if (ucount) {
        db->users = calloc(ucount, sizeof(User));
        if (!db->users) goto fail;
    }
    for (i = 0; i < ucount; i++) {
        User *u = &db->users[db->nusers];
        unsigned char *vbuf = NULL;
        size_t vlen = 0;

        if (cur_read_blob(&c, &u->name, &u->name_len, MAX_NAME) != 0) goto fail;
        if (cur_read(&c, u->salt, SALTLEN) != 0) goto fail;
        if (cur_read_blob(&c, &vbuf, &vlen, crypto_pwhash_STRBYTES) != 0)
            goto fail;
        /* verifier must be a NUL-terminated string; store as such */
        u->verifier = malloc(vlen + 1);
        if (!u->verifier) { free(vbuf); goto fail; }
        if (vlen) memcpy(u->verifier, vbuf, vlen);
        u->verifier[vlen] = '\0';
        u->verifier_len = vlen;
        sodium_memzero(vbuf, vlen);
        free(vbuf);
        /* reject embedded NUL inside verifier string region */
        if (strlen(u->verifier) != vlen) goto fail;
        db->nusers++;
    }

    /* Files */
    if (cur_read_u32(&c, &fcount) != 0) goto fail;
    if (fcount > MAX_RECORDS || fcount > c.remaining) goto fail;
    if (fcount) {
        db->files = calloc(fcount, sizeof(FileRec));
        if (!db->files) goto fail;
    }
    for (i = 0; i < fcount; i++) {
        FileRec *fr = &db->files[db->nfiles];
        unsigned char flag;

        if (cur_read_blob(&c, &fr->owner, &fr->owner_len, MAX_NAME) != 0)
            goto fail;
        if (cur_read_blob(&c, &fr->name, &fr->name_len, MAX_NAME) != 0)
            goto fail;
        if (cur_read(&c, &flag, 1) != 0) goto fail;
        if (flag != 0 && flag != 1) goto fail;
        fr->has_content = flag;
        if (fr->has_content) {
            if (cur_read(&c, fr->nonce, NONCELEN) != 0) goto fail;
            if (cur_read_blob(&c, &fr->ct, &fr->ct_len,
                              MAX_CONTENT + ABYTES) != 0) goto fail;
            if (fr->ct_len < ABYTES) goto fail; /* must hold the tag */
        }
        db->nfiles++;
    }

    /* No trailing junk allowed. */
    if (c.remaining != 0) goto fail;

    /* Reject injected duplicate records (tamper detection). */
    if (has_duplicates(db, db->nusers, 0) != 0) goto fail;
    if (has_duplicates(db, db->nfiles, 1) != 0) goto fail;

    return 0;

fail:
    db_free(db);
    return -1;
}

/* Load enc.db if present. Missing file => empty DB (first run). Corrupt or
 * tampered file (structural) => returns -1 (caller -> invalid). */
static int db_load(DB *db) {
    unsigned char *data = NULL;
    size_t len = 0;
    int rc;

    db_init(db);

    if (access(DB_PATH, F_OK) != 0) {
        return 0; /* no db yet */
    }
    if (read_entire_file(DB_PATH, &data, &len, MAX_DB_SIZE) != 0) {
        return -1;
    }
    rc = db_parse(data, len, db);
    free(data);
    return rc;
}

/* ----------------------------------------------------------------------- */
/* DB serialization + atomic save.                                         */
/* ----------------------------------------------------------------------- */
static int append_bytes(unsigned char **buf, size_t *cap, size_t *len,
                        const void *src, size_t n) {
    if (*len + n < *len) return -1; /* overflow */
    if (*len + n > *cap) {
        size_t newcap = *cap ? *cap : 256;
        unsigned char *tmp;
        while (newcap < *len + n) {
            if (newcap > (SIZE_MAX / 2)) return -1;
            newcap *= 2;
        }
        tmp = realloc(*buf, newcap);
        if (!tmp) return -1;
        *buf = tmp;
        *cap = newcap;
    }
    if (n) memcpy(*buf + *len, src, n);
    *len += n;
    return 0;
}

static int append_u32(unsigned char **buf, size_t *cap, size_t *len,
                      uint32_t v) {
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    return append_bytes(buf, cap, len, b, 4);
}

static int append_blob(unsigned char **buf, size_t *cap, size_t *len,
                       const unsigned char *src, size_t n) {
    if (n > 0xffffffffUL) return -1;
    if (append_u32(buf, cap, len, (uint32_t)n) != 0) return -1;
    return append_bytes(buf, cap, len, src, n);
}

static int db_serialize(const DB *db, unsigned char **out, size_t *out_len) {
    unsigned char *buf = NULL;
    size_t cap = 0, len = 0;
    size_t i;

    *out = NULL;
    *out_len = 0;

    if (db->nusers > 0xffffffffUL || db->nfiles > 0xffffffffUL) goto fail;

    if (append_bytes(&buf, &cap, &len, DB_MAGIC, DB_MAGIC_LEN) != 0) goto fail;

    if (append_u32(&buf, &cap, &len, (uint32_t)db->nusers) != 0) goto fail;
    for (i = 0; i < db->nusers; i++) {
        const User *u = &db->users[i];
        if (append_blob(&buf, &cap, &len, u->name, u->name_len) != 0) goto fail;
        if (append_bytes(&buf, &cap, &len, u->salt, SALTLEN) != 0) goto fail;
        if (append_blob(&buf, &cap, &len,
                        (const unsigned char *)u->verifier,
                        u->verifier_len) != 0) goto fail;
    }

    if (append_u32(&buf, &cap, &len, (uint32_t)db->nfiles) != 0) goto fail;
    for (i = 0; i < db->nfiles; i++) {
        const FileRec *fr = &db->files[i];
        unsigned char flag = (unsigned char)(fr->has_content ? 1 : 0);
        if (append_blob(&buf, &cap, &len, fr->owner, fr->owner_len) != 0)
            goto fail;
        if (append_blob(&buf, &cap, &len, fr->name, fr->name_len) != 0)
            goto fail;
        if (append_bytes(&buf, &cap, &len, &flag, 1) != 0) goto fail;
        if (fr->has_content) {
            if (append_bytes(&buf, &cap, &len, fr->nonce, NONCELEN) != 0)
                goto fail;
            if (append_blob(&buf, &cap, &len, fr->ct, fr->ct_len) != 0)
                goto fail;
        }
    }

    *out = buf;
    *out_len = len;
    return 0;

fail:
    free(buf);
    return -1;
}

/* Write data to enc.db atomically with 0600 perms (tmp file + rename). */
static int db_save(const DB *db) {
    unsigned char *buf = NULL;
    size_t len = 0, written = 0;
    int fd = -1;
    FILE *f = NULL;

    if (db_serialize(db, &buf, &len) != 0) return -1;

    fd = open(DB_TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) goto fail;
    f = fdopen(fd, "wb");
    if (!f) { close(fd); goto fail; }

    if (len) {
        written = fwrite(buf, 1, len, f);
        if (written != len) { fclose(f); goto fail; }
    }
    if (fflush(f) != 0) { fclose(f); goto fail; }
    if (fclose(f) != 0) { f = NULL; goto fail; }

    if (rename(DB_TMP_PATH, DB_PATH) != 0) goto fail;

    free(buf);
    return 0;

fail:
    free(buf);
    unlink(DB_TMP_PATH);
    return -1;
}

/* ----------------------------------------------------------------------- */
/* Lookups.                                                                */
/* ----------------------------------------------------------------------- */
static int name_eq(const unsigned char *a, size_t alen,
                   const char *b, size_t blen) {
    if (alen != blen) return 0;
    if (alen == 0) return 1;
    return memcmp(a, b, alen) == 0;
}

static User *find_user(DB *db, const char *user, size_t ulen) {
    size_t i;
    for (i = 0; i < db->nusers; i++) {
        if (name_eq(db->users[i].name, db->users[i].name_len, user, ulen))
            return &db->users[i];
    }
    return NULL;
}

static FileRec *find_file(DB *db, const char *owner, size_t olen,
                          const char *fname, size_t flen) {
    size_t i;
    for (i = 0; i < db->nfiles; i++) {
        if (name_eq(db->files[i].owner, db->files[i].owner_len, owner, olen) &&
            name_eq(db->files[i].name, db->files[i].name_len, fname, flen))
            return &db->files[i];
    }
    return NULL;
}

/* ----------------------------------------------------------------------- */
/* Crypto helpers.                                                         */
/* ----------------------------------------------------------------------- */

/* Derive a 32-byte content key from (key, salt) via Argon2id. 0 on success. */
static int derive_key(unsigned char out[KEYLEN], const char *key,
                      size_t keylen, const unsigned char salt[SALTLEN]) {
    if (crypto_pwhash(out, KEYLEN, key, keylen, salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1; /* out of memory */
    }
    return 0;
}

/* Build AAD = owner || 0x00 || name. Caller frees *out. */
static int build_aad(const unsigned char *owner, size_t olen,
                     const unsigned char *name, size_t nlen,
                     unsigned char **out, size_t *out_len) {
    size_t total;
    unsigned char *buf;

    if (olen > SIZE_MAX - 1) return -1;
    if (nlen > SIZE_MAX - 1 - olen) return -1;
    total = olen + 1 + nlen;

    buf = malloc(total ? total : 1);
    if (!buf) return -1;
    if (olen) memcpy(buf, owner, olen);
    buf[olen] = 0x00;
    if (nlen) memcpy(buf + olen + 1, name, nlen);

    *out = buf;
    *out_len = total;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Actions.                                                                */
/* ----------------------------------------------------------------------- */
static int do_register(DB *db, const char *user, size_t ulen,
                       const char *key, size_t klen) {
    User *u;
    User *tmp;
    char verifier[crypto_pwhash_STRBYTES];

    if (!key) return -1;                 /* register needs -k */
    if (find_user(db, user, ulen))       /* reject re-register */
        return -1;

    if (crypto_pwhash_str(verifier, key, klen,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        return -1; /* out of memory */
    }

    if (db->nusers + 1 < db->nusers) return -1; /* overflow guard */
    tmp = realloc(db->users, (db->nusers + 1) * sizeof(User));
    if (!tmp) return -1;
    db->users = tmp;

    u = &db->users[db->nusers];
    memset(u, 0, sizeof(*u));
    u->name = xmalloc_or_die(ulen ? ulen : 1);
    if (ulen) memcpy(u->name, user, ulen);
    u->name_len = ulen;
    randombytes_buf(u->salt, SALTLEN);
    u->verifier_len = strlen(verifier);
    u->verifier = malloc(u->verifier_len + 1);
    if (!u->verifier) { free(u->name); return -1; }
    memcpy(u->verifier, verifier, u->verifier_len + 1);
    sodium_memzero(verifier, sizeof(verifier));

    db->nusers++;
    return db_save(db);
}

static int do_create(DB *db, const char *user, size_t ulen,
                     const char *fname, size_t flen) {
    FileRec *fr;
    FileRec *tmp;

    if (!fname) return -1;                /* create needs -f */
    if (!find_user(db, user, ulen)) return -1; /* file owned by a real user */

    if (find_file(db, user, ulen, fname, flen))
        return 0;                         /* already exists: no-op */

    if (db->nfiles + 1 < db->nfiles) return -1;
    tmp = realloc(db->files, (db->nfiles + 1) * sizeof(FileRec));
    if (!tmp) return -1;
    db->files = tmp;

    fr = &db->files[db->nfiles];
    memset(fr, 0, sizeof(*fr));
    fr->owner = xmalloc_or_die(ulen ? ulen : 1);
    if (ulen) memcpy(fr->owner, user, ulen);
    fr->owner_len = ulen;
    fr->name = xmalloc_or_die(flen ? flen : 1);
    if (flen) memcpy(fr->name, fname, flen);
    fr->name_len = flen;
    fr->has_content = 0;

    db->nfiles++;
    return db_save(db);
}

static int do_write(DB *db, const char *user, size_t ulen,
                    const char *key, size_t klen,
                    const char *fname, size_t flen,
                    const char *infile, const char *text) {
    User *u;
    FileRec *fr;
    unsigned char dk[KEYLEN];
    unsigned char *content = NULL;
    size_t content_len = 0;
    int content_owned = 0;          /* whether we must free content */
    unsigned char *aad = NULL;
    size_t aad_len = 0;
    unsigned char *ct = NULL;
    unsigned long long ct_len = 0;
    unsigned char nonce[NONCELEN];
    int rc = -1;

    if (!key || !fname) return -1;
    u = find_user(db, user, ulen);
    if (!u) return -1;
    if (crypto_pwhash_str_verify(u->verifier, key, klen) != 0) return -1;

    fr = find_file(db, user, ulen, fname, flen);
    if (!fr) return -1;             /* must be created first */

    /* Resolve content source: -i file, else inline text, else empty. */
    if (infile) {
        if (read_entire_file(infile, &content, &content_len, MAX_CONTENT) != 0)
            return -1;
        content_owned = 1;
    } else if (text) {
        content = (unsigned char *)text;
        content_len = strlen(text);
        if (content_len > MAX_CONTENT) return -1;
    } else {
        content = (unsigned char *)"";
        content_len = 0;
    }

    if (derive_key(dk, key, klen, u->salt) != 0) goto cleanup;
    if (build_aad(fr->owner, fr->owner_len, fr->name, fr->name_len,
                  &aad, &aad_len) != 0) goto cleanup;

    if (content_len > SIZE_MAX - ABYTES) goto cleanup;
    ct = malloc(content_len + ABYTES);
    if (!ct) goto cleanup;

    randombytes_buf(nonce, NONCELEN);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &ct_len, content, content_len, aad, aad_len,
            NULL, nonce, dk) != 0) {
        goto cleanup;
    }

    /* Commit into the file record. */
    free(fr->ct);
    fr->ct = ct;
    ct = NULL;
    fr->ct_len = (size_t)ct_len;
    memcpy(fr->nonce, nonce, NONCELEN);
    fr->has_content = 1;

    rc = db_save(db);

cleanup:
    sodium_memzero(dk, sizeof(dk));
    free(aad);
    free(ct);
    if (content_owned) free(content);
    return rc;
}

static int do_read(DB *db, const char *user, size_t ulen,
                   const char *key, size_t klen,
                   const char *fname, size_t flen, const char *outfile) {
    User *u;
    FileRec *fr;
    unsigned char dk[KEYLEN];
    unsigned char *aad = NULL;
    size_t aad_len = 0;
    unsigned char *pt = NULL;
    unsigned long long pt_len = 0;
    int rc = -1;

    if (!key || !fname) return -1;
    u = find_user(db, user, ulen);
    if (!u) return -1;
    if (crypto_pwhash_str_verify(u->verifier, key, klen) != 0) return -1;

    fr = find_file(db, user, ulen, fname, flen);
    if (!fr) return -1;

    if (fr->has_content) {
        if (fr->ct_len < ABYTES) return -1;
        if (derive_key(dk, key, klen, u->salt) != 0) goto cleanup;
        if (build_aad(fr->owner, fr->owner_len, fr->name, fr->name_len,
                      &aad, &aad_len) != 0) goto cleanup;

        pt = malloc((fr->ct_len - ABYTES) ? (fr->ct_len - ABYTES) : 1);
        if (!pt) goto cleanup;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt, &pt_len, NULL, fr->ct, fr->ct_len, aad, aad_len,
                fr->nonce, dk) != 0) {
            goto cleanup; /* wrong key or tampered -> invalid */
        }
    }
    /* else: created but never written -> empty content */

    /* Emit output verbatim (no added newline). */
    if (outfile) {
        int fd;
        FILE *of;
        if (is_reserved_db_name(outfile)) goto cleanup;
        fd = open(outfile, O_WRONLY | O_CREAT, 0600);
        if (fd < 0) goto cleanup;
        if (fd_targets_db(fd)) { close(fd); goto cleanup; }
        if (ftruncate(fd, 0) != 0) { close(fd); goto cleanup; }
        of = fdopen(fd, "wb");
        if (!of) { close(fd); goto cleanup; }
        if (pt_len) {
            if (fwrite(pt, 1, (size_t)pt_len, of) != (size_t)pt_len) {
                fclose(of);
                goto cleanup;
            }
        }
        if (fflush(of) != 0) { fclose(of); goto cleanup; }
        if (fclose(of) != 0) goto cleanup;
    } else {
        if (pt_len) {
            if (fwrite(pt, 1, (size_t)pt_len, stdout) != (size_t)pt_len)
                goto cleanup;
        }
        fflush(stdout);
    }

    rc = 0;

cleanup:
    sodium_memzero(dk, sizeof(dk));
    free(aad);
    if (pt) {
        sodium_memzero(pt, pt_len ? (size_t)pt_len :
                       (fr && fr->ct_len > ABYTES ? fr->ct_len - ABYTES : 0));
        free(pt);
    }
    return rc;
}

/* ----------------------------------------------------------------------- */
/* main: parse args, dispatch.                                             */
/* ----------------------------------------------------------------------- */
int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *action, *text;
    size_t ulen, klen = 0, flen = 0;
    DB db;
    int c, rc;

    if (sodium_init() < 0) die_invalid();

    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;  /* last occurrence wins */
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  die_invalid();
        }
    }

    if (!user) die_invalid();
    if (optind >= argc) die_invalid();

    action = argv[optind];
    text   = (optind + 1 < argc) ? argv[optind + 1] : NULL;
    if (optind + 2 < argc) die_invalid(); /* at most action + one text arg */

    /* Bound user-controlled string lengths. */
    ulen = strlen(user);
    if (ulen == 0 || ulen > MAX_NAME) die_invalid();
    if (key) {
        klen = strlen(key);
        if (klen > MAX_KEY) die_invalid();
    }
    if (file) {
        flen = strlen(file);
        if (flen == 0 || flen > MAX_NAME) die_invalid();
    }

    if (db_load(&db) != 0) die_invalid(); /* missing-ok; corrupt -> invalid */

    if (strcmp(action, "register") == 0) {
        if (text) { db_free(&db); die_invalid(); }
        rc = do_register(&db, user, ulen, key, klen);
    } else if (strcmp(action, "create") == 0) {
        if (text) { db_free(&db); die_invalid(); }
        rc = do_create(&db, user, ulen, file, flen);
    } else if (strcmp(action, "write") == 0) {
        rc = do_write(&db, user, ulen, key, klen, file, flen, infile, text);
    } else if (strcmp(action, "read") == 0) {
        if (text) { db_free(&db); die_invalid(); }
        rc = do_read(&db, user, ulen, key, klen, file, flen, outfile);
    } else {
        db_free(&db);
        die_invalid();
        return 255; /* unreachable */
    }

    db_free(&db);

    if (rc != 0) die_invalid();

    fflush(stdout);
    return 0;
}
