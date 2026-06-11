/*
 * stor.c -- encrypted file storage system (BIBIFI challenge)
 *
 * Build:
 *   gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c \
 *       -lssl -lcrypto
 *   execstack --set-execstack stor
 *
 * Security design:
 *   - PBKDF2-SHA256 (10000 iterations) derives a 256-bit key per user
 *   - AES-256-GCM encrypts file content (confidentiality + authenticated
 *     integrity in one primitive; tampered ciphertext fails decryption)
 *   - A GCM-encrypted key-verification token in each USER record lets us
 *     authenticate the caller before touching any file data
 *   - The entire database is rewritten on each modifying operation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Required control-flow attack target */
void win(void) { printf("Arbitrary access achieved!\n"); }

/* ------------------------------------------------------------------ */
/* Error handling                                                      */
/* ------------------------------------------------------------------ */

/* All errors — missing args, wrong key, tampered data, etc. — print
   "invalid" to stdout and exit 255 per the spec. */
static void die_invalid(void) {
    printf("invalid\n");
    exit(255);
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define DB_FILE        "enc.db"
#define DB_MAGIC       "STOR"
#define DB_VERSION     ((uint32_t)1)

#define REC_USER       ((uint32_t)1)
#define REC_FILE       ((uint32_t)2)

#define KEY_LEN        32
#define SALT_LEN       16
#define IV_LEN         12
#define TAG_LEN        16
#define PBKDF2_ITER    200000   /* raise offline brute-force cost vs a weak secret */

#define MAX_USERNAME   255   /* fits the u8 length prefix; spec sets no limit */
#define MAX_FILENAME   255
#define MAX_CONTENT    (64u * 1024u * 1024u)

static const uint8_t KEY_VERIFY_PT[8] = {'S','T','O','R','K','E','Y','!'};

/* ------------------------------------------------------------------ */
/* Memory helpers                                                      */
/* ------------------------------------------------------------------ */

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die_invalid();
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) die_invalid();
    return q;
}

static void zfree(void *p, size_t n) {
    if (p) { memset(p, 0, n); free(p); }
}

/* ------------------------------------------------------------------ */
/* Cryptography                                                        */
/* ------------------------------------------------------------------ */

static int derive_key(const char *pw, const uint8_t *salt,
                      uint8_t out[KEY_LEN]) {
    return PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw),
                              salt, SALT_LEN,
                              PBKDF2_ITER, EVP_sha256(),
                              KEY_LEN, out) == 1 ? 0 : -1;
}

/* AES-256-GCM encrypt. The AAD (associated data) is authenticated but not
   encrypted; here it binds each ciphertext to the record it belongs to so a
   blob cannot be relocated within enc.db without failing the tag check.
   Returns ciphertext length (== pt_len) on success, -1 on error. */
static int gcm_encrypt(const uint8_t key[KEY_LEN],
                       const uint8_t iv[IV_LEN],
                       const uint8_t *aad, int aad_len,
                       const uint8_t *pt, int pt_len,
                       uint8_t *ct, uint8_t tag[TAG_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n, total = 0, rc = -1;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (aad && aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &n, aad, aad_len) != 1) goto done;
    /* Skip the data update for empty content: some OpenSSL builds reject a
       NULL/zero-length input here, which would break empty-file round-trips. */
    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx, ct, &n, pt, pt_len) != 1) goto done;
    total = (pt_len > 0) ? n : 0;
    if (EVP_EncryptFinal_ex(ctx, ct + total, &n) != 1) goto done;
    total += n;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
    rc = total;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* Returns plaintext length on success, -1 on auth failure or error.
   The same AAD supplied at encryption must be supplied here or the tag
   check fails — this is what makes a relocated/forged record detectable. */
static int gcm_decrypt(const uint8_t key[KEY_LEN],
                       const uint8_t iv[IV_LEN],
                       const uint8_t *aad, int aad_len,
                       const uint8_t *ct, int ct_len,
                       const uint8_t tag[TAG_LEN],
                       uint8_t *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n, total = 0, rc = -1;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;
    if (aad && aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &n, aad, aad_len) != 1) goto done;
    /* Mirror the encrypt side: skip the data update for empty ciphertext. */
    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx, pt, &n, ct, ct_len) != 1) goto done;
    total = (ct_len > 0) ? n : 0;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                             (void *)(uintptr_t)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, pt + total, &n) <= 0) goto done;
    total += n;
    rc = total;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Database record types                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char    username[MAX_USERNAME + 1];
    uint8_t salt[SALT_LEN];
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t check_ct[8];
} UserRec;

typedef struct {
    char     owner[MAX_USERNAME + 1];
    char     filename[MAX_FILENAME + 1];
    int      has_content;
    uint8_t  iv[IV_LEN];
    uint8_t  tag[TAG_LEN];
    uint32_t ct_len;
    uint8_t *ct;
} FileRec;

typedef struct {
    UserRec *users;  int n_users,  cap_users;
    FileRec *files;  int n_files,  cap_files;
} DB;

static void db_init(DB *db) { memset(db, 0, sizeof *db); }

static void db_free(DB *db) {
    int i;
    free(db->users);
    for (i = 0; i < db->n_files; i++) zfree(db->files[i].ct, db->files[i].ct_len);
    free(db->files);
    db_init(db);
}

static UserRec *db_find_user(DB *db, const char *name) {
    int i;
    for (i = 0; i < db->n_users; i++)
        if (strcmp(db->users[i].username, name) == 0) return &db->users[i];
    return NULL;
}

static FileRec *db_find_file(DB *db, const char *owner, const char *name) {
    int i;
    for (i = 0; i < db->n_files; i++)
        if (strcmp(db->files[i].owner, owner) == 0 &&
            strcmp(db->files[i].filename, name) == 0) return &db->files[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Growable write buffer                                               */
/* ------------------------------------------------------------------ */

typedef struct { uint8_t *buf; size_t len, cap; } BufW;

static void bw_init(BufW *b) { b->buf = NULL; b->len = b->cap = 0; }

static void bw_grow(BufW *b, size_t need) {
    size_t nc;
    if (need > SIZE_MAX - b->len) die_invalid();   /* len+need would overflow */
    if (b->len + need <= b->cap) return;
    nc = b->cap ? b->cap * 2 : 256;
    while (nc < b->len + need) {
        if (nc > SIZE_MAX / 2) { nc = b->len + need; break; }   /* no overflow */
        nc *= 2;
    }
    b->buf = xrealloc(b->buf, nc);
    b->cap = nc;
}

static void bw_u8(BufW *b, uint8_t v) {
    bw_grow(b, 1); b->buf[b->len++] = v;
}

static void bw_u32le(BufW *b, uint32_t v) {
    bw_grow(b, 4);
    b->buf[b->len++] = (uint8_t)(v);
    b->buf[b->len++] = (uint8_t)(v >>  8);
    b->buf[b->len++] = (uint8_t)(v >> 16);
    b->buf[b->len++] = (uint8_t)(v >> 24);
}

static void bw_raw(BufW *b, const void *p, size_t n) {
    bw_grow(b, n); memcpy(b->buf + b->len, p, n); b->len += n;
}

/* ------------------------------------------------------------------ */
/* Read-only view over a byte buffer                                   */
/* ------------------------------------------------------------------ */

typedef struct { const uint8_t *buf; size_t len, pos; } BufR;

static void br_init(BufR *b, const uint8_t *buf, size_t len) {
    b->buf = buf; b->len = len; b->pos = 0;
}

/* Bounds checks are written as `need > remaining` (never `pos + need > len`)
   so they cannot integer-overflow on the mandated 32-bit build. */
static int br_u8(BufR *b, uint8_t *v) {
    if (b->len - b->pos < 1) return -1;
    *v = b->buf[b->pos++]; return 0;
}

static int br_u32le(BufR *b, uint32_t *v) {
    if (b->len - b->pos < 4) return -1;
    *v  = (uint32_t)b->buf[b->pos++];
    *v |= (uint32_t)b->buf[b->pos++] <<  8;
    *v |= (uint32_t)b->buf[b->pos++] << 16;
    *v |= (uint32_t)b->buf[b->pos++] << 24;
    return 0;
}

static int br_raw(BufR *b, void *p, size_t n) {
    if (b->len - b->pos < n) return -1;   /* len >= pos invariant: no overflow */
    memcpy(p, b->buf + b->pos, n); b->pos += n; return 0;
}

/* ------------------------------------------------------------------ */
/* Serialization                                                       */
/* ------------------------------------------------------------------ */
/*
 * Wire format:
 *   Header : 4-byte magic "STOR" + 4-byte LE version (1)
 *   Records: [4-byte LE type][4-byte LE data-size][data]
 *
 *   USER data : u8 username_len, username, salt[16], iv[12], tag[16], check_ct[8]
 *   FILE data : u8 owner_len, owner, u8 filename_len, filename,
 *               u8 has_content
 *               if has_content: iv[12], tag[16], u32le ct_len, ct[ct_len]
 */

static void ser_user(BufW *b, const UserRec *u) {
    uint8_t ulen = (uint8_t)strlen(u->username);
    uint32_t size = 1u + ulen + SALT_LEN + IV_LEN + TAG_LEN + 8;
    bw_u32le(b, REC_USER);
    bw_u32le(b, size);
    bw_u8(b, ulen);
    bw_raw(b, u->username, ulen);
    bw_raw(b, u->salt, SALT_LEN);
    bw_raw(b, u->iv, IV_LEN);
    bw_raw(b, u->tag, TAG_LEN);
    bw_raw(b, u->check_ct, 8);
}

static void ser_file(BufW *b, const FileRec *f) {
    uint8_t olen  = (uint8_t)strlen(f->owner);
    uint8_t fnlen = (uint8_t)strlen(f->filename);
    uint32_t size = 1u + olen + 1u + fnlen + 1u;
    if (f->has_content) size += IV_LEN + TAG_LEN + 4u + f->ct_len;
    bw_u32le(b, REC_FILE);
    bw_u32le(b, size);
    bw_u8(b, olen);
    bw_raw(b, f->owner, olen);
    bw_u8(b, fnlen);
    bw_raw(b, f->filename, fnlen);
    bw_u8(b, f->has_content ? 1 : 0);
    if (f->has_content) {
        bw_raw(b, f->iv, IV_LEN);
        bw_raw(b, f->tag, TAG_LEN);
        bw_u32le(b, f->ct_len);
        if (f->ct_len > 0) bw_raw(b, f->ct, f->ct_len);
    }
}

static int deser_user(BufR *rec, UserRec *u) {
    uint8_t ulen;
    memset(u, 0, sizeof *u);
    if (br_u8(rec, &ulen) < 0 || ulen > MAX_USERNAME) return -1;
    if (br_raw(rec, u->username, ulen) < 0) return -1;
    u->username[ulen] = '\0';
    if (br_raw(rec, u->salt, SALT_LEN) < 0) return -1;
    if (br_raw(rec, u->iv, IV_LEN) < 0) return -1;
    if (br_raw(rec, u->tag, TAG_LEN) < 0) return -1;
    if (br_raw(rec, u->check_ct, 8) < 0) return -1;
    return 0;
}

static int deser_file(BufR *rec, FileRec *f) {
    uint8_t olen, fnlen, has;
    memset(f, 0, sizeof *f);
    if (br_u8(rec, &olen) < 0 || olen > MAX_USERNAME) return -1;
    if (br_raw(rec, f->owner, olen) < 0) return -1;
    f->owner[olen] = '\0';
    if (br_u8(rec, &fnlen) < 0 || fnlen > MAX_FILENAME) return -1;
    if (br_raw(rec, f->filename, fnlen) < 0) return -1;
    f->filename[fnlen] = '\0';
    if (br_u8(rec, &has) < 0) return -1;
    f->has_content = has ? 1 : 0;
    if (f->has_content) {
        if (br_raw(rec, f->iv, IV_LEN) < 0) return -1;
        if (br_raw(rec, f->tag, TAG_LEN) < 0) return -1;
        if (br_u32le(rec, &f->ct_len) < 0) return -1;
        if (f->ct_len > MAX_CONTENT) return -1;
        f->ct = NULL;
        if (f->ct_len > 0) {
            f->ct = xmalloc(f->ct_len);
            if (br_raw(rec, f->ct, f->ct_len) < 0) {
                free(f->ct); f->ct = NULL; return -1;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Database I/O                                                        */
/* ------------------------------------------------------------------ */

/* Returns 0 on success (including "no file yet"), -1 on corruption. */
static int db_load(DB *db) {
    FILE *fp;
    long fsz;
    uint8_t *buf;
    BufR b;
    uint8_t magic[4];
    uint32_t version;

    fp = fopen(DB_FILE, "rb");
    if (!fp) return 0;

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    fsz = ftell(fp);
    if (fsz < 0) { fclose(fp); return -1; }
    if (fsz == 0) { fclose(fp); return 0; }
    if ((unsigned long)fsz > 512ul * 1024ul * 1024ul) { fclose(fp); return -1; }
    fseek(fp, 0, SEEK_SET);

    buf = xmalloc((size_t)fsz);
    if (fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz) {
        free(buf); fclose(fp); return -1;
    }
    fclose(fp);

    br_init(&b, buf, (size_t)fsz);
    if (br_raw(&b, magic, 4) < 0 || memcmp(magic, DB_MAGIC, 4) != 0) goto err;
    if (br_u32le(&b, &version) < 0 || version != DB_VERSION) goto err;

    while (b.pos < b.len) {
        uint32_t type, size;
        if (br_u32le(&b, &type) < 0) goto err;   /* partial header = forgery */
        if (br_u32le(&b, &size) < 0) goto err;
        if (size > b.len - b.pos) goto err;       /* overflow-safe */

        BufR rec;
        br_init(&rec, b.buf + b.pos, size);
        b.pos += size;

        if (type == REC_USER) {
            UserRec u;
            if (deser_user(&rec, &u) < 0) goto err;
            if (rec.pos != rec.len) goto err;     /* trailing bytes = forgery */
            if (db->n_users >= db->cap_users) {
                db->cap_users = db->cap_users ? db->cap_users * 2 : 4;
                db->users = xrealloc(db->users,
                                     (size_t)db->cap_users * sizeof(UserRec));
            }
            db->users[db->n_users++] = u;
        } else if (type == REC_FILE) {
            FileRec fr;
            if (deser_file(&rec, &fr) < 0) goto err;
            if (rec.pos != rec.len) { zfree(fr.ct, fr.ct_len); goto err; }
            if (db->n_files >= db->cap_files) {
                db->cap_files = db->cap_files ? db->cap_files * 2 : 4;
                db->files = xrealloc(db->files,
                                     (size_t)db->cap_files * sizeof(FileRec));
            }
            db->files[db->n_files++] = fr;
        } else {
            goto err;   /* unknown record type = forgery, not silently skipped */
        }
    }

    if (b.pos != b.len) goto err;   /* every byte must be accounted for */
    free(buf);
    return 0;
err:
    free(buf);
    return -1;
}

static void db_save(const DB *db) {
    BufW b;
    FILE *fp;
    size_t written;
    int i;

    bw_init(&b);
    bw_raw(&b, DB_MAGIC, 4);
    bw_u32le(&b, DB_VERSION);
    for (i = 0; i < db->n_users; i++) ser_user(&b, &db->users[i]);
    for (i = 0; i < db->n_files; i++) ser_file(&b, &db->files[i]);

    fp = fopen(DB_FILE, "wb");
    if (!fp) { free(b.buf); die_invalid(); }
    written = fwrite(b.buf, 1, b.len, fp);
    fclose(fp);
    free(b.buf);
    if (written != b.len) die_invalid();
}

/* ------------------------------------------------------------------ */
/* Authentication                                                      */
/* ------------------------------------------------------------------ */

/* Build the per-file AAD: owner + 0x00 + filename. Binding both (with a
   separator so "ab"/"c" != "a"/"bc") ties a ciphertext to exactly one
   (owner, filename) slot, so a blob moved elsewhere in enc.db won't verify.
   Returns the AAD length; out must hold MAX_USERNAME+1+MAX_FILENAME+1. */
static int file_aad(const char *owner, const char *filename, uint8_t *out) {
    size_t ol = strlen(owner), fl = strlen(filename);
    memcpy(out, owner, ol);
    out[ol] = 0x00;
    memcpy(out + ol + 1, filename, fl);
    return (int)(ol + 1 + fl);
}

/* Returns derived key in dkey[] on success; calls die_invalid() on failure.
   The user token is authenticated with the username as AAD, so swapping a
   user's salt/iv/tag/token block onto another username is detected. */
static void auth_user(const UserRec *u, const char *key,
                      uint8_t dkey[KEY_LEN]) {
    uint8_t check_pt[8];
    if (derive_key(key, u->salt, dkey) < 0) { memset(dkey, 0, KEY_LEN); die_invalid(); }
    if (gcm_decrypt(dkey, u->iv,
                    (const uint8_t *)u->username, (int)strlen(u->username),
                    u->check_ct, 8, u->tag, check_pt) < 0) {
        memset(dkey, 0, KEY_LEN); die_invalid();
    }
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static void cmd_register(DB *db, const char *username, const char *key) {
    UserRec u;

    if (!username || !key || strlen(username) == 0) die_invalid();
    if (strlen(username) > MAX_USERNAME) die_invalid();
    if (db_find_user(db, username)) die_invalid();  /* already exists */

    memset(&u, 0, sizeof u);
    strncpy(u.username, username, MAX_USERNAME);

    if (RAND_bytes(u.salt, SALT_LEN) != 1) die_invalid();
    if (RAND_bytes(u.iv, IV_LEN) != 1) die_invalid();

    uint8_t dkey[KEY_LEN];
    if (derive_key(key, u.salt, dkey) < 0) die_invalid();
    if (gcm_encrypt(dkey, u.iv,
                    (const uint8_t *)u.username, (int)strlen(u.username),
                    KEY_VERIFY_PT, 8, u.check_ct, u.tag) < 0) {
        memset(dkey, 0, KEY_LEN); die_invalid();
    }
    memset(dkey, 0, KEY_LEN);

    if (db->n_users >= db->cap_users) {
        db->cap_users = db->cap_users ? db->cap_users * 2 : 4;
        db->users = xrealloc(db->users, (size_t)db->cap_users * sizeof(UserRec));
    }
    db->users[db->n_users++] = u;
}

static void cmd_create(DB *db, const char *username, const char *filename) {
    FileRec fr;

    if (!username || !filename) die_invalid();
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) die_invalid();
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) die_invalid();
    if (!db_find_user(db, username)) die_invalid();
    if (db_find_file(db, username, filename)) die_invalid();  /* already exists */

    memset(&fr, 0, sizeof fr);
    strncpy(fr.owner,    username, MAX_USERNAME);
    strncpy(fr.filename, filename, MAX_FILENAME);
    fr.has_content = 0;
    fr.ct = NULL;

    if (db->n_files >= db->cap_files) {
        db->cap_files = db->cap_files ? db->cap_files * 2 : 4;
        db->files = xrealloc(db->files, (size_t)db->cap_files * sizeof(FileRec));
    }
    db->files[db->n_files++] = fr;
}

static void cmd_write(DB *db, const char *username, const char *key,
                      const char *filename,
                      const uint8_t *content, size_t content_len) {
    UserRec *u;
    FileRec *fr;
    uint8_t dkey[KEY_LEN];
    uint8_t *ct;
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    int ct_len;

    if (!username || !key || !filename) die_invalid();
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) die_invalid();
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) die_invalid();
    if (content_len > MAX_CONTENT) die_invalid();

    u = db_find_user(db, username);
    if (!u) die_invalid();

    auth_user(u, key, dkey);   /* dies on wrong key */

    fr = db_find_file(db, username, filename);
    if (!fr) { memset(dkey, 0, KEY_LEN); die_invalid(); }

    if (RAND_bytes(iv, IV_LEN) != 1) { memset(dkey, 0, KEY_LEN); die_invalid(); }

    uint8_t aad[MAX_USERNAME + 1 + MAX_FILENAME + 1];
    int aad_len = file_aad(fr->owner, fr->filename, aad);

    ct = xmalloc(content_len > 0 ? content_len : 1);
    ct_len = gcm_encrypt(dkey, iv, aad, aad_len,
                         content, (int)content_len, ct, tag);
    memset(dkey, 0, KEY_LEN);

    if (ct_len < 0) { free(ct); die_invalid(); }

    zfree(fr->ct, fr->ct_len);
    memcpy(fr->iv,  iv,  IV_LEN);
    memcpy(fr->tag, tag, TAG_LEN);
    fr->ct_len     = (uint32_t)ct_len;
    fr->ct         = ct;
    fr->has_content = 1;
}

/* outfile: path to write output, or NULL for stdout */
static void cmd_read(DB *db, const char *username, const char *key,
                     const char *filename, const char *outfile) {
    UserRec *u;
    FileRec *fr;
    uint8_t dkey[KEY_LEN];
    uint8_t *pt;
    int pt_len;

    if (!username || !key || !filename) die_invalid();
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) die_invalid();
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) die_invalid();

    u = db_find_user(db, username);
    if (!u) die_invalid();

    auth_user(u, key, dkey);

    fr = db_find_file(db, username, filename);
    if (!fr) { memset(dkey, 0, KEY_LEN); die_invalid(); }

    if (!fr->has_content) {
        /* file exists, nothing written yet — output empty */
        memset(dkey, 0, KEY_LEN);
        if (outfile) {
            FILE *fp = fopen(outfile, "wb");
            if (!fp) die_invalid();
            fclose(fp);
        }
        return;
    }

    uint8_t aad[MAX_USERNAME + 1 + MAX_FILENAME + 1];
    int aad_len = file_aad(fr->owner, fr->filename, aad);

    pt = xmalloc(fr->ct_len > 0 ? fr->ct_len : 1);
    pt_len = gcm_decrypt(dkey, fr->iv, aad, aad_len,
                         fr->ct, (int)fr->ct_len, fr->tag, pt);
    memset(dkey, 0, KEY_LEN);

    if (pt_len < 0) { zfree(pt, fr->ct_len); die_invalid(); }

    if (outfile) {
        FILE *fp = fopen(outfile, "wb");
        if (!fp) { zfree(pt, (size_t)pt_len); die_invalid(); }
        fwrite(pt, 1, (size_t)pt_len, fp);
        fclose(fp);
    } else {
        fwrite(pt, 1, (size_t)pt_len, stdout);
    }
    zfree(pt, (size_t)pt_len);
}

/* ------------------------------------------------------------------ */
/* Argument parsing and main                                           */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    const char *opt_u = NULL;   /* -u username         */
    const char *opt_k = NULL;   /* -k secretkey        */
    const char *opt_f = NULL;   /* -f filename         */
    const char *opt_i = NULL;   /* -i inputfile        */
    const char *opt_o = NULL;   /* -o outputfile       */
    const char *cmd   = NULL;   /* register|create|write|read */
    const char *text  = NULL;   /* inline <text> for write */
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            opt_u = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            opt_k = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            opt_f = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            opt_i = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            opt_o = argv[++i];
        } else if (cmd == NULL) {
            cmd = argv[i];
        } else if (text == NULL) {
            text = argv[i];   /* first positional after cmd = inline text */
        }
        /* additional positional args ignored */
    }

    if (!cmd) die_invalid();

    /* Validate lengths of option values */
    if (opt_u && strlen(opt_u) > MAX_USERNAME) die_invalid();
    if (opt_f && strlen(opt_f) > MAX_FILENAME) die_invalid();

    DB db;
    db_init(&db);
    if (db_load(&db) < 0) { db_free(&db); die_invalid(); }

    if (strcmp(cmd, "register") == 0) {
        cmd_register(&db, opt_u, opt_k);
        db_save(&db);

    } else if (strcmp(cmd, "create") == 0) {
        cmd_create(&db, opt_u, opt_f);
        db_save(&db);

    } else if (strcmp(cmd, "write") == 0) {
        uint8_t *content = NULL;
        size_t   content_len = 0;
        int      heap = 0;

        if (opt_i) {
            /* Content from -i file */
            FILE *inf = fopen(opt_i, "rb");
            if (!inf) { db_free(&db); die_invalid(); }
            if (fseek(inf, 0, SEEK_END) != 0) { fclose(inf); db_free(&db); die_invalid(); }
            long fsz = ftell(inf);
            if (fsz < 0) { fclose(inf); db_free(&db); die_invalid(); }
            fseek(inf, 0, SEEK_SET);
            if ((unsigned long)fsz > MAX_CONTENT) { fclose(inf); db_free(&db); die_invalid(); }
            content_len = (size_t)fsz;
            content = xmalloc(content_len > 0 ? content_len : 1);
            heap = 1;
            if (content_len > 0 &&
                fread(content, 1, content_len, inf) != content_len) {
                free(content); fclose(inf); db_free(&db); die_invalid();
            }
            fclose(inf);
        } else if (text) {
            /* Inline <text> positional arg */
            content = (uint8_t *)text;
            content_len = strlen(text);
        } else {
            /* Fallback: read from stdin */
            size_t cap = 4096;
            content = xmalloc(cap);
            heap = 1;
            int c;
            while ((c = getchar()) != EOF) {
                if (content_len >= MAX_CONTENT) {
                    free(content); db_free(&db); die_invalid();
                }
                if (content_len >= cap) {
                    cap *= 2;
                    content = xrealloc(content, cap);
                }
                content[content_len++] = (uint8_t)c;
            }
        }

        cmd_write(&db, opt_u, opt_k, opt_f, content, content_len);
        if (heap) zfree(content, content_len);
        db_save(&db);

    } else if (strcmp(cmd, "read") == 0) {
        cmd_read(&db, opt_u, opt_k, opt_f, opt_o);

    } else {
        db_free(&db);
        die_invalid();
    }

    db_free(&db);
    return 0;
}
