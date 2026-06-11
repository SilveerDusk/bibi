/*
 * stor.c — BiBiFi secure file store implementation.
 *
 * Database format (enc.db):
 *   The file is a serialized collection of records, each AEAD-encrypted
 *   with a master key derived from a fixed passphrase + per-record salt.
 *
 *   File layout:
 *     [MAGIC 4B][NUM_USERS 4B][NUM_FILES 4B]
 *     [USER_RECORD ...] x NUM_USERS
 *     [FILE_RECORD ...] x NUM_FILES
 *     [HMAC_SHA256 32B]   <- over everything above
 *
 *   USER_RECORD:
 *     [username_len 4B][username ...][key_hash 32B][key_salt 32B]
 *
 *   FILE_RECORD:
 *     [filename_len 4B][filename ...][owner_len 4B][owner ...]
 *     [content_len 4B][encrypted_content ...][nonce 16B][content_salt 32B]
 *
 * Security:
 *   - User keys are stored as PBKDF2-SHA256(key, salt, 100000 iters, 32B).
 *   - File content is encrypted with AES-256-GCM using a key derived from
 *     PBKDF2-SHA256(user_key, content_salt, 100000 iters, 32B).
 *   - A HMAC-SHA256 over the entire file (using a fixed master HMAC key)
 *     provides integrity / tamper detection.
 *
 * Build:
 *   gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c \
 *       -lssl -lcrypto
 *   execstack --set-execstack stor
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* ---- Constants ---- */
#define DB_FILE        "enc.db"
#define MAGIC          0x53544F52u  /* "STOR" */
#define SALT_LEN       32
#define KEY_LEN        32           /* AES-256 */
#define NONCE_LEN      12           /* GCM 96-bit nonce */
#define TAG_LEN        16           /* GCM auth tag */
#define HASH_LEN       32           /* SHA-256 output */
#define PBKDF2_ITERS   100000
#define MAX_USERS      256
#define MAX_FILES      4096
#define MAX_NAME       256
#define MAX_CONTENT    (1 << 20)    /* 1 MB */

/* Master HMAC key — fixed, compiled in.  Protects db integrity. */
static const unsigned char MASTER_HMAC_KEY[32] = {
    0x4b,0x3a,0x7f,0x21,0x9c,0x55,0xe8,0x3d,
    0xb1,0x06,0x44,0xfa,0x2e,0x91,0x0c,0x78,
    0xd5,0x8b,0x47,0x3e,0xa9,0xcc,0x1f,0x60,
    0x77,0x24,0xbd,0x50,0x08,0x3c,0x92,0x6a
};

/* ---- Data structures ---- */
typedef struct {
    char     username[MAX_NAME];
    uint8_t  key_hash[HASH_LEN];   /* PBKDF2(key, salt) */
    uint8_t  key_salt[SALT_LEN];
} User;

typedef struct {
    char     filename[MAX_NAME];
    char     owner[MAX_NAME];
    uint8_t *enc_content;          /* AES-256-GCM ciphertext + tag */
    uint32_t enc_len;              /* len of enc_content (plaintext_len + TAG_LEN) */
    uint8_t  nonce[NONCE_LEN];
    uint8_t  content_salt[SALT_LEN];
} File;

typedef struct {
    uint32_t num_users;
    uint32_t num_files;
    User     users[MAX_USERS];
    File     files[MAX_FILES];
} DB;

/* ---- Error helper ---- */
static int invalid(void) {
    printf("invalid");
    return 255;
}

/* ---- Memory helpers ---- */
static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) {
        printf("invalid");
        exit(255);
    }
    return p;
}

/* ---- Crypto helpers ---- */

/* PBKDF2-SHA256 */
static int derive_key(const char *password, size_t passlen,
                      const uint8_t *salt, size_t saltlen,
                      uint8_t *out, size_t outlen)
{
    return PKCS5_PBKDF2_HMAC(password, (int)passlen,
                              salt, (int)saltlen,
                              PBKDF2_ITERS,
                              EVP_sha256(),
                              (int)outlen, out);
}

/* AES-256-GCM encrypt.
 * out must be at least (inlen + TAG_LEN) bytes.
 * Returns total written bytes, or -1 on error.
 */
static int aes_gcm_encrypt(const uint8_t *key,
                            const uint8_t *nonce,
                            const uint8_t *in, int inlen,
                            uint8_t *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, clen = 0;
    int ok = 1;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) { ok=0; goto done; }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) { ok=0; goto done; }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) { ok=0; goto done; }
    if (!EVP_EncryptUpdate(ctx, out, &len, in, inlen)) { ok=0; goto done; }
    clen = len;
    if (!EVP_EncryptFinal_ex(ctx, out + clen, &len)) { ok=0; goto done; }
    clen += len;
    /* append tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out + clen)) { ok=0; goto done; }
    clen += TAG_LEN;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? clen : -1;
}

/* AES-256-GCM decrypt.
 * in is ciphertext (inlen - TAG_LEN bytes) followed by TAG_LEN-byte tag.
 * out must be at least (inlen - TAG_LEN) bytes.
 * Returns plaintext length, or -1 on auth failure.
 */
static int aes_gcm_decrypt(const uint8_t *key,
                            const uint8_t *nonce,
                            const uint8_t *in, int inlen,
                            uint8_t *out)
{
    if (inlen < TAG_LEN) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ciphlen = inlen - TAG_LEN;
    int len = 0, plen = 0;
    int ok = 1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) { ok=0; goto done; }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL)) { ok=0; goto done; }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) { ok=0; goto done; }
    if (!EVP_DecryptUpdate(ctx, out, &len, in, ciphlen)) { ok=0; goto done; }
    plen = len;
    /* set expected tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                              (void *)(in + ciphlen))) { ok=0; goto done; }
    if (EVP_DecryptFinal_ex(ctx, out + plen, &len) <= 0) { ok=0; goto done; }
    plen += len;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? plen : -1;
}

/* HMAC-SHA256 */
static void compute_hmac(const uint8_t *data, size_t len, uint8_t *out)
{
    unsigned int outlen = HASH_LEN;
    HMAC(EVP_sha256(), MASTER_HMAC_KEY, sizeof(MASTER_HMAC_KEY),
         data, len, out, &outlen);
}

/* Constant-time memcmp (returns 0 if equal) */
static int ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *p = (const uint8_t *)a;
    const uint8_t *q = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= p[i] ^ q[i];
    return (int)diff;
}

/* ---- Serialization helpers ---- */

/* Write a 4-byte little-endian uint32 to buf, advance pos */
static void write_u32(uint8_t *buf, size_t *pos, uint32_t v)
{
    buf[(*pos)++] = (uint8_t)(v & 0xff);
    buf[(*pos)++] = (uint8_t)((v >> 8) & 0xff);
    buf[(*pos)++] = (uint8_t)((v >> 16) & 0xff);
    buf[(*pos)++] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t read_u32(const uint8_t *buf, size_t *pos)
{
    uint32_t v = (uint32_t)buf[*pos]
               | ((uint32_t)buf[*pos+1] << 8)
               | ((uint32_t)buf[*pos+2] << 16)
               | ((uint32_t)buf[*pos+3] << 24);
    *pos += 4;
    return v;
}

static void write_bytes(uint8_t *buf, size_t *pos, const void *src, size_t n)
{
    memcpy(buf + *pos, src, n);
    *pos += n;
}

static void read_bytes(const uint8_t *buf, size_t *pos, void *dst, size_t n)
{
    memcpy(dst, buf + *pos, n);
    *pos += n;
}

static void write_str(uint8_t *buf, size_t *pos, const char *s)
{
    uint32_t len = (uint32_t)strlen(s);
    write_u32(buf, pos, len);
    write_bytes(buf, pos, s, len);
}

/* Read a string into dst (max maxlen-1 chars + NUL).  Returns 0 on error. */
static int read_str(const uint8_t *buf, size_t *pos, size_t bufsize,
                    char *dst, size_t maxlen)
{
    if (*pos + 4 > bufsize) return 0;
    uint32_t len = read_u32(buf, pos);
    if (len >= maxlen) return 0;
    if (*pos + len > bufsize) return 0;
    read_bytes(buf, pos, dst, len);
    dst[len] = '\0';
    return 1;
}

/* ---- DB size estimation ---- */
static size_t db_serialized_size(const DB *db)
{
    /* header */
    size_t sz = 4 + 4 + 4; /* MAGIC + num_users + num_files */
    for (uint32_t i = 0; i < db->num_users; i++) {
        sz += 4 + strlen(db->users[i].username);
        sz += HASH_LEN + SALT_LEN;
    }
    for (uint32_t i = 0; i < db->num_files; i++) {
        sz += 4 + strlen(db->files[i].filename);
        sz += 4 + strlen(db->files[i].owner);
        sz += 4 + db->files[i].enc_len;
        sz += NONCE_LEN + SALT_LEN;
    }
    sz += HASH_LEN; /* trailing HMAC */
    return sz;
}

/* ---- Save DB ---- */
static int db_save(const DB *db)
{
    size_t sz = db_serialized_size(db);
    uint8_t *buf = (uint8_t *)xmalloc(sz);
    size_t pos = 0;

    write_u32(buf, &pos, MAGIC);
    write_u32(buf, &pos, db->num_users);
    write_u32(buf, &pos, db->num_files);

    for (uint32_t i = 0; i < db->num_users; i++) {
        const User *u = &db->users[i];
        write_str(buf, &pos, u->username);
        write_bytes(buf, &pos, u->key_hash, HASH_LEN);
        write_bytes(buf, &pos, u->key_salt, SALT_LEN);
    }

    for (uint32_t i = 0; i < db->num_files; i++) {
        const File *f = &db->files[i];
        write_str(buf, &pos, f->filename);
        write_str(buf, &pos, f->owner);
        write_u32(buf, &pos, f->enc_len);
        if (f->enc_len > 0)
            write_bytes(buf, &pos, f->enc_content, f->enc_len);
        write_bytes(buf, &pos, f->nonce, NONCE_LEN);
        write_bytes(buf, &pos, f->content_salt, SALT_LEN);
    }

    /* HMAC over everything so far */
    uint8_t mac[HASH_LEN];
    compute_hmac(buf, pos, mac);
    write_bytes(buf, &pos, mac, HASH_LEN);

    FILE *fp = fopen(DB_FILE, "wb");
    if (!fp) { free(buf); return 0; }
    size_t written = fwrite(buf, 1, pos, fp);
    fclose(fp);
    free(buf);
    return (written == pos) ? 1 : 0;
}

/* ---- Load DB ---- */
static int db_load(DB *db)
{
    memset(db, 0, sizeof(*db));

    FILE *fp = fopen(DB_FILE, "rb");
    if (!fp) return 1; /* no db yet — start fresh */

    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsz < (long)(4 + 4 + 4 + HASH_LEN)) {
        fclose(fp);
        return 0; /* too small, tampered */
    }

    uint8_t *buf = (uint8_t *)xmalloc((size_t)fsz);
    if (fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz) {
        fclose(fp);
        free(buf);
        return 0;
    }
    fclose(fp);

    /* Verify HMAC */
    uint8_t expected_mac[HASH_LEN];
    compute_hmac(buf, (size_t)fsz - HASH_LEN, expected_mac);
    if (ct_memcmp(buf + fsz - HASH_LEN, expected_mac, HASH_LEN) != 0) {
        free(buf);
        return 0; /* integrity failure */
    }

    size_t pos = 0;
    size_t bufsize = (size_t)fsz - HASH_LEN; /* parse only payload */

    if (pos + 12 > bufsize) { free(buf); return 0; }
    uint32_t magic = read_u32(buf, &pos);
    if (magic != MAGIC) { free(buf); return 0; }

    db->num_users = read_u32(buf, &pos);
    db->num_files = read_u32(buf, &pos);

    if (db->num_users > MAX_USERS || db->num_files > MAX_FILES) {
        free(buf); return 0;
    }

    for (uint32_t i = 0; i < db->num_users; i++) {
        User *u = &db->users[i];
        if (!read_str(buf, &pos, bufsize, u->username, MAX_NAME)) { free(buf); return 0; }
        if (pos + HASH_LEN + SALT_LEN > bufsize) { free(buf); return 0; }
        read_bytes(buf, &pos, u->key_hash, HASH_LEN);
        read_bytes(buf, &pos, u->key_salt, SALT_LEN);
    }

    for (uint32_t i = 0; i < db->num_files; i++) {
        File *f = &db->files[i];
        if (!read_str(buf, &pos, bufsize, f->filename, MAX_NAME)) { free(buf); return 0; }
        if (!read_str(buf, &pos, bufsize, f->owner, MAX_NAME)) { free(buf); return 0; }
        if (pos + 4 > bufsize) { free(buf); return 0; }
        f->enc_len = read_u32(buf, &pos);
        if (f->enc_len > MAX_CONTENT + TAG_LEN) { free(buf); return 0; }
        if (pos + f->enc_len > bufsize) { free(buf); return 0; }
        if (f->enc_len > 0) {
            f->enc_content = (uint8_t *)xmalloc(f->enc_len);
            read_bytes(buf, &pos, f->enc_content, f->enc_len);
        } else {
            f->enc_content = NULL;
        }
        if (pos + NONCE_LEN + SALT_LEN > bufsize) { free(buf); return 0; }
        read_bytes(buf, &pos, f->nonce, NONCE_LEN);
        read_bytes(buf, &pos, f->content_salt, SALT_LEN);
    }

    free(buf);
    return 1;
}

static void db_free(DB *db)
{
    for (uint32_t i = 0; i < db->num_files; i++) {
        free(db->files[i].enc_content);
        db->files[i].enc_content = NULL;
    }
}

/* ---- Lookup helpers ---- */
static User *find_user(DB *db, const char *username)
{
    for (uint32_t i = 0; i < db->num_users; i++)
        if (strcmp(db->users[i].username, username) == 0)
            return &db->users[i];
    return NULL;
}

static File *find_file(DB *db, const char *filename, const char *owner)
{
    for (uint32_t i = 0; i < db->num_files; i++)
        if (strcmp(db->files[i].filename, filename) == 0 &&
            strcmp(db->files[i].owner, owner) == 0)
            return &db->files[i];
    return NULL;
}

/* Verify key against stored hash; returns 1 if valid */
static int verify_key(const User *u, const char *key)
{
    uint8_t derived[HASH_LEN];
    if (!derive_key(key, strlen(key), u->key_salt, SALT_LEN, derived, HASH_LEN))
        return 0;
    return (ct_memcmp(derived, u->key_hash, HASH_LEN) == 0) ? 1 : 0;
}

/* ---- Main ---- */
int main(int argc, char **argv)
{
    char *user    = NULL;
    char *key     = NULL;
    char *file    = NULL;
    char *infile  = NULL;
    char *outfile = NULL;
    int c;

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

    if (!user) return invalid();
    if (optind >= argc) return invalid();

    const char *action  = argv[optind];
    const char *content = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    /* Validate username / key / file lengths */
    if (strlen(user) >= MAX_NAME) return invalid();
    if (key    && strlen(key)    >= MAX_NAME) return invalid();
    if (file   && strlen(file)   >= MAX_NAME) return invalid();

    /* Load state */
    DB db;
    if (!db_load(&db)) return invalid();

    /* ------------------------------------------------------------------ */
    if (strcmp(action, "register") == 0) {
        if (!key) { db_free(&db); return invalid(); }

        User *u = find_user(&db, user);
        if (!u) {
            if (db.num_users >= MAX_USERS) { db_free(&db); return invalid(); }
            u = &db.users[db.num_users++];
            strncpy(u->username, user, MAX_NAME - 1);
            u->username[MAX_NAME - 1] = '\0';
        }

        /* Generate fresh salt and derive hash */
        if (!RAND_bytes(u->key_salt, SALT_LEN)) { db_free(&db); return invalid(); }
        if (!derive_key(key, strlen(key), u->key_salt, SALT_LEN,
                        u->key_hash, HASH_LEN)) { db_free(&db); return invalid(); }

        if (!db_save(&db)) { db_free(&db); return invalid(); }
        db_free(&db);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    if (strcmp(action, "create") == 0) {
        if (!file) { db_free(&db); return invalid(); }

        /* User must exist */
        User *u = find_user(&db, user);
        if (!u) { db_free(&db); return invalid(); }

        /* If file already exists for this owner, no-op */
        if (find_file(&db, file, user)) {
            db_free(&db);
            return 0;
        }

        if (db.num_files >= MAX_FILES) { db_free(&db); return invalid(); }
        File *f = &db.files[db.num_files++];
        memset(f, 0, sizeof(*f));
        strncpy(f->filename, file, MAX_NAME - 1);
        f->filename[MAX_NAME - 1] = '\0';
        strncpy(f->owner, user, MAX_NAME - 1);
        f->owner[MAX_NAME - 1] = '\0';
        f->enc_content = NULL;
        f->enc_len = 0;
        /* nonce and salt are zeroed — content is empty, no encryption needed */

        if (!db_save(&db)) { db_free(&db); return invalid(); }
        db_free(&db);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    if (strcmp(action, "write") == 0) {
        if (!key || !file) { db_free(&db); return invalid(); }

        User *u = find_user(&db, user);
        if (!u) { db_free(&db); return invalid(); }
        if (!verify_key(u, key)) { db_free(&db); return invalid(); }

        File *f = find_file(&db, file, user);
        if (!f) { db_free(&db); return invalid(); }

        /* Gather plaintext */
        uint8_t *plaintext = NULL;
        size_t   ptlen     = 0;

        if (infile) {
            FILE *fp = fopen(infile, "rb");
            if (!fp) { db_free(&db); return invalid(); }
            fseek(fp, 0, SEEK_END);
            long fsz = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (fsz < 0 || fsz > MAX_CONTENT) { fclose(fp); db_free(&db); return invalid(); }
            ptlen = (size_t)fsz;
            plaintext = (uint8_t *)xmalloc(ptlen + 1);
            if (fread(plaintext, 1, ptlen, fp) != ptlen) {
                fclose(fp); free(plaintext); db_free(&db); return invalid();
            }
            fclose(fp);
            /* strip trailing newline added by shell echo */
            if (ptlen > 0 && plaintext[ptlen - 1] == '\n') ptlen--;
        } else if (content) {
            ptlen = strlen(content);
            if (ptlen > MAX_CONTENT) { db_free(&db); return invalid(); }
            plaintext = (uint8_t *)xmalloc(ptlen + 1);
            memcpy(plaintext, content, ptlen);
        } else {
            /* empty write */
            plaintext = (uint8_t *)xmalloc(1);
            ptlen = 0;
        }

        /* Derive file encryption key from user key + fresh salt */
        uint8_t new_salt[SALT_LEN];
        if (!RAND_bytes(new_salt, SALT_LEN)) {
            free(plaintext); db_free(&db); return invalid();
        }
        uint8_t fkey[KEY_LEN];
        if (!derive_key(key, strlen(key), new_salt, SALT_LEN, fkey, KEY_LEN)) {
            free(plaintext); db_free(&db); return invalid();
        }

        uint8_t new_nonce[NONCE_LEN];
        if (!RAND_bytes(new_nonce, NONCE_LEN)) {
            free(plaintext); db_free(&db); return invalid();
        }

        uint8_t *ciphertext = (uint8_t *)xmalloc(ptlen + TAG_LEN + 1);
        int clen = aes_gcm_encrypt(fkey, new_nonce, plaintext, (int)ptlen, ciphertext);
        free(plaintext);
        if (clen < 0) {
            free(ciphertext); db_free(&db); return invalid();
        }

        free(f->enc_content);
        f->enc_content = ciphertext;
        f->enc_len     = (uint32_t)clen;
        memcpy(f->nonce, new_nonce, NONCE_LEN);
        memcpy(f->content_salt, new_salt, SALT_LEN);

        if (!db_save(&db)) { db_free(&db); return invalid(); }
        db_free(&db);
        return 0;
    }

    /* ------------------------------------------------------------------ */
    if (strcmp(action, "read") == 0) {
        if (!key || !file) { db_free(&db); return invalid(); }

        User *u = find_user(&db, user);
        if (!u) { db_free(&db); return invalid(); }
        if (!verify_key(u, key)) { db_free(&db); return invalid(); }

        File *f = find_file(&db, file, user);
        if (!f) { db_free(&db); return invalid(); }

        /* Empty file */
        if (f->enc_len == 0 || f->enc_content == NULL) {
            if (outfile) {
                FILE *fp = fopen(outfile, "wb");
                if (!fp) { db_free(&db); return invalid(); }
                fclose(fp);
            }
            /* print nothing */
            db_free(&db);
            return 0;
        }

        /* Derive file key */
        uint8_t fkey[KEY_LEN];
        if (!derive_key(key, strlen(key), f->content_salt, SALT_LEN, fkey, KEY_LEN)) {
            db_free(&db); return invalid();
        }

        uint8_t *plaintext = (uint8_t *)xmalloc(f->enc_len + 1);
        int plen = aes_gcm_decrypt(fkey, f->nonce, f->enc_content, (int)f->enc_len, plaintext);
        if (plen < 0) {
            free(plaintext); db_free(&db); return invalid();
        }
        plaintext[plen] = '\0';

        if (outfile) {
            FILE *fp = fopen(outfile, "wb");
            if (!fp) { free(plaintext); db_free(&db); return invalid(); }
            fwrite(plaintext, 1, (size_t)plen, fp);
            fclose(fp);
        } else {
            fwrite(plaintext, 1, (size_t)plen, stdout);
        }

        free(plaintext);
        db_free(&db);
        return 0;
    }

    /* Unknown action */
    db_free(&db);
    return invalid();
}
