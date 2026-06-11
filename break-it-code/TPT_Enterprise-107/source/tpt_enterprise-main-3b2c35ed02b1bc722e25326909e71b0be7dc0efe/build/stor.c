/*
 * stor.c - BiBiFi secure file store.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_PATH "enc.db"
#define MAGIC "STOR3\n"
#define HASH_HEX_LEN 64
#define SALT_LEN 16
#define NONCE_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32
#define KDF_ROUNDS 100000

#define MAX_USERNAME_LEN 64
#define MAX_KEY_LEN 128
#define MAX_FILENAME_LEN 256
#define MAX_CONTENT_LEN (16 * 1024 * 1024)
#define MAX_DB_LEN (64 * 1024 * 1024)

typedef struct {
    char *name;
    unsigned char salt[SALT_LEN];
    char verifier[HASH_HEX_LEN + 1];
} User;

typedef struct {
    char *owner;
    char *name;
    unsigned char *cipher;
    size_t len;
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    int protected;
} FileEntry;

typedef struct {
    User *users;
    size_t user_count;
    FileEntry *files;
    size_t file_count;
} Store;

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} StrBuf;

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

static int invalid(void) {
    printf("invalid");
    return 255;
}

static char *xstrdup(const char *s) {
    size_t n;
    char *out;

    if (!s) return NULL;
    n = strlen(s) + 1;
    out = (char *)malloc(n);
    if (!out) return NULL;
    memcpy(out, s, n);
    return out;
}

static void free_store(Store *st) {
    size_t i;

    for (i = 0; i < st->user_count; i++) free(st->users[i].name);
    for (i = 0; i < st->file_count; i++) {
        free(st->files[i].owner);
        free(st->files[i].name);
        free(st->files[i].cipher);
    }
    free(st->users);
    free(st->files);
    memset(st, 0, sizeof(*st));
}

static void hex_encode(const unsigned char *in, size_t len, char *out) {
    static const char table[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = table[in[i] >> 4];
        out[i * 2 + 1] = table[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode_fixed(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;

    if (strlen(hex) != out_len * 2) return 0;
    for (i = 0; i < out_len; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static int hex_decode_alloc(const char *hex, unsigned char **out, size_t *out_len) {
    size_t len, i;
    unsigned char *buf;

    if (strcmp(hex, "-") == 0) {
        buf = (unsigned char *)malloc(1);
        if (!buf) return 0;
        *out = buf;
        *out_len = 0;
        return 1;
    }
    len = strlen(hex);
    if (len % 2 != 0 || len / 2 > MAX_CONTENT_LEN) return 0;
    buf = (unsigned char *)malloc(len / 2 + 1);
    if (!buf) return 0;
    for (i = 0; i < len; i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return 0;
        }
        buf[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out = buf;
    *out_len = len / 2;
    return 1;
}

static char *hex_decode_string(const char *hex) {
    unsigned char *raw;
    size_t len;
    char *s;

    if (!hex_decode_alloc(hex, &raw, &len)) return NULL;
    s = (char *)malloc(len + 1);
    if (!s) {
        free(raw);
        return NULL;
    }
    memcpy(s, raw, len);
    s[len] = '\0';
    free(raw);
    return s;
}

static char *hex_encode_string(const char *s) {
    size_t len = strlen(s);
    char *out;

    if (len > (SIZE_MAX - 1) / 2) return NULL;
    out = (char *)malloc(len * 2 + 1);
    if (!out) return NULL;
    hex_encode((const unsigned char *)s, len, out);
    return out;
}

static char *hex_encode_bytes_or_dash(const unsigned char *bytes, size_t len) {
    char *out;

    if (len == 0) return xstrdup("-");
    if (len > (SIZE_MAX - 1) / 2) return NULL;
    out = (char *)malloc(len * 2 + 1);
    if (!out) return NULL;
    hex_encode(bytes, len, out);
    return out;
}

static int derive_key(const char *key, const unsigned char salt[SALT_LEN],
                      unsigned char out[KEY_LEN]) {
    return PKCS5_PBKDF2_HMAC(key, (int)strlen(key), salt, SALT_LEN, KDF_ROUNDS,
                             EVP_sha256(), KEY_LEN, out) == 1;
}

static void verifier_hex(const char *user, const unsigned char key[KEY_LEN],
                         char out_hex[HASH_HEX_LEN + 1]) {
    SHA256_CTX ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, "verify|", 7);
    SHA256_Update(&ctx, user, strlen(user));
    SHA256_Update(&ctx, "|", 1);
    SHA256_Update(&ctx, key, KEY_LEN);
    SHA256_Final(digest, &ctx);
    hex_encode(digest, sizeof(digest), out_hex);
}

static User *find_user(Store *st, const char *name) {
    size_t i;

    for (i = 0; i < st->user_count; i++) {
        if (strcmp(st->users[i].name, name) == 0) return &st->users[i];
    }
    return NULL;
}

static FileEntry *find_file(Store *st, const char *owner, const char *name) {
    size_t i;

    for (i = 0; i < st->file_count; i++) {
        if (strcmp(st->files[i].owner, owner) == 0 &&
            strcmp(st->files[i].name, name) == 0) {
            return &st->files[i];
        }
    }
    return NULL;
}

static int verify_user_key(Store *st, const char *user, const char *key,
                           unsigned char out_key[KEY_LEN]) {
    User *u;
    char verifier[HASH_HEX_LEN + 1];

    if (!key) return 0;
    u = find_user(st, user);
    if (!u) return 0;
    if (!derive_key(key, u->salt, out_key)) return 0;
    verifier_hex(user, out_key, verifier);
    return strcmp(u->verifier, verifier) == 0;
}

static int add_or_update_user(Store *st, const char *name, const char *key) {
    User *u;
    User *new_users;
    unsigned char derived[KEY_LEN];

    u = find_user(st, name);
    if (!u) {
        new_users = (User *)realloc(st->users, (st->user_count + 1) * sizeof(User));
        if (!new_users) return 0;
        st->users = new_users;
        u = &st->users[st->user_count++];
        memset(u, 0, sizeof(*u));
        u->name = xstrdup(name);
        if (!u->name) return 0;
    }
    if (RAND_bytes(u->salt, SALT_LEN) != 1) return 0;
    if (!derive_key(key, u->salt, derived)) return 0;
    verifier_hex(name, derived, u->verifier);
    OPENSSL_cleanse(derived, sizeof(derived));
    return 1;
}

static int add_file(Store *st, const char *owner, const char *name) {
    FileEntry *f;
    FileEntry *new_files;

    if (find_file(st, owner, name)) return 1;
    new_files = (FileEntry *)realloc(st->files, (st->file_count + 1) * sizeof(FileEntry));
    if (!new_files) return 0;
    st->files = new_files;
    f = &st->files[st->file_count++];
    memset(f, 0, sizeof(*f));
    f->owner = xstrdup(owner);
    f->name = xstrdup(name);
    f->cipher = (unsigned char *)malloc(1);
    if (!f->owner || !f->name || !f->cipher) return 0;
    f->len = 0;
    f->protected = 0;
    return 1;
}

static int aad_update(EVP_CIPHER_CTX *ctx, const char *owner, const char *name) {
    int out_len;

    return EVP_EncryptUpdate(ctx, NULL, &out_len, (const unsigned char *)owner,
                             (int)strlen(owner)) == 1 &&
           EVP_EncryptUpdate(ctx, NULL, &out_len, (const unsigned char *)"|", 1) == 1 &&
           EVP_EncryptUpdate(ctx, NULL, &out_len, (const unsigned char *)name,
                             (int)strlen(name)) == 1;
}

static int aad_update_dec(EVP_CIPHER_CTX *ctx, const char *owner, const char *name) {
    int out_len;

    return EVP_DecryptUpdate(ctx, NULL, &out_len, (const unsigned char *)owner,
                             (int)strlen(owner)) == 1 &&
           EVP_DecryptUpdate(ctx, NULL, &out_len, (const unsigned char *)"|", 1) == 1 &&
           EVP_DecryptUpdate(ctx, NULL, &out_len, (const unsigned char *)name,
                             (int)strlen(name)) == 1;
}

static int encrypt_file(FileEntry *f, const unsigned char key[KEY_LEN],
                        const unsigned char *plain, size_t len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *cipher = NULL;
    int out_len = 0;
    int final_len = 0;
    int ok = 0;

    if (len > MAX_CONTENT_LEN) return 0;
    cipher = (unsigned char *)malloc(len + 1);
    if (!cipher) return 0;
    if (RAND_bytes(f->nonce, NONCE_LEN) != 1) goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, f->nonce) != 1) goto done;
    if (!aad_update(ctx, f->owner, f->name)) goto done;
    if (len > 0 &&
        EVP_EncryptUpdate(ctx, cipher, &out_len, plain, (int)len) != 1) goto done;
    if (EVP_EncryptFinal_ex(ctx, cipher + out_len, &final_len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, f->tag) != 1) goto done;

    free(f->cipher);
    f->cipher = cipher;
    f->len = len;
    f->protected = 1;
    cipher = NULL;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    free(cipher);
    return ok;
}

static int decrypt_file(FileEntry *f, const unsigned char key[KEY_LEN],
                        unsigned char **plain_out) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *plain = NULL;
    int out_len = 0;
    int final_len = 0;
    int ok = 0;

    if (!f->protected) {
        plain = (unsigned char *)malloc(1);
        if (!plain) return 0;
        *plain_out = plain;
        return f->len == 0;
    }
    plain = (unsigned char *)malloc(f->len + 1);
    if (!plain) return 0;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, f->nonce) != 1) goto done;
    if (!aad_update_dec(ctx, f->owner, f->name)) goto done;
    if (f->len > 0 &&
        EVP_DecryptUpdate(ctx, plain, &out_len, f->cipher, (int)f->len) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, f->tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plain + out_len, &final_len) != 1) goto done;
    *plain_out = plain;
    plain = NULL;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    return ok;
}

static int sb_init(StrBuf *sb) {
    sb->cap = 256;
    sb->len = 0;
    sb->buf = (char *)malloc(sb->cap);
    if (!sb->buf) return 0;
    sb->buf[0] = '\0';
    return 1;
}

static int sb_reserve(StrBuf *sb, size_t extra) {
    size_t need = sb->len + extra + 1;
    char *p;

    if (need < sb->len || need > MAX_DB_LEN) return 0;
    while (sb->cap < need) {
        if (sb->cap > MAX_DB_LEN / 2) return 0;
        sb->cap *= 2;
    }
    p = (char *)realloc(sb->buf, sb->cap);
    if (!p) return 0;
    sb->buf = p;
    return 1;
}

static int sb_append_len(StrBuf *sb, const char *s, size_t n) {
    if (!sb_reserve(sb, n)) return 0;
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 1;
}

static int sb_append(StrBuf *sb, const char *s) {
    return sb_append_len(sb, s, strlen(s));
}

static int sb_append_size(StrBuf *sb, size_t n) {
    char tmp[32];

    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)n);
    return sb_append(sb, tmp);
}

static int build_body(Store *st, StrBuf *body) {
    size_t i;

    if (!sb_init(body)) return 0;
    if (!sb_append(body, MAGIC)) return 0;
    for (i = 0; i < st->user_count; i++) {
        char *name_hex = hex_encode_string(st->users[i].name);
        char salt_hex[SALT_LEN * 2 + 1];
        if (!name_hex) return 0;
        hex_encode(st->users[i].salt, SALT_LEN, salt_hex);
        if (!sb_append(body, "U ") || !sb_append(body, name_hex) ||
            !sb_append(body, " ") || !sb_append(body, salt_hex) ||
            !sb_append(body, " ") || !sb_append(body, st->users[i].verifier) ||
            !sb_append(body, "\n")) {
            free(name_hex);
            return 0;
        }
        free(name_hex);
    }
    for (i = 0; i < st->file_count; i++) {
        char *owner_hex = hex_encode_string(st->files[i].owner);
        char *name_hex = hex_encode_string(st->files[i].name);
        char *cipher_hex = hex_encode_bytes_or_dash(st->files[i].cipher, st->files[i].len);
        char nonce_hex[NONCE_LEN * 2 + 1];
        char tag_hex[TAG_LEN * 2 + 1];
        if (!owner_hex || !name_hex || !cipher_hex) {
            free(owner_hex);
            free(name_hex);
            free(cipher_hex);
            return 0;
        }
        if (st->files[i].protected) {
            hex_encode(st->files[i].nonce, NONCE_LEN, nonce_hex);
            hex_encode(st->files[i].tag, TAG_LEN, tag_hex);
        } else {
            strcpy(nonce_hex, "-");
            strcpy(tag_hex, "-");
        }
        if (!sb_append(body, "F ") || !sb_append(body, owner_hex) ||
            !sb_append(body, " ") || !sb_append(body, name_hex) ||
            !sb_append(body, " ") || !sb_append_size(body, st->files[i].len) ||
            !sb_append(body, " ") || !sb_append(body, nonce_hex) ||
            !sb_append(body, " ") || !sb_append(body, tag_hex) ||
            !sb_append(body, " ") || !sb_append(body, cipher_hex) ||
            !sb_append(body, "\n")) {
            free(owner_hex);
            free(name_hex);
            free(cipher_hex);
            return 0;
        }
        free(owner_hex);
        free(name_hex);
        free(cipher_hex);
    }
    return 1;
}

static int save_store(Store *st) {
    StrBuf body;
    FILE *fp;
    int ok;

    if (!build_body(st, &body)) return 0;
    fp = fopen(DB_PATH, "wb");
    if (!fp) {
        free(body.buf);
        return 0;
    }
    ok = fwrite(body.buf, 1, body.len, fp) == body.len && fclose(fp) == 0;
    free(body.buf);
    return ok;
}

static int read_all(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp;
    long n;
    unsigned char *buf;

    fp = fopen(path, "rb");
    if (!fp) return 0;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    n = ftell(fp);
    if (n < 0 || n > MAX_DB_LEN) {
        fclose(fp);
        return 0;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)n + 1);
    if (!buf) {
        fclose(fp);
        return 0;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    buf[n] = '\0';
    *out = buf;
    *out_len = (size_t)n;
    return 1;
}

static int parse_user(Store *st, char *line) {
    char *name_hex = strtok(line + 2, " ");
    char *salt_hex = strtok(NULL, " ");
    char *verifier = strtok(NULL, " ");
    User *new_users;
    User *u;

    if (!name_hex || !salt_hex || !verifier || strtok(NULL, " ") ||
        strlen(verifier) != HASH_HEX_LEN) {
        return 0;
    }
    new_users = (User *)realloc(st->users, (st->user_count + 1) * sizeof(User));
    if (!new_users) return 0;
    st->users = new_users;
    u = &st->users[st->user_count++];
    memset(u, 0, sizeof(*u));
    u->name = hex_decode_string(name_hex);
    if (!u->name || strlen(u->name) > MAX_USERNAME_LEN) return 0;
    if (find_user(st, u->name) != u) return 0;
    if (!hex_decode_fixed(salt_hex, u->salt, SALT_LEN)) return 0;
    memcpy(u->verifier, verifier, HASH_HEX_LEN + 1);
    return 1;
}

static int parse_file(Store *st, char *line) {
    char *owner_hex = strtok(line + 2, " ");
    char *name_hex = strtok(NULL, " ");
    char *len_s = strtok(NULL, " ");
    char *nonce_hex = strtok(NULL, " ");
    char *tag_hex = strtok(NULL, " ");
    char *cipher_hex = strtok(NULL, " ");
    FileEntry *new_files;
    FileEntry *f;
    unsigned long expected_len;
    char *end = NULL;

    if (!owner_hex || !name_hex || !len_s || !nonce_hex || !tag_hex || !cipher_hex ||
        strtok(NULL, " ")) {
        return 0;
    }
    expected_len = strtoul(len_s, &end, 10);
    if (!end || *end != '\0' || expected_len > MAX_CONTENT_LEN) return 0;

    new_files = (FileEntry *)realloc(st->files, (st->file_count + 1) * sizeof(FileEntry));
    if (!new_files) return 0;
    st->files = new_files;
    f = &st->files[st->file_count++];
    memset(f, 0, sizeof(*f));
    f->owner = hex_decode_string(owner_hex);
    f->name = hex_decode_string(name_hex);
    if (!f->owner || !f->name ||
        strlen(f->owner) > MAX_USERNAME_LEN ||
        strlen(f->name) > MAX_FILENAME_LEN) {
        return 0;
    }
    if (find_file(st, f->owner, f->name) != f) return 0;
    if (!hex_decode_alloc(cipher_hex, &f->cipher, &f->len)) return 0;
    if (f->len != (size_t)expected_len) return 0;
    if (strcmp(nonce_hex, "-") == 0 && strcmp(tag_hex, "-") == 0) {
        if (f->len != 0) return 0;
        f->protected = 0;
        return 1;
    }
    if (!hex_decode_fixed(nonce_hex, f->nonce, NONCE_LEN)) return 0;
    if (!hex_decode_fixed(tag_hex, f->tag, TAG_LEN)) return 0;
    f->protected = 1;
    return 1;
}

static int load_store(Store *st) {
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    char *body;
    char *line;
    char *saveptr = NULL;

    memset(st, 0, sizeof(*st));
    if (!read_all(DB_PATH, &raw, &raw_len)) return 1;
    if (raw_len < strlen(MAGIC) || memcmp(raw, MAGIC, strlen(MAGIC)) != 0) {
        free(raw);
        return 0;
    }
    body = (char *)raw;
    line = strtok_r(body, "\n", &saveptr);
    if (!line || strcmp(line, "STOR3") != 0) {
        free(raw);
        return 0;
    }
    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        if (strncmp(line, "U ", 2) == 0) {
            if (!parse_user(st, line)) {
                free(raw);
                return 0;
            }
        } else if (strncmp(line, "F ", 2) == 0) {
            if (!parse_file(st, line)) {
                free(raw);
                return 0;
            }
        } else {
            free(raw);
            return 0;
        }
    }
    free(raw);
    return 1;
}

static int read_input_file(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp;
    long n;
    unsigned char *buf;

    fp = fopen(path, "rb");
    if (!fp) return 0;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }
    n = ftell(fp);
    if (n < 0 || n > MAX_CONTENT_LEN) {
        fclose(fp);
        return 0;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)n + 1);
    if (!buf) {
        fclose(fp);
        return 0;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    *out_len = (size_t)n;
    if (*out_len > 0 && buf[*out_len - 1] == '\n') {
        (*out_len)--;
        if (*out_len > 0 && buf[*out_len - 1] == '\r') (*out_len)--;
    }
    *out = buf;
    return 1;
}

static int get_input_content(const char *infile, const char *arg,
                             unsigned char **out, size_t *out_len) {
    size_t len;

    if (infile) return read_input_file(infile, out, out_len);
    if (!arg) arg = "";
    len = strlen(arg);
    if (len > MAX_CONTENT_LEN) return 0;
    *out = (unsigned char *)malloc(len + 1);
    if (!*out) return 0;
    memcpy(*out, arg, len);
    *out_len = len;
    return 1;
}

static int write_output(const char *outfile, const unsigned char *data, size_t len) {
    FILE *fp;
    int ok;

    if (!outfile) return fwrite(data, 1, len, stdout) == len;
    fp = fopen(outfile, "wb");
    if (!fp) return 0;
    ok = fwrite(data, 1, len, fp) == len && fclose(fp) == 0;
    return ok;
}

int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *action;
    const char *content;
    Store st;
    int c;
    int rc = 255;

    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user = optarg; break;
            case 'k': key = optarg; break;
            case 'f': file = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return invalid();
        }
    }

    if (!user) return invalid();
    if (optind >= argc) return invalid();
    if (strlen(user) > MAX_USERNAME_LEN) return invalid();
    if (key && strlen(key) > MAX_KEY_LEN) return invalid();
    if (file && strlen(file) > MAX_FILENAME_LEN) return invalid();

    action = argv[optind];
    content = (optind + 1 < argc) ? argv[optind + 1] : NULL;
    if (content && strlen(content) > MAX_CONTENT_LEN) return invalid();

    if (!load_store(&st)) return invalid();

    if (strcmp(action, "register") == 0) {
        if (!key || file || infile || outfile || content) goto bad;
        if (!add_or_update_user(&st, user, key)) goto bad;
        if (!save_store(&st)) goto bad;
        rc = 0;
        goto done;
    }

    if (strcmp(action, "create") == 0) {
        if (!file || infile || outfile || content) goto bad;
        if (!add_file(&st, user, file)) goto bad;
        if (!save_store(&st)) goto bad;
        rc = 0;
        goto done;
    }

    if (strcmp(action, "write") == 0) {
        FileEntry *f;
        unsigned char *plain = NULL;
        unsigned char derived[KEY_LEN];
        size_t len = 0;

        if (!key || !file || outfile || !verify_user_key(&st, user, key, derived)) goto bad;
        f = find_file(&st, user, file);
        if (!f) {
            OPENSSL_cleanse(derived, sizeof(derived));
            goto bad;
        }
        if (!get_input_content(infile, content, &plain, &len)) {
            OPENSSL_cleanse(derived, sizeof(derived));
            goto bad;
        }
        if (!encrypt_file(f, derived, plain, len)) {
            OPENSSL_cleanse(derived, sizeof(derived));
            free(plain);
            goto bad;
        }
        OPENSSL_cleanse(derived, sizeof(derived));
        OPENSSL_cleanse(plain, len);
        free(plain);
        if (!save_store(&st)) goto bad;
        rc = 0;
        goto done;
    }

    if (strcmp(action, "read") == 0) {
        FileEntry *f;
        unsigned char *plain = NULL;
        unsigned char derived[KEY_LEN];

        if (!key || !file || infile || content || !verify_user_key(&st, user, key, derived)) goto bad;
        f = find_file(&st, user, file);
        if (!f) {
            OPENSSL_cleanse(derived, sizeof(derived));
            goto bad;
        }
        if (!decrypt_file(f, derived, &plain)) {
            OPENSSL_cleanse(derived, sizeof(derived));
            goto bad;
        }
        OPENSSL_cleanse(derived, sizeof(derived));
        if (!write_output(outfile, plain, f->len)) {
            OPENSSL_cleanse(plain, f->len);
            free(plain);
            goto bad;
        }
        OPENSSL_cleanse(plain, f->len);
        free(plain);
        rc = 0;
        goto done;
    }

bad:
    free_store(&st);
    return invalid();

done:
    free_store(&st);
    return rc;
}
