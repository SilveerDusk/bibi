#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#define DB_FILE "enc.db"

#define SALT_LEN 16
#define NONCE_LEN 16
#define KEY_LEN 32
#define TAG_LEN 32

typedef enum {
    CMD_NONE = 0,
    CMD_REGISTER,
    CMD_CREATE,
    CMD_WRITE,
    CMD_READ
} Command;

typedef struct {
    char *username;
    char *key;
    char *filename;
    char *inputfile;
    char *outputfile;
    char *text;
    Command cmd;
    int cmd_count;
} Args;

typedef struct {
    char *user;
    char *user_id;
    unsigned char salt[SALT_LEN];
    unsigned char verifier[TAG_LEN];
} User;

typedef struct {
    char *user;
    char *name;
    char *user_id;
    char *file_id;
    unsigned char *data;
    size_t len;
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    int has_crypto;
} StoredFile;

typedef struct {
    User *users;
    size_t user_count;
    StoredFile *files;
    size_t file_count;
} Database;

static char *hex_encode(const unsigned char *data, size_t len);

/* ===== required target ===== */

void win(void) {
    printf("Arbitrary access achieved!\n");
}

static int invalid(void) {
    printf("invalid\n");
    return 255;
}

/* ===== tiny utilities ===== */

static char *xstrdup(const char *s) {
    size_t n;
    char *p;

    if (!s) return NULL;
    n = strlen(s);
    p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n + 1);
    return p;
}

static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n) {
    size_t i;
    unsigned char diff = 0;

    for (i = 0; i < n; i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static int random_bytes(unsigned char *buf, size_t len) {
    FILE *fp;
    size_t got;

    fp = fopen("/dev/urandom", "rb");
    if (!fp) return 0;

    got = fread(buf, 1, len, fp);
    fclose(fp);

    return got == len;
}

static void put_u64_be(unsigned char out[8], uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

/* ===== SHA-256, because apparently package managers needed drama ===== */

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX_LOCAL;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
    0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
    0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
    0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
    0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
    0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
    0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
    0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
    0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void sha256_transform(SHA256_CTX_LOCAL *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) |
               ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) |
               ((uint32_t)data[j + 3]);
    }

    for (; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX_LOCAL *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
}

static void sha256_update(SHA256_CTX_LOCAL *ctx, const uint8_t *data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX_LOCAL *ctx, uint8_t hash[32]) {
    uint32_t i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;

    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xff);
    }
}

/* ===== HMAC-SHA256 ===== */

typedef struct {
    SHA256_CTX_LOCAL inner;
    SHA256_CTX_LOCAL outer;
} HMAC_CTX_LOCAL;

static void hmac_init(HMAC_CTX_LOCAL *ctx, const unsigned char *key, size_t key_len) {
    unsigned char kopad[64];
    unsigned char kipad[64];
    unsigned char keyhash[32];
    unsigned char keyblock[64];
    size_t i;

    memset(keyblock, 0, sizeof(keyblock));

    if (key_len > 64) {
        SHA256_CTX_LOCAL sctx;
        sha256_init(&sctx);
        sha256_update(&sctx, key, key_len);
        sha256_final(&sctx, keyhash);
        memcpy(keyblock, keyhash, 32);
    } else {
        memcpy(keyblock, key, key_len);
    }

    for (i = 0; i < 64; i++) {
        kipad[i] = keyblock[i] ^ 0x36;
        kopad[i] = keyblock[i] ^ 0x5c;
    }

    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, kipad, 64);

    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, kopad, 64);
}

static void hmac_update(HMAC_CTX_LOCAL *ctx, const unsigned char *data, size_t len) {
    if (len > 0) sha256_update(&ctx->inner, data, len);
}

static void hmac_final(HMAC_CTX_LOCAL *ctx, unsigned char out[32]) {
    unsigned char inner_hash[32];

    sha256_final(&ctx->inner, inner_hash);
    sha256_update(&ctx->outer, inner_hash, 32);
    sha256_final(&ctx->outer, out);
}

static void hmac_sha256(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char out[32]
) {
    HMAC_CTX_LOCAL ctx;
    hmac_init(&ctx, key, key_len);
    hmac_update(&ctx, msg, msg_len);
    hmac_final(&ctx, out);
}

/* ===== crypto-ish storage helpers ===== */



static void derive_key(const char *secret, const unsigned char salt[SALT_LEN], unsigned char out[KEY_LEN]) {
    HMAC_CTX_LOCAL ctx;

    hmac_init(&ctx, (const unsigned char *)secret, strlen(secret));
    hmac_update(&ctx, (const unsigned char *)"stor-key-v2", strlen("stor-key-v2"));
    hmac_update(&ctx, salt, SALT_LEN);
    hmac_final(&ctx, out);
}

static void make_verifier(const unsigned char key[KEY_LEN], unsigned char out[TAG_LEN]) {
    hmac_sha256(
        key,
        KEY_LEN,
        (const unsigned char *)"stor-verify-v2",
        strlen("stor-verify-v2"),
        out
    );
}

static void make_public_id(
    const char *prefix,
    const char *a,
    const char *b,
    unsigned char out[TAG_LEN]
) {
    HMAC_CTX_LOCAL ctx;
    static const unsigned char db_pepper[32] = {
        0x91,0x37,0x42,0xa8,0x5c,0x0f,0x63,0x2d,
        0x99,0x14,0xef,0x77,0x21,0xb4,0x6a,0xc0,
        0x1d,0x82,0x58,0xbe,0x35,0x49,0xd3,0x06,
        0x74,0xaa,0x19,0x5e,0xc8,0x40,0xf2,0x0b
    };

    hmac_init(&ctx, db_pepper, sizeof(db_pepper));
    hmac_update(&ctx, (const unsigned char *)prefix, strlen(prefix));
    hmac_update(&ctx, (const unsigned char *)"\0", 1);
    hmac_update(&ctx, (const unsigned char *)a, strlen(a));

    if (b) {
        hmac_update(&ctx, (const unsigned char *)"\0", 1);
        hmac_update(&ctx, (const unsigned char *)b, strlen(b));
    }

    hmac_final(&ctx, out);
}

static char *user_id_hex(const char *user) {
    unsigned char id[TAG_LEN];
    make_public_id("user", user, NULL, id);
    return hex_encode(id, TAG_LEN);
}

static char *file_id_hex(const char *user, const char *filename) {
    unsigned char id[TAG_LEN];
    make_public_id("file", user, filename, id);
    return hex_encode(id, TAG_LEN);
}

static void stream_xor(
    const unsigned char key[KEY_LEN],
    const unsigned char nonce[NONCE_LEN],
    const unsigned char *in,
    unsigned char *out,
    size_t len
) {
    uint64_t counter = 0;
    size_t pos = 0;

    while (pos < len) {
        HMAC_CTX_LOCAL ctx;
        unsigned char block[32];
        unsigned char ctr[8];
        size_t take;
        size_t i;

        put_u64_be(ctr, counter);

        hmac_init(&ctx, key, KEY_LEN);
        hmac_update(&ctx, (const unsigned char *)"stor-stream-v2", strlen("stor-stream-v2"));
        hmac_update(&ctx, nonce, NONCE_LEN);
        hmac_update(&ctx, ctr, 8);
        hmac_final(&ctx, block);

        take = len - pos;
        if (take > 32) take = 32;

        for (i = 0; i < take; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }

        pos += take;
        counter++;
    }
}

static void make_file_tag(
    const unsigned char key[KEY_LEN],
    const char *user,
    const char *filename,
    const unsigned char nonce[NONCE_LEN],
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char out[TAG_LEN]
) {
    HMAC_CTX_LOCAL ctx;
    unsigned char lenbuf[8];

    put_u64_be(lenbuf, (uint64_t)ciphertext_len);

    hmac_init(&ctx, key, KEY_LEN);
    hmac_update(&ctx, (const unsigned char *)"stor-file-v2", strlen("stor-file-v2"));
    hmac_update(&ctx, (const unsigned char *)user, strlen(user));
    hmac_update(&ctx, (const unsigned char *)"\0", 1);
    hmac_update(&ctx, (const unsigned char *)filename, strlen(filename));
    hmac_update(&ctx, (const unsigned char *)"\0", 1);
    hmac_update(&ctx, nonce, NONCE_LEN);
    hmac_update(&ctx, lenbuf, 8);
    hmac_update(&ctx, ciphertext, ciphertext_len);
    hmac_final(&ctx, out);
}

/* ===== CLI parsing ===== */

static int is_command(const char *s) {
    return strcmp(s, "register") == 0 ||
           strcmp(s, "create") == 0 ||
           strcmp(s, "write") == 0 ||
           strcmp(s, "read") == 0;
}

static Command parse_command(const char *s) {
    if (strcmp(s, "register") == 0) return CMD_REGISTER;
    if (strcmp(s, "create") == 0) return CMD_CREATE;
    if (strcmp(s, "write") == 0) return CMD_WRITE;
    if (strcmp(s, "read") == 0) return CMD_READ;
    return CMD_NONE;
}

static int parse_args(int argc, char **argv, Args *args) {
    int i;

    memset(args, 0, sizeof(*args));

    for (i = 1; i < argc; i++) {
        char *cur = argv[i];

        if (strcmp(cur, "-u") == 0) {
            if (i + 1 >= argc) return 0;
            args->username = argv[++i];
        } else if (strcmp(cur, "-k") == 0) {
            if (i + 1 >= argc) return 0;
            args->key = argv[++i];
        } else if (strcmp(cur, "-f") == 0) {
            if (i + 1 >= argc) return 0;
            args->filename = argv[++i];
        } else if (strcmp(cur, "-i") == 0) {
            if (i + 1 >= argc) return 0;
            args->inputfile = argv[++i];
        } else if (strcmp(cur, "-o") == 0) {
            if (i + 1 >= argc) return 0;
            args->outputfile = argv[++i];
        } else if (is_command(cur)) {
            args->cmd = parse_command(cur);
            args->cmd_count++;
        } else {
            if (args->text != NULL) return 0;
            args->text = cur;
        }
    }

    if (args->cmd_count != 1) return 0;
    if (!args->username || strlen(args->username) == 0) return 0;

    switch (args->cmd) {
        case CMD_REGISTER:
            if (!args->key || strlen(args->key) == 0) return 0;
            if (args->filename || args->inputfile || args->outputfile || args->text) return 0;
            return 1;

        case CMD_CREATE:
            if (!args->filename || strlen(args->filename) == 0) return 0;
            if (args->inputfile || args->outputfile || args->text) return 0;
            return 1;

        case CMD_WRITE:
            if (!args->key || strlen(args->key) == 0) return 0;
            if (!args->filename || strlen(args->filename) == 0) return 0;
            if (args->inputfile && args->text) return 0;
            if (!args->inputfile && !args->text) return 0;
            if (args->outputfile) return 0;
            return 1;

        case CMD_READ:
            if (!args->key || strlen(args->key) == 0) return 0;
            if (!args->filename || strlen(args->filename) == 0) return 0;
            if (args->inputfile || args->text) return 0;
            return 1;

        default:
            return 0;
    }
}

/* ===== hex helpers ===== */

static char hex_digit(unsigned int v) {
    return (char)(v < 10 ? '0' + v : 'a' + (v - 10));
}

static int from_hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static char *hex_encode(const unsigned char *data, size_t len) {
    char *out;
    size_t i;

    out = (char *)malloc(len * 2 + 1);
    if (!out) return NULL;

    for (i = 0; i < len; i++) {
        out[i * 2] = hex_digit((data[i] >> 4) & 0xf);
        out[i * 2 + 1] = hex_digit(data[i] & 0xf);
    }

    out[len * 2] = '\0';
    return out;
}

static unsigned char *hex_decode(const char *s, size_t *out_len) {
    size_t n, i;
    unsigned char *out;

    n = strlen(s);
    if (n % 2 != 0) return NULL;

    out = (unsigned char *)malloc(n / 2 + 1);
    if (!out) return NULL;

    for (i = 0; i < n; i += 2) {
        int a = from_hex(s[i]);
        int b = from_hex(s[i + 1]);

        if (a < 0 || b < 0) {
            free(out);
            return NULL;
        }

        out[i / 2] = (unsigned char)((a << 4) | b);
    }

    *out_len = n / 2;
    return out;
}

static int hex_decode_fixed(const char *s, unsigned char *out, size_t expected_len) {
    unsigned char *tmp;
    size_t len;

    tmp = hex_decode(s, &len);
    if (!tmp) return 0;

    if (len != expected_len) {
        free(tmp);
        return 0;
    }

    memcpy(out, tmp, expected_len);
    free(tmp);
    return 1;
}

/* ===== DB helpers ===== */

static void db_init(Database *db) {
    memset(db, 0, sizeof(*db));
}

static void db_free(Database *db) {
    size_t i;

    for (i = 0; i < db->user_count; i++) {
        free(db->users[i].user);
        free(db->users[i].user_id);
    }
    free(db->users);

    for (i = 0; i < db->file_count; i++) {
        free(db->files[i].user);
        free(db->files[i].name);
        free(db->files[i].user_id);
        free(db->files[i].file_id);
        free(db->files[i].data);
    }
    free(db->files);
}

static User *find_user(Database *db, const char *user) {
    size_t i;
    char *uid = user_id_hex(user);

    if (!uid) return NULL;

    for (i = 0; i < db->user_count; i++) {
        if (strcmp(db->users[i].user_id, uid) == 0) {
            free(uid);
            return &db->users[i];
        }
    }

    free(uid);
    return NULL;
}

static StoredFile *find_file(Database *db, const char *user, const char *name) {
    size_t i;
    char *uid = user_id_hex(user);
    char *fid = file_id_hex(user, name);

    if (!uid || !fid) {
        free(uid);
        free(fid);
        return NULL;
    }

    for (i = 0; i < db->file_count; i++) {
        if (strcmp(db->files[i].user_id, uid) == 0 &&
            strcmp(db->files[i].file_id, fid) == 0) {
            free(uid);
            free(fid);
            return &db->files[i];
        }
    }

    free(uid);
    free(fid);
    return NULL;
}

static int db_add_user(
    Database *db,
    const char *user,
    const unsigned char salt[SALT_LEN],
    const unsigned char verifier[TAG_LEN]
) {
    User *new_users;
    char *u;
    char *uid;

    if (find_user(db, user)) return 0;

    new_users = (User *)realloc(db->users, sizeof(User) * (db->user_count + 1));
    if (!new_users) return 0;
    db->users = new_users;

    u = xstrdup(user);
    uid = user_id_hex(user);

    if (!u || !uid) {
        free(u);
        free(uid);
        return 0;
    }

    db->users[db->user_count].user = u;
    db->users[db->user_count].user_id = uid;
    memcpy(db->users[db->user_count].salt, salt, SALT_LEN);
    memcpy(db->users[db->user_count].verifier, verifier, TAG_LEN);
    db->user_count++;

    return 1;
}

static int db_add_user_loaded(
    Database *db,
    const char *stored_user_id,
    const unsigned char salt[SALT_LEN],
    const unsigned char verifier[TAG_LEN]
) {
    User *new_users;

    new_users = (User *)realloc(db->users, sizeof(User) * (db->user_count + 1));
    if (!new_users) return 0;
    db->users = new_users;

    db->users[db->user_count].user = xstrdup("");
    db->users[db->user_count].user_id = xstrdup(stored_user_id);

    if (!db->users[db->user_count].user || !db->users[db->user_count].user_id) {
        free(db->users[db->user_count].user);
        free(db->users[db->user_count].user_id);
        return 0;
    }

    memcpy(db->users[db->user_count].salt, salt, SALT_LEN);
    memcpy(db->users[db->user_count].verifier, verifier, TAG_LEN);
    db->user_count++;

    return 1;
}

static int db_add_file(Database *db, const char *user, const char *name) {
    StoredFile *new_files;

    if (find_file(db, user, name)) return 0;

    new_files = (StoredFile *)realloc(db->files, sizeof(StoredFile) * (db->file_count + 1));
    if (!new_files) return 0;
    db->files = new_files;

    db->files[db->file_count].user = xstrdup(user);
    db->files[db->file_count].name = xstrdup(name);
    db->files[db->file_count].user_id = user_id_hex(user);
    db->files[db->file_count].file_id = file_id_hex(user, name);

    if (!db->files[db->file_count].user ||
        !db->files[db->file_count].name ||
        !db->files[db->file_count].user_id ||
        !db->files[db->file_count].file_id) {
        free(db->files[db->file_count].user);
        free(db->files[db->file_count].name);
        free(db->files[db->file_count].user_id);
        free(db->files[db->file_count].file_id);
        return 0;
    }

    db->files[db->file_count].data = NULL;
    db->files[db->file_count].len = 0;
    memset(db->files[db->file_count].nonce, 0, NONCE_LEN);
    memset(db->files[db->file_count].tag, 0, TAG_LEN);
    db->files[db->file_count].has_crypto = 0;

    db->file_count++;
    return 1;
}

static int db_add_file_loaded(
    Database *db,
    const char *stored_user_id,
    const char *stored_file_id
) {
    StoredFile *new_files;

    new_files = (StoredFile *)realloc(db->files, sizeof(StoredFile) * (db->file_count + 1));
    if (!new_files) return 0;
    db->files = new_files;

    db->files[db->file_count].user = xstrdup("");
    db->files[db->file_count].name = xstrdup("");
    db->files[db->file_count].user_id = xstrdup(stored_user_id);
    db->files[db->file_count].file_id = xstrdup(stored_file_id);

    if (!db->files[db->file_count].user ||
        !db->files[db->file_count].name ||
        !db->files[db->file_count].user_id ||
        !db->files[db->file_count].file_id) {
        free(db->files[db->file_count].user);
        free(db->files[db->file_count].name);
        free(db->files[db->file_count].user_id);
        free(db->files[db->file_count].file_id);
        return 0;
    }

    db->files[db->file_count].data = NULL;
    db->files[db->file_count].len = 0;
    memset(db->files[db->file_count].nonce, 0, NONCE_LEN);
    memset(db->files[db->file_count].tag, 0, TAG_LEN);
    db->files[db->file_count].has_crypto = 0;

    db->file_count++;
    return 1;
}

static char *read_db_line(FILE *fp) {
    size_t cap = 256;
    size_t len = 0;
    int ch;
    char *buf;

    buf = (char *)malloc(cap);
    if (!buf) return NULL;

    while ((ch = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            char *nbuf;
            cap *= 2;
            nbuf = (char *)realloc(buf, cap);
            if (!nbuf) {
                free(buf);
                return NULL;
            }
            buf = nbuf;
        }

        if (ch == '\n') break;
        buf[len++] = (char)ch;
    }

    if (ch == EOF && len == 0) {
        free(buf);
        return NULL;
    }

    if (len > 0 && buf[len - 1] == '\r') len--;
    buf[len] = '\0';

    return buf;
}

static int db_load(Database *db) {
    FILE *fp;
    char *line;

    fp = fopen(DB_FILE, "r");
    if (!fp) {
        if (errno == ENOENT) return 1;
        return 0;
    }

    while ((line = read_db_line(fp)) != NULL) {
        char *type;
        char *a;
        char *b;
        char *c;
        char *d;
        char *e;

        if (line[0] == '\0') {
            free(line);
            continue;
        }

        type = strtok(line, " ");
        if (!type) {
            free(line);
            fclose(fp);
            return 0;
        }

        if (strcmp(type, "U") == 0) {
            unsigned char salt[SALT_LEN];
            unsigned char verifier[TAG_LEN];

            a = strtok(NULL, " ");
            b = strtok(NULL, " ");
            c = strtok(NULL, " ");
            d = strtok(NULL, " ");

            if (!a || !b || !c || d) {
                free(line);
                fclose(fp);
                return 0;
            }

            if (!hex_decode_fixed(b, salt, SALT_LEN) ||
                !hex_decode_fixed(c, verifier, TAG_LEN)) {
                free(line);
                fclose(fp);
                return 0;
            }

            if (!db_add_user_loaded(db, a, salt, verifier)) {
                free(line);
                fclose(fp);
                return 0;
            }
        } else if (strcmp(type, "F") == 0) {
            unsigned char *raw_data = NULL;
            size_t data_len = 0;
            StoredFile *sf;

            a = strtok(NULL, " ");
            b = strtok(NULL, " ");
            c = strtok(NULL, " ");
            d = strtok(NULL, " ");
            e = strtok(NULL, " ");

            if (!a || !b || !c || !d || !e || strtok(NULL, " ")) {
                free(line);
                fclose(fp);
                return 0;
            }

            if (!db_add_file_loaded(db, a, b)) {
                free(line);
                fclose(fp);
                return 0;
            }

            sf = &db->files[db->file_count - 1];

            if (strcmp(c, "-") == 0 && strcmp(d, "-") == 0 && strcmp(e, "-") == 0) {
                sf->has_crypto = 0;
            } else {
                if (!hex_decode_fixed(c, sf->nonce, NONCE_LEN) ||
                    !hex_decode_fixed(e, sf->tag, TAG_LEN)) {
                    free(line);
                    fclose(fp);
                    return 0;
                }

                if (strcmp(d, "-") == 0) {
                    raw_data = NULL;
                    data_len = 0;
                } else {
                    raw_data = hex_decode(d, &data_len);
                    if (!raw_data) {
                        free(line);
                        fclose(fp);
                        return 0;
                    }
                }

                sf->data = raw_data;
                sf->len = data_len;
                sf->has_crypto = 1;
            }
        } else {
            free(line);
            fclose(fp);
            return 0;
        }

        free(line);
    }

    fclose(fp);
    return 1;
}

static int db_save(Database *db) {
    FILE *fp;
    size_t i;

    fp = fopen(DB_FILE, "w");
    if (!fp) return 0;

    for (i = 0; i < db->user_count; i++) {
        char *hu = xstrdup(db->users[i].user_id);
        char *hs = hex_encode(db->users[i].salt, SALT_LEN);
        char *hv = hex_encode(db->users[i].verifier, TAG_LEN);

        if (!hu || !hs || !hv) {
            free(hu);
            free(hs);
            free(hv);
            fclose(fp);
            return 0;
        }

        fprintf(fp, "U %s %s %s\n", hu, hs, hv);

        free(hu);
        free(hs);
        free(hv);
    }

    for (i = 0; i < db->file_count; i++) {
        char *hu = xstrdup(db->files[i].user_id);
        char *hn = xstrdup(db->files[i].file_id);
        if (!hu || !hn) {
            free(hu);
            free(hn);
            fclose(fp);
            return 0;
        }

        if (!db->files[i].has_crypto) {
            fprintf(fp, "F %s %s - - -\n", hu, hn);
        } else {
            char *hnonce = hex_encode(db->files[i].nonce, NONCE_LEN);
            char *hdata;
            char *htag = hex_encode(db->files[i].tag, TAG_LEN);

            if (db->files[i].len == 0) {
                hdata = xstrdup("-");
            } else {
                hdata = hex_encode(db->files[i].data, db->files[i].len);
            }

            if (!hnonce || !hdata || !htag) {
                free(hu);
                free(hn);
                free(hnonce);
                free(hdata);
                free(htag);
                fclose(fp);
                return 0;
            }

            fprintf(fp, "F %s %s %s %s %s\n", hu, hn, hnonce, hdata, htag);

            free(hnonce);
            free(hdata);
            free(htag);
        }

        free(hu);
        free(hn);
    }

    fclose(fp);
    return 1;
}

/* ===== file IO ===== */

static int read_whole_file(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp;
    long sz;
    unsigned char *buf;

    fp = fopen(path, "rb");
    if (!fp) return 0;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }

    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return 0;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }

    buf = (unsigned char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return 0;
    }

    if (sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return 0;
    }

    fclose(fp);

    *out = buf;
    *out_len = (size_t)sz;
    return 1;
}

static int write_whole_file_new(const char *path, const unsigned char *data, size_t len) {
    FILE *check;
    FILE *fp;

    check = fopen(path, "rb");
    if (check) {
        fclose(check);
        return 0;
    }

    fp = fopen(path, "wb");
    if (!fp) return 0;

    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return 1;
}

/* ===== command logic ===== */

static int authenticate(Database *db, const char *user, const char *key, unsigned char out_key[KEY_LEN]) {
    User *u;
    unsigned char verifier[TAG_LEN];

    u = find_user(db, user);
    if (!u) return 0;

    derive_key(key, u->salt, out_key);
    make_verifier(out_key, verifier);

    return ct_equal(verifier, u->verifier, TAG_LEN);
}

static int do_register(Database *db, Args *args) {
    unsigned char salt[SALT_LEN];
    unsigned char userkey[KEY_LEN];
    unsigned char verifier[TAG_LEN];

    if (!random_bytes(salt, SALT_LEN)) return invalid();

    derive_key(args->key, salt, userkey);
    make_verifier(userkey, verifier);

    if (!db_add_user(db, args->username, salt, verifier)) return invalid();
    if (!db_save(db)) return invalid();

    return 0;
}

static int do_create(Database *db, Args *args) {
    if (!find_user(db, args->username)) return invalid();
    if (!db_add_file(db, args->username, args->filename)) return invalid();
    if (!db_save(db)) return invalid();

    return 0;
}

static int do_write(Database *db, Args *args) {
    StoredFile *sf;
    unsigned char userkey[KEY_LEN];
    unsigned char *plain = NULL;
    unsigned char *cipher = NULL;
    size_t plain_len = 0;

    if (!authenticate(db, args->username, args->key, userkey)) return invalid();

    sf = find_file(db, args->username, args->filename);
    if (!sf) return invalid();

    if (args->inputfile) {
        if (!read_whole_file(args->inputfile, &plain, &plain_len)) return invalid();
    } else {
        plain_len = strlen(args->text);
        plain = (unsigned char *)malloc(plain_len + 1);
        if (!plain) return invalid();
        memcpy(plain, args->text, plain_len);
    }

    cipher = (unsigned char *)malloc(plain_len + 1);
    if (!cipher) {
        free(plain);
        return invalid();
    }

    if (!random_bytes(sf->nonce, NONCE_LEN)) {
        free(plain);
        free(cipher);
        return invalid();
    }

    stream_xor(userkey, sf->nonce, plain, cipher, plain_len);
    make_file_tag(userkey, args->username, args->filename, sf->nonce, cipher, plain_len, sf->tag);

    free(plain);
    free(sf->data);

    sf->data = cipher;
    sf->len = plain_len;
    sf->has_crypto = 1;

    if (!db_save(db)) return invalid();

    return 0;
}

static int do_read(Database *db, Args *args) {
    StoredFile *sf;
    unsigned char userkey[KEY_LEN];
    unsigned char expected[TAG_LEN];
    unsigned char *plain;

    if (!authenticate(db, args->username, args->key, userkey)) return invalid();

    sf = find_file(db, args->username, args->filename);
    if (!sf) return invalid();

    if (!sf->has_crypto) {
        if (args->outputfile) {
            if (!write_whole_file_new(args->outputfile, (const unsigned char *)"", 0)) return invalid();
        } else {
            printf("\n");
        }
        return 0;
    }

    make_file_tag(userkey, args->username, args->filename, sf->nonce, sf->data, sf->len, expected);
    if (!ct_equal(expected, sf->tag, TAG_LEN)) return invalid();

    plain = (unsigned char *)malloc(sf->len + 1);
    if (!plain) return invalid();

    stream_xor(userkey, sf->nonce, sf->data, plain, sf->len);

    if (args->outputfile) {
        if (!write_whole_file_new(args->outputfile, plain, sf->len)) {
            free(plain);
            return invalid();
        }
    } else {
        if (sf->len > 0 && fwrite(plain, 1, sf->len, stdout) != sf->len) {
            free(plain);
            return invalid();
        }
        printf("\n");
    }

    free(plain);
    return 0;
}

/* ===== main ===== */

int main(int argc, char **argv) {
    Args args;
    Database db;
    int rc;

    if (!parse_args(argc, argv, &args)) return invalid();

    db_init(&db);

    if (!db_load(&db)) {
        db_free(&db);
        return invalid();
    }

    switch (args.cmd) {
        case CMD_REGISTER:
            rc = do_register(&db, &args);
            break;
        case CMD_CREATE:
            rc = do_create(&db, &args);
            break;
        case CMD_WRITE:
            rc = do_write(&db, &args);
            break;
        case CMD_READ:
            rc = do_read(&db, &args);
            break;
        default:
            rc = invalid();
            break;
    }

    db_free(&db);
    return rc;
}