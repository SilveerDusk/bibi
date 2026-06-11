/*
 * stor.c - BiBiFi secure file store.
 *
 * CLI:
 *   ./stor -u <user> [-k <key>] [-f <file>] [-i <infile>] [-o <outfile>] <action> [text]
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_PATH "enc.db"
#define MAGIC "STORDB1"
#define MAGIC_LEN 8
#define VERSION 1U
#define SALT_LEN 16
#define NONCE_LEN 16
#define HASH_LEN 32
#define KEY_LEN 32
#define KEY_MATERIAL_LEN 64
#define MAX_FIELD_LEN (1024U * 1024U)
#define MAX_CONTENT_LEN (16U * 1024U * 1024U)
#define PBKDF2_ITERS 20000U
#define PAD_BLOCK 256U

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

static int invalid(void) {
    printf("invalid");
    return 255;
}

typedef struct {
    uint32_t len;
    unsigned char *data;
    unsigned char salt[SALT_LEN];
    unsigned char verifier[HASH_LEN];
} User;

typedef struct {
    uint32_t owner_len;
    unsigned char *owner;
    uint32_t name_len;
    unsigned char *name;
    unsigned char nonce[NONCE_LEN];
    uint32_t cipher_len;
    unsigned char *cipher;
    unsigned char tag[HASH_LEN];
} FileEntry;

typedef struct {
    uint32_t user_count;
    User *users;
    uint32_t file_count;
    FileEntry *files;
} Db;

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char data[64];
    uint32_t datalen;
} Sha256;

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

static uint32_t load_be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static void store_be64(unsigned char *p, uint64_t v) {
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}

static uint64_t load_be64(const unsigned char *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static const uint32_t k256[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void sha256_transform(Sha256 *ctx, const unsigned char data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; i++, j += 4) m[i] = load_be32(data + j);
    for (; i < 64; i++) {
        uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + s1 + ch + k256[i] + m[i];
        t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256 *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667U; ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U; ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU; ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU; ctx->state[7] = 0x5be0cd19U;
}

static void sha256_update(Sha256 *ctx, const unsigned char *data, uint32_t len) {
    uint32_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, unsigned char hash[HASH_LEN]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (uint64_t)ctx->datalen * 8U;
    store_be64(ctx->data + 56, ctx->bitlen);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 8; i++) store_be32(hash + i * 4, ctx->state[i]);
}

static void hmac_sha256(const unsigned char *key, uint32_t key_len,
                        const unsigned char *data, uint32_t data_len,
                        unsigned char out[HASH_LEN]) {
    unsigned char k0[64], ipad[64], opad[64], inner[HASH_LEN];
    uint32_t i;
    memset(k0, 0, sizeof(k0));
    if (key_len > 64) {
        Sha256 s;
        sha256_init(&s);
        sha256_update(&s, key, key_len);
        sha256_final(&s, k0);
    } else if (key_len) {
        memcpy(k0, key, key_len);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, ipad, 64);
    sha256_update(&s, data, data_len);
    sha256_final(&s, inner);
    sha256_init(&s);
    sha256_update(&s, opad, 64);
    sha256_update(&s, inner, HASH_LEN);
    sha256_final(&s, out);
}

static int hmac2(const unsigned char *key, uint32_t key_len,
                 const unsigned char *a, uint32_t a_len,
                 const unsigned char *b, uint32_t b_len,
                 unsigned char out[HASH_LEN]) {
    unsigned char *buf = NULL;
    uint32_t total;
    if (a_len > UINT32_MAX - b_len) return 0;
    total = a_len + b_len;
    buf = (unsigned char *)malloc(total ? total : 1);
    if (!buf) return 0;
    if (a_len) memcpy(buf, a, a_len);
    if (b_len) memcpy(buf + a_len, b, b_len);
    hmac_sha256(key, key_len, buf, total, out);
    free(buf);
    return 1;
}

static int consttime_eq(const unsigned char *a, const unsigned char *b, uint32_t len) {
    unsigned char diff = 0;
    uint32_t i;
    for (i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static int pbkdf2_sha256(const char *password, const unsigned char *salt,
                         uint32_t salt_len, unsigned char *out, uint32_t out_len) {
    uint32_t pass_len = (uint32_t)strlen(password);
    uint32_t block = 1, pos = 0;
    while (pos < out_len) {
        unsigned char *msg = (unsigned char *)malloc(salt_len + 4);
        unsigned char u[HASH_LEN], t[HASH_LEN];
        uint32_t i, n;
        if (!msg) return 0;
        memcpy(msg, salt, salt_len);
        store_be32(msg + salt_len, block);
        hmac_sha256((const unsigned char *)password, pass_len, msg, salt_len + 4, u);
        memcpy(t, u, HASH_LEN);
        for (i = 1; i < PBKDF2_ITERS; i++) {
            hmac_sha256((const unsigned char *)password, pass_len, u, HASH_LEN, u);
            for (n = 0; n < HASH_LEN; n++) t[n] ^= u[n];
        }
        n = out_len - pos < HASH_LEN ? out_len - pos : HASH_LEN;
        memcpy(out + pos, t, n);
        pos += n;
        block++;
        free(msg);
    }
    return 1;
}

static int random_bytes(unsigned char *buf, uint32_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

static void db_free(Db *db) {
    uint32_t i;
    for (i = 0; i < db->user_count; i++) free(db->users[i].data);
    for (i = 0; i < db->file_count; i++) {
        free(db->files[i].owner);
        free(db->files[i].name);
        free(db->files[i].cipher);
    }
    free(db->users);
    free(db->files);
    memset(db, 0, sizeof(*db));
}

static int read_exact(FILE *f, void *buf, uint32_t len) {
    return len == 0 || fread(buf, 1, len, f) == len;
}

static int write_exact(FILE *f, const void *buf, uint32_t len) {
    return len == 0 || fwrite(buf, 1, len, f) == len;
}

static int read_u32(FILE *f, uint32_t *v) {
    unsigned char b[4];
    if (!read_exact(f, b, 4)) return 0;
    *v = load_be32(b);
    return 1;
}

static int write_u32(FILE *f, uint32_t v) {
    unsigned char b[4];
    store_be32(b, v);
    return write_exact(f, b, 4);
}

static int read_field(FILE *f, unsigned char **data, uint32_t *len) {
    if (!read_u32(f, len) || *len > MAX_FIELD_LEN) return 0;
    *data = NULL;
    if (*len) {
        *data = (unsigned char *)malloc(*len);
        if (!*data || !read_exact(f, *data, *len)) return 0;
    }
    return 1;
}

static int validate_db(const Db *db) {
    uint32_t i, j;
    for (i = 0; i < db->user_count; i++) {
        if (db->users[i].len != HASH_LEN || !db->users[i].data) return 0;
        for (j = i + 1; j < db->user_count; j++) {
            if (db->users[j].len == HASH_LEN &&
                consttime_eq(db->users[i].data, db->users[j].data, HASH_LEN)) {
                return 0;
            }
        }
    }
    for (i = 0; i < db->file_count; i++) {
        if (db->files[i].owner_len != HASH_LEN || db->files[i].name_len != HASH_LEN ||
            !db->files[i].owner || !db->files[i].name) {
            return 0;
        }
        if (db->files[i].cipher_len > 0 && db->files[i].cipher_len < 8) return 0;
        for (j = i + 1; j < db->file_count; j++) {
            if (db->files[j].owner_len == HASH_LEN && db->files[j].name_len == HASH_LEN &&
                consttime_eq(db->files[i].owner, db->files[j].owner, HASH_LEN) &&
                consttime_eq(db->files[i].name, db->files[j].name, HASH_LEN)) {
                return 0;
            }
        }
    }
    return 1;
}

static int load_db(Db *db) {
    FILE *f;
    unsigned char magic[MAGIC_LEN];
    uint32_t version, i;
    memset(db, 0, sizeof(*db));
    f = fopen(DB_PATH, "rb");
    if (!f) return errno == ENOENT;
    if (!read_exact(f, magic, MAGIC_LEN) || memcmp(magic, MAGIC, MAGIC_LEN) != 0 ||
        !read_u32(f, &version) || version != VERSION ||
        !read_u32(f, &db->user_count) || db->user_count > 100000 ||
        !read_u32(f, &db->file_count) || db->file_count > 100000) {
        fclose(f);
        return 0;
    }
    db->users = (User *)calloc(db->user_count ? db->user_count : 1, sizeof(User));
    db->files = (FileEntry *)calloc(db->file_count ? db->file_count : 1, sizeof(FileEntry));
    if (!db->users || !db->files) {
        fclose(f);
        db_free(db);
        return 0;
    }
    for (i = 0; i < db->user_count; i++) {
        if (!read_field(f, &db->users[i].data, &db->users[i].len) ||
            !read_exact(f, db->users[i].salt, SALT_LEN) ||
            !read_exact(f, db->users[i].verifier, HASH_LEN)) {
            fclose(f);
            db_free(db);
            return 0;
        }
    }
    for (i = 0; i < db->file_count; i++) {
        if (!read_field(f, &db->files[i].owner, &db->files[i].owner_len) ||
            !read_field(f, &db->files[i].name, &db->files[i].name_len) ||
            !read_exact(f, db->files[i].nonce, NONCE_LEN) ||
            !read_u32(f, &db->files[i].cipher_len) ||
            db->files[i].cipher_len > MAX_CONTENT_LEN + 4096U) {
            fclose(f);
            db_free(db);
            return 0;
        }
        if (db->files[i].cipher_len) {
            db->files[i].cipher = (unsigned char *)malloc(db->files[i].cipher_len);
            if (!db->files[i].cipher ||
                !read_exact(f, db->files[i].cipher, db->files[i].cipher_len)) {
                fclose(f);
                db_free(db);
                return 0;
            }
        }
        if (!read_exact(f, db->files[i].tag, HASH_LEN)) {
            fclose(f);
            db_free(db);
            return 0;
        }
    }
    if (fgetc(f) != EOF) {
        fclose(f);
        db_free(db);
        return 0;
    }
    if (!validate_db(db)) {
        fclose(f);
        db_free(db);
        return 0;
    }
    fclose(f);
    return 1;
}

static int save_db(const Db *db) {
    FILE *f = fopen(DB_PATH ".tmp", "wb");
    uint32_t i;
    if (!f) return 0;
    if (!write_exact(f, MAGIC, MAGIC_LEN) || !write_u32(f, VERSION) ||
        !write_u32(f, db->user_count) || !write_u32(f, db->file_count)) goto fail;
    for (i = 0; i < db->user_count; i++) {
        if (!write_u32(f, db->users[i].len) ||
            !write_exact(f, db->users[i].data, db->users[i].len) ||
            !write_exact(f, db->users[i].salt, SALT_LEN) ||
            !write_exact(f, db->users[i].verifier, HASH_LEN)) goto fail;
    }
    for (i = 0; i < db->file_count; i++) {
        if (!write_u32(f, db->files[i].owner_len) ||
            !write_exact(f, db->files[i].owner, db->files[i].owner_len) ||
            !write_u32(f, db->files[i].name_len) ||
            !write_exact(f, db->files[i].name, db->files[i].name_len) ||
            !write_exact(f, db->files[i].nonce, NONCE_LEN) ||
            !write_u32(f, db->files[i].cipher_len) ||
            !write_exact(f, db->files[i].cipher, db->files[i].cipher_len) ||
            !write_exact(f, db->files[i].tag, HASH_LEN)) goto fail;
    }
    if (fclose(f) != 0) return 0;
    return rename(DB_PATH ".tmp", DB_PATH) == 0;
fail:
    fclose(f);
    unlink(DB_PATH ".tmp");
    return 0;
}

static void name_id(const char *kind, const char *value, unsigned char out[HASH_LEN]) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, (const unsigned char *)kind, (uint32_t)strlen(kind));
    sha256_update(&s, (const unsigned char *)value, (uint32_t)strlen(value));
    sha256_final(&s, out);
}

static int find_user(Db *db, const char *name) {
    unsigned char id[HASH_LEN];
    uint32_t i;
    name_id("user:", name, id);
    for (i = 0; i < db->user_count; i++) {
        if (db->users[i].len == HASH_LEN && consttime_eq(db->users[i].data, id, HASH_LEN)) return (int)i;
    }
    return -1;
}

static int find_file(Db *db, const char *owner, const char *name) {
    unsigned char owner_id[HASH_LEN], name_id_buf[HASH_LEN];
    uint32_t i;
    name_id("user:", owner, owner_id);
    name_id("file:", name, name_id_buf);
    for (i = 0; i < db->file_count; i++) {
        if (db->files[i].owner_len == HASH_LEN && db->files[i].name_len == HASH_LEN &&
            consttime_eq(db->files[i].owner, owner_id, HASH_LEN) &&
            consttime_eq(db->files[i].name, name_id_buf, HASH_LEN)) return (int)i;
    }
    return -1;
}

static int make_verifier(const unsigned char *mac_key, const char *user,
                         unsigned char out[HASH_LEN]) {
    unsigned char prefix[] = "stor verifier v1";
    return hmac2(mac_key, KEY_LEN, prefix, (uint32_t)strlen((char *)prefix),
                 (const unsigned char *)user, (uint32_t)strlen(user), out);
}

static int derive_and_verify(User *u, const char *user, const char *key,
                             unsigned char enc_key[KEY_LEN],
                             unsigned char mac_key[KEY_LEN]) {
    unsigned char km[KEY_MATERIAL_LEN], verifier[HASH_LEN];
    if (!pbkdf2_sha256(key, u->salt, SALT_LEN, km, KEY_MATERIAL_LEN)) return 0;
    memcpy(enc_key, km, KEY_LEN);
    memcpy(mac_key, km + KEY_LEN, KEY_LEN);
    if (!make_verifier(mac_key, user, verifier)) {
        memset(km, 0, sizeof(km));
        return 0;
    }
    memset(km, 0, sizeof(km));
    return consttime_eq(verifier, u->verifier, HASH_LEN);
}

static int add_user(Db *db, const char *name, const char *key) {
    int idx = find_user(db, name);
    User *u;
    unsigned char km[KEY_MATERIAL_LEN], id[HASH_LEN];
    if (strlen(name) > MAX_FIELD_LEN) return 0;
    if (idx >= 0) return 0;
    if (idx < 0) {
        User *new_users = (User *)realloc(db->users, (db->user_count + 1) * sizeof(User));
        if (!new_users) return 0;
        db->users = new_users;
        u = &db->users[db->user_count++];
        memset(u, 0, sizeof(*u));
        name_id("user:", name, id);
        u->len = HASH_LEN;
        u->data = (unsigned char *)malloc(u->len);
        if (u->len && !u->data) return 0;
        memcpy(u->data, id, u->len);
    }
    if (!random_bytes(u->salt, SALT_LEN)) return 0;
    if (!pbkdf2_sha256(key, u->salt, SALT_LEN, km, KEY_MATERIAL_LEN)) return 0;
    if (!make_verifier(km + KEY_LEN, name, u->verifier)) {
        memset(km, 0, sizeof(km));
        return 0;
    }
    memset(km, 0, sizeof(km));
    return 1;
}

static int add_file(Db *db, const char *owner, const char *name) {
    FileEntry *fe;
    unsigned char owner_id[HASH_LEN], name_id_buf[HASH_LEN];
    if (find_file(db, owner, name) >= 0) return 1;
    if (strlen(owner) > MAX_FIELD_LEN || strlen(name) > MAX_FIELD_LEN) return 0;
    FileEntry *new_files = (FileEntry *)realloc(db->files, (db->file_count + 1) * sizeof(FileEntry));
    if (!new_files) return 0;
    db->files = new_files;
    fe = &db->files[db->file_count++];
    memset(fe, 0, sizeof(*fe));
    name_id("user:", owner, owner_id);
    name_id("file:", name, name_id_buf);
    fe->owner_len = HASH_LEN;
    fe->name_len = HASH_LEN;
    fe->owner = (unsigned char *)malloc(fe->owner_len);
    fe->name = (unsigned char *)malloc(fe->name_len);
    if ((fe->owner_len && !fe->owner) || (fe->name_len && !fe->name)) return 0;
    memcpy(fe->owner, owner_id, fe->owner_len);
    memcpy(fe->name, name_id_buf, fe->name_len);
    return random_bytes(fe->nonce, NONCE_LEN);
}

static unsigned char *make_aad(FileEntry *fe, uint32_t *aad_len) {
    unsigned char *aad;
    *aad_len = 4 + fe->owner_len + 4 + fe->name_len;
    aad = (unsigned char *)malloc(*aad_len);
    if (!aad) return NULL;
    store_be32(aad, fe->owner_len);
    memcpy(aad + 4, fe->owner, fe->owner_len);
    store_be32(aad + 4 + fe->owner_len, fe->name_len);
    memcpy(aad + 8 + fe->owner_len, fe->name, fe->name_len);
    return aad;
}

static int crypt_stream(const unsigned char enc_key[KEY_LEN], const unsigned char nonce[NONCE_LEN],
                        const unsigned char *aad, uint32_t aad_len,
                        const unsigned char *in, unsigned char *out, uint32_t len) {
    unsigned char seed[HASH_LEN], block[HASH_LEN], ctrbuf[HASH_LEN + 4];
    uint32_t pos = 0, ctr = 0;
    hmac_sha256(enc_key, KEY_LEN, aad, aad_len, seed);
    while (pos < len) {
        uint32_t take, i;
        memcpy(ctrbuf, seed, HASH_LEN);
        store_be32(ctrbuf + HASH_LEN, ctr++);
        if (!hmac2(enc_key, KEY_LEN, nonce, NONCE_LEN, ctrbuf, HASH_LEN + 4, block)) return 0;
        take = len - pos < HASH_LEN ? len - pos : HASH_LEN;
        for (i = 0; i < take; i++) out[pos + i] = in[pos + i] ^ block[i];
        pos += take;
    }
    return 1;
}

static int make_tag(const unsigned char mac_key[KEY_LEN], const unsigned char *aad, uint32_t aad_len,
                    const unsigned char nonce[NONCE_LEN], const unsigned char *cipher,
                    uint32_t cipher_len, unsigned char out[HASH_LEN]) {
    unsigned char *buf;
    uint32_t prefix_len, total;
    if (aad_len > UINT32_MAX - NONCE_LEN - 4) return 0;
    prefix_len = aad_len + NONCE_LEN + 4;
    if (cipher_len > UINT32_MAX - prefix_len) return 0;
    total = prefix_len + cipher_len;
    buf = (unsigned char *)malloc(total ? total : 1);
    if (!buf) return 0;
    memcpy(buf, aad, aad_len);
    memcpy(buf + aad_len, nonce, NONCE_LEN);
    store_be32(buf + aad_len + NONCE_LEN, cipher_len);
    memcpy(buf + aad_len + NONCE_LEN + 4, cipher, cipher_len);
    hmac_sha256(mac_key, KEY_LEN, buf, total, out);
    free(buf);
    return 1;
}

static int encrypt_file(FileEntry *fe, const unsigned char enc_key[KEY_LEN],
                        const unsigned char mac_key[KEY_LEN],
                        const unsigned char *plain, uint32_t plain_len) {
    uint32_t payload_data_len, payload_len, aad_len;
    unsigned char *payload, *aad;
    if (plain_len > MAX_CONTENT_LEN) return 0;
    payload_data_len = ((plain_len + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK;
    if (payload_data_len == 0) payload_data_len = PAD_BLOCK;
    payload_len = 8 + payload_data_len;
    payload = (unsigned char *)malloc(payload_len);
    if (!payload) return 0;
    store_be64(payload, plain_len);
    if (plain_len) memcpy(payload + 8, plain, plain_len);
    if (payload_data_len > plain_len &&
        !random_bytes(payload + 8 + plain_len, payload_data_len - plain_len)) {
        free(payload);
        return 0;
    }
    free(fe->cipher);
    fe->cipher = (unsigned char *)malloc(payload_len);
    if (!fe->cipher) {
        free(payload);
        fe->cipher_len = 0;
        return 0;
    }
    fe->cipher_len = payload_len;
    if (!random_bytes(fe->nonce, NONCE_LEN)) {
        free(payload);
        return 0;
    }
    aad = make_aad(fe, &aad_len);
    if (!aad) {
        free(payload);
        return 0;
    }
    if (!crypt_stream(enc_key, fe->nonce, aad, aad_len, payload, fe->cipher, fe->cipher_len) ||
        !make_tag(mac_key, aad, aad_len, fe->nonce, fe->cipher, fe->cipher_len, fe->tag)) {
        free(aad);
        free(payload);
        return 0;
    }
    free(aad);
    free(payload);
    return 1;
}

static int decrypt_file(FileEntry *fe, const unsigned char enc_key[KEY_LEN],
                        const unsigned char mac_key[KEY_LEN],
                        unsigned char **plain, uint32_t *plain_len) {
    unsigned char tag[HASH_LEN], *aad, *payload;
    uint32_t aad_len;
    *plain = NULL;
    *plain_len = 0;
    if (fe->cipher_len == 0) return 0;
    if (fe->cipher_len < 8 || fe->cipher_len > MAX_CONTENT_LEN + 4096U) return 0;
    aad = make_aad(fe, &aad_len);
    if (!aad) return 0;
    if (!make_tag(mac_key, aad, aad_len, fe->nonce, fe->cipher, fe->cipher_len, tag)) {
        free(aad);
        return 0;
    }
    if (!consttime_eq(tag, fe->tag, HASH_LEN)) {
        free(aad);
        return 0;
    }
    payload = (unsigned char *)malloc(fe->cipher_len);
    if (!payload) {
        free(aad);
        return 0;
    }
    if (!crypt_stream(enc_key, fe->nonce, aad, aad_len, fe->cipher, payload, fe->cipher_len)) {
        free(aad);
        free(payload);
        return 0;
    }
    *plain_len = (uint32_t)load_be64(payload);
    if (*plain_len > fe->cipher_len - 8 || *plain_len > MAX_CONTENT_LEN) {
        free(aad);
        free(payload);
        return 0;
    }
    if (*plain_len) {
        *plain = (unsigned char *)malloc(*plain_len);
        if (!*plain) {
            free(aad);
            free(payload);
            return 0;
        }
        memcpy(*plain, payload + 8, *plain_len);
    }
    free(aad);
    free(payload);
    return 1;
}

static int read_whole_file(const char *path, unsigned char **buf, uint32_t *len) {
    FILE *f = fopen(path, "rb");
    long sz;
    *buf = NULL;
    *len = 0;
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || sz > (long)MAX_CONTENT_LEN ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }
    *len = (uint32_t)sz;
    if (*len) {
        *buf = (unsigned char *)malloc(*len);
        if (!*buf || fread(*buf, 1, *len, f) != *len) {
            fclose(f);
            free(*buf);
            return 0;
        }
    }
    fclose(f);
    return 1;
}

static int output_bytes(const char *path, const unsigned char *buf, uint32_t len) {
    FILE *f = path ? fopen(path, "wb") : stdout;
    if (!f) return 0;
    if (!write_exact(f, buf, len)) {
        if (path) fclose(f);
        return 0;
    }
    if (path && fclose(f) != 0) return 0;
    return 1;
}

int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *action, *content = NULL;
    Db db;
    int c, rc = 255;

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

    if (!user || optind >= argc) return invalid();
    action = argv[optind];
    if (optind + 1 < argc) content = argv[optind + 1];
    if (optind + 2 < argc) return invalid();
    if (!load_db(&db)) return invalid();

    if (strcmp(action, "register") == 0) {
        if (!key || file || infile || outfile || content) goto done_invalid;
        if (!add_user(&db, user, key) || !save_db(&db)) goto done_invalid;
        rc = 0;
        goto done;
    }

    if (strcmp(action, "create") == 0) {
        if (!file || infile || outfile || content || find_user(&db, user) < 0) goto done_invalid;
        if (!add_file(&db, user, file) || !save_db(&db)) goto done_invalid;
        rc = 0;
        goto done;
    }

    if (strcmp(action, "write") == 0) {
        int ui, fi;
        unsigned char enc_key[KEY_LEN], mac_key[KEY_LEN];
        unsigned char *plain = NULL;
        uint32_t plain_len = 0;
        if (!key || !file || outfile) goto done_invalid;
        ui = find_user(&db, user);
        fi = find_file(&db, user, file);
        if (ui < 0 || fi < 0 || !derive_and_verify(&db.users[ui], user, key, enc_key, mac_key)) goto done_invalid;
        if (infile) {
            if (!read_whole_file(infile, &plain, &plain_len)) goto done_invalid;
        } else if (content) {
            plain_len = (uint32_t)strlen(content);
            plain = (unsigned char *)malloc(plain_len ? plain_len : 1);
            if (!plain) goto done_invalid;
            memcpy(plain, content, plain_len);
        }
        if (!encrypt_file(&db.files[fi], enc_key, mac_key, plain, plain_len) || !save_db(&db)) {
            free(plain);
            goto done_invalid;
        }
        free(plain);
        rc = 0;
        goto done;
    }

    if (strcmp(action, "read") == 0) {
        int ui, fi;
        unsigned char enc_key[KEY_LEN], mac_key[KEY_LEN];
        unsigned char *plain = NULL;
        uint32_t plain_len = 0;
        if (!key || !file || infile || content) goto done_invalid;
        ui = find_user(&db, user);
        fi = find_file(&db, user, file);
        if (ui < 0 || fi < 0 || !derive_and_verify(&db.users[ui], user, key, enc_key, mac_key)) goto done_invalid;
        if (!decrypt_file(&db.files[fi], enc_key, mac_key, &plain, &plain_len) ||
            !output_bytes(outfile, plain, plain_len)) {
            free(plain);
            goto done_invalid;
        }
        free(plain);
        rc = 0;
        goto done;
    }

done_invalid:
    rc = invalid();
done:
    db_free(&db);
    return rc;
}
