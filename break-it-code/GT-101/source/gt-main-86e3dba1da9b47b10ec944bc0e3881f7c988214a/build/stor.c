
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define DB_PATH        "enc.db"
#define MAGIC          "STORDB02"
#define MAGIC_LEN      8
#define SALT_LEN       32          
#define ENC_KEY_LEN    32          
#define MAC_KEY_LEN    32          
#define DERIVED_LEN    (ENC_KEY_LEN + MAC_KEY_LEN) 
#define IV_LEN         16
#define HMAC_LEN       32
#define PBKDF2_ITERS   300000      
#define MAX_USERS      1024
#define MAX_FILES      1024
#define MAX_NAME_LEN   255
#define MAX_CONTENT    (600UL * 1024UL * 1024UL)


void win(void) { printf("Arbitrary access achieved!\n"); }


static int invalid(void) { printf("invalid"); return 255; }

static void secure_wipe(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) vp[i] = 0;
}


static void *safe_malloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { printf("invalid"); exit(255); }
    return p;
}
static void *safe_realloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { printf("invalid"); exit(255); }
    return q;
}


typedef struct {
    char    *filename;
    uint8_t  iv[IV_LEN];
    uint8_t  content_hmac[HMAC_LEN];
    uint32_t content_len;
    uint8_t *ciphertext;
} FileEntry;

typedef struct {
    char      *username;
    uint8_t    salt[SALT_LEN];
    uint8_t    auth_tag[HMAC_LEN];
    uint32_t   num_files;
    FileEntry *files;
} UserEntry;

typedef struct {
    uint32_t   num_users;
    UserEntry *users;
} Database;


static int safe_memcmp(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= x[i] ^ y[i];
    return (int)diff;
}


static int derive_keys(const char *password, const uint8_t salt[SALT_LEN],
                       uint8_t enc_key[ENC_KEY_LEN],
                       uint8_t mac_key[MAC_KEY_LEN]) {
    uint8_t derived[DERIVED_LEN];
    int ok = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, SALT_LEN,
                                PBKDF2_ITERS, EVP_sha256(),
                                DERIVED_LEN, derived);
    if (ok) {
        memcpy(enc_key, derived,              ENC_KEY_LEN);
        memcpy(mac_key, derived + ENC_KEY_LEN, MAC_KEY_LEN);
    }
    secure_wipe(derived, DERIVED_LEN);
    return ok;
}


static void compute_auth_tag(const uint8_t mac_key[MAC_KEY_LEN],
                             const char *username,
                             uint8_t out[HMAC_LEN]) {
    size_t ulen = strlen(username);
    size_t buflen = 4 + ulen;
    uint8_t *buf = safe_malloc(buflen);
    memcpy(buf, "AUTH", 4);
    memcpy(buf + 4, username, ulen);
    unsigned int hlen = HMAC_LEN;
    HMAC(EVP_sha256(), mac_key, MAC_KEY_LEN, buf, buflen, out, &hlen);
    secure_wipe(buf, buflen);
    free(buf);
}


static void compute_content_hmac(const uint8_t mac_key[MAC_KEY_LEN],
                                 const char *username,
                                 const char *filename,
                                 const uint8_t iv[IV_LEN],
                                 const uint8_t *ciphertext, uint32_t ct_len,
                                 uint8_t out[HMAC_LEN]) {
    HMAC_CTX *hc = HMAC_CTX_new();
    if (!hc) { printf("invalid"); exit(255); }
    unsigned int hlen = HMAC_LEN;
    HMAC_Init_ex(hc, mac_key, MAC_KEY_LEN, EVP_sha256(), NULL);
    HMAC_Update(hc, (const uint8_t *)"DATA", 4);
    HMAC_Update(hc, (const uint8_t *)username, strlen(username));
    HMAC_Update(hc, (const uint8_t *)filename, strlen(filename));
    HMAC_Update(hc, iv, IV_LEN);
    if (ct_len > 0) HMAC_Update(hc, ciphertext, ct_len);
    HMAC_Final(hc, out, &hlen);
    HMAC_CTX_free(hc);
}


static int aes_encrypt(const uint8_t enc_key[ENC_KEY_LEN],
                       const uint8_t iv[IV_LEN],
                       const uint8_t *plain, int plain_len,
                       uint8_t **out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int max_len = plain_len + 16;
    *out = safe_malloc(max_len);
    int l1 = 0, l2 = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) &&
             EVP_EncryptUpdate(ctx, *out, &l1, plain, plain_len) &&
             EVP_EncryptFinal_ex(ctx, *out + l1, &l2);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(*out); *out = NULL; return -1; }
    return l1 + l2;
}

static int aes_decrypt(const uint8_t enc_key[ENC_KEY_LEN],
                       const uint8_t iv[IV_LEN],
                       const uint8_t *cipher, int cipher_len,
                       uint8_t **out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    *out = safe_malloc(cipher_len + 1);
    int l1 = 0, l2 = 0;
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) &&
             EVP_DecryptUpdate(ctx, *out, &l1, cipher, cipher_len) &&
             EVP_DecryptFinal_ex(ctx, *out + l1, &l2);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) { free(*out); *out = NULL; return -1; }
    (*out)[l1 + l2] = '\0';
    return l1 + l2;
}


static int write_u16(FILE *f, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)(v & 0xff) };
    return fwrite(b, 1, 2, f) == 2 ? 0 : -1;
}
static int write_u32(FILE *f, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v>>24),(uint8_t)(v>>16),(uint8_t)(v>>8),(uint8_t)v };
    return fwrite(b, 1, 4, f) == 4 ? 0 : -1;
}
static int write_bytes(FILE *f, const void *p, size_t n) {
    return fwrite(p, 1, n, f) == n ? 0 : -1;
}
static int read_u16(FILE *f, uint16_t *v) {
    uint8_t b[2];
    if (fread(b, 1, 2, f) != 2) return -1;
    *v = ((uint16_t)b[0] << 8) | b[1];
    return 0;
}
static int read_u32(FILE *f, uint32_t *v) {
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return -1;
    *v = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    return 0;
}
static int read_bytes(FILE *f, void *p, size_t n) {
    return fread(p, 1, n, f) == n ? 0 : -1;
}


static void free_db(Database *db) {
    for (uint32_t i = 0; i < db->num_users; i++) {
        UserEntry *u = &db->users[i];
        free(u->username);
        for (uint32_t j = 0; j < u->num_files; j++) {
            free(u->files[j].filename);
            if (u->files[j].ciphertext) {
                secure_wipe(u->files[j].ciphertext, u->files[j].content_len);
                free(u->files[j].ciphertext);
            }
        }
        free(u->files);
    }
    free(db->users);
    db->users = NULL;
    db->num_users = 0;
}


static int load_db(Database *db) {
    db->num_users = 0;
    db->users = NULL;

    FILE *f = fopen(DB_PATH, "rb");
    if (!f) return 0; 

    uint8_t magic[MAGIC_LEN];
    if (read_bytes(f, magic, MAGIC_LEN) || memcmp(magic, MAGIC, MAGIC_LEN)) {
        fclose(f); return -1;
    }

    uint32_t nu;
    if (read_u32(f, &nu) || nu > MAX_USERS) { fclose(f); return -1; }

    db->users = nu ? safe_malloc(nu * sizeof(UserEntry)) : NULL;
    if (nu) memset(db->users, 0, nu * sizeof(UserEntry));
    db->num_users = nu;

    for (uint32_t i = 0; i < nu; i++) {
        UserEntry *u = &db->users[i];
        uint16_t ulen;
        if (read_u16(f, &ulen) || ulen == 0 || ulen > MAX_NAME_LEN) {
            fclose(f); return -1;
        }
        u->username = safe_malloc(ulen + 1);
        if (read_bytes(f, u->username, ulen)) { fclose(f); return -1; }
        u->username[ulen] = '\0';

        if (read_bytes(f, u->salt,     SALT_LEN)) { fclose(f); return -1; }
        if (read_bytes(f, u->auth_tag, HMAC_LEN)) { fclose(f); return -1; }

        uint32_t nf;
        if (read_u32(f, &nf) || nf > MAX_FILES) { fclose(f); return -1; }
        u->num_files = nf;
        u->files = nf ? safe_malloc(nf * sizeof(FileEntry)) : NULL;
        if (nf) memset(u->files, 0, nf * sizeof(FileEntry));

        for (uint32_t j = 0; j < nf; j++) {
            FileEntry *fe = &u->files[j];
            uint16_t flen;
            if (read_u16(f, &flen) || flen == 0 || flen > MAX_NAME_LEN) {
                fclose(f); return -1;
            }
            fe->filename = safe_malloc(flen + 1);
            if (read_bytes(f, fe->filename, flen)) { fclose(f); return -1; }
            fe->filename[flen] = '\0';

            if (read_bytes(f, fe->iv,           IV_LEN))  { fclose(f); return -1; }
            if (read_bytes(f, fe->content_hmac, HMAC_LEN)){ fclose(f); return -1; }
            if (read_u32(f, &fe->content_len))             { fclose(f); return -1; }
            if (fe->content_len > MAX_CONTENT + 32)        { fclose(f); return -1; }

            fe->ciphertext = fe->content_len ? safe_malloc(fe->content_len) : NULL;
            if (fe->content_len &&
                read_bytes(f, fe->ciphertext, fe->content_len)) {
                fclose(f); return -1;
            }
        }
    }

    uint8_t probe;
    if (fread(&probe, 1, 1, f) != 0) { fclose(f); return -1; }

    fclose(f);
    return 0;
}


static int save_db(const Database *db) {
    FILE *f = fopen(DB_PATH, "wb");
    if (!f) return -1;

    if (write_bytes(f, MAGIC, MAGIC_LEN)) goto err;
    if (write_u32(f, db->num_users))      goto err;

    for (uint32_t i = 0; i < db->num_users; i++) {
        const UserEntry *u = &db->users[i];
        uint16_t ulen = (uint16_t)strlen(u->username);
        if (write_u16(f, ulen))                    goto err;
        if (write_bytes(f, u->username, ulen))     goto err;
        if (write_bytes(f, u->salt,     SALT_LEN)) goto err;
        if (write_bytes(f, u->auth_tag, HMAC_LEN)) goto err;
        if (write_u32(f, u->num_files))            goto err;

        for (uint32_t j = 0; j < u->num_files; j++) {
            const FileEntry *fe = &u->files[j];
            uint16_t flen = (uint16_t)strlen(fe->filename);
            if (write_u16(f, flen))                          goto err;
            if (write_bytes(f, fe->filename, flen))          goto err;
            if (write_bytes(f, fe->iv,           IV_LEN))   goto err;
            if (write_bytes(f, fe->content_hmac, HMAC_LEN)) goto err;
            if (write_u32(f, fe->content_len))               goto err;
            if (fe->content_len &&
                write_bytes(f, fe->ciphertext, fe->content_len)) goto err;
        }
    }
    fclose(f);
    return 0;
err:
    fclose(f);
    return -1;
}


static UserEntry *find_user(Database *db, const char *username) {
    for (uint32_t i = 0; i < db->num_users; i++)
        if (strcmp(db->users[i].username, username) == 0)
            return &db->users[i];
    return NULL;
}

static FileEntry *find_file(UserEntry *u, const char *filename) {
    for (uint32_t j = 0; j < u->num_files; j++)
        if (strcmp(u->files[j].filename, filename) == 0)
            return &u->files[j];
    return NULL;
}


static int verify_key(UserEntry *u, const char *key,
                      uint8_t enc_key_out[ENC_KEY_LEN],
                      uint8_t mac_key_out[MAC_KEY_LEN]) {
    uint8_t enc_key[ENC_KEY_LEN], mac_key[MAC_KEY_LEN];
    if (!derive_keys(key, u->salt, enc_key, mac_key)) {
        return -1;
    }
    uint8_t expected[HMAC_LEN];
    compute_auth_tag(mac_key, u->username, expected);
    int ok = (safe_memcmp(expected, u->auth_tag, HMAC_LEN) == 0);
    secure_wipe(expected, HMAC_LEN);
    if (ok && enc_key_out) memcpy(enc_key_out, enc_key, ENC_KEY_LEN);
    if (ok && mac_key_out) memcpy(mac_key_out, mac_key, MAC_KEY_LEN);
    secure_wipe(enc_key, ENC_KEY_LEN);
    secure_wipe(mac_key, MAC_KEY_LEN);
    return ok ? 0 : -1;
}


static int do_register(Database *db, const char *username, const char *key) {
    if (!username || !key) return invalid();
    if (strlen(username) == 0 || strlen(username) > MAX_NAME_LEN) return invalid();

    uint8_t salt[SALT_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1) return invalid();

    uint8_t enc_key[ENC_KEY_LEN], mac_key[MAC_KEY_LEN];
    if (!derive_keys(key, salt, enc_key, mac_key)) return invalid();

    uint8_t auth_tag[HMAC_LEN];
    compute_auth_tag(mac_key, username, auth_tag);

    secure_wipe(enc_key, ENC_KEY_LEN);
    secure_wipe(mac_key, MAC_KEY_LEN);

    UserEntry *u = find_user(db, username);
    if (u) {
        memcpy(u->salt,     salt,     SALT_LEN);
        memcpy(u->auth_tag, auth_tag, HMAC_LEN);
        
        for (uint32_t j = 0; j < u->num_files; j++) {
            FileEntry *fe = &u->files[j];
            if (fe->ciphertext) {
                secure_wipe(fe->ciphertext, fe->content_len);
                free(fe->ciphertext);
                fe->ciphertext = NULL;
            }
            fe->content_len = 0;
            secure_wipe(fe->iv,           IV_LEN);
            secure_wipe(fe->content_hmac, HMAC_LEN);
        }
    } else {
        if (db->num_users >= MAX_USERS) return invalid();
        db->users = safe_realloc(db->users,
                                 (db->num_users + 1) * sizeof(UserEntry));
        u = &db->users[db->num_users++];
        memset(u, 0, sizeof(*u));
        u->username = safe_malloc(strlen(username) + 1);
        strcpy(u->username, username);
        memcpy(u->salt,     salt,     SALT_LEN);
        memcpy(u->auth_tag, auth_tag, HMAC_LEN);
    }

    secure_wipe(auth_tag, HMAC_LEN);
    secure_wipe(salt, SALT_LEN);
    return save_db(db) ? invalid() : 0;
}


static int do_create(Database *db, const char *username, const char *filename) {
    if (!username || !filename) return invalid();
    if (strlen(filename) == 0 || strlen(filename) > MAX_NAME_LEN) return invalid();

    UserEntry *u = find_user(db, username);
    if (!u) return invalid();

    if (find_file(u, filename)) return 0;  /* idempotent */
    if (u->num_files >= MAX_FILES) return invalid();

    u->files = safe_realloc(u->files, (u->num_files + 1) * sizeof(FileEntry));
    FileEntry *fe = &u->files[u->num_files++];
    memset(fe, 0, sizeof(*fe));
    fe->filename = safe_malloc(strlen(filename) + 1);
    strcpy(fe->filename, filename);

    return save_db(db) ? invalid() : 0;
}


static int do_write(Database *db,
                    const char *username, const char *key,
                    const char *filename,
                    const char *infile, const char *content) {
    if (!username || !key || !filename) return invalid();

    UserEntry *u = find_user(db, username);
    if (!u) return invalid();

    uint8_t enc_key[ENC_KEY_LEN], mac_key[MAC_KEY_LEN];
    if (verify_key(u, key, enc_key, mac_key)) return invalid();

    FileEntry *fe = find_file(u, filename);
    if (!fe) {
        secure_wipe(enc_key, ENC_KEY_LEN);
        secure_wipe(mac_key, MAC_KEY_LEN);
        return invalid();
    }

    uint8_t *plain = NULL;
    int plain_len  = 0;

    if (infile) {
        FILE *fin = fopen(infile, "rb");
        if (!fin) {
            secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
            return invalid();
        }
        fseek(fin, 0, SEEK_END);
        long sz = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        if (sz < 0 || (unsigned long)sz > MAX_CONTENT) {
            fclose(fin);
            secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
            return invalid();
        }
        plain = safe_malloc(sz ? (size_t)sz : 1);
        if (sz && (long)fread(plain, 1, sz, fin) != sz) {
            fclose(fin); secure_wipe(plain, sz); free(plain);
            secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
            return invalid();
        }
        fclose(fin);
        plain_len = (int)sz;
    } else {
        const char *src = content ? content : "";
        plain_len = (int)strlen(src);
        if ((unsigned long)plain_len > MAX_CONTENT) {
            secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
            return invalid();
        }
        plain = safe_malloc(plain_len + 1);
        memcpy(plain, src, plain_len);
    }

    uint8_t iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        secure_wipe(plain, plain_len); free(plain);
        secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
        return invalid();
    }

    uint8_t *cipher = NULL;
    int ct_len = aes_encrypt(enc_key, iv, plain, plain_len, &cipher);
    secure_wipe(plain, plain_len);
    free(plain);
    secure_wipe(enc_key, ENC_KEY_LEN);  

    if (ct_len < 0) {
        secure_wipe(mac_key, MAC_KEY_LEN);
        return invalid();
    }

   
    uint8_t hmac[HMAC_LEN];
    compute_content_hmac(mac_key, username, filename, iv,
                         cipher, (uint32_t)ct_len, hmac);
    secure_wipe(mac_key, MAC_KEY_LEN);

    if (fe->ciphertext) {
        secure_wipe(fe->ciphertext, fe->content_len);
        free(fe->ciphertext);
    }
    fe->ciphertext  = cipher;
    fe->content_len = (uint32_t)ct_len;
    memcpy(fe->iv,           iv,   IV_LEN);
    memcpy(fe->content_hmac, hmac, HMAC_LEN);
    secure_wipe(hmac, HMAC_LEN);

    return save_db(db) ? invalid() : 0;
}


static int do_read(Database *db,
                   const char *username, const char *key,
                   const char *filename, const char *outfile) {
    if (!username || !key || !filename) return invalid();

    UserEntry *u = find_user(db, username);
    if (!u) return invalid();

    uint8_t enc_key[ENC_KEY_LEN], mac_key[MAC_KEY_LEN];
    if (verify_key(u, key, enc_key, mac_key)) return invalid();

    FileEntry *fe = find_file(u, filename);
    if (!fe) {
        secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
        return invalid();
    }


    if (fe->content_len == 0) {
        secure_wipe(enc_key, ENC_KEY_LEN); secure_wipe(mac_key, MAC_KEY_LEN);
        if (outfile) {
            FILE *fout = fopen(outfile, "wb");
            if (!fout) return invalid();
            fclose(fout);
        }
        fflush(stdout);
        return 0;
    }


    uint8_t expected_hmac[HMAC_LEN];
    compute_content_hmac(mac_key, username, filename,
                         fe->iv, fe->ciphertext, fe->content_len,
                         expected_hmac);
    secure_wipe(mac_key, MAC_KEY_LEN);

    if (safe_memcmp(expected_hmac, fe->content_hmac, HMAC_LEN)) {
        secure_wipe(expected_hmac, HMAC_LEN);
        secure_wipe(enc_key, ENC_KEY_LEN);
        return invalid();
    }
    secure_wipe(expected_hmac, HMAC_LEN);

    uint8_t *plain = NULL;
    int plain_len = aes_decrypt(enc_key, fe->iv,
                                fe->ciphertext, (int)fe->content_len,
                                &plain);
    secure_wipe(enc_key, ENC_KEY_LEN);

    if (plain_len < 0) return invalid();

 
    int ret = 0;
    if (outfile) {
        FILE *fout = fopen(outfile, "wb");
        if (!fout) { ret = invalid(); goto out; }
        if (plain_len && (int)fwrite(plain, 1, plain_len, fout) != plain_len) {
            fclose(fout); ret = invalid(); goto out;
        }
        fclose(fout);
    } else {
        if (plain_len && (int)fwrite(plain, 1, plain_len, stdout) != plain_len) {
            ret = invalid(); goto out;
        }
        fflush(stdout);
    }

out:
    secure_wipe(plain, plain_len);
    free(plain);
    return ret;
}

/* ── main ───────────────────────────────────────────────────────────── */
int main(int argc, char **argv) {
    if (RAND_status() != 1) return invalid();

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

    if (!user || optind >= argc) return invalid();

    const char *action  = argv[optind];
    const char *content = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    Database db;
    if (load_db(&db)) return invalid();

    int ret;
    if      (strcmp(action, "register") == 0) ret = do_register(&db, user, key);
    else if (strcmp(action, "create")   == 0) ret = do_create(&db, user, file);
    else if (strcmp(action, "write")    == 0) ret = do_write(&db, user, key, file, infile, content);
    else if (strcmp(action, "read")     == 0) ret = do_read(&db, user, key, file, outfile);
    else                                       ret = invalid();

    free_db(&db);
    return ret;
}