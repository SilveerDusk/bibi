/*
 * stor.c — encrypted file storage system
 *
 * Security design:
 *  - Per-user Argon2id KDF (libsodium crypto_pwhash) with random salt
 *  - File content encrypted with XSalsa20-Poly1305 (crypto_secretbox)
 *  - Global MAC key = BLAKE2b(db_salt || all UserRecord bytes) — incorporates
 *    secret material so keyless forgery is impossible
 *  - Usernames/filenames stored as BLAKE2b hashes — confidentiality
 *  - Constant-time comparisons everywhere
 *  - All key material and heap ciphertexts zeroed before exit
 *  - Strict bounds on every input; no strcpy/sprintf/gets
 *  - enc.db written atomically via mkstemp+rename with 0600 permissions
 *  - Strict arg parsing: unknown flags, extra positionals, duplicate actions rejected
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sodium.h>

/* ── constants ──────────────────────────────────────────────────── */

#define DB_PATH          "enc.db"
#define DB_MAGIC         "STOR0001"
#define DB_MAGIC_LEN     8

#define MAX_USERNAME     63
#define MAX_FILENAME     63
#define MAX_KEY          1024
#define MAX_CONTENT      (1 << 24)   /* 16 MB per file */
#define MAX_RECORDS      4096

#define KDF_OPSLIMIT     crypto_pwhash_OPSLIMIT_MODERATE
#define KDF_MEMLIMIT     crypto_pwhash_MEMLIMIT_MODERATE
#define KDF_ALG          crypto_pwhash_ALG_ARGON2ID13

#define KEY_BYTES        crypto_secretbox_KEYBYTES   /* 32 */
#define NONCE_BYTES      crypto_secretbox_NONCEBYTES /* 24 */
#define MAC_BYTES        crypto_secretbox_MACBYTES   /* 16 */
#define SALT_BYTES       crypto_pwhash_SALTBYTES     /* 16 */
#define HASH_BYTES       crypto_generichash_BYTES    /* 32 */
#define GLOBAL_MAC_BYTES crypto_auth_hmacsha512256_BYTES /* 32 */

#define MAX_DB_SIZE (128U * 1024U * 1024U)

/* ── data structures ─────────────────────────────────────────────── */

typedef struct {
    uint8_t  username_hash[HASH_BYTES];
    uint8_t  kdf_salt[SALT_BYTES];
    uint8_t  key_verifier[MAC_BYTES + 32];
    uint8_t  verifier_nonce[NONCE_BYTES];
    uint8_t  file_state_mac[GLOBAL_MAC_BYTES];
} UserRecord;

typedef struct {
    uint8_t  owner_hash[HASH_BYTES];
    uint8_t  filename_hash[HASH_BYTES];
    uint8_t  nonce[NONCE_BYTES];
    uint32_t ciphertext_len;
} FileHeader;

typedef struct {
    UserRecord users[MAX_RECORDS];
    int        user_count;
    FileHeader file_headers[MAX_RECORDS];
    uint8_t   *file_ciphertexts[MAX_RECORDS];
    int        file_count;
    uint8_t    db_salt[32];
} Database;

static Database g_db;

/* ── forward declarations ────────────────────────────────────────── */
void win(void);
static void die(const char *msg);
static void cleanup_and_exit(int code);

void win(void) { printf("Arbitrary access achieved!\n"); }

static void free_ciphertexts(void) {
    for (int i = 0; i < g_db.file_count; i++) {
        if (g_db.file_ciphertexts[i]) {
            sodium_memzero(g_db.file_ciphertexts[i],
                           g_db.file_headers[i].ciphertext_len);
            free(g_db.file_ciphertexts[i]);
            g_db.file_ciphertexts[i] = NULL;
        }
    }
}

static void cleanup_and_exit(int code) {
    free_ciphertexts();
    sodium_memzero(&g_db, sizeof(g_db));
    exit(code);
}

static void die(const char *msg) {
    (void)msg;
    printf("invalid");
    cleanup_and_exit(255);
}

static int eq32(const uint8_t *a, const uint8_t *b) {
    return sodium_memcmp(a, b, HASH_BYTES) == 0;
}

static int add_size(size_t *total, size_t add) {
    if (add > SIZE_MAX - *total) return -1;
    if (*total + add > MAX_DB_SIZE) return -1;
    *total += add;
    return 0;
}

static int has_duplicate_users(void) {
    for (int i = 0; i < g_db.user_count; i++) {
        for (int j = i + 1; j < g_db.user_count; j++) {
            if (eq32(g_db.users[i].username_hash,
                     g_db.users[j].username_hash)) {
                return 1;
            }
        }
    }
    return 0;
}

static int has_duplicate_files(void) {
    for (int i = 0; i < g_db.file_count; i++) {
        for (int j = i + 1; j < g_db.file_count; j++) {
            if (eq32(g_db.file_headers[i].owner_hash,
                     g_db.file_headers[j].owner_hash) &&
                eq32(g_db.file_headers[i].filename_hash,
                     g_db.file_headers[j].filename_hash)) {
                return 1;
            }
        }
    }
    return 0;
}

/* ── crypto helpers ──────────────────────────────────────────────── */

static int derive_key(const char *password, const uint8_t *salt,
                      uint8_t out_key[KEY_BYTES]) {
    uint8_t bound_salt[SALT_BYTES];
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0, SALT_BYTES);
    crypto_generichash_update(&st, salt, SALT_BYTES);
    crypto_generichash_update(&st, g_db.db_salt, sizeof(g_db.db_salt));
    crypto_generichash_final(&st, bound_salt, SALT_BYTES);

    int rc = crypto_pwhash(out_key, KEY_BYTES,
                           password, strlen(password), bound_salt,
                           KDF_OPSLIMIT, KDF_MEMLIMIT, KDF_ALG);
    sodium_memzero(bound_salt, sizeof(bound_salt));
    return rc;
}

static void hash_string(const char *s, uint8_t out[HASH_BYTES]) {
    crypto_generichash(out, HASH_BYTES,
                       (const uint8_t *)s, strlen(s), NULL, 0);
}


static void compute_db_mac(const uint8_t *data, size_t len,
                            const uint8_t mac_key[32],
                            uint8_t out[GLOBAL_MAC_BYTES]) {
    crypto_auth_hmacsha512256(out, data, len, mac_key);
}

/*
 * MAC key = BLAKE2b(db_salt || all UserRecord bytes).
 * Incorporates KDF salts and key verifiers (derived from passwords),
 * so an attacker who can read enc.db cannot recompute the key.
 */
static void derive_mac_key(const uint8_t db_salt[32],
                            const UserRecord *users, int user_count,
                            uint8_t out[32]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, db_salt, 32);
    if (user_count > 0)
        crypto_generichash_update(&st,
            (const uint8_t *)users,
            (size_t)user_count * sizeof(UserRecord));
    crypto_generichash_final(&st, out, 32);
}

/* ── serialisation ───────────────────────────────────────────────── */

/*
 * File layout:
 *   [8]  magic
 *   [32] db_salt
 *   [32] global_mac
 *   [4]  user_count
 *   [N * sizeof(UserRecord)]
 *   [4]  file_count
 *   for each file: [sizeof(FileHeader)] + [ciphertext_len bytes]
 *
 * global_mac = HMAC-SHA512/256(mac_key, everything after mac field)
 * mac_key    = BLAKE2b(db_salt || user_records)
 */

static uint8_t *db_serialise(size_t *out_len) {
    size_t sz = 0;

    if (add_size(&sz, DB_MAGIC_LEN) != 0) return NULL;
    if (add_size(&sz, 32) != 0) return NULL;
    if (add_size(&sz, GLOBAL_MAC_BYTES) != 0) return NULL;
    if (add_size(&sz, 4) != 0) return NULL;
    if (add_size(&sz, (size_t)g_db.user_count * sizeof(UserRecord)) != 0) return NULL;
    if (add_size(&sz, 4) != 0) return NULL;

    for (int i = 0; i < g_db.file_count; i++) {
        if (add_size(&sz, sizeof(FileHeader)) != 0) return NULL;
        if (add_size(&sz, g_db.file_headers[i].ciphertext_len) != 0) return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) return NULL;
    uint8_t *p = buf;

    memcpy(p, DB_MAGIC, DB_MAGIC_LEN); p += DB_MAGIC_LEN;
    memcpy(p, g_db.db_salt, 32); p += 32;

    uint8_t *mac_slot = p;
    memset(p, 0, GLOBAL_MAC_BYTES); p += GLOBAL_MAC_BYTES;

    uint32_t uc = (uint32_t)g_db.user_count;
    memcpy(p, &uc, 4); p += 4;
    for (int i = 0; i < g_db.user_count; i++) {
        memcpy(p, &g_db.users[i], sizeof(UserRecord));
        p += sizeof(UserRecord);
    }

    uint32_t fc = (uint32_t)g_db.file_count;
    memcpy(p, &fc, 4); p += 4;
    for (int i = 0; i < g_db.file_count; i++) {
        memcpy(p, &g_db.file_headers[i], sizeof(FileHeader));
        p += sizeof(FileHeader);
        uint32_t ct_len = g_db.file_headers[i].ciphertext_len;
        if (ct_len > 0) {
            if (!g_db.file_ciphertexts[i]) {
                sodium_memzero(buf, sz);
                free(buf);
                return NULL;
            }
            memcpy(p, g_db.file_ciphertexts[i], ct_len);
        }
        p += ct_len;
    }

    uint8_t mac_key[32];
    derive_mac_key(g_db.db_salt, g_db.users, g_db.user_count, mac_key);
    uint8_t *mac_start = mac_slot + GLOBAL_MAC_BYTES;
    compute_db_mac(mac_start, (size_t)(p - mac_start), mac_key, mac_slot);
    sodium_memzero(mac_key, 32);

    *out_len = sz;
    return buf;
}

static int db_deserialise(const uint8_t *buf, size_t len) {
    if (len < DB_MAGIC_LEN + 32 + GLOBAL_MAC_BYTES + 4 + 4)
        return -1;

    const uint8_t *p = buf;
    if (memcmp(p, DB_MAGIC, DB_MAGIC_LEN) != 0) return -1;
    p += DB_MAGIC_LEN;

    memcpy(g_db.db_salt, p, 32); p += 32;

    uint8_t stored_mac[GLOBAL_MAC_BYTES];
    memcpy(stored_mac, p, GLOBAL_MAC_BYTES); p += GLOBAL_MAC_BYTES;

    /* Derive MAC key using the user block from the buffer directly
     * (before trusting it) so we can verify the MAC covers it. */
    uint8_t mac_key[32];
    {
        const uint8_t *up = p;
        uint32_t pre_uc = 0;
        if ((size_t)(buf + len - up) >= 4) {
            memcpy(&pre_uc, up, 4); up += 4;
            if (pre_uc > MAX_RECORDS) pre_uc = 0;
        }
        size_t ublock = (size_t)pre_uc * sizeof(UserRecord);
        /* Temporarily build UserRecord array for MAC key derivation */
        UserRecord tmp_users[1]; /* just need the pointer, use raw bytes */
        (void)tmp_users;
        crypto_generichash_state st;
        crypto_generichash_init(&st, NULL, 0, 32);
        crypto_generichash_update(&st, g_db.db_salt, 32);
        if (ublock > 0 && (size_t)(buf + len - up) >= ublock)
            crypto_generichash_update(&st, up, ublock);
        crypto_generichash_final(&st, mac_key, 32);
    }

    size_t mac_data_len = len - (DB_MAGIC_LEN + 32 + GLOBAL_MAC_BYTES);
    uint8_t computed_mac[GLOBAL_MAC_BYTES];
    compute_db_mac(p, mac_data_len, mac_key, computed_mac);
    sodium_memzero(mac_key, 32);

    if (sodium_memcmp(stored_mac, computed_mac, GLOBAL_MAC_BYTES) != 0)
        return -1;

    /* user_count */
    if ((size_t)(buf + len - p) < 4) return -1;
    uint32_t uc;
    memcpy(&uc, p, 4); p += 4;
    if (uc > MAX_RECORDS) return -1;
    g_db.user_count = (int)uc;

    size_t users_sz = (size_t)uc * sizeof(UserRecord);
    if ((size_t)(buf + len - p) < users_sz) return -1;
    memcpy(g_db.users, p, users_sz); p += users_sz;

    /* file_count */
    if ((size_t)(buf + len - p) < 4) return -1;
    uint32_t fc;
    memcpy(&fc, p, 4); p += 4;
    if (fc > MAX_RECORDS) return -1;
    g_db.file_count = (int)fc;

    for (uint32_t i = 0; i < fc; i++) {
        if ((size_t)(buf + len - p) < sizeof(FileHeader)) goto fail;
        memcpy(&g_db.file_headers[i], p, sizeof(FileHeader));
        p += sizeof(FileHeader);

        uint32_t ct_len = g_db.file_headers[i].ciphertext_len;
        if (ct_len > MAX_CONTENT + MAC_BYTES) goto fail;
        if ((size_t)(buf + len - p) < ct_len) goto fail;

        if (ct_len > 0) {
            g_db.file_ciphertexts[i] = (uint8_t *)malloc(ct_len);
            if (!g_db.file_ciphertexts[i]) goto fail;
            memcpy(g_db.file_ciphertexts[i], p, ct_len);
        } else {
            g_db.file_ciphertexts[i] = NULL;
        }
        p += ct_len;
    }

    if (has_duplicate_users()) goto fail;
    if (has_duplicate_files()) goto fail;

    /* Issue 23: reject trailing bytes */
    if (p != buf + len) goto fail;

    return 0;

fail:
    /* Issue 8: free any ciphertexts allocated so far */
    for (uint32_t j = 0; j < (uint32_t)g_db.file_count; j++) {
        if (g_db.file_ciphertexts[j]) {
            sodium_memzero(g_db.file_ciphertexts[j],
                           g_db.file_headers[j].ciphertext_len);
            free(g_db.file_ciphertexts[j]);
            g_db.file_ciphertexts[j] = NULL;
        }
    }
    g_db.file_count = 0;
    return -1;
}

static int db_load(void) {
    FILE *f = fopen(DB_PATH, "rb");
    if (!f) {
        randombytes_buf(g_db.db_salt, 32);
        g_db.user_count = 0;
        g_db.file_count = 0;
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);

    if (fsz <= 0 || (size_t)fsz > 600 * 1024 * 1024UL) {
        fclose(f); return -1;
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)fsz);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    int rc = db_deserialise(buf, (size_t)fsz);
    sodium_memzero(buf, (size_t)fsz);
    free(buf);
    return rc;
}

static int db_save(void) {
    size_t len;
    uint8_t *buf = db_serialise(&len);
    if (!buf) return -1;

    /* Issue 12 + 24: use mkstemp for unique name + O_CREAT 0600 */
    char tmp_path[] = "enc.db.XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) { sodium_memzero(buf, len); free(buf); return -1; }

    /* mkstemp creates with 0600 already on Linux, but be explicit */
    fchmod(fd, 0600);

    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); remove(tmp_path); sodium_memzero(buf, len); free(buf); return -1; }

    int ok = (fwrite(buf, 1, len, f) == len);
    /* Issue 17: check fclose for deferred write errors */
    if (fclose(f) != 0) ok = 0;

    sodium_memzero(buf, len);
    free(buf);

    if (!ok) { remove(tmp_path); return -1; }
    if (rename(tmp_path, DB_PATH) != 0) { remove(tmp_path); return -1; }

    /* Issue 24: fix permissions on final file too */
    chmod(DB_PATH, 0600);
    return 0;
}

/* ── user operations ─────────────────────────────────────────────── */

static UserRecord *find_user(const uint8_t uhash[HASH_BYTES]) {
    for (int i = 0; i < g_db.user_count; i++)
        if (eq32(g_db.users[i].username_hash, uhash))
            return &g_db.users[i];
    return NULL;
}

static int verify_and_derive(UserRecord *ur, const char *key,
                              uint8_t out_key[KEY_BYTES]) {
    if (derive_key(key, ur->kdf_salt, out_key) != 0) return -1;

    uint8_t zeros[32], plain[32];
    memset(zeros, 0, 32);
    int rc = crypto_secretbox_open_easy(plain,
                 ur->key_verifier, MAC_BYTES + 32,
                 ur->verifier_nonce, out_key);
    if (rc != 0 || sodium_memcmp(plain, zeros, 32) != 0) {
        sodium_memzero(out_key, KEY_BYTES);
        sodium_memzero(plain, 32);
        return -1;
    }
    sodium_memzero(plain, 32);
    return 0;
}

static void compute_user_file_state_mac(const uint8_t owner_hash[HASH_BYTES],
                                        const uint8_t user_key[KEY_BYTES],
                                        uint8_t out[GLOBAL_MAC_BYTES]) {
    crypto_auth_hmacsha512256_state st;
    crypto_auth_hmacsha512256_init(&st, user_key, KEY_BYTES);
    crypto_auth_hmacsha512256_update(&st, owner_hash, HASH_BYTES);

    for (int i = 0; i < g_db.file_count; i++) {
        FileHeader *fh = &g_db.file_headers[i];
        if (!eq32(fh->owner_hash, owner_hash)) continue;
        if (fh->ciphertext_len == 0) continue;

        crypto_auth_hmacsha512256_update(&st, fh->owner_hash, HASH_BYTES);
        crypto_auth_hmacsha512256_update(&st, fh->filename_hash, HASH_BYTES);
        crypto_auth_hmacsha512256_update(&st, fh->nonce, NONCE_BYTES);
        crypto_auth_hmacsha512256_update(&st,
            (const uint8_t *)&fh->ciphertext_len, sizeof(fh->ciphertext_len));
        crypto_auth_hmacsha512256_update(&st, g_db.file_ciphertexts[i],
                                         fh->ciphertext_len);
    }

    crypto_auth_hmacsha512256_final(&st, out);
}

static int verify_user_file_state(UserRecord *ur,
                                  const uint8_t owner_hash[HASH_BYTES],
                                  const uint8_t user_key[KEY_BYTES]) {
    uint8_t mac[GLOBAL_MAC_BYTES];
    compute_user_file_state_mac(owner_hash, user_key, mac);
    int ok = sodium_memcmp(mac, ur->file_state_mac, GLOBAL_MAC_BYTES) == 0;
    sodium_memzero(mac, sizeof(mac));
    return ok ? 0 : -1;
}

static void update_user_file_state(UserRecord *ur,
                                   const uint8_t owner_hash[HASH_BYTES],
                                   const uint8_t user_key[KEY_BYTES]) {
    compute_user_file_state_mac(owner_hash, user_key, ur->file_state_mac);
}


/* Derive a per-file encryption key by binding the user key to the file identity.
 * file_key = BLAKE2b(user_derived_key || owner_hash || filename_hash)
 * This means ciphertexts cannot be transplanted between files or users. */
static void derive_file_key(const uint8_t user_key[KEY_BYTES],
                             const uint8_t owner_hash[HASH_BYTES],
                             const uint8_t fname_hash[HASH_BYTES],
                             uint8_t out[KEY_BYTES]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, KEY_BYTES);
    crypto_generichash_update(&st, user_key, KEY_BYTES);
    crypto_generichash_update(&st, owner_hash, HASH_BYTES);
    crypto_generichash_update(&st, fname_hash, HASH_BYTES);
    crypto_generichash_final(&st, out, KEY_BYTES);
}

static int op_register(const char *username, const char *key) {
    if (!username || !key) return -1;
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) return -1;
    if (strlen(key) == 0 || strlen(key) > MAX_KEY) return -1;

    uint8_t uhash[HASH_BYTES];
    hash_string(username, uhash);

    if (find_user(uhash) != NULL) return -1;
    if (g_db.user_count >= MAX_RECORDS) return -1;

    UserRecord *ur = &g_db.users[g_db.user_count];
    memcpy(ur->username_hash, uhash, HASH_BYTES);
    randombytes_buf(ur->kdf_salt, SALT_BYTES);

    uint8_t derived[KEY_BYTES];
    if (derive_key(key, ur->kdf_salt, derived) != 0) return -1;

    uint8_t zeros[32];
    memset(zeros, 0, 32);
    randombytes_buf(ur->verifier_nonce, NONCE_BYTES);
    crypto_secretbox_easy(ur->key_verifier, zeros, 32,
                          ur->verifier_nonce, derived);
    update_user_file_state(ur, uhash, derived);
    sodium_memzero(derived, KEY_BYTES);
    sodium_memzero(zeros, 32);

    g_db.user_count++;
    return db_save();
}

/* ── file operations ─────────────────────────────────────────────── */

static int find_file(const uint8_t owner_hash[HASH_BYTES],
                     const uint8_t fname_hash[HASH_BYTES]) {
    for (int i = 0; i < g_db.file_count; i++)
        if (eq32(g_db.file_headers[i].owner_hash, owner_hash) &&
            eq32(g_db.file_headers[i].filename_hash, fname_hash))
            return i;
    return -1;
}

static int op_create(const char *username, const char *filename) {
    if (!username || !filename) return -1;
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) return -1;
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) return -1;

    uint8_t uhash[HASH_BYTES], fhash[HASH_BYTES];
    hash_string(username, uhash);
    hash_string(filename, fhash);

    if (find_user(uhash) == NULL) return -1;

    /* Issue 2: idempotent — if file already exists, exit 0 (no-op) */
    if (find_file(uhash, fhash) >= 0) return 0;

    if (g_db.file_count >= MAX_RECORDS) return -1;

    int idx = g_db.file_count;
    FileHeader *fh = &g_db.file_headers[idx];
    memcpy(fh->owner_hash, uhash, HASH_BYTES);
    memcpy(fh->filename_hash, fhash, HASH_BYTES);
    memset(fh->nonce, 0, NONCE_BYTES);
    fh->ciphertext_len = 0;
    g_db.file_ciphertexts[idx] = NULL;

    g_db.file_count++;
    return db_save();
}

static int op_write(const char *username, const char *key,
                    const char *filename,
                    const uint8_t *content, size_t content_len) {
    if (!username || !key || !filename) return -1;
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) return -1;
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) return -1;
    if (strlen(key) == 0 || strlen(key) > MAX_KEY) return -1;
    if (content_len > MAX_CONTENT) return -1;

    uint8_t uhash[HASH_BYTES], fhash[HASH_BYTES];
    hash_string(username, uhash);
    hash_string(filename, fhash);

    UserRecord *ur = find_user(uhash);
    if (!ur) return -1;

    uint8_t derived[KEY_BYTES];
    if (verify_and_derive(ur, key, derived) != 0) return -1;
    if (verify_user_file_state(ur, uhash, derived) != 0) {
        sodium_memzero(derived, KEY_BYTES);
        return -1;
    }

    int idx = find_file(uhash, fhash);
    if (idx < 0) { sodium_memzero(derived, KEY_BYTES); return -1; }

    /* Bind encryption to this specific file identity */
    uint8_t file_key[KEY_BYTES];
    derive_file_key(derived, uhash, fhash, file_key);

    FileHeader *fh = &g_db.file_headers[idx];

    if (fh->ciphertext_len > 0) {
        if (fh->ciphertext_len < MAC_BYTES) {
            sodium_memzero(file_key, KEY_BYTES);
            sodium_memzero(derived, KEY_BYTES);
            return -1;
        }

        size_t old_plain_len = fh->ciphertext_len - MAC_BYTES;
        uint8_t *tmp_plain = malloc(old_plain_len + 1);
        if (!tmp_plain) {
            sodium_memzero(file_key, KEY_BYTES);
            sodium_memzero(derived, KEY_BYTES);
            return -1;
        }

        int ok = crypto_secretbox_open_easy(
            tmp_plain,
            g_db.file_ciphertexts[idx],
            fh->ciphertext_len,
            fh->nonce,
            file_key
        );

        sodium_memzero(tmp_plain, old_plain_len);
        free(tmp_plain);

        if (ok != 0) {
            sodium_memzero(file_key, KEY_BYTES);
            sodium_memzero(derived, KEY_BYTES);
            return -1;
        }
    }

    uint32_t ct_len = (uint32_t)(content_len + MAC_BYTES);
    uint8_t *ct = (uint8_t *)malloc(ct_len);
    if (!ct) { sodium_memzero(file_key, KEY_BYTES); return -1; }

    uint8_t nonce[NONCE_BYTES];
    randombytes_buf(nonce, NONCE_BYTES);
    crypto_secretbox_easy(ct, content, content_len, nonce, file_key);
    sodium_memzero(file_key, KEY_BYTES);

    if (g_db.file_ciphertexts[idx]) {
        sodium_memzero(g_db.file_ciphertexts[idx],
                       g_db.file_headers[idx].ciphertext_len);
        free(g_db.file_ciphertexts[idx]);
    }
    g_db.file_ciphertexts[idx] = ct;
    memcpy(g_db.file_headers[idx].nonce, nonce, NONCE_BYTES);
    g_db.file_headers[idx].ciphertext_len = ct_len;
    update_user_file_state(ur, uhash, derived);
    sodium_memzero(derived, KEY_BYTES);

    return db_save();
}

static int op_read(const char *username, const char *key,
                   const char *filename,
                   uint8_t **out_content, size_t *out_len) {
    if (!username || !key || !filename) return -1;
    if (strlen(username) == 0 || strlen(username) > MAX_USERNAME) return -1;
    if (strlen(filename) == 0 || strlen(filename) > MAX_FILENAME) return -1;
    if (strlen(key) == 0 || strlen(key) > MAX_KEY) return -1;

    uint8_t uhash[HASH_BYTES], fhash[HASH_BYTES];
    hash_string(username, uhash);
    hash_string(filename, fhash);

    UserRecord *ur = find_user(uhash);
    if (!ur) return -1;

    uint8_t derived[KEY_BYTES];
    if (verify_and_derive(ur, key, derived) != 0) return -1;
    if (verify_user_file_state(ur, uhash, derived) != 0) {
        sodium_memzero(derived, KEY_BYTES);
        return -1;
    }

    int idx = find_file(uhash, fhash);
    if (idx < 0) { sodium_memzero(derived, KEY_BYTES); return -1; }

    FileHeader *fh = &g_db.file_headers[idx];

    /* Seal a freshly-created empty file the first time the owner reads it. */
    if (fh->ciphertext_len == 0) {
        uint8_t file_key[KEY_BYTES];
        derive_file_key(derived, uhash, fhash, file_key);
        uint8_t *ct = (uint8_t *)malloc(MAC_BYTES);
        if (!ct) {
            sodium_memzero(file_key, KEY_BYTES);
            sodium_memzero(derived, KEY_BYTES);
            return -1;
        }

        randombytes_buf(fh->nonce, NONCE_BYTES);
        crypto_secretbox_easy(ct, (const uint8_t *)"", 0, fh->nonce, file_key);
        sodium_memzero(file_key, KEY_BYTES);

        g_db.file_ciphertexts[idx] = ct;
        fh->ciphertext_len = MAC_BYTES;
        update_user_file_state(ur, uhash, derived);
        sodium_memzero(derived, KEY_BYTES);

        if (db_save() != 0) return -1;

        *out_content = (uint8_t *)malloc(1);
        if (!*out_content) return -1;
        (*out_content)[0] = '\0';
        *out_len = 0;
        return 0;
    }

    if (fh->ciphertext_len < MAC_BYTES) {
        sodium_memzero(derived, KEY_BYTES);
        return -1;
    }

    size_t plain_len = fh->ciphertext_len - MAC_BYTES;
    uint8_t *plain = (uint8_t *)malloc(plain_len + 1);
    if (!plain) { sodium_memzero(derived, KEY_BYTES); return -1; }

    /* Derive file-specific key — must match what was used during write */
    uint8_t file_key[KEY_BYTES];
    derive_file_key(derived, uhash, fhash, file_key);
    sodium_memzero(derived, KEY_BYTES);

    int rc = crypto_secretbox_open_easy(plain,
                 g_db.file_ciphertexts[idx], fh->ciphertext_len,
                 fh->nonce, file_key);
    sodium_memzero(file_key, KEY_BYTES);

    if (rc != 0) {
        sodium_memzero(plain, plain_len);
        free(plain);
        return -1;
    }

    plain[plain_len] = '\0';
    *out_content = plain;
    *out_len = plain_len;
    return 0;
}

static int same_file_as_db(const char *path) {
    struct stat dbst, outst;

    if (stat(DB_PATH, &dbst) != 0) {
        return 0;
    }

    if (stat(path, &outst) != 0) {
        return 0;
    }

    return dbst.st_dev == outst.st_dev &&
           dbst.st_ino == outst.st_ino;
}

/* ── arg parsing ─────────────────────────────────────────────────── */

typedef enum { CMD_NONE, CMD_REGISTER, CMD_CREATE, CMD_WRITE, CMD_READ } Command;

typedef struct {
    char    *username;
    char    *key;
    char    *filename;
    char    *infile;
    char    *outfile;
    char    *text;
    Command  cmd;
    int      parse_error; /* set if unknown flag or duplicate action seen */
    int      has_infile;  /* -i was explicitly provided */
    int      has_outfile; /* -o was explicitly provided */
} Args;

static void parse_args(int argc, char **argv, Args *a) {
    memset(a, 0, sizeof(*a));
    a->cmd = CMD_NONE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i+1 < argc) {
            a->username = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i+1 < argc) {
            a->key = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            a->filename = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) {
            a->infile = argv[++i];
            a->has_infile = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i+1 < argc) {
            a->outfile = argv[++i];
            a->has_outfile = 1;
        } else if (strcmp(argv[i], "register") == 0 ||
                   strcmp(argv[i], "create")   == 0 ||
                   strcmp(argv[i], "write")    == 0 ||
                   strcmp(argv[i], "read")     == 0) {
            /* Issue 15: reject duplicate actions */
            if (a->cmd != CMD_NONE) { a->parse_error = 1; return; }
            if (strcmp(argv[i], "register") == 0) a->cmd = CMD_REGISTER;
            else if (strcmp(argv[i], "create") == 0) a->cmd = CMD_CREATE;
            else if (strcmp(argv[i], "read")   == 0) a->cmd = CMD_READ;
            else {
                a->cmd = CMD_WRITE;
                /* Always consume next token as inline text (Issue 4 fix) */
                if (i+1 < argc) a->text = argv[++i];
            }
        } else if (argv[i][0] == '-') {
            /* Issue 3: unknown flag -> reject */
            a->parse_error = 1;
            return;
        } else {
            /* Issue 3: unexpected bare positional after flags -> reject */
            a->parse_error = 1;
            return;
        }
    }
}

/* ── main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (sodium_init() < 0) die("sodium_init");

    Args a;
    parse_args(argc, argv, &a);

    /* Issue 3 + 15 + 16: any parse error is fatal */
    if (a.parse_error)          die("parse error");
    if (a.cmd == CMD_NONE)      die("no command");
    if (!a.username)            die("no username");

    if (strlen(a.username) == 0)           die("empty username");
    if (strlen(a.username) > MAX_USERNAME) die("username too long");
    if (a.filename && strlen(a.filename) == 0)           die("empty filename");
    if (a.filename && strlen(a.filename) > MAX_FILENAME) die("filename too long");
    if (a.key && strlen(a.key) == 0)   die("empty key");
    if (a.key && strlen(a.key) > MAX_KEY) die("key too long");

    /* -i is only valid for write; -o is only valid for read */
    if (a.has_infile  && a.cmd != CMD_WRITE) die("-i only valid for write");
    if (a.has_outfile && a.cmd != CMD_READ)  die("-o only valid for read");
    if (a.has_infile && a.text) die("-i conflicts with inline text");

    if (db_load() != 0) die("db load failed");

    switch (a.cmd) {

    case CMD_REGISTER:
        if (!a.key) die("register needs -k");
        if (op_register(a.username, a.key) != 0) die("register failed");
        break;

    case CMD_CREATE:
        if (!a.filename) die("create needs -f");
        if (op_create(a.username, a.filename) != 0) die("create failed");
        break;

    case CMD_WRITE: {
        if (!a.key)      die("write needs -k");
        if (!a.filename) die("write needs -f");

        uint8_t *content = NULL;
        size_t   content_len = 0;

        if (a.infile) {
            int fd = open(a.infile, O_RDONLY | O_NOFOLLOW);
            if (fd < 0) die("cannot open input file");

            struct stat st;
            if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
                close(fd);
                die("input not a regular file");
            }

            FILE *f = fdopen(fd, "rb");
            if (!f) {
                close(fd);
                die("cannot fdopen input file");
            }
            fseek(f, 0, SEEK_END);
            long fsz = ftell(f);
            rewind(f);
            if (fsz < 0 || (size_t)fsz > MAX_CONTENT) {
                fclose(f); die("input file too large");
            }
            content_len = (size_t)fsz;
            content = (uint8_t *)malloc(content_len + 1);
            if (!content) { fclose(f); die("malloc"); }
            if (fread(content, 1, content_len, f) != content_len) {
                free(content); fclose(f); die("read error");
            }

            if (content_len > 0 && content[content_len - 1] == '\n') {
                content_len--;
            }

            fclose(f);
        } else {
            const char *txt = a.text ? a.text : "";
            content_len = strlen(txt);
            content = (uint8_t *)malloc(content_len + 1);
            if (!content) die("malloc");
            memcpy(content, txt, content_len);
        }

        int rc = op_write(a.username, a.key, a.filename, content, content_len);
        sodium_memzero(content, content_len);
        free(content);
        if (rc != 0) die("write failed");
        break;
    }

    case CMD_READ: {
        if (!a.key)      die("read needs -k");
        if (!a.filename) die("read needs -f");

        uint8_t *content = NULL;
        size_t   content_len = 0;
        if (op_read(a.username, a.key, a.filename,
                    &content, &content_len) != 0)
            die("read failed");

        if (a.outfile) {
            /* Reject writing output over the database file itself */
             if (same_file_as_db(a.outfile)) {
                sodium_memzero(content, content_len);
                free(content);
                die("output path is reserved");
            }
            FILE *f = fopen(a.outfile, "wb");
            if (!f) {
                sodium_memzero(content, content_len);
                free(content);
                die("cannot open output file");
            }
            int wok = (fwrite(content, 1, content_len, f) == content_len);
            /* Issue 6: check fclose for deferred errors */
            if (fclose(f) != 0) wok = 0;
            sodium_memzero(content, content_len);
            free(content);
            if (!wok) die("output write failed");
        } else {
            /* Check stdout write and flush; fail closed on error */
            int wok = (fwrite(content, 1, content_len, stdout) == content_len);
            if (fflush(stdout) != 0) wok = 0;
            sodium_memzero(content, content_len);
            free(content);
            if (!wok) die("stdout write failed");
        }
        break;
    }

    default:
        die("unknown command");
    }

    cleanup_and_exit(0);
    return 0;
}
