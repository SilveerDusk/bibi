/*
 * stor.c — Multi-User Secure implementation for BIBIFI file store.
 * Fully compatible with tests.json, the official Linux Makefile,
 * dlmalloc isolation, and OpenSSL Authenticated Encryption (AES-GCM).
 */

#ifndef WIN32
#define WIN32 1
#endif
#define _GNU_SOURCE 1

#define USE_DL_MALLOC
#include <stddef.h>

/* Forward declare dlmalloc signatures to prevent type mismatches */
void* malloc(size_t);
void free(void*);
void* calloc(size_t, size_t);
void* realloc(void*, size_t);

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define DB_FILE "enc.db"
#define MAX_USERS 32
#define MAX_FILES_PER_USER 32

#define MAX_USER_LEN 128
#define MAX_FILE_LEN 128
#define MAX_PAYLOAD_LEN 4096

#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 12
#define TAG_LEN 16

/* Structural entry for an isolated virtual file storage tracking block */
typedef struct {
    char filename[MAX_FILE_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned long long ciphertext_len;
    unsigned char ciphertext[MAX_PAYLOAD_LEN];
    int is_active;
} file_record_t;

/* Structural layout representing a user entity record block */
typedef struct {
    char username[MAX_USER_LEN];
    unsigned char salt[SALT_LEN];
    unsigned char key_hash_tag[32]; /* Verification hash */
    file_record_t files[MAX_FILES_PER_USER];
    int is_active;
} user_record_t;

/* Global state directory tree representation */
typedef struct {
    user_record_t users[MAX_USERS];
} db_state_t;

/* ---- Required: do not remove ---- */
void win(void) {
    printf("Arbitrary access achieved!\n");
}

/* Print "invalid" and return 255 — use this for ALL error paths. */
static int invalid(void) {
    printf("invalid");
    return 255;
}

/* Derives encryption and authentication assets from password securely */
static int derive_user_keys(const char *password, const unsigned char *salt, 
                             unsigned char *out_enc_key, unsigned char *out_auth_tag) {
    /* PBKDF2 Key Derivation */
    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, SALT_LEN, 
                                2000, KEY_LEN, out_enc_key)) {
        return -1;
    }
    /* Simple distinct string tag for authentication checking */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, out_enc_key, KEY_LEN) ||
        !EVP_DigestFinal_ex(ctx, out_auth_tag, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* Safely pulls plain text payloads from file streams directly into bounded blocks */
static unsigned char *read_input_file(const char *path, unsigned long long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    unsigned char *buf = malloc(size > 0 ? size : 1);
    if (!buf) { fclose(f); exit(0); }

    if (size > 0) {
        size_t read_bytes = fread(buf, 1, size, f);
        if (read_bytes != (size_t)size) {
            free(buf);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);
    *out_len = (unsigned long long)size;
    return buf;
}

int main(int argc, char **argv) {
    /* Securely allocate the massive state structure onto the heap to prevent stack overflow */
    db_state_t *db = calloc(1, sizeof(db_state_t));
    if (!db) exit(0);

    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
    int c;

    opterr = 0;
    while ((c = getopt(argc, argv, "u:k:f:i:o:")) != -1) {
        switch (c) {
            case 'u': user    = optarg; break;
            case 'k': key     = optarg; break;
            case 'f': file    = optarg; break;
            case 'i': infile  = optarg; break;
            case 'o': outfile = optarg; break;
            default:  free(db); return invalid();
        }
    }

    if (!user || strlen(user) >= MAX_USER_LEN || strlen(user) == 0) { free(db); return invalid(); }
    if (optind >= argc) { free(db); return invalid(); }

    const char *action = argv[optind];
    const char *content_inline = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    int act_reg    = (strcmp(action, "register") == 0);
    int act_create = (strcmp(action, "create") == 0);
    int act_write  = (strcmp(action, "write") == 0);
    int act_read   = (strcmp(action, "read") == 0);

    if (!act_reg && !act_create && !act_write && !act_read) { free(db); return invalid(); }
    if ((act_reg || act_write || act_read) && !key) { free(db); return invalid(); }
    if ((act_create || act_write || act_read) && (!file || strlen(file) >= MAX_FILE_LEN || strlen(file) == 0)) { free(db); return invalid(); }

    /* Read existing database layout mapping */
    if (access(DB_FILE, F_OK) == 0) {
        FILE *f_db = fopen(DB_FILE, "rb");
        if (f_db) {
            size_t read_sz = fread(db, 1, sizeof(db_state_t), f_db);
            fclose(f_db);
            if (read_sz != sizeof(db_state_t)) {
                memset(db, 0, sizeof(db_state_t));
            }
        }
    }

    int user_idx = -1;
    for (int i = 0; i < MAX_USERS; i++) {
        if (db->users[i].is_active && strcmp(db->users[i].username, user) == 0) {
            user_idx = i;
            break;
        }
    }

    /* ---------------- ACTION: REGISTER ---------------- */
    if (act_reg) {
        if (user_idx == -1) {
            for (int i = 0; i < MAX_USERS; i++) {
                if (!db->users[i].is_active) {
                    user_idx = i;
                    break;
                }
            }
        }
        if (user_idx == -1) { free(db); return invalid(); }

        unsigned char salt[SALT_LEN];
        unsigned char enc_key[KEY_LEN];
        unsigned char auth_tag[32];

        if (!RAND_bytes(salt, SALT_LEN)) { free(db); return invalid(); }
        if (derive_user_keys(key, salt, enc_key, auth_tag) != 0) { free(db); return invalid(); }

        user_record_t *u_rec = &db->users[user_idx];
        memset(u_rec, 0, sizeof(user_record_t));
        strncpy(u_rec->username, user, MAX_USER_LEN - 1);
        memcpy(u_rec->salt, salt,  SALT_LEN);
        memcpy(u_rec->key_hash_tag, auth_tag, 32);
        u_rec->is_active = 1;

        FILE *f_out = fopen(DB_FILE, "wb");
        if (!f_out) { free(db); return invalid(); }
        fwrite(db, 1, sizeof(db_state_t), f_out);
        fclose(f_out);

        OPENSSL_cleanse(enc_key, KEY_LEN);
        free(db);
        return 0;
    }

    if (user_idx == -1) { free(db); return invalid(); }
    user_record_t *u_rec = &db->users[user_idx];

    /* ---------------- ACTION: CREATE ---------------- */
    if (act_create) {
        int file_idx = -1;
        for (int i = 0; i < MAX_FILES_PER_USER; i++) {
            if (u_rec->files[i].is_active && strcmp(u_rec->files[i].filename, file) == 0) {
                file_idx = i;
                break;
            }
        }

        if (file_idx == -1) {
            for (int i = 0; i < MAX_FILES_PER_USER; i++) {
                if (!u_rec->files[i].is_active) {
                    file_idx = i;
                    break;
                }
            }
            if (file_idx == -1) { free(db); return invalid(); }

            file_record_t *f_rec = &u_rec->files[file_idx];
            memset(f_rec, 0, sizeof(file_record_t));
            strncpy(f_rec->filename, file, MAX_FILE_LEN - 1);
            f_rec->is_active = 1;

            FILE *f_out = fopen(DB_FILE, "wb");
            if (!f_out) { free(db); return invalid(); }
            fwrite(db, 1, sizeof(db_state_t), f_out);
            fclose(f_out);
        }

        free(db);
        return 0;
    }

    /* ---------------- CRYPTO VALIDATION FOR READ / WRITE ---------------- */
    unsigned char enc_key[KEY_LEN];
    unsigned char auth_tag[32];
    if (derive_user_keys(key, u_rec->salt, enc_key, auth_tag) != 0) { free(db); return invalid(); }

    if (CRYPTO_memcmp(u_rec->key_hash_tag, auth_tag, 32) != 0) {
        OPENSSL_cleanse(enc_key, KEY_LEN);
        free(db);
        return invalid();
    }

    int file_idx = -1;
    for (int i = 0; i < MAX_FILES_PER_USER; i++) {
        if (u_rec->files[i].is_active && strcmp(u_rec->files[i].filename, file) == 0) {
            file_idx = i;
            break;
        }
    }
    if (file_idx == -1) {
        OPENSSL_cleanse(enc_key, KEY_LEN);
        free(db);
        return invalid();
    }
    file_record_t *f_rec = &u_rec->files[file_idx];

    /* ---------------- ACTION: WRITE ---------------- */
    if (act_write) {
        unsigned char *plaintext_payload = NULL;
        unsigned long long plaintext_len = 0;

        if (infile) {
            plaintext_payload = read_input_file(infile, &plaintext_len);
            if (!plaintext_payload) { OPENSSL_cleanse(enc_key, KEY_LEN); free(db); return invalid(); }
        } else if (content_inline) {
            plaintext_len = strlen(content_inline);
            plaintext_payload = malloc(plaintext_len > 0 ? plaintext_len : 1);
            if (!plaintext_payload) { free(db); exit(0); }
            memcpy(plaintext_payload, content_inline, plaintext_len);
        } else {
            plaintext_payload = malloc(1);
            if (!plaintext_payload) { free(db); exit(0); }
            plaintext_len = 0;
        }

        if (plaintext_len > MAX_PAYLOAD_LEN) {
            free(plaintext_payload);
            OPENSSL_cleanse(enc_key, KEY_LEN);
            free(db);
            return invalid();
        }

        unsigned char iv[IV_LEN];
        if (!RAND_bytes(iv, IV_LEN)) {
            free(plaintext_payload);
            OPENSSL_cleanse(enc_key, KEY_LEN);
            free(db);
            return invalid();
        }

                /* OpenSSL Authenticated AES-GCM Encrypt Engine */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid(); 
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, enc_key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }

        int outlen = 0;
        if (EVP_EncryptUpdate(ctx, f_rec->ciphertext, &outlen, plaintext_payload, plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }
        int total_len = outlen;

        if (EVP_EncryptFinal_ex(ctx, f_rec->ciphertext + total_len, &outlen) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }
        total_len += outlen;

        unsigned char tag[TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }
        EVP_CIPHER_CTX_free(ctx);

        memcpy(f_rec->iv, iv, IV_LEN);
        memcpy(f_rec->tag, tag, TAG_LEN);
        f_rec->ciphertext_len = total_len;

        FILE *f_out = fopen(DB_FILE, "wb");
        if (!f_out) { 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid(); 
        }
        fwrite(db, 1, sizeof(db_state_t), f_out);
        fclose(f_out);

        free(plaintext_payload);
        OPENSSL_cleanse(enc_key, KEY_LEN);
        free(db);
        return 0;
    }

    /* ---------------- ACTION: READ ---------------- */
    if (act_read) {
        unsigned char *plaintext_payload = malloc(f_rec->ciphertext_len > 0 ? f_rec->ciphertext_len : 1);
        if (!plaintext_payload) { 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            exit(0); 
        }

        /* OpenSSL Authenticated AES-GCM Decrypt Engine */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid(); 
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, enc_key, f_rec->iv) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }

        int outlen = 0;
        if (EVP_DecryptUpdate(ctx, plaintext_payload, &outlen, f_rec->ciphertext, f_rec->ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }
        int total_len = outlen;

        /* Verify the Integrity Tag before finishing */
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, f_rec->tag) != 1) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }

        /* If tag checking fails, EVP_DecryptFinal returns <= 0 (Immediate Tamper / Forgery Rejection) */
        if (EVP_DecryptFinal_ex(ctx, plaintext_payload + total_len, &outlen) <= 0) {
            EVP_CIPHER_CTX_free(ctx); 
            free(plaintext_payload); 
            OPENSSL_cleanse(enc_key, KEY_LEN); 
            free(db); 
            return invalid();
        }
        total_len += outlen;
        EVP_CIPHER_CTX_free(ctx);

        if (outfile) {
            FILE *f_out = fopen(outfile, "wb");
            if (!f_out) { 
                free(plaintext_payload); 
                OPENSSL_cleanse(enc_key, KEY_LEN); 
                free(db); 
                return invalid(); 
            }
            if (total_len > 0) fwrite(plaintext_payload, 1, total_len, f_out);
            fclose(f_out);
        } else {
            if (total_len > 0) fwrite(plaintext_payload, 1, total_len, stdout);
        }

        free(plaintext_payload);
        OPENSSL_cleanse(enc_key, KEY_LEN);
        free(db);
        return 0;
    }

    OPENSSL_cleanse(enc_key, KEY_LEN);
    free(db);
    return invalid();
}
