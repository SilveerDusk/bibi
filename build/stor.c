/*
 * stor.c — BiBiFi secure file store implementation.
 *
 * Implements a CLI encrypted file store with:
 * - User registration with key-based authentication
 * - File creation and encrypted content storage
 * - Persistent state in "enc.db"
 * - Multi-user isolation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define DB_FILE "enc.db"
#define MAX_NAME 256
#define MAX_CONTENT 65536
#define SALT_SIZE 16
#define IV_SIZE 16

typedef struct {
    char username[MAX_NAME];
    unsigned char salt[SALT_SIZE];
    unsigned char key_hash[32];
} User;

typedef struct {
    char username[MAX_NAME];
    char filename[MAX_NAME];
    unsigned char iv[IV_SIZE];
    int encrypted_len;
} FileMeta;

typedef struct {
    User *users;
    int user_count;
    FileMeta *files;
    unsigned char **file_data;
    int file_count;
} Database;

void win(void) {
    printf("Arbitrary access achieved!\n");
}

static int invalid(void) {
    printf("invalid");
    return 255;
}

static void hash_key(const char *key, const unsigned char *salt, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, key, strlen(key));
    EVP_DigestUpdate(ctx, salt, SALT_SIZE);
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
}

static int db_load(Database *db) {
    FILE *f = fopen(DB_FILE, "rb");
    if (!f) {
        db->users = NULL;
        db->user_count = 0;
        db->files = NULL;
        db->file_data = NULL;
        db->file_count = 0;
        return 0;
    }

    if (fread(&db->user_count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    if (db->user_count > 0) {
        db->users = malloc(db->user_count * sizeof(User));
        if (fread(db->users, sizeof(User), db->user_count, f) != (size_t)db->user_count) {
            fclose(f);
            return -1;
        }
    } else {
        db->users = NULL;
    }

    if (fread(&db->file_count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    if (db->file_count > 0) {
        db->files = malloc(db->file_count * sizeof(FileMeta));
        db->file_data = malloc(db->file_count * sizeof(unsigned char *));

        for (int i = 0; i < db->file_count; i++) {
            if (fread(&db->files[i], sizeof(FileMeta), 1, f) != 1) {
                fclose(f);
                return -1;
            }

            if (db->files[i].encrypted_len > 0) {
                db->file_data[i] = malloc(db->files[i].encrypted_len);
                if (fread(db->file_data[i], 1, db->files[i].encrypted_len, f) != (size_t)db->files[i].encrypted_len) {
                    fclose(f);
                    return -1;
                }
            } else {
                db->file_data[i] = NULL;
            }
        }
    } else {
        db->files = NULL;
        db->file_data = NULL;
    }

    fclose(f);
    return 0;
}

static int db_save(Database *db) {
    FILE *f = fopen(DB_FILE, "wb");
    if (!f) return -1;

    if (fwrite(&db->user_count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    if (db->user_count > 0) {
        if (fwrite(db->users, sizeof(User), db->user_count, f) != (size_t)db->user_count) {
            fclose(f);
            return -1;
        }
    }

    if (fwrite(&db->file_count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    for (int i = 0; i < db->file_count; i++) {
        if (fwrite(&db->files[i], sizeof(FileMeta), 1, f) != 1) {
            fclose(f);
            return -1;
        }

        if (db->files[i].encrypted_len > 0 && db->file_data[i]) {
            if (fwrite(db->file_data[i], 1, db->files[i].encrypted_len, f) != (size_t)db->files[i].encrypted_len) {
                fclose(f);
                return -1;
            }
        }
    }

    fclose(f);
    return 0;
}

static int db_find_user(Database *db, const char *username) {
    for (int i = 0; i < db->user_count; i++) {
        if (strcmp(db->users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

static int db_find_file(Database *db, const char *username, const char *filename) {
    for (int i = 0; i < db->file_count; i++) {
        if (strcmp(db->files[i].username, username) == 0 &&
            strcmp(db->files[i].filename, filename) == 0) {
            return i;
        }
    }
    return -1;
}

static int verify_key(Database *db, const char *username, const char *key) {
    int idx = db_find_user(db, username);
    if (idx < 0) return -1;

    unsigned char hash[32];
    hash_key(key, db->users[idx].salt, hash);

    if (memcmp(hash, db->users[idx].key_hash, 32) == 0) {
        return 0;
    }
    return -1;
}

static unsigned char *encrypt_data(const char *plaintext, const unsigned char *key, unsigned char *iv, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *ciphertext = malloc(strlen(plaintext) + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    if (!RAND_bytes(iv, IV_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, strlen(plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *out_len = ciphertext_len;
    return ciphertext;
}

static char *decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    char *plaintext = malloc(ciphertext_len + 1);
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        free(plaintext);
        return NULL;
    }

    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    return plaintext;
}

int main(int argc, char **argv) {
    char *user = NULL, *key = NULL, *file = NULL;
    char *infile = NULL, *outfile = NULL;
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

    Database db;
    if (db_load(&db) < 0) return invalid();

    if (strcmp(action, "register") == 0) {
        if (!key) return invalid();
        if (strlen(user) >= MAX_NAME || strlen(key) >= MAX_NAME) return invalid();

        int idx = db_find_user(&db, user);
        if (idx >= 0) {
            // Re-register: update key
            RAND_bytes(db.users[idx].salt, SALT_SIZE);
            hash_key(key, db.users[idx].salt, db.users[idx].key_hash);
        } else {
            // New user
            db.users = realloc(db.users, (db.user_count + 1) * sizeof(User));
            strcpy(db.users[db.user_count].username, user);
            RAND_bytes(db.users[db.user_count].salt, SALT_SIZE);
            hash_key(key, db.users[db.user_count].salt, db.users[db.user_count].key_hash);
            db.user_count++;
        }

        if (db_save(&db) < 0) return invalid();
        return 0;
    }

    if (strcmp(action, "create") == 0) {
        if (!file) return invalid();
        if (strlen(user) >= MAX_NAME || strlen(file) >= MAX_NAME) return invalid();

        int idx = db_find_user(&db, user);
        if (idx < 0) return invalid();

        int file_idx = db_find_file(&db, user, file);
        if (file_idx >= 0) {
            // File already exists, no-op
            return 0;
        }

        db.files = realloc(db.files, (db.file_count + 1) * sizeof(FileMeta));
        db.file_data = realloc(db.file_data, (db.file_count + 1) * sizeof(unsigned char *));
        strcpy(db.files[db.file_count].username, user);
        strcpy(db.files[db.file_count].filename, file);
        memset(db.files[db.file_count].iv, 0, IV_SIZE);
        db.files[db.file_count].encrypted_len = 0;
        db.file_data[db.file_count] = NULL;
        db.file_count++;

        if (db_save(&db) < 0) return invalid();
        return 0;
    }

    if (strcmp(action, "write") == 0) {
        if (!key || !file) return invalid();
        if (strlen(user) >= MAX_NAME || strlen(file) >= MAX_NAME) return invalid();

        if (verify_key(&db, user, key) < 0) return invalid();

        int file_idx = db_find_file(&db, user, file);
        if (file_idx < 0) return invalid();

        char plaintext[MAX_CONTENT];
        plaintext[0] = '\0';

        if (infile) {
            FILE *f = fopen(infile, "r");
            if (!f) return invalid();
            size_t read = fread(plaintext, 1, sizeof(plaintext) - 1, f);
            plaintext[read] = '\0';
            fclose(f);
        } else if (content) {
            strncpy(plaintext, content, sizeof(plaintext) - 1);
            plaintext[sizeof(plaintext) - 1] = '\0';
        }

        int idx = db_find_user(&db, user);
        unsigned char key_hash[32];
        hash_key(key, db.users[idx].salt, key_hash);

        int enc_len;
        unsigned char *encrypted = encrypt_data(plaintext, key_hash, db.files[file_idx].iv, &enc_len);
        if (!encrypted) return invalid();

        if (db.file_data[file_idx]) {
            free(db.file_data[file_idx]);
        }
        db.file_data[file_idx] = encrypted;
        db.files[file_idx].encrypted_len = enc_len;

        if (db_save(&db) < 0) return invalid();
        return 0;
    }

    if (strcmp(action, "read") == 0) {
        if (!key || !file) return invalid();
        if (strlen(user) >= MAX_NAME || strlen(file) >= MAX_NAME) return invalid();

        if (verify_key(&db, user, key) < 0) return invalid();

        int file_idx = db_find_file(&db, user, file);
        if (file_idx < 0) return invalid();

        int idx = db_find_user(&db, user);
        unsigned char key_hash[32];
        hash_key(key, db.users[idx].salt, key_hash);

        char *plaintext = decrypt_data(db.file_data[file_idx],
                                       db.files[file_idx].encrypted_len,
                                       key_hash,
                                       db.files[file_idx].iv);
        if (!plaintext) return invalid();

        if (outfile) {
            FILE *f = fopen(outfile, "w");
            if (!f) {
                free(plaintext);
                return invalid();
            }
            fprintf(f, "%s", plaintext);
            fclose(f);
        } else {
            printf("%s", plaintext);
        }

        free(plaintext);
        return 0;
    }

    return invalid();
}
