/*
 * stor.c — BiBiFi secure file store implementation.
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
#define SALT_SIZE 16
#define IV_SIZE 16
#define TAG_SIZE 16
#define PBKDF2_ITERATIONS 10000

typedef struct {
    char username[MAX_NAME];
    unsigned char salt[SALT_SIZE];
    unsigned char key_hash[32];
} User;

typedef struct {
    char username[MAX_NAME];
    char filename[MAX_NAME];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
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
    PKCS5_PBKDF2_HMAC(key, strlen(key), salt, SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), 32, hash);
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
        if (!db->users) { fclose(f); return -1; }
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
        if (!db->files) { fclose(f); return -1; }
        db->file_data = malloc(db->file_count * sizeof(unsigned char *));
        if (!db->file_data) { fclose(f); return -1; }

        for (int i = 0; i < db->file_count; i++) {
            if (fread(&db->files[i], sizeof(FileMeta), 1, f) != 1) {
                fclose(f);
                return -1;
            }

            if (db->files[i].encrypted_len > 0) {
                db->file_data[i] = malloc(db->files[i].encrypted_len);
                if (!db->file_data[i]) { fclose(f); return -1; }
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

static unsigned char *encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *iv, unsigned char *tag, const char *username, const char *filename, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    unsigned char *ciphertext = malloc(plaintext_len > 0 ? plaintext_len : 1);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len = 0, ciphertext_len = 0;

    if (!RAND_bytes(iv, IV_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    
    EVP_EncryptUpdate(ctx, NULL, &len, (unsigned char *)username, strlen(username));
    EVP_EncryptUpdate(ctx, NULL, &len, (unsigned char *)filename, strlen(filename));

    if (plaintext_len > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
        ciphertext_len = len;
    }
    
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);

    EVP_CIPHER_CTX_free(ctx);
    *out_len = ciphertext_len;
    return ciphertext;
}

static unsigned char *decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, const unsigned char *tag, const char *username, const char *filename, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    
    unsigned char *plaintext = malloc(ciphertext_len > 0 ? ciphertext_len : 1);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }
    
    EVP_DecryptUpdate(ctx, NULL, &len, (unsigned char *)username, strlen(username));
    EVP_DecryptUpdate(ctx, NULL, &len, (unsigned char *)filename, strlen(filename));

    if (ciphertext_len > 0) {
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
        plaintext_len = len;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag);

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        free(plaintext);
        return NULL;
    }

    plaintext_len += len;
    *out_len = plaintext_len;
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
            return invalid();
        } else {
            User *new_users = realloc(db.users, (db.user_count + 1) * sizeof(User));
            if (!new_users) return invalid();
            db.users = new_users;
            
            memset(&db.users[db.user_count], 0, sizeof(User));
            strcpy(db.users[db.user_count].username, user);
            if (!RAND_bytes(db.users[db.user_count].salt, SALT_SIZE)) return invalid();
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
            return 0;
        }

        FileMeta *new_files = realloc(db.files, (db.file_count + 1) * sizeof(FileMeta));
        if (!new_files) return invalid();
        db.files = new_files;
        
        unsigned char **new_file_data = realloc(db.file_data, (db.file_count + 1) * sizeof(unsigned char *));
        if (!new_file_data) return invalid();
        db.file_data = new_file_data;

        memset(&db.files[db.file_count], 0, sizeof(FileMeta));
        strcpy(db.files[db.file_count].username, user);
        strcpy(db.files[db.file_count].filename, file);
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

        unsigned char *plaintext = NULL;
        long plaintext_len = 0;

        if (infile) {
            FILE *f = fopen(infile, "rb");
            if (!f) return invalid();
            
            fseek(f, 0, SEEK_END);
            plaintext_len = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            if (plaintext_len < 0) {
                fclose(f);
                return invalid();
            }

            if (plaintext_len > 0) {
                plaintext = malloc(plaintext_len);
                if (!plaintext) {
                    fclose(f);
                    return invalid();
                }
                if (fread(plaintext, 1, plaintext_len, f) != (size_t)plaintext_len) {
                    free(plaintext);
                    fclose(f);
                    return invalid();
                }
            }
            fclose(f);
        } else if (content) {
            plaintext_len = strlen(content);
            if (plaintext_len > 0) {
                plaintext = malloc(plaintext_len);
                if (!plaintext) return invalid();
                memcpy(plaintext, content, plaintext_len);
            }
        }

        int idx = db_find_user(&db, user);
        unsigned char key_hash[32];
        hash_key(key, db.users[idx].salt, key_hash);

        int enc_len = 0;
        unsigned char *encrypted = encrypt_data(plaintext, plaintext_len, key_hash, db.files[file_idx].iv, db.files[file_idx].tag, user, file, &enc_len);
        
        if (plaintext) free(plaintext);

        if (!encrypted && plaintext_len >= 0) return invalid();

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

        int plaintext_len = 0;
        unsigned char *plaintext = NULL;
        
        if (db.files[file_idx].encrypted_len >= 0 && db.file_data[file_idx]) {
            plaintext = decrypt_data(db.file_data[file_idx],
                                     db.files[file_idx].encrypted_len,
                                     key_hash,
                                     db.files[file_idx].iv,
                                     db.files[file_idx].tag,
                                     user,
                                     file,
                                     &plaintext_len);
                                     
            if (!plaintext) return invalid();
        } else if (db.files[file_idx].encrypted_len == 0 && !db.file_data[file_idx]) {
            // It's possible to read an empty file that was created but never written to.
            // In that case, we can just return empty.
            plaintext_len = 0;
        } else {
            return invalid();
        }

        if (outfile) {
            FILE *f = fopen(outfile, "wb");
            if (!f) {
                if (plaintext) free(plaintext);
                return invalid();
            }
            if (plaintext_len > 0) {
                if (fwrite(plaintext, 1, plaintext_len, f) != (size_t)plaintext_len) {
                    if (plaintext) free(plaintext);
                    fclose(f);
                    return invalid();
                }
            }
            fclose(f);
        } else {
            if (plaintext_len > 0) {
                fwrite(plaintext, 1, plaintext_len, stdout);
            }
        }

        if (plaintext) free(plaintext);
        return 0;
    }

    return invalid();
}
