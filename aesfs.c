/**
 * AES-256 Encrypted In-Memory File System using FUSE
 * 
 * This file system implements:
 * - POSIX-compliant file operations in user space
 * - AES-256-CFB transparent encryption/decryption
 * - Per-file key management with CSPRNG-generated keys
 * 
 * Author: Hank8933
 * License: MIT
 */

#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>

/* Compile with -DDEBUG to enable debug output */
#ifdef DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, "[DEBUG] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while(0)
#endif

/* Configuration */
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define INITIAL_CAPACITY 16
#define INITIAL_CONTENT_SIZE 4096

/* Key storage directory (relative to working directory) */
static const char *key_dir = "keys";

/* ============================================================================
 * Data Structures - Dynamic Arrays
 * ============================================================================ */

typedef struct {
    char *name;              /* File/directory name */
    unsigned char *content;  /* Encrypted content (NULL for directories) */
    size_t content_size;     /* Size of encrypted content */
    size_t content_capacity; /* Allocated capacity for content */
    int is_directory;        /* 1 if directory, 0 if file */
} FSEntry;

typedef struct {
    FSEntry *entries;
    size_t count;
    size_t capacity;
} FileSystem;

static FileSystem fs = {NULL, 0, 0};

/* ============================================================================
 * File System Entry Management
 * ============================================================================ */

static int fs_init(void) {
    fs.entries = malloc(INITIAL_CAPACITY * sizeof(FSEntry));
    if (!fs.entries) {
        return -ENOMEM;
    }
    fs.capacity = INITIAL_CAPACITY;
    fs.count = 0;
    return 0;
}

static void fs_cleanup(void) {
    for (size_t i = 0; i < fs.count; i++) {
        free(fs.entries[i].name);
        free(fs.entries[i].content);
    }
    free(fs.entries);
    fs.entries = NULL;
    fs.count = 0;
    fs.capacity = 0;
}

static int fs_grow_if_needed(void) {
    if (fs.count >= fs.capacity) {
        size_t new_capacity = fs.capacity * 2;
        FSEntry *new_entries = realloc(fs.entries, new_capacity * sizeof(FSEntry));
        if (!new_entries) {
            return -ENOMEM;
        }
        fs.entries = new_entries;
        fs.capacity = new_capacity;
    }
    return 0;
}

static int find_entry(const char *path) {
    if (path[0] == '/') path++;
    for (size_t i = 0; i < fs.count; i++) {
        if (strcmp(path, fs.entries[i].name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int is_directory(const char *path) {
    int idx = find_entry(path);
    return (idx >= 0 && fs.entries[idx].is_directory);
}

static int is_file(const char *path) {
    int idx = find_entry(path);
    return (idx >= 0 && !fs.entries[idx].is_directory);
}

/* ============================================================================
 * Key Management
 * ============================================================================ */

static int get_key_path(const char *filename, char *key_path, size_t key_path_size) {
    if (filename[0] == '/') filename++;
    int ret = snprintf(key_path, key_path_size, "%s/%s.key", key_dir, filename);
    if (ret < 0 || (size_t)ret >= key_path_size) {
        return -1;
    }
    return 0;
}

static int read_key(const char *filename, unsigned char *key) {
    char key_path[PATH_MAX];
    if (get_key_path(filename, key_path, sizeof(key_path)) < 0) {
        return -1;
    }
    
    FILE *key_file = fopen(key_path, "rb");
    if (!key_file) {
        return -1;
    }
    
    size_t bytes_read = fread(key, 1, AES_KEY_SIZE, key_file);
    fclose(key_file);
    
    return (bytes_read == AES_KEY_SIZE) ? 0 : -1;
}

static int write_key(const char *filename, const unsigned char *key) {
    char key_path[PATH_MAX];
    if (get_key_path(filename, key_path, sizeof(key_path)) < 0) {
        return -1;
    }
    
    /* Ensure parent directories exist */
    char *path_copy = strdup(key_path);
    if (!path_copy) {
        return -1;
    }
    
    /* Find and create each directory component */
    char *p = path_copy;
    while ((p = strchr(p + 1, '/')) != NULL) {
        *p = '\0';
        struct stat st;
        if (stat(path_copy, &st) == -1) {
            if (mkdir(path_copy, 0700) == -1) {
                free(path_copy);
                return -1;
            }
        }
        *p = '/';
    }
    free(path_copy);
    
    FILE *key_file = fopen(key_path, "wb");
    if (!key_file) {
        return -1;
    }
    
    size_t bytes_written = fwrite(key, 1, AES_KEY_SIZE, key_file);
    fclose(key_file);
    
    return (bytes_written == AES_KEY_SIZE) ? 0 : -1;
}

static int delete_key(const char *filename) {
    char key_path[PATH_MAX];
    if (get_key_path(filename, key_path, sizeof(key_path)) < 0) {
        return -1;
    }
    return remove(key_path);
}

static int generate_and_store_key(const char *filename) {
    unsigned char key[AES_KEY_SIZE];
    
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        fprintf(stderr, "Error: Failed to generate random key\n");
        return -1;
    }
    
    if (write_key(filename, key) < 0) {
        fprintf(stderr, "Error: Failed to write key for %s\n", filename);
        return -1;
    }
    
    DEBUG_PRINT("Generated key for: %s\n", filename);
    return 0;
}

/* ============================================================================
 * AES-256-CFB Encryption/Decryption
 * ============================================================================ */

/**
 * Encrypt data using AES-256-CFB
 * Output format: [IV (16 bytes)][Ciphertext]
 * Returns: total output size on success, -1 on error
 */
static int aes_encrypt(const unsigned char *key, const unsigned char *in, 
                       size_t in_size, unsigned char *out, size_t out_capacity) {
    if (out_capacity < in_size + AES_IV_SIZE) {
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    /* Generate random IV */
    unsigned char iv[AES_IV_SIZE];
    if (!RAND_bytes(iv, AES_IV_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(out, iv, AES_IV_SIZE);
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int out_len1, out_len2;
    if (EVP_EncryptUpdate(ctx, out + AES_IV_SIZE, &out_len1, in, (int)in_size) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_EncryptFinal_ex(ctx, out + AES_IV_SIZE + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2 + AES_IV_SIZE;
}

/**
 * Decrypt data using AES-256-CFB
 * Input format: [IV (16 bytes)][Ciphertext]
 * Returns: decrypted size on success, -1 on error
 */
static int aes_decrypt(const unsigned char *key, const unsigned char *in,
                       size_t in_size, unsigned char *out, size_t out_capacity) {
    if (in_size <= AES_IV_SIZE) {
        return 0;  /* No data to decrypt */
    }
    
    if (out_capacity < in_size - AES_IV_SIZE) {
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    /* Extract IV from input */
    unsigned char iv[AES_IV_SIZE];
    memcpy(iv, in, AES_IV_SIZE);
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int out_len1, out_len2;
    if (EVP_DecryptUpdate(ctx, out, &out_len1, in + AES_IV_SIZE, (int)(in_size - AES_IV_SIZE)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2;
}

/* ============================================================================
 * File/Directory Operations
 * ============================================================================ */

static int add_entry(const char *name, int is_dir) {
    if (name[0] == '/') name++;
    
    if (fs_grow_if_needed() < 0) {
        return -ENOMEM;
    }
    
    FSEntry *entry = &fs.entries[fs.count];
    entry->name = strdup(name);
    if (!entry->name) {
        return -ENOMEM;
    }
    
    entry->is_directory = is_dir;
    entry->content = NULL;
    entry->content_size = 0;
    entry->content_capacity = 0;
    
    if (!is_dir) {
        entry->content = malloc(INITIAL_CONTENT_SIZE);
        if (!entry->content) {
            free(entry->name);
            return -ENOMEM;
        }
        entry->content_capacity = INITIAL_CONTENT_SIZE;
        
        if (generate_and_store_key(name) < 0) {
            free(entry->content);
            free(entry->name);
            return -EIO;
        }
    }
    
    fs.count++;
    DEBUG_PRINT("Added %s: %s\n", is_dir ? "directory" : "file", name);
    return 0;
}

static int remove_entry(const char *name) {
    if (name[0] == '/') name++;
    
    int idx = find_entry(name);
    if (idx < 0) {
        return -ENOENT;
    }
    
    FSEntry *entry = &fs.entries[idx];
    
    /* Delete key file if this is a file */
    if (!entry->is_directory) {
        delete_key(name);
    }
    
    free(entry->name);
    free(entry->content);
    
    /* Shift remaining entries */
    for (size_t i = idx; i < fs.count - 1; i++) {
        fs.entries[i] = fs.entries[i + 1];
    }
    fs.count--;
    
    DEBUG_PRINT("Removed: %s\n", name);
    return 0;
}

/* ============================================================================
 * FUSE Operation Implementations
 * ============================================================================ */

static int do_getattr(const char *path, struct stat *st) {
    memset(st, 0, sizeof(struct stat));
    
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);
    
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }
    
    int idx = find_entry(path);
    if (idx < 0) {
        return -ENOENT;
    }
    
    FSEntry *entry = &fs.entries[idx];
    if (entry->is_directory) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    } else {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = entry->content_size;
    }
    
    return 0;
}

static int do_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi) {
    (void)offset;
    (void)fi;
    
    filler(buffer, ".", NULL, 0);
    filler(buffer, "..", NULL, 0);
    
    if (strcmp(path, "/") == 0) {
        /* List root directory */
        for (size_t i = 0; i < fs.count; i++) {
            /* Only show top-level entries (no '/' in name) */
            if (strchr(fs.entries[i].name, '/') == NULL) {
                filler(buffer, fs.entries[i].name, NULL, 0);
            }
        }
    } else {
        /* List subdirectory */
        if (!is_directory(path)) {
            return -ENOENT;
        }
        
        const char *search_path = path;
        if (search_path[0] == '/') search_path++;
        size_t search_len = strlen(search_path);
        
        for (size_t i = 0; i < fs.count; i++) {
            const char *name = fs.entries[i].name;
            if (strncmp(name, search_path, search_len) == 0 &&
                name[search_len] == '/') {
                const char *subname = name + search_len + 1;
                /* Only show direct children */
                if (strchr(subname, '/') == NULL) {
                    filler(buffer, subname, NULL, 0);
                }
            }
        }
    }
    
    return 0;
}

static int do_read(const char *path, char *buffer, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    (void)fi;
    
    int idx = find_entry(path);
    if (idx < 0) {
        return -ENOENT;
    }
    
    FSEntry *entry = &fs.entries[idx];
    if (entry->is_directory) {
        return -EISDIR;
    }
    
    if (entry->content_size == 0) {
        return 0;
    }
    
    /* Read encryption key */
    unsigned char key[AES_KEY_SIZE];
    const char *filename = path;
    if (filename[0] == '/') filename++;
    if (read_key(filename, key) < 0) {
        return -EIO;
    }
    
    /* Decrypt content */
    unsigned char *decrypted = malloc(entry->content_size);
    if (!decrypted) {
        return -ENOMEM;
    }
    
    int decrypted_size = aes_decrypt(key, entry->content, entry->content_size,
                                     decrypted, entry->content_size);
    if (decrypted_size < 0) {
        free(decrypted);
        return -EIO;
    }
    
    /* Copy requested portion to buffer */
    if (offset >= decrypted_size) {
        free(decrypted);
        return 0;
    }
    
    size_t available = decrypted_size - offset;
    size_t to_copy = (size < available) ? size : available;
    memcpy(buffer, decrypted + offset, to_copy);
    
    free(decrypted);
    return (int)to_copy;
}

static int do_write(const char *path, const char *buffer, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    
    int idx = find_entry(path);
    if (idx < 0) {
        return -ENOENT;
    }
    
    FSEntry *entry = &fs.entries[idx];
    if (entry->is_directory) {
        return -EISDIR;
    }
    
    /* Read encryption key */
    unsigned char key[AES_KEY_SIZE];
    const char *filename = path;
    if (filename[0] == '/') filename++;
    if (read_key(filename, key) < 0) {
        return -EIO;
    }
    
    /* Decrypt existing content */
    unsigned char *decrypted = NULL;
    int decrypted_size = 0;
    
    if (entry->content_size > 0) {
        decrypted = malloc(entry->content_size);
        if (!decrypted) {
            return -ENOMEM;
        }
        decrypted_size = aes_decrypt(key, entry->content, entry->content_size,
                                     decrypted, entry->content_size);
        if (decrypted_size < 0) {
            free(decrypted);
            return -EIO;
        }
    }
    
    /* Calculate new size */
    size_t new_size = offset + size;
    if ((size_t)decrypted_size > new_size) {
        new_size = decrypted_size;
    }
    
    /* Allocate buffer for merged content */
    unsigned char *new_content = calloc(new_size, 1);
    if (!new_content) {
        free(decrypted);
        return -ENOMEM;
    }
    
    /* Copy existing content */
    if (decrypted && decrypted_size > 0) {
        memcpy(new_content, decrypted, decrypted_size);
    }
    free(decrypted);
    
    /* Write new data at offset */
    memcpy(new_content + offset, buffer, size);
    
    /* Encrypt and store */
    size_t encrypted_capacity = new_size + AES_IV_SIZE + EVP_MAX_BLOCK_LENGTH;
    if (encrypted_capacity > entry->content_capacity) {
        unsigned char *new_buf = realloc(entry->content, encrypted_capacity);
        if (!new_buf) {
            free(new_content);
            return -ENOMEM;
        }
        entry->content = new_buf;
        entry->content_capacity = encrypted_capacity;
    }
    
    int encrypted_size = aes_encrypt(key, new_content, new_size,
                                     entry->content, entry->content_capacity);
    free(new_content);
    
    if (encrypted_size < 0) {
        return -EIO;
    }
    
    entry->content_size = encrypted_size;
    DEBUG_PRINT("Wrote %zu bytes to %s\n", size, path);
    
    return (int)size;
}

static int do_mkdir(const char *path, mode_t mode) {
    (void)mode;
    
    if (find_entry(path) >= 0) {
        return -EEXIST;
    }
    
    return add_entry(path, 1);
}

static int do_mknod(const char *path, mode_t mode, dev_t rdev) {
    (void)mode;
    (void)rdev;
    
    if (find_entry(path) >= 0) {
        return -EEXIST;
    }
    
    return add_entry(path, 0);
}

static int do_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    (void)fi;
    
    if (find_entry(path) >= 0) {
        return -EEXIST;
    }
    
    return add_entry(path, 0);
}

static int do_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    
    if (!is_file(path)) {
        return -ENOENT;
    }
    return 0;
}

static int do_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    (void)fi;
    return 0;
}

static int do_rmdir(const char *path) {
    if (!is_directory(path)) {
        return -ENOENT;
    }
    return remove_entry(path);
}

static int do_unlink(const char *path) {
    if (!is_file(path)) {
        return -ENOENT;
    }
    return remove_entry(path);
}

static int do_utimens(const char *path, const struct timespec ts[2]) {
    (void)ts;
    
    if (strcmp(path, "/") == 0 || find_entry(path) >= 0) {
        return 0;
    }
    return -ENOENT;
}

static int do_truncate(const char *path, off_t size) {
    int idx = find_entry(path);
    if (idx < 0) {
        return -ENOENT;
    }
    
    FSEntry *entry = &fs.entries[idx];
    if (entry->is_directory) {
        return -EISDIR;
    }
    
    if (size == 0) {
        entry->content_size = 0;
        return 0;
    }
    
    /* Read key and decrypt */
    unsigned char key[AES_KEY_SIZE];
    const char *filename = path;
    if (filename[0] == '/') filename++;
    if (read_key(filename, key) < 0) {
        return -EIO;
    }
    
    /* Decrypt, truncate, re-encrypt */
    if (entry->content_size > 0) {
        unsigned char *decrypted = malloc(entry->content_size);
        if (!decrypted) {
            return -ENOMEM;
        }
        
        int decrypted_size = aes_decrypt(key, entry->content, entry->content_size,
                                         decrypted, entry->content_size);
        if (decrypted_size < 0) {
            free(decrypted);
            return -EIO;
        }
        
        size_t new_size = ((size_t)size < (size_t)decrypted_size) ? size : decrypted_size;
        
        int encrypted_size = aes_encrypt(key, decrypted, new_size,
                                         entry->content, entry->content_capacity);
        free(decrypted);
        
        if (encrypted_size < 0) {
            return -EIO;
        }
        entry->content_size = encrypted_size;
    }
    
    return 0;
}

/* ============================================================================
 * FUSE Operations Structure
 * ============================================================================ */

static struct fuse_operations operations = {
    .getattr  = do_getattr,
    .readdir  = do_readdir,
    .read     = do_read,
    .write    = do_write,
    .mkdir    = do_mkdir,
    .mknod    = do_mknod,
    .create   = do_create,
    .open     = do_open,
    .release  = do_release,
    .rmdir    = do_rmdir,
    .unlink   = do_unlink,
    .utimens  = do_utimens,
    .truncate = do_truncate,
};

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int main(int argc, char *argv[]) {
    /* Ensure keys directory exists */
    struct stat st = {0};
    if (stat(key_dir, &st) == -1) {
        if (mkdir(key_dir, 0700) == -1) {
            fprintf(stderr, "Error: Cannot create keys directory\n");
            return 1;
        }
    }
    
    /* Initialize file system */
    if (fs_init() < 0) {
        fprintf(stderr, "Error: Cannot initialize file system\n");
        return 1;
    }
    
    /* Run FUSE main loop */
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    int ret = fuse_main(args.argc, args.argv, &operations, NULL);
    
    /* Cleanup */
    fuse_opt_free_args(&args);
    fs_cleanup();
    
    return ret;
}
