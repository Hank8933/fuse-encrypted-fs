# AES-256 Encrypted In-Memory File System (FUSE)

A user-space file system implementation using FUSE (Filesystem in Userspace) that provides transparent AES-256 encryption for all files.

## Features

- **POSIX-Compliant File Operations**: Create, read, write, delete files and directories
- **Transparent Encryption**: AES-256-CFB encryption/decryption on I/O operations
- **Per-File Key Management**: Each file has a unique encryption key generated using CSPRNG
- **In-Memory Storage**: Fast file operations with data stored in memory

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Applications                       │
│                  (cat, echo, ls, vim, etc.)                 │
└─────────────────────────┬───────────────────────────────────┘
                          │ POSIX Syscalls
┌─────────────────────────▼───────────────────────────────────┐
│                      VFS (Kernel)                           │
└─────────────────────────┬───────────────────────────────────┘
                          │ FUSE Protocol
┌─────────────────────────▼───────────────────────────────────┐
│                    aesfs (User Space)                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ FUSE Ops    │  │ AES-256-CFB  │  │ Key Management     │  │
│  │ (VFS Layer) │◄─┤ Crypto Engine│◄─┤ (RAND_bytes)       │  │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
│         │                                     │             │
│         ▼                                     ▼             │
│  ┌──────────────────────┐            ┌───────────────────┐  │
│  │ In-Memory FS Storage │            │ keys/*.key files  │  │
│  │ (Dynamic Arrays)     │            │ (32-byte AES key) │  │
│  └──────────────────────┘            └───────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Linux with FUSE support
- GCC compiler
- OpenSSL development libraries
- FUSE development libraries

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt-get install build-essential libfuse-dev libssl-dev pkg-config
```

## Build

```bash
# Release build
make

# Debug build (enables verbose logging)
make debug

# Clean
make clean
```

## Usage

```bash
# Create a mount point
mkdir -p /tmp/encrypted_mount

# Mount the file system (foreground mode for debugging)
./aesfs -f /tmp/encrypted_mount

# In another terminal, use the file system
echo "Hello, World!" > /tmp/encrypted_mount/secret.txt
cat /tmp/encrypted_mount/secret.txt

# Unmount
fusermount -u /tmp/encrypted_mount
```

### Command Line Options

- `-f`: Run in foreground (useful for debugging)
- `-d`: Enable FUSE debug output
- `-s`: Single-threaded operation

## Implementation Details

### Encryption

- **Algorithm**: AES-256-CFB (Cipher Feedback Mode)
- **Key Size**: 256-bit (32 bytes)
- **IV Size**: 128-bit (16 bytes), randomly generated per write operation
- **Library**: OpenSSL EVP API

### Key Management

- Each file gets a unique key generated using `RAND_bytes()` (CSPRNG)
- Keys are stored in the `keys/` directory as `<filename>.key`
- Key files are 32 bytes of raw binary data

### FUSE Operations Implemented

| Operation | Description |
|-----------|-------------|
| `getattr` | Get file/directory attributes |
| `readdir` | List directory contents |
| `read`    | Read file content (with decryption) |
| `write`   | Write file content (with encryption) |
| `create`  | Create new file |
| `mkdir`   | Create new directory |
| `unlink`  | Delete file |
| `rmdir`   | Delete directory |
| `open`    | Open file |
| `release` | Close file |
| `truncate`| Truncate file |
| `utimens` | Update timestamps |

## Security Notes

> ⚠️ **Educational Project**: This is a demonstration project for learning FUSE and cryptography concepts.

- Keys are stored unencrypted in the `keys/` directory
- In-memory storage means data is lost on unmount
- For production use, consider proper key management (e.g., key derivation, secure storage)

## License

MIT License - See [LICENSE](LICENSE) file for details.
