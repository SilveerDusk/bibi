# BiBiFi Oneshot Prompt

## Project Overview

**BiBiFi** is a competitive security coding challenge. You are implementing **`stor`** — a secure, encrypted command-line file store in C.

## Quick Facts

- **Language**: C (32-bit, strict compilation flags)
- **Target**: Ubuntu 18.04 (Docker recommended)
- **Persistence**: `enc.db` file in current directory
- **Encryption**: OpenSSL/libcrypto required
- **Memory**: dlmalloc custom allocator (provided, immutable)
- **Build**: `make` in `build/` directory
- **Tests**: 10 test cases defined in `tests.json`

## Your Task

Implement a CLI encrypted file store with these commands:

| Command    | Flags                          | Behavior                                  |
| ---------- | ------------------------------ | ----------------------------------------- |
| `register` | `-u <user> -k <key>`           | Register user with authentication key     |
| `create`   | `-u <user> -f <file>`          | Create empty file (no key needed)         |
| `write`    | `-u <user> -k <key> -f <file>` | Write content (arg or `-i` file input)    |
| `read`     | `-u <user> -k <key> -f <file>` | Read content (stdout or `-o` file output) |

## Error Handling

- **On any error**: Print exactly `invalid` and exit 255
- **On success**: Exit 0

## Key Requirements

1. User registration with key-based authentication
2. File creation without needing the key
3. Encrypted write/read operations (content encrypted with user's key)
4. Last flag wins: when `-k` is specified twice, use the last value
5. Persist all state to `enc.db`
6. Handle wrong key rejection gracefully

## Compilation Details

**Compiler Flags**:

```bash
gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c -lssl -lcrypto
execstack --set-execstack stor
```

- `-m32`: 32-bit compilation
- `-fno-stack-protector`: Disable stack protections
- `malloc-2.7.2.c`: Required allocator (immutable)
- `-lssl -lcrypto`: OpenSSL libraries

## Build Instructions

### Option A: Docker (recommended)

```bash
docker build --platform=linux/amd64 -t bibifi-sandbox -f Dockerfile.sandbox .
docker run --rm -it --platform=linux/amd64 -v $(pwd)/build:/connect bibifi-sandbox
make
```

### Option B: Native

```bash
cd build/
make
```

## Test Cases

The grader runs 10 tests from `tests.json`:

1. **register_and_create** - Register user, create file
2. **write_and_read** - Write content and read it back
3. **last_occurrence_wins** - Duplicate flags use last value
4. **wrong_key_rejected** - Wrong key fails with "invalid" exit 255
5. **file_not_found** - Reading non-existent file fails
6. **multiple_users** - Multiple users with separate data
7. **read_without_key** - Reading without providing key fails
8. **create_duplicate_file** - Creating existing file fails
9. **file_content_type** - Content can be arbitrary strings
10. **persistence** - Data persists across program invocations

## Project Structure

```
.
├── README.md
├── instructions/
│   ├── 01-onboarding.pdf
│   ├── 02-problem-statement.pdf
│   ├── 03-build-it-flow.pdf
│   ├── 04-scoring.pdf
│   └── 05-navigation-guide.pdf
└── starter-package/
    ├── Dockerfile.sandbox
    ├── README.md
    ├── tests.json
    └── build/
        ├── Makefile
        ├── stor.c (← IMPLEMENT THIS)
        └── malloc-2.7.2.c (provided, immutable)
```

## Current State

- `stor.c` is a stub that compiles but fails all tests
- No implementation yet
- All test files are in `tests.json` for reference

## Success Criteria

- Pass all 10 test cases in `tests.json`
- Build without warnings/errors
- Proper error handling with "invalid" + exit 255
- Secure encryption/decryption of file content
- Persistent state in `enc.db`

## Notes

- Do NOT modify `malloc-2.7.2.c`
- Focus on `stor.c` implementation
- Use OpenSSL APIs for encryption
- Consider data structures for user/file management
- Encryption key should derive from the user's password
- File data must be encrypted when stored
