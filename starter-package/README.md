# BiBiFi — Secure File Store (`stor`)

## Project Overview

**BiBiFi** is a competitive security coding challenge. This task focuses on implementing **`stor`** — a secure, encrypted command-line file store in C.

### Key Facts

- **Language**: C (32-bit x86, strict compilation flags)
- **Target Platform**: Ubuntu 18.04 (Docker recommended)
- **Persistence**: `enc.db` file in current directory
- **Encryption**: OpenSSL/libcrypto required
- **Memory Allocator**: dlmalloc custom allocator (provided, immutable)
- **Build**: `make` in `build/` directory

## What's in this Package

```
build/
  stor.c             ← Implementation (replace the stub)
  Makefile           ← Build rules (gcc -m32, dlmalloc, execstack)
  malloc-2.7.2.c     ← Custom allocator (DO NOT MODIFY)
Dockerfile.sandbox   ← Ubuntu 18.04 build environment
tests.json           ← 10 functionality tests
```

## The Challenge

Implement a CLI encrypted file store with these commands:

| Command    | Flags                          | Behavior                                  |
| ---------- | ------------------------------ | ----------------------------------------- |
| `register` | `-u <user> -k <key>`           | Register user with authentication key     |
| `create`   | `-u <user> -f <file>`          | Create empty file (no key needed)         |
| `write`    | `-u <user> -k <key> -f <file>` | Write content (arg or `-i` file input)    |
| `read`     | `-u <user> -k <key> -f <file>` | Read content (stdout or `-o` file output) |

### Error Handling

- **On any error**: Print exactly `invalid` and exit 255
- **On success**: Exit 0

## Key Requirements

1. **User registration** with key-based authentication
2. **File creation** without needing the key
3. **Encrypted write/read** operations (content encrypted with user's key)
4. **Last flag wins**: When `-k` is specified twice, use the last value
5. **Persist all state** to `enc.db`
6. **Handle wrong key** rejection gracefully
7. **Multi-user isolation** — users can only access their own files with correct key

## Build Instructions

### Option A: Docker (Recommended)

```bash
# Build the sandbox image (one-time)
docker build --platform=linux/amd64 -t bibifi-sandbox -f Dockerfile.sandbox .

# Run interactively — your build/ dir is mounted at /connect
docker run --rm -it --platform=linux/amd64 -v $(pwd)/build:/connect bibifi-sandbox

# Inside the container:
make
./stor -u alice -k secret123 register
```

### Option B: Native Build (requires 32-bit toolchain)

```bash
cd build/
make
```

## Build Constraints

- **Compiler Flags**: `-O0 -g -m32 -fno-stack-protector`
- **Allocator**: Must link `malloc-2.7.2.c` (dlmalloc)
- **Stack**: Must be executable (`execstack --set-execstack stor`)
- **Libraries**: `-lssl -lcrypto` (OpenSSL), optionally `-lsodium` (libsodium)
- **Target**: 32-bit x86 on Ubuntu 18.04

## Test Cases

The grader runs 10 tests from `tests.json`:

1. **register_and_create** — Register user, create file
2. **write_and_read** — Write content and read it back
3. **last_occurrence_wins** — Duplicate flags use last value
4. **wrong_key_rejected** — Wrong key fails with "invalid" exit 255
5. **create_no_key_required** — Create works without -k flag
6. **missing_username_invalid** — No -u → error
7. **missing_action_invalid** — No action → error
8. **multi_user_isolation** — Users can't read each other's files
9. **write_from_file** — Write using `-i` inputfile
10. **write_out_file** — Read using `-o` outputfile

### Manual Testing Example

```bash
rm -f enc.db
./stor -u alice -k secret123 register           # expect exit 0
./stor -u alice -f notes create                 # expect exit 0
./stor -u alice -k secret123 -f notes write "hello world"  # expect exit 0
./stor -u alice -k secret123 -f notes read      # expect stdout: "hello world", exit 0
./stor -u alice -k WRONGKEY -f notes read       # expect stdout: "invalid", exit 255
```

## Security Requirements

- **Privacy**: An adversary without the auth token must not learn file contents
- **Integrity**: Detect any unauthorized modifications to `enc.db`
- **Non-Negotiable**: The `win()` function must remain in the binary (do NOT remove it)

## Submission

### For CI/CD Pipeline

Push your implementation to your team's GitHub repo:

1. Commit changes to `build/stor.c` on your feature branch
2. Push to GitHub
3. Create a pull request to `main`
4. The CI pipeline will automatically:
   - Build the Docker image
   - Compile with `make`
   - Run all 10 tests from `tests.json`
   - Report pass/fail for each test

### What Gets Evaluated

✅ **Passing Tests**: All 10 test cases must pass  
✅ **Compilation**: No warnings or errors  
✅ **Error Handling**: Proper "invalid" + exit 255  
✅ **Encryption**: Secure encryption/decryption of file content  
✅ **Persistence**: State correctly persists to `enc.db`  
✅ **Security**: Multi-user isolation and key verification

## Important Notes

- **Do NOT modify** `malloc-2.7.2.c` — it's immutable
- **Focus on** `stor.c` implementation
- **Use** OpenSSL APIs for encryption (AES-256 recommended)
- **Consider** data structures for user/file management
- **Encryption**: Key should derive from user's password
- **File data**: Must be encrypted when stored in `enc.db`

## Getting Help

- Review `tests.json` for exact test behavior and expected outputs
- Check `ONESHOT_PROMPT.md` for quick reference
- Test manually using the example commands above
- Use `rm -f enc.db` between test runs to reset state
