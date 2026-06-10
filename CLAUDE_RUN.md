# Claude Run: BiBiFi Stor Implementation

## Current Status
Implementing and testing the `stor` encrypted file store for BiBiFi CTF challenge.
Branch: `first-stab-stor`

**Latest**: Encountered Docker build issues with i386 package repos. Created alternative test setup with 64-bit compilation for logic verification. Awaiting permission to run Docker tests.

## What We're Working On
- ✅ Implemented full `stor.c` with:
  - User registration with SHA256 key hashing + salt
  - File creation, encrypted write/read operations
  - Binary database format (`enc.db`) for persistence
  - Multi-user isolation
  - AES-256-CBC encryption with IV per file
  - Support for `-i` input files and `-o` output files
  
- ✅ Updated README.md with:
  - Comprehensive project overview
  - Build instructions (Docker + native)
  - All 10 test case descriptions
  - Security requirements
  - CI/CD submission workflow
  - Manual testing examples

- 🔧 **Current Issue**: Docker build failing on Ubuntu 18.04 repo issues
  - `gcc-multilib` package no longer available in old Ubuntu 18.04 repos
  - This is a known issue with EOL Ubuntu releases

## Key Issues Encountered
1. **i386 Package Repos Deprecated**: Ubuntu 20.04+ and Debian no longer maintain i386 in standard repos
2. **Docker Architecture Mismatch**: Some images fail to execute /bin/bash
3. **execstack Not Available**: Debian Bullseye doesn't have this package

## Files Modified
- `starter-package/build/stor.c` — Full implementation (336 lines)
- `starter-package/README.md` — Enhanced with full project context
- `starter-package/Dockerfile.sandbox` — Original Ubuntu 18.04 (working on repo issues)
- `starter-package/build/test.sh` — Test script created
- `starter-package/build/Makefile.test` — 64-bit test Makefile

## Next Steps
- [ ] Get Docker image building successfully
- [ ] Run test suite from `tests.json` (10 tests)
- [ ] Debug any failing tests
- [ ] Verify multi-user isolation, wrong key rejection, persistence
- [ ] Final validation before merging to main

## Test Cases to Verify
1. register_and_create — User registration + file creation
2. write_and_read — Write content and read it back
3. last_occurrence_wins — Duplicate flag handling
4. wrong_key_rejected — Wrong key → "invalid" + exit 255
5. create_no_key_required — Create works without -k flag
6. missing_username_invalid — No -u → error
7. missing_action_invalid — No action → error
8. multi_user_isolation — Users can't read each other's files
9. write_from_file — Write using `-i` inputfile
10. write_out_file — Read using `-o` outputfile

## Technical Details
- **Language**: C (32-bit target, but testing 64-bit first)
- **Encryption**: OpenSSL/libcrypto (AES-256-CBC)
- **Allocation**: dlmalloc (malloc-2.7.2.c) — immutable
- **Flags**: `-O0 -g -fno-stack-protector` (originally `-m32`)
- **Database**: Binary format with users, files, encrypted data
