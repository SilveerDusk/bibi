# SMK-112 (`stor`) — Break Notes

Target team: 112. Source: `build/stor.c` (457 lines), `malloc-2.7.2.c` (dlmalloc), Makefile
(`gcc -O0 -g -m32 -fno-stack-protector`, `execstack --set-execstack`). Static analysis only
(32-bit Linux ELF, macOS host). enc.db verified to match struct layout exactly.

## Crypto / on-disk format (verified against enc.db)
- AES-256-GCM, key = PBKDF2-HMAC-SHA1(password, salt, 2000 iters, 32 bytes). Per-write random IV.
  Auth verification = SHA256(enc_key) stored as `key_hash_tag`, checked via `CRYPTO_memcmp`
  (stor.c:258). The crypto is genuinely authenticated and keyed by the secret password.
- Struct sizes (i386 SysV ABI, confirmed against file): `file_record_t`=4264, `user_record_t`=136628,
  `db_state_t`=4372096 = exact file size (32 users). Offsets confirmed: user2 base 0x215b4,
  file1 ciphertext 0x154, file2 ciphertext 0x21708. Both files: ciphertext_len = 48 (GCM/CTR =>
  plaintext is also 48 bytes).
- CONFIDENTIALITY (file2): NOT recoverable. Decryption requires the PBKDF2-derived key; the
  password is not on disk and not derivable. No ECB, no plaintext, no key-from-username. No
  confidentiality claim is made (honest: nothing allows plaintext reconstruction without the key).

---

## Findings ranked by severity x confidence

### 1. [INTEGRITY, 100] Re-register account takeover — HIGH confidence  ✅ draft built
- Root cause: stor.c:181-214. REGISTER does not reject an existing username. When the user
  already exists, `user_idx` is not reset, and the handler falls through to `memset(u_rec,0)` +
  installs attacker salt/key_hash and `fwrite`s the db. No key check vs the existing account.
- Trigger: `stor -u user1 -k attacker_pw register`.
- Effect: wipes user1's entire record (including file1) and rebinds the account to the attacker's
  key. Grader's real-key re-read of user1/file1 fails CRYPTO_memcmp (stor.c:258) and returns
  `invalid` instead of the original content => differs => integrity broken.
- Draft: `integrity-reregister-takeover/`.
- Confidence: HIGH. Unambiguous missing guard; persistence is unconditional.

### 2. [CORRECTNESS, 25] `write` ignores stdin — HIGH confidence  ✅ draft built
- Root cause: stor.c:279-295. Payload comes only from `-i` file or inline `argv[optind+1]`. No
  stdin read exists anywhere in the program. Missing input => stores 0 bytes (line 291-295).
- Spec + sample test.json both deliver write content over stdin, implying the oracle reads stdin.
- Trigger: write with content only on stdin, then read back. Oracle returns the text; this impl
  returns empty.
- Draft: `correctness-stdin-ignored/`.
- Confidence: HIGH that the binary ignores stdin. Medium that the grader exercises the `expected`
  path exactly as encoded (trailing-newline-on-read uncertainty noted in description).

### 3. [CORRECTNESS, 25] `read` / `invalid` output have no trailing newline — NEEDS oracle
- stor.c:445 `fwrite(plaintext,...)` and stor.c:72 `printf("invalid")` emit no newline. If the
  reference oracle terminates output with `\n`, every read/error diverges. Cannot confirm without
  the oracle's exact formatting. Not drafted (would conflict with finding #2's expected values if
  wrong-signed). Treat as backup/needs-testing.
- Confidence: LOW-MEDIUM (depends entirely on oracle formatting convention).

### 4. [SECURITY/win(), 100] control-flow hijack to `win()` — UNLIKELY / NEEDS-testing
- `win()` (stor.c:66) is never called. Reaching it needs memory corruption overwriting a return
  address / GOT. Reviewed all copies: `strncpy(...,MAX-1)` (bounded), `memcpy` lengths bounded
  (salt/iv/tag fixed; ciphertext bounded by `plaintext_len > MAX_PAYLOAD_LEN` reject at
  stor.c:297). No `strcpy/strcat/sprintf/gets/scanf`, no format-string (`printf` uses literals).
  `db` is heap-allocated (calloc), not stack. username/filename length-checked (>=128 rejected,
  stor.c:145,158). No off-by-one found. No viable corruption primitive identified.
- Confidence: LOW that this is exploitable. Not drafted.

### 5. [CRASH, 50] heap overflow via trusted on-disk `ciphertext_len` — NOT reachable by attacker
- READ path `malloc(f_rec->ciphertext_len)` (stor.c:380) and DecryptUpdate write trust the
  on-disk length. If an attacker could set ciphertext_len > MAX_PAYLOAD_LEN with matching
  ciphertext, the decrypt buffer (malloc'd to len) is fine, but the on-disk ciphertext buffer is
  only 4096; reading a record whose stored ciphertext_len exceeds 4096 would read past the inline
  array within the mapped db copy (still within the giant db allocation, so no segfault) — and to
  even reach READ you must pass the per-user key check (stor.c:258). The grader only lets the
  attacker run CLI commands against a FRESH db (no raw db editing), and the write path caps len at
  4096 (stor.c:297). So there is no attacker-controlled path to oversize ciphertext_len.
- Confidence: NOT exploitable under the stated threat model.

### 6. [misc] write `>` vs `>=` bound at MAX_PAYLOAD_LEN — safe
- stor.c:297 allows `plaintext_len == 4096`; GCM/CTR ciphertext == 4096 fits `ciphertext[4096]`
  exactly; Final writes 0 extra; tag stored separately. No overflow.

### 7. [misc] register can fill all 32 slots / DoS — low value
- Attacker can register up to 32 users; after that register returns invalid (stor.c:190). Pre-built
  state already has 2 users, leaving 30 slots. Not a scored category on its own.

---

## Top recommendations
1. Submit `integrity-reregister-takeover/` (highest value, highest confidence — 100 pts).
2. Submit `correctness-stdin-ignored/` (25 pts, high confidence on the bug; verify oracle newline).
3. Do NOT claim confidentiality — crypto is sound and key is unrecoverable.
4. win()/security and crash categories: no viable primitive found under the threat model.
