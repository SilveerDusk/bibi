# TPT_Enterprise (team 107) — break analysis

Target: `source/.../build/stor.c` (+ `Makefile`, bundled `malloc-2.7.2.c` dlmalloc).
Build: `gcc -O0 -g -m32 -fno-stack-protector ... ; execstack --set-execstack`.

## enc.db decoded
```
STOR3
U user1 <salt16> <verifier64>
U user2 <salt16> <verifier64>
F user1 file1 len=48 <nonce> <tag> <cipher48>
F user2 file2 len=48 <nonce> <tag> <cipher48>
```
Both flags are 48-byte plaintexts (GCM is a stream cipher: ct len == pt len).

## Crypto assessment (why confidentiality + crypto-integrity are NOT feasible)
- Per-file AES-256-GCM. Key = PBKDF2-HMAC-SHA256(user key, random 16B salt, 100k rounds, 32B).
- Random 12B nonce per write. Tag stored. AAD = `owner|name`.
- Verifier = SHA256("verify|"+user+"|"+derived_key) stored hex; checked on read/write.
- No key/contents leak anywhere. No ECB, no fixed nonce, no plaintext storage.
- => CONFIDENTIALITY: cannot reconstruct user2/file2 plaintext without the key. NOT claimed.
- => Bit-flip integrity on ciphertext: GCM tag verification (decrypt_file line 370-371) rejects
  any modified ciphertext/nonce/tag. NOT feasible via crypto tampering.

## Memory safety assessment (why crash/security via overflow are NOT feasible)
- All fixed stack buffers are written by `hex_encode` of fixed-length inputs
  (salt_hex[33], nonce_hex[25], tag_hex[33]) — bounded.
- `memcpy(u->verifier, verifier, 65)` (stor.c:555) into `verifier[65]`, guarded by
  `strlen(verifier)==64` (stor.c:543) — exact fit, safe.
- All content/db lengths capped (MAX_CONTENT_LEN 16MB, MAX_DB_LEN 64MB); `(int)len` casts safe at 16MB on -m32.
- All `printf` use literal format strings — no format-string bug.
- `win()` (stor.c:61) is never called and there is no control-flow-hijack primitive.
  => SECURITY / control-flow: NOT feasible by static analysis.

---

## Findings ranked (severity × confidence)

### 1. INTEGRITY — unauthenticated user re-registration / account takeover  [HIGH value, HIGH confidence on mechanism]
- Category: integrity (100).
- Root cause: `add_or_update_user` (stor.c:249-269) updates an EXISTING user's salt+verifier
  with no verification of the current key. `register` action (stor.c:741-747) calls it with only
  `-u`/`-k` and never checks that the caller already owns the account.
- Trigger: re-`register user1` with an attacker-chosen key, then `write user1/file1` with that key.
  This passes `verify_user_key` (now bound to the attacker key) and re-encrypts the stored
  file1 ciphertext — modifying user1's data without ever knowing user1's real key.
- Effect on grader: grader re-reads file1 with the ORIGINAL key. After re-registration the
  original key's verifier no longer matches, so the original-key read now returns `invalid`
  instead of the original INTEGRITY_FLAG, AND the on-disk ciphertext for user1/file1 has been
  replaced. Either way user1/file1 has been modified without the key.
- Confidence: HIGH that the data is modified without auth. MEDIUM that this satisfies the exact
  grader predicate "original-key re-read differs" — it differs (flag -> invalid), but if the grader
  demands a *successful* read yielding different bytes, GCM prevents that (see crypto assessment),
  so this is the strongest integrity lever available. Draft: `integrity-reregister/`.

### 2. CORRECTNESS — write does not read stdin  [MEDIUM value, MEDIUM-HIGH confidence]
- Category: correctness (25).
- Root cause: spec says write input may come "via -i file / inline / stdin", but
  `get_input_content` (stor.c:683-696) only handles `-i` (infile) or the inline `content` arg.
  There is NO code path reading from stdin anywhere in the program.
- Trigger: `write` with neither `-i` nor an inline text argument, content supplied on stdin.
  `content` is NULL, so it writes an EMPTY file. A correct oracle writes the stdin bytes.
- Detected via a subsequent `read`: correct oracle returns the stdin text; this impl returns "".
- Confidence: HIGH that stdin is ignored. MEDIUM that the oracle reads stdin (depends on the
  reference impl honoring the spec's stdin clause). Draft: `correctness-stdin-ignored/`.

### 3. CORRECTNESS — `create` accepts a stray `-k`  [LOW value, LOW confidence]
- Category: correctness (25).
- Root cause: `create` (stor.c:749-755) rejects `infile/outfile/content` but NOT `-k`.
  Spec describes create as "no key". A reference oracle MIGHT reject `-k` on create.
- Trigger: `stor -u x -k anything -f f create`. This impl accepts (rc 0); a strict oracle may
  return `invalid`/255.
- Confidence: LOW — spec doesn't explicitly mandate rejecting extra `-k`; ambiguous vs oracle.
  Draft provided but flagged uncertain: `correctness-create-accepts-key/`.

### Other things checked, ruled out
- Username/filename newline/space injection into db: names are hex-encoded on save
  (`hex_encode_string`), so no line/delimiter injection. NOT feasible.
- Trusted on-disk length: `parse_file` (stor.c:559-602) cross-checks `expected_len` against the
  actual decoded cipher length (stor.c:592) and caps at MAX_CONTENT_LEN — no length-confusion crash.
- Re-register to read another user's file: after re-register the GCM key changes (new salt),
  so decrypt of the OLD ciphertext fails the tag — cannot read existing content. (Only modify.)
- Huge write: capped gracefully (inline arg + infile both length-checked) — no crash.
