# Husker_Bots (Team 115) — Break Notes

Target: `source/.../build/stor.c` (651 lines). Built 32-bit, `-fno-stack-protector`,
execstack. DB: AES-256-GCM file content, PBKDF2-SHA256(100k) key derivation per
record, HMAC-SHA256 over whole file with a compiled-in master key.

## Overall crypto/memory assessment (why the "big" categories fail)

- **Confidentiality (file2): NOT feasible.** Content is AES-256-GCM. The file key is
  `PBKDF2(user_key, content_salt, 100k)` (stor.c:570-573, 622-625). The user key is the
  unknown team flag. enc.db ships only ciphertext+tag+nonce+salt. No plaintext, no
  key reuse weakness, no ECB, no username-derived key. Cannot reconstruct plaintext.
- **Integrity (file1): NOT feasible.** Two independent layers: (1) GCM tag authenticates
  the ciphertext under the file key; (2) HMAC-SHA256 over the entire serialized DB using
  `MASTER_HMAC_KEY` is verified on every load (stor.c:348-354). Any byte you flip in
  enc.db fails the HMAC check → `db_load` returns 0 → `invalid`. Even if you bypassed
  HMAC, GCM auth would fail. Bit-flip forgery is blocked. (The master HMAC key IS
  compiled into the shipped `stor` binary, but the grader re-reads file1 with the REAL
  key against a FRESH build; re-MAC'ing a tampered db still needs to forge the GCM tag,
  which needs the unknown file key. Dead end.)
- **Control flow / win(): NOT feasible.** `win()` (stor.c:46) is never called. To reach
  it we'd need to corrupt a return address. All user-controlled strings are bounded:
  `read_str` rejects `len >= MAX_NAME` before copy (stor.c:255), all `strncpy` use
  `MAX_NAME-1` (stor.c:480,511,513), enc_len bounded to `MAX_CONTENT+TAG_LEN`
  (stor.c:384). No `gets`/`scanf`/`sprintf`/`strcat` on stack buffers; no format-string
  (`printf("invalid")` is a literal). No overflow path into a saved EIP found.
- **Crash: no confirmed crash.** Single-command content is bounded to 1 MB on both the
  `-i` path (stor.c:545) and inline path (stor.c:556). No int overflow reachable in one
  test (would need ~4096 x 1 MB files to overflow 32-bit `size_t` in
  `db_serialized_size`, far beyond a bounded command list). Empty-write path allocs
  `xmalloc(1)` and GCM-encrypts inlen=0 fine. No NULL deref / UAF found.

## Findings, ranked by severity x confidence

### 1. [CORRECTNESS — HIGH confidence] `write` ignores stdin entirely
- Category: correctness (5 pts).
- Root cause: stor.c:539-563. Write input is taken ONLY from `-i <file>` (infile) or the
  inline positional `content` arg. There is **no `read()`/`fread(stdin)` anywhere**. When
  neither `-i` nor an inline content arg is given, the code falls to the `else` branch
  (stor.c:559-563) and performs an **empty write** (`ptlen = 0`).
- Spec deviation: the program spec lists write input as "via -i file/inline/**stdin**",
  and the sample `test.json` provides write content over `"stdin"`. A correct/reference
  implementation stores the stdin bytes; this target stores nothing. Re-reading the file
  then returns empty vs. the piped content.
- Trigger (fresh db): register user, create file, `write` with content piped on stdin
  (no `-i`, no inline arg), then `read`. Target prints empty; oracle prints the stdin
  text. Provided as the high-confidence draft below.
- Confidence: HIGH that stdin is ignored (confirmed in source). The grader compares to
  the reference oracle; if the oracle reads stdin (as the spec/sample implies), this is a
  scoring deviation. Drafted as a `correctness` test with `expected` = the stdin content.

### 2. [CORRECTNESS/AUTH — MEDIUM confidence] `register` overwrites an existing user's
   credentials with no proof of the old key
- Root cause: stor.c:476-491. `register` on an existing username re-generates `key_salt`
  and re-derives `key_hash` from the supplied key, with **no verification of the prior
  key**. Anyone can "take over" any account's credential record.
- Impact limit: this does NOT yield confidentiality or integrity scoring. File content
  keys derive from the ORIGINAL key + per-file salt, so after takeover `read`/`write`
  with the new key fail GCM auth → `invalid`. So no content access. It is purely an
  auth-model / correctness deviation (re-register should arguably require the existing
  key or be rejected). Whether the reference oracle rejects re-register is unknown.
- Confidence: MEDIUM. Behavior is confirmed; whether it deviates from the oracle is
  uncertain. Not drafted as a primary test (oracle behavior unknown). Worth a
  correctness probe if the oracle rejects duplicate register.

### 3. [CORRECTNESS — LOW] Trailing-newline strip asymmetry
- stor.c:552-553 strips a single trailing `\n` from `-i` file input only, not from inline
  content. Probably matches reference; low value. Not drafted.

### 4. [CORRECTNESS — LOW] `invalid` printed without trailing newline
- stor.c:97,105 print `"invalid"` (no newline), return 255. Matches spec ("print exactly
  `invalid`"). No deviation. Noted for completeness.

## Confirmed safe (no break)
- HMAC verify on load: stor.c:348-354 (constant-time compare ct_memcmp).
- Key verify: PBKDF2 + ct_memcmp (stor.c:428-434). Constant-time, salted.
- Bounds in read_str / db_load: stor.c:250-260, 366-395.
- find_file requires matching owner (stor.c:418-425) — no cross-user content access.
- find_file/find_user use strcmp (exact match), not substring — no prefix confusion.
