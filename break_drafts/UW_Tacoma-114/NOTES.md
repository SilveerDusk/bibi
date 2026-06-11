# UW_Tacoma-114 — Break Notes

Target: `UW_Tacoma-114/source/.../build/stor.c` (referred to below as `stor.c`).
Build: 32-bit, `-fno-stack-protector`, exec stack. Oracle reference =
`starter-package/build/stor.c`.

## Executive summary

This is an unusually well-hardened submission. The crypto and the binary parser
are essentially textbook-correct, which closes the high-value categories:

- **Crypto / confidentiality (file2): NOT exploitable.** AES-256-GCM with a
  per-user random 16-byte salt, PBKDF2-HMAC-SHA256 @ 200,000 iterations, fresh
  random 12-byte IV per write. Plaintext cannot be reconstructed without the
  key. No ECB, no keystream reuse, no username-as-key. Confidentiality of
  user2/file2 CANNOT be claimed.
- **Integrity (file1): NOT exploitable.** Content is GCM-authenticated; the AAD
  binds owner+0x00+filename (`file_aad`, stor.c:467), so a record cannot be
  relocated or bit-flipped without failing the tag check. Re-reading file1 with
  the real key cannot be made to differ.
- **Security / win(): NOT reachable.** `win()` (stor.c:26) is never called and
  there is no memory-corruption primitive to redirect control (see below).
- **Crash: no primitive found.** The parser uses overflow-safe bounds checks
  and rejects trailing/garbage bytes.

The realistic wins are **correctness** divergences from the reference oracle.

## Findings ranked by severity x confidence

### 1. [correctness, HIGH] Re-create of an existing file: error vs success
- Root cause: `cmd_create` calls `die_invalid()` when the (owner,filename)
  already exists — `stor.c:529`. The oracle returns success (idempotent no-op)
  — `starter-package/build/stor.c:359-362` (`SUCCESS_OUT()`).
- Divergence: 3rd command (`create` of an already-created file): oracle exit 0
  / stdout ""; target exit 255 / stdout "invalid\n". Differs in BOTH exit code
  and output, so it is robust to whitespace normalization.
- Trigger: register attacker -> create note -> create note again.
- Uses only a fresh attacker account; does not need any victim key or the
  shipped records.
- Draft: `create-existing-file-mismatch/`.
- Confidence: HIGH (target source unambiguous). Sole assumption: grader oracle
  == shipped starter semantics.

### 2. [correctness, MEDIUM] Trailing newline on the `invalid` error string
- Root cause: target prints `"invalid\n"` (`die_invalid`, stor.c:35); oracle
  prints `"invalid"` with no newline (`invalid()`, starter stor.c:48).
- Divergence: any error path; stdout "invalid\n" vs "invalid", both exit 255.
- Trigger: a single bogus action token.
- Draft: `invalid-trailing-newline/`.
- Confidence: MEDIUM. Certain at the byte level, but the grader may trim
  trailing whitespace, or its oracle may also print the newline. Harmless if it
  does not fire.

## Areas checked and found SAFE (negative results, for completeness)

- **Memory safety / overflow.** Fixed buffers `username[256]`/`filename[256]`
  are written via `strncpy(.., MAX_*=255)` on zeroed structs (stor.c:501,
  532-533); deser writes at most `ulen<=255` bytes then NUL at index <=255
  (stor.c:326-328, 339-344). `file_aad` writes <=511 bytes into a 512-byte
  buffer (stor.c:467-473, 570, 620). No strcpy/strcat/sprintf/scanf on
  attacker-length-controlled data. No format strings.
- **Binary parser / trusted lengths.** `db_load` validates magic+version,
  checks `size > b.len - b.pos` using subtraction (overflow-safe on 32-bit,
  stor.c:400), sub-parses each record in a bounded `BufR`, rejects unknown
  record types (stor.c:427), rejects trailing bytes inside a record
  (stor.c:409,419) and at end-of-buffer (stor.c:431). `ct_len` capped at
  MAX_CONTENT and read through bounds-checked `br_raw` (stor.c:350-356). No
  trusted-length over-read/alloc.
- **Integer overflow.** `bw_grow` and the `br_*` readers explicitly guard
  against `SIZE_MAX` / `len-pos` overflow (stor.c:218, 256-273).
- **Auth.** Key is verified by GCM-decrypting a fixed token with the username
  as AAD (`auth_user`, stor.c:478-487); wrong key -> tag failure -> die. No
  accept-any. No account-takeover re-register (duplicate `register` ->
  die_invalid, stor.c:498). Cross-user read/write impossible: `db_find_file`
  requires `owner==username` (stor.c:200-206) and the caller must auth as that
  owner.
- **Parsing / delimiter injection.** Usernames/filenames are length-prefixed on
  disk (not newline-delimited) and bound into the GCM AAD with a 0x00
  separator, so no "ab"/"c" vs "a"/"bc" forgery.
- **stdin write.** Unlike some submissions, this target DOES read stdin when
  neither -i nor inline text is given (stor.c:718-734), so the
  "stdin-write-ignored" correctness bug does NOT apply here.
- **Last-wins args.** Loop overwrites `opt_*` on repeat (stor.c:655-672),
  matching spec.

## enc.db layout (confirmed via xxd)
Header `STOR` + ver 1. USER user1 (size 0x3a), USER user2 (size 0x3a),
FILE user1/file1 (has_content=1, ct_len=0x30=48), FILE user2/file2
(has_content=1, ct_len=0x30=48). 48-byte ciphertexts are consistent with GCM
(plaintext_len == ct_len; tag stored separately), i.e. ~48-byte secrets. No
plaintext leakage in the file.
