# kevwjin (team 106) — break analysis of `stor`

Source: `break-it-code/kevwjin-106/source/kevwjin-main-d982f89a98a7d2b59358c8008cdfb35bff503b8b/build/stor.c`
Build: 32-bit, `-fno-stack-protector`, exec stack, links old `malloc-2.7.2.c`.

## Executive summary
This implementation is **strongly hardened**. The intended memory-corruption / crypto / auth attack
surfaces are all closed:

- **Crypto = Encrypt-then-MAC done correctly.** Keys = PBKDF2-SHA256(key, per-user random salt, 20000 iters)
  split into `enc_key`/`mac_key` (`stor.c:227`, `:473`). Keystream = HMAC(enc_key, nonce || seed || ctr),
  seed = HMAC(enc_key, aad) (`crypt_stream` `stor.c:550`). Tag = HMAC(mac_key, aad||nonce||cipher_len||cipher)
  (`make_tag` `stor.c:568`), verified with constant-time compare BEFORE decrypt (`decrypt_file` `stor.c:649`).
  => No bit-flip integrity (full MAC over ciphertext+aad+nonce+len), no plaintext recovery (keystream needs
  the secret enc_key), no ECB. A fresh random nonce is generated on **every** write (`encrypt_file` `stor.c:614`),
  so no keystream reuse even on rewrite.
- **Identities are hashed, fixed-length.** Username/filename are SHA256("user:"+name)/SHA256("file:"+name)
  (`name_id` `stor.c:435`). Stored fields are always 32 bytes; `validate_db` rejects any user/file field
  whose length != 32 (`stor.c:308`). => No newline/delimiter injection to forge user1/file1, no length-confusion.
- **Auth.** `find_user`/`find_file` always key off the *requesting* user (`stor.c:443`,`:453`), and read/write
  require `derive_and_verify` (correct key) (`stor.c:764`, `:790`). Re-`register` of an existing user fails
  (`add_user` returns 0 when user exists, `stor.c:493`) → no account takeover / verifier overwrite.
- **Memory / integer safety.** All length math is overflow-checked (`hmac2` `:209`, `make_tag` `:573`).
  Load path caps counts at 100000 (`:345`), field lengths at `MAX_FIELD_LEN`=1MB (`read_field` `:299`),
  cipher_len at `MAX_CONTENT_LEN+4096` (`:371`), rejects cipher_len in (0,8) (`:324`), and requires exact EOF
  (`:391`). Fixed stack buffers (Sha256.data[64], hmac k0/ipad/opad[64], crypt_stream seed/block[32]/ctrbuf[36])
  are all written within bounds. No `strcpy/strcat/sprintf/scanf/gets`; only bounded `memcpy`/`fread`.
- **Huge write is graceful.** `read_whole_file` caps at `MAX_CONTENT_LEN` (`:689`); `encrypt_file` rejects
  `plain_len > MAX_CONTENT_LEN` (`:593`); padded payload_len (16MB+8) stays under the load cap → reloads fine.
  No overflow, no crash.

I found **no** confirmed crash / integrity / confidentiality / security(win) exploit. `win()` (`stor.c:30`)
is never reachable — there is no path that calls it and no memory-corruption primitive to redirect control.

## Ranked findings

### 1. [correctness] `write` ignores stdin entirely — MEDIUM confidence
- Category: correctness (25)
- Root cause: `main` only reads input from `-i <infile>` (`stor.c:765`) or the inline trailing `content` arg
  (`stor.c:767`). There is **no stdin read path at all**. The program spec explicitly lists input methods as
  "`-i file` / inline / **stdin**", and the sample `test.json` feeds the write via `"stdin"`.
- Behavior here: `stor -u U -k K -f F write` with data on stdin and no `-i`/inline → `plain=NULL`, `plain_len=0`
  → `encrypt_file(NULL,0)` succeeds → stores an **empty** file, exits 0. A later `read` returns empty.
- If the reference oracle reads stdin (as the spec/sample implies), the oracle's `read` returns the stdin bytes
  while this build returns nothing → outputs differ. Machine-checkable via `expected`.
- Trigger: see `write-ignores-stdin/test.json`.
- Honesty: confidence is MEDIUM because the exact oracle stdin semantics aren't given to us; the divergence is
  real *if* the oracle honors stdin (strongly implied by the spec wording and the sample crash test).

### 2. [correctness] `write` with NO input source silently succeeds writing empty content — LOW/MEDIUM
- Category: correctness (25)
- Root cause: same code path as #1. With neither `-i`, inline content, nor stdin consumed, the write still
  returns 0 and overwrites the file with empty content (`stor.c:756`-`779`). A reference that treats "no input"
  as an error would print `invalid`/255.
- Trigger: see `write-no-input-succeeds/test.json`.
- Honesty: LOW/MEDIUM — depends on oracle's handling of a missing input source.

### Considered and REJECTED (no break)
- Bit-flip integrity on file1: rejected — full HMAC tag over ciphertext+aad+nonce+len, MAC-then-decrypt.
- Confidentiality recovery of user2/file2: **rejected** — plaintext is XORed with an HMAC keystream keyed by the
  secret PBKDF2-derived enc_key; no known/derivable plaintext, no nonce reuse, no ECB. Cannot reconstruct
  plaintext without the key. (Plaintext length is bounded to 0..256 bytes by cipher_len=264, but that leaks
  nothing usable.) Not claiming confidentiality.
- Account takeover / re-register: rejected — `add_user` refuses existing users.
- Cross-user read: rejected — owner is always the requester's hashed name.
- Crash via malformed enc.db: rejected — counts/lengths/EOF all validated before use.
- Heap/stack overflow, format string, off-by-one: none found; no format-string sinks, all copies bounded.
- Integer overflow in size math: rejected — explicit `UINT32_MAX - x` guards.

## Recommendation
Submit finding #1 (stdin) as the primary correctness probe and #2 as a secondary. No high-value
(crash/integrity/confidentiality/security) break is supported by the code; do not submit fabricated ones.
