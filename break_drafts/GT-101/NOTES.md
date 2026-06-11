# Break Notes — Target GT (team 101), program `stor`

Source: `break-it-code/GT-101/source/gt-main-86e3dba1da9b47b10ec944bc0e3881f7c988214a/build/stor.c`
Custom allocator statically linked: `malloc-2.7.2.c` (dlmalloc 2.7.2).
Build: `gcc -O0 -g -m32 -fno-stack-protector ... ; execstack --set-execstack stor`.

## Executive summary

This is a **hardened, largely correct** implementation. The crypto is genuine and strong:

- Per-user random 32-byte salt; keys derived via `PKCS5_PBKDF2_HMAC` SHA-256, **300,000 iterations** (`derive_keys`, stor.c:82-96).
- Content is **AES-256-CBC encrypt-then-MAC**. The `content_hmac` is HMAC-SHA256 over `"DATA" || username || filename || iv || ciphertext` keyed by a `mac_key` derived from the secret (`compute_content_hmac`, stor.c:114-131; checked before decrypt in `do_read`, stor.c:548-558).
- Key verification uses a separate `auth_tag` = HMAC over `"AUTH" || username` keyed by mac_key, compared with a constant-time `safe_memcmp` (stor.c:73-79, `verify_key` stor.c:336-352).
- No fixed-size stack buffers receive attacker input. Both `strcpy` sites (stor.c:394, 419) copy into `safe_malloc(strlen(x)+1)` — not overflowable. No `sprintf`/`strcat`/`scanf`/`gets`. No format-string sinks (every `printf` uses a literal).
- Huge writes are bounded (`MAX_CONTENT` = 600 MiB checks at stor.c:456, 472) and use `safe_malloc` which exits gracefully on OOM.
- `load_db` validates magic, caps `num_users`/`num_files` (≤1024), caps name lengths (≤255), caps `content_len`, and rejects trailing bytes (stor.c:216-282). No integer overflow on 32-bit (max struct-array allocs ~77 KB).

### enc.db layout (confirmed by parse)
`STORDB02` | num_users=2 | [u16 ulen=5 "user1" | salt32 | auth_tag32 | num_files=1 | u16 flen=5 "file1" | iv16 | hmac32 | u32 clen=64 | ct64] | [user2/file2 same shape, clen=64]. Parses exactly, 0 bytes remaining. Each ciphertext = 4 AES blocks → plaintext 48–63 bytes + PKCS#7.

---

## Findings, ranked by severity × confidence

### 1. INTEGRITY — keyless account/file takeover via `register` overwrite  (severity HIGH, confidence MEDIUM)
**Root cause:** `do_register` lets ANYONE re-register an already-existing username with no proof of prior ownership. When the user already exists it overwrites `salt` + `auth_tag` with values derived from the attacker's key, AND wipes every file's content (sets `content_len=0`, zeroes iv/hmac, frees ciphertext). See stor.c:371-397, specifically the `if (u)` branch stor.c:372-386.

**Effect on the integrity target:** After
```
stor -u user1 -k ATTACKER register
```
user1/file1's original ciphertext is destroyed (`content_len=0`) and the stored `auth_tag` now matches the attacker's key, not the real key. The DB is re-saved (stor.c:401). Reading `user1/file1` afterward with the REAL key fails `verify_key` (new salt/auth_tag → mismatch, stor.c:345) and returns `invalid` — the original `$INTEGRITY_FLAG` content is no longer recoverable. Optionally the attacker can also `create`+`write` new attacker-controlled content under their own key.

**Trigger:** single command, uses shipped enc.db. See `integrity-register-takeover/test.json`.

**Confidence note (honest):** This unquestionably *destroys/alters* user1/file1 without the key (clear spec violation of the integrity property in README §Integrity "Modify user1's file1 without knowing their key"). The uncertainty is purely about grader semantics: the grader "verifies by reading file1 with the original key." After takeover that read returns `invalid` (content gone) rather than a *different valid plaintext*. If the grader scores "content read with real key != original flag" this passes; if it strictly requires a successful read returning a different value, it may not register. I include a variant that also writes new content under the attacker key so file1 still reads successfully — but only under the attacker key, not the real one (re-read with real key still yields `invalid`). There is no way to make file1 read a *different valid plaintext under the real key* because that requires forging `content_hmac`, which needs the secret-derived `mac_key`. So this is the maximal achievable integrity break; submit and let the grader judge.

### 2. CORRECTNESS — stdin input source is not implemented  (severity LOW, confidence MEDIUM)
**Root cause:** The spec lists three `write` input sources: `-i <inputfile>`, inline `<text>`, or **stdin**. `do_write` (stor.c:425-478) only handles `infile` and the inline `content` argv token; if neither is present it uses `src = ""` (stor.c:470) and writes EMPTY content. There is no `read()/fgets/getchar/stdin` use anywhere in the program.

**Effect:** `echo -n "hello" | stor -u a -k s -f x write` (no inline text, no `-i`) stores empty content. A spec-correct oracle would store `"hello"`; reading it back returns `"hello"`. Target returns empty → stdout differs.

**Trigger:** fresh-db sequence (register, create, write with stdin, read). See `correctness-stdin-ignored/test.json`.

**Confidence note:** Depends on the oracle actually implementing stdin per spec. If the reference impl also ignores stdin, this won't grade. Provided as the most defensible correctness candidate. The `expected` block encodes the spec-correct behavior (read returns the stdin bytes).

### 3. CONFIDENTIALITY — NOT VIABLE
file2 is AES-256-CBC encrypted under a PBKDF2(300k)-derived key from a per-user random salt, with encrypt-then-MAC. No fixed/derivable key, no ECB, no plaintext leakage. The 64-byte ciphertext reveals only that the flag is 48–63 bytes. Cannot recover plaintext from enc.db without the secret. Do not submit a confidentiality break.

### 4. CRASH — NOT FOUND
All attacker-length inputs flow into heap buffers sized by `strlen+1` or bounded `safe_malloc`; OOM exits gracefully via `safe_malloc`/`safe_realloc` (stor.c:39-48). `load_db` bounds every length field and rejects trailing data. Decrypt/HMAC failures return `invalid` cleanly. No unbounded recursion, no signed/unsigned size confusion reaching an allocation, no `alloca`. The custom dlmalloc 2.7.2 is exploitable in principle but there is **no heap-overflow / double-free primitive in the application code** to drive it. No viable crash found.

### 5. SECURITY (control flow → win()) — NOT FOUND
`win()` (stor.c:28) is never referenced and there is no memory-corruption primitive (no stack buffer overflow, no controllable write-what-where) to redirect control to it. `-fno-stack-protector` + execstack are exploitation *enablers* but are inert without an overflow, and none exists in the source. Not viable.

---

## Bottom line
The only categories with any traction are **integrity** (#1, via the keyless `register` overwrite — destroys the integrity target; grader-semantics-dependent) and **correctness** (#2, missing stdin input; oracle-dependent). Confidentiality, crash, and control-flow are all non-viable against this implementation.
