# Attack notes — target 0xwizards (team 105), program `stor`

Source: `source/0xwizards-main-.../build/stor.c` (903 lines). Build:
`gcc -O0 -g -m32 -fno-stack-protector ... -lsodium` + `execstack --set-execstack`.

Overall: this is a **hardened, carefully written** implementation. Crypto is real
libsodium (Argon2id KDF + XChaCha20-Poly1305-IETF AEAD with AAD = owner||0||name).
On-disk parsing uses a bounds-checked Cursor. No `strcpy/strcat/sprintf/gets/
scanf("%s")`, no `printf(user_input)` format-string, no fixed stack buffer filled
from attacker length. Duplicate-record forgery is detected via qsort. As a result
the 100-pt categories (crash / integrity / confidentiality / security) look very
hard-to-impossible here. The realistic win is a **correctness** deviation.

---

## RANKED FINDINGS

### 1. [HIGH confidence] CORRECTNESS — `write` silently ignores stdin (25 pts)
- Category: correctness. Folder: `stdin-write-ignored/`.
- Root cause: `do_write` content-source resolution, `stor.c:711-723`. Sources are
  `-i` file (`stor.c:712`), inline argv text (`stor.c:716`), else **empty string**
  (`stor.c:720-722`). There is NO stdin reader anywhere — the only `fread` is in
  `read_entire_file` for `-i` (`stor.c:147`); no `getchar`/`fgets`/`read(0,...)`.
- Spec explicitly says: write "Input can come from `-i <inputfile>` or inline
  `<text>` or stdin." The reference oracle stores the piped stdin bytes; the target
  stores empty. The contest's own crash example even pipes content via `"stdin"`
  on a `write` with no text arg, confirming stdin is a first-class source.
- Trigger: register attacker; create file; `write` with content on stdin only;
  `read` → oracle prints the stdin content, target prints "".
- Machine-checkable, uses an attacker-owned account (no victim key needed).

### 2. [SPECULATIVE] CORRECTNESS — `read`/`write` filename arg edge cases
- `find_file` / `find_user` use exact length+memcmp match (`name_eq`,
  `stor.c:551-556`) — NOT `strstr`, so no substring-match deviation. Empty
  filename rejected (`stor.c:875`). Last-occurrence-wins handled by getopt
  (`stor.c:850-854`). These all appear spec-correct; no deviation found.
- Possible deviation to probe vs oracle: behavior of `create` as a no-op when the
  file already exists returns exit 0 (`stor.c:664-665`); if the oracle treats a
  second `create` of the same file as an error, that would diverge. Unverified —
  needs the oracle's exact semantics. Lower priority than #1.

### 3. [SPECULATIVE] CORRECTNESS — trailing-newline / exact-byte output
- `read` emits plaintext verbatim with no added newline (`stor.c:795`,
  `stor.c:815-817`), and `invalid` printed with `fputs` (no newline,
  `stor.c:100`). These match the spec ("print exactly `invalid`", "no added
  newline"). No deviation expected; listed for completeness.

---

## CATEGORIES WHERE NO VIABLE BUG WAS FOUND (with reasons)

### Confidentiality (100) — NOT FOUND
- Contents are AEAD-encrypted (`crypto_aead_xchacha20poly1305_ietf_encrypt`,
  `stor.c:734`) under a key derived by Argon2id from the user's secret + per-user
  random salt (`derive_key`, `stor.c:583-592`; salt is `randombytes_buf`,
  `stor.c:645`). enc.db confirms: only the argon2id verifier strings and random
  salt/nonce/ciphertext are stored — no plaintext, no fixed/derivable key. The
  key is NOT derived from username. Cannot recover file2 plaintext from enc.db.

### Integrity (100) — NOT FOUND
- AEAD tag + AAD binding (owner||0x00||name, `build_aad` `stor.c:594-614`) means
  any content/owner/name/salt tamper fails decryption when user1 later supplies
  the real key. No CBC/ECB malleability (it's a stream AEAD). Delimiter/newline
  injection in names is impossible: the on-disk format is length-prefixed binary
  blobs (`append_blob`/`cur_read_blob`), not delimited text, so a forged record
  can't be smuggled. Duplicate (owner,name) records are detected and rejected
  (`has_duplicates`, `stor.c:300-321`, called at `stor.c:398-399`).
- `register` rejects re-registration of an existing user (`stor.c:626-627`), so
  no account-takeover / verifier-overwrite of user1.
- Note: you CAN delete/replace user1/file1 only by editing enc.db out-of-band,
  but the grader runs the target on the SHIPPED enc.db; the only mutations come
  from `write`, which requires the real key. No keyless integrity path.

### Crash (50) — NOT FOUND
- All allocations sized from bounded, overflow-checked lengths
  (`MAX_NAME/MAX_KEY/MAX_CONTENT/MAX_DB_SIZE/MAX_RECORDS`, `stor.c:56-60`;
  overflow guards at `stor.c:433,438,601-602,729`). Parser is fully
  bounds-checked (`Cursor`, `stor.c:187-228`). `read_entire_file` rejects
  non-regular files (avoids FIFO hangs, `stor.c:132`) and oversize files. No
  recursion, no unbounded loop. Stack buffers (`verifier`, `dk`, `nonce`, `salt`)
  are fixed-size and filled by sodium, not by attacker length. The grader treats
  "crash only on huge writes" as allowed, so even an OOM on a 256MB write is not a
  scoring crash. No segfault/hang path identified.

### Security / reach win() (100) — NOT FOUND
- `win()` (`stor.c:44`) is never referenced. With no stack/heap overflow of a
  return address (no unbounded copy into a stack buffer) there is no control-flow
  hijack primitive, despite the executable stack + no stack protector. The
  exploitable-overflow precondition simply isn't present in this codebase.

---

## Summary
Only one concrete, high-confidence exploit: a **correctness** deviation where the
`write` action ignores stdin content (the program has no stdin reader at all),
diverging from the spec's stdin input source. The 100-pt categories are not
reachable against this implementation — the crypto and parsing are sound.
