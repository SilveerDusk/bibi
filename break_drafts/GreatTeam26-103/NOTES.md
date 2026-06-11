# Break analysis — GreatTeam26 (team 103), program `stor`

Static analysis only (32-bit Linux ELF, not runnable on macOS host).
Source: `.../build/stor.c`. Built `-O0 -g -m32 -fno-stack-protector`, execstack set.

## Overall assessment
This is a hardened, defensively-written implementation. Crypto, parsing, and
memory handling are all careful. Most categories look UNBREAKABLE; one clear
correctness deviation exists.

---

## Findings ranked by severity x confidence

### 1. [CORRECTNESS, 25] `write` never reads stdin — HIGH confidence (CONFIRMED)
- Root cause: `do_write()` `stor.c:560-571`. Input precedence is `-i` infile,
  then inline text arg, then a hardcoded empty string. There is NO stdin read
  path anywhere in the program. grep for stdin/fread/getline/read( shows the
  only `fread` is in `read_file_all` (`stor.c:275`), used for `-i` files and the
  db — never for fd 0.
- Spec explicitly: write content comes "via -i file, inline text, or stdin".
  The README's own crash example feeds content over `"stdin"`. A correct oracle
  must read stdin when neither `-i` nor inline text is provided.
- Trigger: `write` with content only on stdin → target seals EMPTY content; a
  later `read` prints nothing. Oracle would print the stdin bytes.
- Draft: `stdin-ignored-correctness/`.
- Note: also affects the README crash recipe — feeding a huge payload via stdin
  does nothing here (no allocation), so that crash vector is a no-op too.

### 2. [CORRECTNESS, 25] read of created-but-never-written file → `invalid` — LOW/MED confidence (needs oracle)
- `stor.c:628`: `if (!fl->has_content) ... fail()`. Reading a file that was
  `create`d but never `write`ten returns `invalid`/255. If the reference oracle
  instead returns empty output with exit 0, this is a deviation. Direction of
  the spec is unknown, so confidence is low. Not drafted.

---

## Categories judged NOT breakable (with reasoning)

### Confidentiality (user2/file2) — NOT breakable
- Contents sealed with AES-256-GCM (`gcm_encrypt`, `stor.c:204`). Key = first 32
  bytes of PBKDF2-HMAC-SHA256(secret, random 16-byte salt, 100000 iters)
  (`derive_keys`, `stor.c:184`). IV is random per write (`stor.c:574`).
- enc.db (parsed): user2/file2 ctlen=64, random IV, GCM tag present. No key,
  no plaintext, no static/derivable key (key is the secret flag, not username).
  Reconstruction without the secret is infeasible. Will NOT claim recovery.

### Integrity (user1/file1) — NOT breakable
- AES-256-GCM tag authenticates ct, and AAD = "user1\0file1" binds the blob to
  owner+filename (`make_aad`, `stor.c:476`; verified on read at `stor.c:637`).
  Any byte flip in iv/ct/tag fails `EVP_DecryptFinal_ex` → `read` with real key
  fails the tag, so a forged blob does not "re-read as different content"; it
  reads as invalid. Grader needs a *different valid* content under the real key.
- Cannot re-register user1 (duplicate username rejected, `stor.c:517`). No
  delete. Cannot add a 2nd "file1" (dup filename rejected at parse `stor.c:345`
  and create is a no-op if it exists `stor.c:535`). has_content 1->0 flip is
  caught at read (`stor.c:628`). No forgery primitive without the MAC key.

### Crash — NOT found
- No fixed stack buffers indexed by attacker length; no strcpy/strcat/sprintf/
  scanf/gets/alloca. All sizes via bounds-checked `Rd` (overflow-checked
  `rd_bytes` `stor.c:168`) and overflow-checked `Buf` (`buf_reserve` `stor.c:141`).
- Large inputs: `-i` capped at 63 MiB (`read_file_all` returns -2 → fail),
  padded buffers ~<=64 MiB, db capped 64 MiB at save (`stor.c:416`). All via
  `xmalloc`/`malloc` with graceful `fail()` on OOM. 32-bit addr space (~3GB)
  comfortably holds these. Spec permits graceful huge-write exit.
- Forged-db DoS: counts bounded by file length (`nusers <= remaining/44`,
  `nfiles <= remaining/5`), iters clamped to 4e6, O(n^2) dup checks gated to
  n<=4096. No runaway. Note: integrity/confidentiality tests use the shipped
  db anyway (well-formed, iters=100000).

### Security / win() — NOT reachable
- `win()` (`stor.c:43`) is never called. No buffer overflow, no format string
  (`printf` uses only fixed literals), no OOB write to corrupt a return address.
  execstack + no-stack-protector are irrelevant without a memory-corruption
  primitive, and none exists. No control-flow hijack available.

---

## Misc verified-safe details
- Args: last-wins handled by getopt loop; extra positional rejected; missing
  key/file rejected per action (`stor.c:713-728`). `read -o enc.db/enc.db.tmp`
  blocked (`stor.c:617`). Output files must be regular (no FIFO hang).
- enc.db format confirmed by parser: STOR\x01, 2 users (user1/file1,
  user2/file2), both has_content=1, ctlen=64, iters=100000, no trailing bytes.
