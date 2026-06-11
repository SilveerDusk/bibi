# via (team 102) — break analysis of `stor`

Static analysis only (32-bit Linux ELF, not runnable on macOS host).
Source: `source/.../build/stor.c` (1274 lines), `Makefile`, `malloc-2.7.2.c` (empty → stock glibc malloc).

## TL;DR
This is a **hardened** submission. The crypto is a correctly-constructed
HMAC-SHA256 construction: per-user key derivation from a salt, a verifier for
auth, an HMAC-keystream stream cipher, and encrypt-then-MAC tags that bind
(user, filename, nonce, len, ciphertext). I found **no memory-safety bug, no
auth bypass, and no crypto break** that yields integrity/confidentiality/security.
The realistic scoring opportunities are **correctness** divergences from the
reference oracle. Integrity/confidentiality/security/crash are assessed
infeasible against this code and explained below.

## enc.db contents (decoded)
- U user1 : salt=3bba4dc6a0ae07ab6dea1272a5aadeb4, verifier=0a8ec8...a45e7b31
- U user2 : salt=454097f49deaf836037fd23896468a51, verifier=4890e2...78a23f2
- F user1/file1 : nonce=f2754e3c..594a, ct(48B)=80fc01..f62eb, tag=f64fdb..bac533
- F user2/file2 : nonce=f48f0d91.., ct(48B)=fa3445..b18fb, tag=c6880e..662ef
- Confirmed offline that user_id/file_id for ("user1","file1") and
  ("user2","file2") match the stored IDs exactly (pepper is hardcoded in the
  binary at stor.c:358-363, so all public IDs are attacker-computable — but
  this leaks nothing useful, see below).
- file1 and file2 plaintexts are each 48 bytes long (ciphertext length == plaintext
  length for this stream cipher).

## Crypto model (why integrity/confidentiality are blocked)
- `derive_key(secret,salt)` = HMAC(secret, "stor-key-v2" || salt)  (stor.c:332)
- `make_verifier(userkey)` = HMAC(userkey, "stor-verify-v2")        (stor.c:341)
- `stream_xor` keystream block = HMAC(userkey, "stor-stream-v2" || nonce || ctr) (stor.c:390)
- `make_file_tag` = HMAC(userkey, "stor-file-v2" || user \0 filename \0 nonce || len || ct) (stor.c:427) — encrypt-then-MAC
- `authenticate` recomputes verifier from supplied -k and stored salt, ct-compares (stor.c:1109). Constant-time compare via ct_equal (stor.c:86).

Everything is keyed by `userkey`, which requires the secret `-k key`. Salts and
nonces are public (in enc.db) but useless without the key. user1 and user2
share the same secret key BUT have different salts → different userkeys → no
cross-user keystream/tag reuse. There is no ECB, no static IV reuse across
writes (nonce regenerated each write at stor.c:1173), and MAC covers the
ciphertext+nonce+identity, so bit-flip integrity forgery is detected.

## Findings ranked by severity × confidence

### 1. [correctness, MEDIUM] write has no stdin input path  → `stdin-write-correctness/`
- Root cause: do_write only handles -i or inline text (stor.c:1158-1165); no
  stdin. parse_args rejects write with neither (`return 0`, stor.c:520).
- Spec lists stdin as a valid write input. If the oracle implements stdin,
  via-102 diverges (returns invalid where oracle stores+reads the data).
- Trigger: register/create then `write` with only stdin, then `read`.
- Confidence MEDIUM: divergence in via-102 is CONFIRMED; scoring depends on the
  oracle supporting stdin (cannot verify here).

### 2. [correctness, LOW-MED] repeated command word rejected  → `repeated-command-correctness/`
- Root cause: cmd_count++ per command token then `if (cmd_count != 1) return 0`
  (stor.c:493-495, 502). "register register" → invalid.
- Spec: "Repeated arg: last wins" — a repeated command arguably should be
  accepted. Trigger: `-u atk2 -k atkkey register register`.
- Confidence LOW-MED: depends on whether oracle applies last-wins to the command
  token (vs only -u/-k/-f/-i/-o).

### 3. [correctness, LOW] trailing newline on read-to-stdout
- do_read always appends `printf("\n")` after stdout content (stor.c:1232), and
  for empty/has_crypto=0 files prints just "\n" (stor.c:1209). For -o output it
  writes the raw bytes with NO trailing newline (stor.c:1223).
- If the oracle does not append a trailing newline on stdout reads, outputs
  diverge. Not turned into a test because it requires knowing oracle formatting
  and (for a real file) the secret key. Could be probed with a fresh attacker
  account: register/create/write "X"/read → via-102 prints "X\n".
- Confidence LOW: pure formatting guess about the oracle.

### 4. [create-without-key] create files for ANY existing user — NOT exploitable
- do_create requires only that the user exists; it does NOT require the key
  (stor.c:1138-1140). So an attacker can `create -u user1 -f anything`.
- Why it does NOT help:
  - Cannot clobber the existing user1/file1: db_add_file calls find_file and
    refuses duplicates (stor.c:739) → the integrity target is untouched.
  - A newly created file has has_crypto=0 and cannot be written without the
    key (do_write authenticates, stor.c:1153). Reading it requires the key too.
  - Integrity is judged by re-reading user1/file1 with the REAL key; creating
    unrelated files does not change file1's nonce/ct/tag.
- Documented as a design smell, not a scoring break.

## Categories assessed INFEASIBLE (with reasoning)
- **integrity (forge user1/file1)**: would require producing a valid
  (ciphertext, tag) under user1's userkey, or overwriting the existing record.
  Tag is HMAC(userkey, ...) → needs secret key. Existing file1 cannot be
  re-created/overwritten (dup check). No DB-injection: db_save only ever writes
  hex IDs + hex blobs, never raw user/filename (stor.c:985,1003,1025), so
  newline/space/delimiter injection of a forged `F user1 file1 ...` line is not
  possible. No break found.
- **confidentiality (recover user2/file2)**: keystream = HMAC(userkey, nonce,...);
  userkey needs the secret key. No keystream/nonce reuse usable across users
  (distinct salts). No plaintext/weak/username-derived keying. Honestly NOT
  recoverable without the key — no `output` claim is made.
- **security (win())**: win() (stor.c:63) is never referenced by any code path.
  Triggering it needs control-flow hijack. Despite -fno-stack-protector +
  execstack, I found NO overflow: no strcpy/strcat/sprintf/scanf/gets; all
  printf/fprintf use literal format strings; all fixed buffers (salt16, nonce16,
  tag32, block32, keyblock64, ctx->data64, m[64], ids) are written within bounds
  (hex_decode_fixed enforces exact length before memcpy, stor.c:590-605;
  sha256_update resets at 64; stream_xor take<=32). No usable corruption.
- **crash**: no signal-raising path found. db_load is defensive (length checks,
  realloc growth). The only slow path is stream_xor over a huge -i file, which
  the security model explicitly carves out as an allowed graceful huge-write
  (and large multi-GB inputs are impractical in test.json). The sample
  test.json (stdin write, no -i/no text) does NOT crash — parse_args rejects it
  at stor.c:520 and the program exits "invalid" immediately, never entering the
  write loop.

## Confirmed vs needs-testing
- CONFIRMED by static reading + offline ID recomputation: enc.db layout,
  username/filename = user1/file1 & user2/file2, crypto construction, absence of
  stdin path, repeated-command rejection, dup-file refusal, no raw-string DB
  injection, no obvious memory bug.
- NEEDS LIVE ORACLE to score: all three correctness items hinge on the
  reference implementation's exact behavior for stdin / repeated commands /
  trailing newline.
