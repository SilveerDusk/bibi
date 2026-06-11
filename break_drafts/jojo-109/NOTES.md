# jojo (team 109) — break analysis

Target: `stor` encrypted file store. Source split across stor.c, args.c, io.c,
cmd.c, db.c (+ malloc-2.7.2.c = dlmalloc). Crypto = libsodium: Argon2id KDF
(crypto_pwhash) + XSalsa20-Poly1305 (crypto_secretbox). 32-bit, exec stack.

Overall: this is a well-engineered submission. The crypto is textbook-correct
and there are no fixed-size unbounded copies in the application code. The only
realistic break is a parsing/correctness deviation. Memory-safety, integrity,
confidentiality, and control-flow attacks were investigated and judged
infeasible (reasoning below).

## Ranked findings

### 1. [CORRECTNESS] inline write text equal to a command verb is misparsed — HIGH
- Category: correctness (25)
- Root cause: `args.c:84-95` (args_parse). Bare tokens are matched against
  cmd_from_word() BEFORE being considered as inline text. A `write` payload of
  literal "read"/"register"/"create" is taken as a second command verb; since it
  differs from the active CMD_WRITE, `args.c:87-88` returns 0 → "invalid"/255.
- Trigger: `write read` (see test.json in ./text-is-command-word/).
  jojo: prints "invalid", exit 255. Oracle: stores "read", exit 0; read-back
  prints "read".
- Confidence: HIGH. Pure logic, machine-checkable, no platform/crypto reliance.
- Draft: `text-is-command-word/` (ready).

### 2. [CORRECTNESS] `fail()` prints "invalid\n" (trailing newline) — LOW/NEEDS-ORACLE
- Category: correctness (25)
- Root cause: `stor.c:28` uses `puts("invalid")` which appends '\n'. Spec says
  print "exactly `invalid`". The team itself flags this uncertainty in the
  comment at `stor.c:26-27`.
- Whether this is a deviation depends entirely on the unseen oracle (it likely
  also uses puts → no diff). Not drafted; would be a guess.
- Confidence: LOW (cannot verify without oracle output).

### 3. [CORRECTNESS] `register`/`write` extra-flag rejection strictness — LOW
- `validate()` rejects e.g. register with `-f/-i/-o`/text (`args.c:31-34`) and
  write with `-o` (`args.c:41`). If the oracle is more permissive (ignores
  surplus flags) this diverges, but the spec wording ("needs -u,-k") suggests
  rejection is acceptable. Not drafted. Confidence: LOW.

## Categories ruled out (with reasoning)

### Crash (50) — NOT FOUND
- Only memcpys in app code (db.c:93,100,146; io.c:55) are length-bounded.
- Input is capped: `slurp` enforces IO_MAX_INPUT=64MB (io.c:8,21,33) and returns
  NULL ("invalid") past it — the spec's "graceful huge-write exit". The provided
  crash test.json (giant "AAAA..." stdin) just yields "invalid", no signal.
- `db_save` uses snprintf with size check (`db.c:267-268`); tmp[1024] safe.
- `db_load` counts/lengths are attacker-controlled ONLY via enc.db, but crash/
  correctness runs start from NO enc.db, so db_load is not an attacker surface
  here. Even so, calloc(n,...) overflow returns NULL and get_field is bounded by
  r->left and DB_MAX_FIELD (db.c:143), so a forged db just fails cleanly.
- No format-string sinks (no printf(%s,user) etc.), no scanf, no sprintf.

### Integrity (100) — NOT FEASIBLE
- file1 content = nonce || crypto_secretbox(K_user1, pt) where
  K_user1 = Argon2id(password, random 16B salt) (db.c:398-429, 49-57).
- Poly1305 MAC covers the whole ciphertext; any bit-flip fails
  crypto_secretbox_open_easy on the real-key read (db.c:460). No malleability,
  no ECB, no CBC. Records are bound to the owner via K (per-user salt), so a
  forged/moved record cannot re-read under user1's real key.
- On-disk format is length-prefixed (db.c put_field/get_field), so newline or
  delimiter injection in username/filename cannot restructure other records.

### Confidentiality (100) — NOT FEASIBLE
- file2 = nonce || secretbox(K_user2, pt). K_user2 derived from the secret key
  via Argon2id with a random per-user salt; the key is never stored (only a
  sealed verifier token, db.c:36-39,347-353). No plaintext, no username-derived
  key, no weak/static key. Recovering file2 requires the key (brute force of
  Argon2id-interactive is out of scope). I do NOT claim a recovered plaintext.

### Control flow / win() (100) — NOT FOUND
- No stack buffer overflow reachable. win() (stor.c:18) is only reachable via a
  control-flow hijack; no such primitive exists (no overflow into return
  address; all buffers are heap and bounded).

## enc.db inspection
430 bytes, magic "STOR", version 2, nuser=2 (user1, user2), nfile=2
(user1/file1, user2/file2). Salt_len=16, verifier_len=56 (24 nonce +16 MAC +16
token), content fields = 88 bytes each (24 nonce + len + 16 MAC → len=48
plaintext bytes each for the two flags). All consistent with the source; nothing
leaks plaintext. Matches the README build recipe exactly.

## Recommendation
Submit finding #1 (`text-is-command-word/`). It is the only high-confidence,
fully machine-checkable break against this otherwise solid submission.
