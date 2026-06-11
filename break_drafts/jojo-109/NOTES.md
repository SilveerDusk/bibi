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

## DEEP DIVE (100pt/crash hunt)

Goal of this pass: find the 50pt (crash) and/or 100pt (integrity/confidentiality/
control-flow) bug(s) that other teams scored. RESULT: none are feasible. jojo's
application code is genuinely memory-safe and the crypto is textbook-correct.
The 175 points scored against jojo were almost certainly CORRECTNESS breaks
(the broad-pattern bugs below — note break/ shows duplicate-create and
register-takeover scoring against other teams).

### Method
- Built jojo natively with clang -fsanitize=address,undefined and fuzzed:
  * 6000+ single commands (random argv + stdin)         -> 0 real signals
  * 800+ multi-command sequences reusing enc.db          -> 0 real signals
  (All exit-255 results are the normal "invalid" path; ASan stderr always empty.)
- Differential-fuzzed jojo vs the SHIPPED REFERENCE ORACLE
  (starter-package/build/stor, which runs on macOS arm64): ~4000 sequences.
- Note: an apparent "register fails at username length 256" was an ASAN-ONLY
  artifact; the plain build handles arbitrarily long names fine. NOT a bug.
- Large-write DoS check: 63MB stdin write completes in 0.35s (slurp cap +
  secretbox are fast). No >60s hang anywhere.

### CRASH (50) — STILL NOT FOUND (high confidence)
ASan/UBSan clean across all fuzzing. slurp cap (io.c:8,21,33) holds; the only
buffer the cap lets reach 128MB is freed and bailed cleanly. db_write_content
size math is bounded (db.c:409). db_load is not an attacker surface (fresh DB
for crash runs; mutating commands only ever serialize well-formed data).

### INTEGRITY (100) — STILL NOT FEASIBLE
Per-record secretbox keyed by the OWNER's Argon2id key defeats forgery/move.
Keyless re-register is correctly rejected (cmd.c:9-11) — CONFIRMED. `create`
needs no key but only ADDS new files; it cannot touch file1's stored bytes.
No path mutates an existing record's ciphertext without auth_derive succeeding.

### CONFIDENTIALITY (100) — STILL NOT FEASIBLE
enc.db re-parsed: user1 salt 3d68…, user2 salt a759… (DISTINCT); all four
nonces distinct (no reuse) even though both users share the same $TEAM_FLAG
password. K differs per user via salt. No plaintext leakage. Requires brute
force of Argon2id-interactive — out of scope. No recovered plaintext claimed.

### CONTROL FLOW / win() (100) — STILL NOT FOUND
No stack overflow reachable; all buffers heap and bounded; no hijack primitive.

### NEW correctness breaks found via the oracle binary (drafted, ready)
These are the realistically-scorable bugs (25pt each in the prompt's scale):

1. `correctness-invalid-trailing-newline/` — UPGRADED to MEDIUM-HIGH.
   Confirmed against the real oracle: oracle prints "invalid" (7 bytes), jojo
   prints "invalid\n" (8 bytes, puts() at stor.c:28). Valid read output is
   byte-identical, so the only diff is the error token's trailing newline.
   Affects EVERY error path.

2. `register-extra-flag/` — HIGH. jojo's validate() rejects register carrying a
   stray -f/-o/-i (args.c:31-34); the reference ignores surplus flags.
   `stor -u alice -k s -f x register`: oracle exit 0/"", jojo exit 255/"invalid".

3. `duplicate-create-idempotent/` — HIGH. Same class that scored vs teams
   114/107/104. Reference treats re-create as idempotent success
   (starter stor.c:359-362); jojo returns -1 -> invalid (cmd.c:18-20).
   register atk / create note / create note again: 3rd diverges (oracle 0, jojo 255).

Plus the already-drafted `text-is-command-word/` (HIGH).

### Bottom line
No 50pt or 100pt bug exists. Submit the four correctness breaks; the strongest
are duplicate-create-idempotent and register-extra-flag (HIGH, oracle-verified),
then text-is-command-word (HIGH), then trailing-newline (MEDIUM-HIGH).
