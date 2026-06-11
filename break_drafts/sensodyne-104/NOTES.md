# sensodyne-104 (`stor`) — break analysis

Target team 104. Source reviewed in full:
`build/stor.c` (976 lines) + `build/malloc-2.7.2.c` (vulnerable allocator) + `build/Makefile`.

## Threat-model reminder
- Grader runs **CLI commands only** against a FRESH build seeded from the shipped
  `enc.db` state (user1/file1, user2/file2 present). I cannot drop a pre-forged
  `enc.db` onto disk; I can only run `stor ...` invocations (new attacker users OK).
- This constraint is decisive: several real cryptographic/parser weaknesses below are
  only reachable if you can supply tampered on-disk bytes, which the CLI does not let
  an unprivileged attacker do. Those are documented as "real bug, not CLI-reachable".

---

## Findings ranked by (severity x confidence)

### F1 — `write` silently ignores stdin  [CORRECTNESS, HIGH confidence]
Root cause: `stor.c:793-834` (`parse_args`) + `stor.c:915-921` (`main`, CMD_WRITE).
There is **no stdin read anywhere in the program** (confirmed: the only `fread`s are
the db file at `stor.c:391` and the `-i` input file at `stor.c:906`; no `read(0)`,
`fgets`, `getline`, `scanf`, `getchar`).

Write content is sourced as:
```
const char *txt = a.text ? a.text : "";   // stor.c:916
```
where `a.text` is only ever set from an **inline argv token** (`stor.c:822`). So a
`write` with no inline text and no `-i` writes the **empty string**, regardless of what
is piped on stdin.

The program spec explicitly lists write input methods as "`-i` file / inline / **stdin**",
and the spec's own sample test feeds the payload via `"stdin"`. A correct oracle that
reads stdin will store/return that data; this build stores empty. => `read` afterwards
returns empty (or "first read seals empty file" => empty) while the oracle returns the
stdin bytes. Divergent output = correctness.

Trigger: `register; create; write <stdin="HELLO">; read` and compare read output.
Draft: `correctness-stdin-ignored/`.
Confidence: HIGH that the build ignores stdin (proven by source). Oracle dependence:
the spec names stdin as an input method, so the reference almost certainly reads it.

### F2 — `write` unconditionally eats the next argv token as inline text  [CORRECTNESS, MEDIUM]
Root cause: `stor.c:819-823`. On the `write` action the parser does
`if (i+1 < argc) a->text = argv[++i];` — it consumes the **next token no matter what it
is**, including a following flag like `-k`/`-f`/`-i`. Example:
`stor -u u -k k write -f f` → `-f` is swallowed as the inline text, then bare `f`
triggers `parse_error` → `invalid`. A reference parser that accepts flags in any order
would succeed. Also `-i conflicts with inline text` (`stor.c:859`) fires whenever `-i`
appears before `write` in a way that leaves `a->text` set.
Confidence: MEDIUM — clearly anomalous, but whether it diverges depends on the oracle's
arg grammar. Documented; not shipped as a standalone draft (subsumed by ordering edge
cases that may already match the oracle's "strict last-token" rule).

### F3 — Global DB MAC key is derived only from data stored in the clear in enc.db
[CRYPTO / INTEGRITY — real bug, NOT CLI-reachable, LOW exploitability here]
Root cause: `stor.c:182-193` (`derive_mac_key`) and the deserialise mirror at
`stor.c:284-302`. The header comment (`stor.c:6-8`, `177-181`) claims the MAC key
"incorporates secret material so keyless forgery is impossible." It does not. The MAC
key is `BLAKE2b(db_salt || all UserRecord bytes)`, and **both `db_salt` and the full
UserRecord array are stored verbatim in `enc.db`** (offsets 8 and 76 in the shipped
file). The "key verifier" bytes inside each UserRecord are ciphertext, not secret — they
are right there in the file.

PROVEN: I recomputed the MAC key from file-only bytes and reproduced the stored global
MAC of the shipped `enc.db` exactly (`/tmp/forge.c`, output
`MAC match (recomputed from file-only data): YES - FORGEABLE`). => anyone who can read
`enc.db` can forge a valid global MAC over an arbitrarily edited database.

Why it is NOT a submittable break here: the global MAC only gates *loading* the DB.
Per-file content integrity is additionally protected by `file_state_mac`
(`stor.c:460-498`), which IS keyed by the Argon2-derived `user_key` (needs the secret
password) and is re-checked on every read/write (`stor.c:604, 691`). And the harness
only lets me run CLI commands, not write a forged `enc.db`. So forging the global MAC
buys load-time acceptance but cannot make `read user1/file1` return tampered-but-valid
content, and there is no CLI path to inject the forged bytes. Real design flaw, worth
noting to the build-it side, but not a machine-checkable win under this grader.

### F4 — Vulnerable allocator: dlmalloc 2.7.2 with unsafe `unlink`  [SECURITY/CRASH — real, reachability UNCONFIRMED]
Root cause: `Makefile:5` links `malloc-2.7.2.c`, overriding libc `malloc`/`free`/
`realloc` (no `USE_DL_PREFIX`; confirmed exported as plain `malloc`/`free` via `nm`).
DEBUG is undefined so `check_inuse_chunk`/`check_free_chunk` are no-ops. The `unlink`
macro (`malloc-2.7.2.c:2132`) has **no `FD->bk==P && BK->fd==P` safe-unlink check** —
the textbook write-what-where primitive — and is reached from `fREe` on backward/forward
consolidation (`malloc-2.7.2.c:3776, 3786`). Binary is `-m32 -fno-stack-protector`,
executable stack, and ships an unused `win()` (`stor.c:84`) printing the security flag.

Why UNCONFIRMED: triggering unlink needs a heap **overflow** to forge chunk metadata.
`stor.c` sizes every `malloc` to its `memcpy` and has no app-level heap overflow I could
find. The on-disk `ciphertext_len` is bounds-checked (`stor.c:336-337`) and the
allocation matches the copy length (`stor.c:340-342`). The deserialise `fail:` loop
(`stor.c:359-367`) walks `j < file_count` over possibly-unallocated slots, but `g_db` is
a zero-initialised global and each CLI command is a fresh process, so those pointers are
NULL → safe. No reachable corruption found from the CLI surface. Flagging the allocator
as the intended security vector; needs a 32-bit Linux box + dynamic testing to weaponise
(cannot run here — macOS host, 32-bit ELF).

### F5 — Argon2id MODERATE allocations through the legacy allocator  [CRASH — LOW/SPECULATIVE]
`register` and every keyed op call `crypto_pwhash` (Argon2id MODERATE ≈ 256 MB).
libsodium's secure-memory path uses `mmap` directly, not the overridden `malloc`, so this
likely does not stress dlmalloc. Not pursued.

### Things checked and found SOUND (no break)
- File content crypto: XSalsa20-Poly1305 AEAD (`crypto_secretbox`), random nonce per
  write (`stor.c:656`), per-file key `BLAKE2b(user_key||owner||fname)` (`stor.c:504`).
  No ECB, no nonce reuse, no transplant — confidentiality of user2/file2 is NOT
  recoverable without the password. **No confidentiality claim made.**
- Key check is real: Argon2id + secretbox verifier of a 32-byte zero block
  (`stor.c:442-458`); accept-any / cross-user read not possible.
- Filename/username matching is exact 32-byte hash compare (`eq32`), no substring bug.
- Arg parsing: duplicate actions rejected (`stor.c:815`), unknown flags/positionals
  rejected (`stor.c:824-832`), last-wins for `-u/-k/-f/-i/-o`.
- Deserialise bounds, trailing-byte rejection (`stor.c:353`), dup user/file rejection.
- `-o` cannot overwrite the db (`same_file_as_db`, `stor.c:761-774`).

---

## Submitted drafts
- `correctness-stdin-ignored/` — F1. test.json (register/create/write-via-stdin/read)
  with top-level `expected` matching a stdin-reading oracle. HIGH confidence the build
  diverges; depends on oracle reading stdin (spec says it should).
