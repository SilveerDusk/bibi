# Break-It — Attack Summary (all 11 targets)

Generated from static source review of every target's `stor.c` + `enc.db`, then
validated against the authoritative reference (`starter-package/build/stor.c`)
and functionality suite (`tests.json`). CPSLO-108 ships no source, so 11 targets.

Binaries are 32-bit Linux ELF; this host is macOS. Static analysis was confirmed
**dynamically** in the `bibifi-sandbox` Docker image (Ubuntu 18.04 / linux-amd64).

## Dynamic verification (sandbox) — ALL live breaks confirmed against freshly built binaries

Built with: `docker build --platform=linux/amd64 -t bibifi-sandbox -f Dockerfile.sandbox .`
Harness: `build/break_runner.py` compiles a target + the reference oracle, replays a
test.json against both, and reports per-command stdout/exit + whether they differ.

Run a correctness break vs the oracle:
```
docker run --rm --platform=linux/amd64 -v "$(pwd)":/repo -w /repo bibifi-sandbox -c \
  'python3 /repo/build/break_runner.py \
     --target-src "/repo/break-it-code/SMK-112/source/*/build" \
     --test /repo/break_drafts/SMK-112/correctness-reregister-allowed/test.json'
```

Confirmed results:
- **Integrity (SMK, GT, TPT, Husker)**: simulated the full grader scenario with a
  known key — real-key read returns `ORIGINAL_INTEGRITY_FLAG` before the attack and
  `invalid`/255 after the keyless `register user1`. Original content unrecoverable. ✅
- **Correctness re-register (×4)**: cmd[1] `register atk` again → target exit 0,
  oracle `invalid`/255. Differs on exit code (robust to whitespace trimming). ✅
- **UW_Tacoma re-create**: 2nd `create note` → target `invalid\n`/255, oracle ``/0.
  Differs on exit code. ✅
- **jojo write "read"**: write step → target `invalid`/255, oracle 0; read step →
  oracle prints `read`, target prints nothing. Differs on exit + stdout. ✅
- **via `register register`**: target `invalid\n`/255, oracle ``/0. Differs on exit. ✅
- **Trailing-newline (UW, jojo, via)**: target `invalid\n` vs oracle `invalid`; exit
  codes BOTH 255 — so the ONLY difference is the newline. VALID iff the grader does
  byte-exact stdout comparison; INVALID if it trims. (`DIFFERS(trimmed)=False`.) ⚠

## How the grader judges (recap)
- **correctness (25)**: target stdout/exit differs from the reference oracle.
  `expected[]` MUST equal the oracle's output (validated against `tests.json`).
- **crash (50)**: signal kill or >60s.
- **integrity (100)**: re-reading **user1/file1** with the REAL key returns
  content different from the original.
- **confidentiality (100)**: declared `output` matches **user2/file2** plaintext.
- **security (100)**: `Arbitrary access achieved!` appears in output.

---

## Scoreboard intel (from /contest/bibifi2026/scoreboard/scores.json, break phase early)

Defense — already broken (points lost): jojo −175, UW_Tacoma −150, GT −100; ALL
others 0. Offense leaders: TPT_Enterprise 175, 0xwizards 150, GreatTeam26 100.

Implications:
- Hardened four (0xwizards, GreatTeam26, sensodyne, kevwjin) have 0 breaks against
  them — corroborates "no viable break found." Skip.
- GT / jojo / UW_Tacoma already bleeding — our breaks there are real but likely to
  SPLIT points with other finders. Lower marginal value.
- **HIGH VALUE & UNIQUE: SMK-112, TPT_Enterprise-107, Husker_Bots-115 have ZERO
  breaks against them, yet we hold confirmed 100-pt integrity breaks on all three.**
  Full points, no split. TPT is also the top attacker — breaking it hurts the leader.
- Teams 108/110/111/113/116 are not in our break package; can't be attacked.

Submit order: (1) SMK integrity, (2) TPT integrity, (3) Husker integrity,
(4) via repeated-command, (5) SMK/TPT/Husker correctness fallbacks, (6) GT/jojo/UW.

## TL;DR — what to submit, in priority order

| Pri | Target | id | Type | Draft folder | Confidence |
|----|--------|----|------|--------------|-----------|
| 1 | SMK | 112 | integrity (100) | `SMK-112/integrity-reregister-takeover` | HIGH |
| 1 | GT | 101 | integrity (100) | `GT-101/integrity-register-takeover` | HIGH |
| 1 | TPT_Enterprise | 107 | integrity (100) | `TPT_Enterprise-107/integrity-reregister` | HIGH |
| 1 | Husker_Bots | 115 | integrity (100) | `Husker_Bots-115/integrity-reregister-takeover` | HIGH |
| 2 | SMK/GT/TPT/Husker | — | correctness (25) | `*/correctness-reregister-allowed` | VERY HIGH (fallback for the 4 above) |
| 3 | UW_Tacoma | 114 | correctness (25) | `UW_Tacoma-114/create-existing-file-mismatch` | HIGH |
| 3 | jojo | 109 | correctness (25) | `jojo-109/text-is-command-word` | HIGH |
| 4 | via | 102 | correctness (25) | `via-102/repeated-command-correctness` | MEDIUM |
| 5 | UW_Tacoma / jojo / via | — | correctness (25) | `*/…invalid-trailing-newline` | MEDIUM (grader-trim dependent) |

**Best expected haul:** 4 × 100-pt integrity (SMK, GT, TPT, Husker) + several
25-pt correctness. No penalty for misses, so submit the integrity + its
correctness fallback for all four re-register teams.

---

## The one big bug: unauthenticated re-register (account takeover)

Four teams' `register` handler overwrites an EXISTING user's salt/key-verifier
with no proof of the current key. The reference **rejects** re-register
(`starter-package/build/stor.c:333-335` → `invalid`/255).

| Team | id | Location | On re-register of existing user |
|------|----|----------|--------------------------------|
| SMK | 112 | `stor.c:181-214` | `memset(u_rec,0)` wipes ALL of user1's files, installs attacker key |
| GT | 101 | `stor.c:371-386` | overwrites salt/auth_tag, sets content_len=0 (wipes file content) |
| TPT_Enterprise | 107 | `stor.c:249-269,741-747` | `add_or_update_user` overwrites verifier, no key check |
| Husker_Bots | 115 | `stor.c:473-491` | re-derives `key_hash` from attacker key for existing user |

**Integrity (100):** after the attack, the REAL key no longer reads the original
file1 (verification fails / content wiped) → re-read returns `invalid` ≠ original
→ valid. Note: AEAD/GCM prevents producing a *valid* forged plaintext under the
real key (that needs the secret), so data destruction is the maximal lever — it
still satisfies "content different from the original."

**Correctness (25, fallback):** the same single `register user1 -k X` command
returns 0 on the target but `invalid`/255 on the oracle. This is near-certain and
does not depend on how the grader interprets data destruction. Submit both.

---

## Other correctness breaks

- **UW_Tacoma-114 — re-create existing file** (`stor.c:529` `die_invalid`). Target
  rejects a duplicate `create` (invalid/255); reference treats it as idempotent
  success exit 0 (`starter stor.c:360-361`). Differs in stdout AND exit. HIGH.
- **jojo-109 — inline write text equal to a command verb** (`args.c:84-95`). A
  `write` whose payload is literally `read`/`write`/`register`/`create` is parsed
  as a command token → `invalid`. Reference stores the bytes verbatim. We use
  `write "read"` then read back `read`. HIGH.
- **via-102 — repeated command token rejected** (`stor.c:502` `cmd_count != 1`).
  `register register` → via errors; reference treats the 2nd positional as
  (ignored) content and succeeds. MEDIUM.
- **Trailing newline on `invalid`** — UW_Tacoma (`stor.c:35`), jojo (`stor.c:28`
  `puts`), via (`stor.c:68`) all emit `invalid\n`; the reference emits `invalid`
  with no newline (`starter stor.c:48`). Valid IFF the grader does byte-exact
  stdout comparison (it may trim). MEDIUM; no penalty to try.

---

## Targets with NO viable break found (hardened)

Genuinely solid crypto + memory safety; only attack idea was the (invalid) stdin
one. Reported honestly — do not waste submissions.

- **0xwizards-105** — libsodium Argon2id + XChaCha20-Poly1305 AEAD, AAD-bound,
  length-prefixed bounds-checked parser. No memory/crypto/control-flow bug.
- **GreatTeam26-103** — AES-256-GCM + PBKDF2, AAD-bound, dup/re-register rejected.
- **sensodyne-104** — XSalsa20-Poly1305, real Argon2id. Has a *theoretical*
  forgeable global DB MAC (key = BLAKE2b(db_salt‖records), both on disk —
  `stor.c:182-193`) but per-file MAC is keyed by the secret and the harness only
  runs CLI commands (can't inject a forged enc.db), so it's not reachable here.
  Also links unsafe dlmalloc 2.7.2 + execstack, but no app-level heap overflow to
  weaponize was found. Worth a dynamic re-check in the sandbox.
- **kevwjin-106** — PBKDF2 + Encrypt-then-MAC (HMAC keystream), constant-time tag
  check, re-register rejected. Overflow-guarded sizes.

---

## REJECTED ideas (confirmed invalid — banners added to each draft)

- **"write ignores stdin" (correctness)** — drafted by agents for 9 teams.
  **INVALID:** the reference *also* ignores stdin for write (no stdin path in
  `starter-package/build/stor.c`; write input is inline `<text>` or `-i` only;
  `tests.json` never uses stdin for write). Both oracle and target store empty →
  outputs match → no break.
- **kevwjin "write with no input succeeds"** — reference also succeeds with an
  empty write (exit 0). No deviation.
- **TPT "create accepts stray -k"** — reference also ignores `-k` on create
  (`create_no_key_required` test); no deviation. Draft also had malformed
  `expected[]` keys.

---

## Per-team detail
Each `break_drafts/<team>/NOTES.md` has the full ranked analysis with line cites,
including all ruled-out categories and the reasoning. Confidentiality was NOT
claimed for any team — every target's content encryption is keyed by the secret
with no recoverable/derivable key, so user2/file2 is unrecoverable without it.
