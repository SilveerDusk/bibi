# Breaks tested against us (CPSLO, team 108)

Downloaded from https://hpen-bibi.com/participation/108/breaksubmissions on 2026-06-11.
Each folder is `<submission_id>-<test_name>/` with the attacker's `test.json`, `description.txt`, and a `break_meta.json` sidecar.

**Pending (not yet downloadable):** 16 correctness/crash/integrity breaks from 0xwizards (105), submission IDs 883-899 — `/download` returns "not available yet". Re-pull once tested.

| ID | Test | Attacker | Type | Status | Result | Fix |
|----|------|----------|------|--------|--------|-----|
| 530 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Rejected | Break invalid | — |
| 541 | correctness-create-no-user-CPSLO | jojo (109) | Correctness | Tested | ✅ **Break valid** | Active |
| 596 | correctness-cpslo-dup-create | jojo (109) | Correctness | Rejected | Break invalid | — |
| 597 | correctness-cpslo-empty-file | jojo (109) | Correctness | Rejected | Break invalid | — |
| 598 | correctness-cpslo-empty-key | jojo (109) | Correctness | Rejected | Break invalid | — |
| 599 | correctness-cpslo-empty-user | jojo (109) | Correctness | Rejected | Break invalid | — |
| 602 | correctness-empty-filename-CPSLO | jojo (109) | Correctness | Rejected | Break invalid | — |
| 603 | correctness-empty-key-CPSLO | jojo (109) | Correctness | Rejected | Break invalid | — |
| 604 | correctness-empty-username-CPSLO | jojo (109) | Correctness | Rejected | Break invalid | — |
| 653 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Rejected | Break invalid | — |
| 654 | crash-dlmalloc-CPSLO | jojo (109) | Crash | Rejected | Break invalid | — |
| 655 | integrity-forge-CPSLO | jojo (109) | Integrity | Rejected | Break invalid | — |
| 656 | security-shellcode-CPSLO | jojo (109) | Security | Rejected | Break invalid | — |

## The one valid break against us
**#541 `correctness-create-no-user-CPSLO`** (jojo) — `create` succeeds for a never-registered user; spec requires `invalid`/255. Status **Active** (unfixed). This is the only confirmed hole in our build.

## Notable rejected-but-informative
- **#653 `confidentiality-recover-CPSLO`** — jojo harvested user2/file2's real PBKDF2 salt/key_hash/iv/tag/ciphertext from our `enc.db` and is attempting an offline `hashcat -m 12000` crack. Rejected (flag not cracked), but shows our enc.db material is exposed to attackers. See its description.txt.
