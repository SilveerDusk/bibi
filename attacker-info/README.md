# Breaks tested against us (CPSLO, team 108)

Downloaded from https://hpen-bibi.com/participation/108/breaksubmissions. Last refresh: 2026-06-11 (second pull).
Each folder is `<submission_id>-<test_name>/` with the attacker's `test.json`, `description.txt`, and a `break_meta.json` sidecar.

## ⚠️ VALID breaks against us (all fix-status Active = UNFIXED)

| ID | Test | Attacker | Type | Severity |
|----|------|----------|------|----------|
| 541 | correctness-create-no-user-CPSLO | jojo (109) | Correctness | 25 |
| 888 | team108_huge_blob_length | 0xwizards (105) | Correctness | 25 |
| 891 | team108_input_file_fifo_timeout | 0xwizards (105) | Crash | 50 🟠 |
| 953 | cpslo108-integrity-empty-file | GreatTeam26 (103) | Integrity | 100 🔴 |
| 978 | correctness-long-filename-CPSLO | jojo (109) | Correctness | 25 |
| 979 | correctness-long-key-CPSLO | jojo (109) | Correctness | 25 |
| 980 | correctness-long-username-CPSLO | jojo (109) | Correctness | 25 |
| 987 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | 100 🔴 |
| 1113 | create_no_user | 0xwizards (105) | Correctness | 25 |
| 1116 | register_no_key | 0xwizards (105) | Correctness | 25 |

## All incoming breaks (full log)

| ID | Test | Attacker | Type | Status | Result |
|----|------|----------|------|--------|--------|
| 530 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Rejected | Break invalid |
| 541 | correctness-create-no-user-CPSLO | jojo (109) | Correctness | Tested | ✅ valid |
| 596 | correctness-cpslo-dup-create | jojo (109) | Correctness | Rejected | Break invalid |
| 597 | correctness-cpslo-empty-file | jojo (109) | Correctness | Rejected | Break invalid |
| 598 | correctness-cpslo-empty-key | jojo (109) | Correctness | Rejected | Break invalid |
| 599 | correctness-cpslo-empty-user | jojo (109) | Correctness | Rejected | Break invalid |
| 602 | correctness-empty-filename-CPSLO | jojo (109) | Correctness | Rejected | Break invalid |
| 603 | correctness-empty-key-CPSLO | jojo (109) | Correctness | Rejected | Break invalid |
| 604 | correctness-empty-username-CPSLO | jojo (109) | Correctness | Rejected | Break invalid |
| 653 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Rejected | Break invalid |
| 654 | crash-dlmalloc-CPSLO | jojo (109) | Crash | Rejected | Break invalid |
| 655 | integrity-forge-CPSLO | jojo (109) | Integrity | Rejected | Break invalid |
| 656 | security-shellcode-CPSLO | jojo (109) | Security | Rejected | Break invalid |
| 883 | team108_corrupt_db_accepted | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 884 | team108_create_extra_positional | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 885 | team108_empty_filename | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 886 | team108_empty_username | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 887 | team108_encdb_output_clobber | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 888 | team108_huge_blob_length | 0xwizards (105) | Correctness | Tested | ✅ valid |
| 889 | team108_huge_user_count | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 890 | team108_input_file_device | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 891 | team108_input_file_fifo_timeout | 0xwizards (105) | Crash | Tested | ✅ valid |
| 892 | team108_input_file_is_directory | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 893 | team108_long_key_roundtrip | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 894 | team108_oversized_input_file | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 896 | team108_read_extra_positional | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 897 | team108_register_extra_positional | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 898 | team108_trailing_junk_detected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 899 | team108_write_extra_positional | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 952 | cpslo108-confidentiality-stored-key | GreatTeam26 (103) | Confidentiality | Rejected | Break invalid |
| 953 | cpslo108-integrity-empty-file | GreatTeam26 (103) | Integrity | Tested | ✅ valid |
| 956 | t108_confidentiality-stored-keyhash | GreatTeam26 (103) | Confidentiality | Rejected | Break invalid |
| 957 | t108_crash-db-count-overflow | GreatTeam26 (103) | Crash | Rejected | Break invalid |
| 958 | t108_integrity-stored-keyhash-patch | GreatTeam26 (103) | Integrity | Rejected | Break invalid |
| 959 | CPSLO108-aad-collision-user-file | TPT_Enterprise (107) | Integrity | Rejected | Break invalid |
| 967 | team108-integrity | sensodyne (104) | Integrity | Rejected | Break invalid |
| 968 | CPSLO108-win-control-flow-override | TPT_Enterprise (107) | Security | Rejected | Break invalid |
| 978 | correctness-long-filename-CPSLO | jojo (109) | Correctness | Tested | ✅ valid |
| 979 | correctness-long-key-CPSLO | jojo (109) | Correctness | Tested | ✅ valid |
| 980 | correctness-long-username-CPSLO | jojo (109) | Correctness | Tested | ✅ valid |
| 984 | correctness-write-empty-filename-CPSLO | jojo (109) | Correctness | Rejected | Break invalid |
| 985 | correctness-write-empty-key-CPSLO | jojo (109) | Correctness | Rejected | Break invalid |
| 987 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Tested | ✅ valid |
| 989 | integrity-forge-CPSLO | jojo (109) | Integrity | Rejected | Break invalid |
| 1029 | team108_appended_forgery_accepted | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1030 | team108_bitflip_tamper_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1031 | team108_integrity_target_tamper_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1032 | team108_rollback_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1033 | team108_second_file_tamper_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1034 | team108_tampered_db_create_accepted | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1035 | team108_tampered_db_write_accepted | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1111 | action_wrong_case | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1112 | create_no_file | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1113 | create_no_user | 0xwizards (105) | Correctness | Tested | ✅ valid |
| 1114 | filebomb_many_small | 0xwizards (105) | Crash | Rejected | Break invalid |
| 1115 | large_binary_file_roundtrip | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1116 | register_no_key | 0xwizards (105) | Correctness | Tested | ✅ valid |
| 1117 | tamper_filename_detected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1118 | unknown_action | 0xwizards (105) | Correctness | Testing | — |
| 1119 | unknown_option | 0xwizards (105) | Correctness | Pending | — |
| 1120 | write_before_create | 0xwizards (105) | Correctness | Pending | — |
| 1121 | wrong_key_rejected | 0xwizards (105) | Correctness | Pending | — |

## Root-cause summary of the VALID breaks
- **#987 Confidentiality (jojo)** — `enc.db` stores `key_hash` (PBKDF2 output) in plaintext, and that SAME value is used directly as the AES-256-GCM key. Anyone who reads enc.db extracts the key and decrypts user2/file2. Recovered flag: `f954f202f6ec0f0a1bdd082f95d104ebe06e742ab9813a1f`. **Fix: derive the AES key separately from the stored verifier (e.g. distinct KDF labels / HKDF), never store the encryption key.**
- **#953 Integrity (GreatTeam26)** — `read` treats `encrypted_len==0` as an empty file and SKIPS AES-GCM verification. Rewriting enc.db to set user1/file1 ct-len to 0 empties file1 while user1's real key still verifies. **Fix: always run GCM tag verification; do not special-case len==0.**
- **#891 Crash (0xwizards)** — `write -i <FIFO>` blocks forever (>60s) reading an input FIFO with no writer. **Fix: don't open/read regular-file inputs that are FIFOs/devices, or bound the read.**
- **#978/#979/#980 Correctness (jojo)** — off-by-one: `MAX_NAME=256` with `strlen >= 256` rejects valid 256-char username/key/filename; reference accepts up to 4096. **Fix: use `>` not `>=`, and match the reference's length cap.**
- **#888 Correctness (0xwizards)** — a read after corrupting enc.db metadata still returns content (we don't detect the tamper) where the oracle rejects it. **Fix: authenticate db metadata / detect corruption on load.**
- **#1116 Correctness (0xwizards)** — `register` with no `-k` succeeds; must be invalid/255. **Fix: require a key for register.**
- **#541/#1113 Correctness (jojo / 0xwizards)** — `create` for an unregistered user succeeds; must be invalid/255. **Fix: reject create when the user does not exist.**

**Pending/Testing (not yet judged):** #1118 unknown_action, #1119 unknown_option, #1120 write_before_create, #1121 wrong_key_rejected (all 0xwizards).
