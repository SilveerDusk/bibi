# Breaks tested against us (CPSLO, team 108)

Downloaded from https://hpen-bibi.com/participation/108/breaksubmissions. Last refresh: 2026-06-11 (third pull). 109 total submissions against us; 63 archived locally as `<id>-<name>/`.

## ⚠️ VALID breaks against us (13, all Active = UNFIXED)

| ID | Test | Attacker | Type | Severity | Archived |
|----|------|----------|------|----------|----------|
| 541 | correctness-create-no-user-CPSLO | jojo (109) | Correctness | 25 | ✅ |
| 888 | team108_huge_blob_length | 0xwizards (105) | Correctness | 25 | ✅ |
| 891 | team108_input_file_fifo_timeout | 0xwizards (105) | Crash | 50 🟠 | ✅ |
| 953 | cpslo108-integrity-empty-file | GreatTeam26 (103) | Integrity | 100 🔴 | ✅ |
| 978 | correctness-long-filename-CPSLO | jojo (109) | Correctness | 25 | ✅ |
| 979 | correctness-long-key-CPSLO | jojo (109) | Correctness | 25 | ✅ |
| 980 | correctness-long-username-CPSLO | jojo (109) | Correctness | 25 | ✅ |
| 1113 | create_no_user | 0xwizards (105) | Correctness | 25 | ✅ |
| 1116 | register_no_key | 0xwizards (105) | Correctness | 25 | ✅ |
| 1120 | write_before_create | 0xwizards (105) | Correctness | 25 | ✅ |
| 1357 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | 100 🔴 | ✅ |
| 1624 | team108-integrity-empty-file-forgery | sensodyne (104) | Integrity | 100 🔴 | ✅ |
| 1718 | cpslo108-crash-fifo-output | GreatTeam26 (103) | Crash | 50 🟠 | ✅ |

## Distinct VALID break classes (what to fix)
- **Confidentiality 100** — #987, #1357 (jojo): `key_hash` stored plaintext == AES key; enc.db reader extracts key. **Highest priority.**
- **Integrity 100** — #953 (GreatTeam26), #1624 (sensodyne): `encrypted_len==0` skips GCM verify → file1 emptied while real key still verifies.
- **Crash 50** — #891 (0xwizards): `write -i <FIFO>` hangs >60s. #1718 (GreatTeam26): `read -o <FIFO>`-style output crash.
- **Correctness 25** — #541/#1113 create-no-user; #1116 register-no-key; #978/#979/#980 long name/key/user (MAX_NAME `>=` off-by-one); #888 corrupt-db read; #1120 write-before-create.

**Note:** 46 breaks not archived locally — mostly Rejected tamper-variants whose `/download` returns 404 (artifacts not retained), plus 5 still Pending (#1596-1600).

## Full incoming log
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
| 987 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Rejected | Break invalid |
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
| 1118 | unknown_action | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1119 | unknown_option | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1120 | write_before_create | 0xwizards (105) | Correctness | Tested | ✅ valid |
| 1121 | wrong_key_rejected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1197 | team108_appended_magic_header_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1198 | team108_ascii_replacement_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1199 | team108_back_padding_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1200 | team108_clear_last_64_silent_empty | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1202 | team108_duplicate_prefix_crash | 0xwizards (105) | Crash | Rejected | Break invalid |
| 1204 | team108_flip_at_90_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1206 | team108_full_db_appended_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1207 | team108_middle_marker_forgery_undetected | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1296 | team108_ob_absolute_encdb_output_clobber | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1297 | team108_ob_dev_stdout_leak | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1298 | team108_ob_encdb_fifo_hang | 0xwizards (105) | Crash | Rejected | Break invalid |
| 1299 | team108_ob_encdb_hardlink_clobber | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1300 | team108_ob_encdb_symlink_followed | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1301 | team108_ob_fd1_stdout_leak | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1302 | team108_ob_fd2_stderr_leak | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1303 | team108_ob_input_hardlink_encdb | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1304 | team108_ob_input_symlink_encdb | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1305 | team108_ob_relative_encdb_output_clobber | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1306 | team108_ob_stdout_symlink_leak | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1307 | team108_ob_unreadable_encdb_reads | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1357 | confidentiality-recover-CPSLO | jojo (109) | Confidentiality | Tested | ✅ valid |
| 1472 | team108_ae_append_ff_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1473 | team108_ae_append_nul_undetected | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1474 | team108_ae_encdb_perms_644 | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1475 | team108_ae_filename_plaintext_in_db | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1476 | team108_ae_input_dev_full | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1477 | team108_ae_input_fifo_hang | 0xwizards (105) | Crash | Rejected | Break invalid |
| 1478 | team108_ae_input_symlink_dev_zero | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1479 | team108_ae_output_dev_full_accepted | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1480 | team108_ae_output_symlink_dev_full | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1481 | team108_ae_tamper_then_create | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1482 | team108_ae_tamper_then_register | 0xwizards (105) | Integrity | Rejected | Break invalid |
| 1483 | team108_ae_username_plaintext_in_db | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1484 | team108_ae_write_extra_positional_after_text | 0xwizards (105) | Correctness | Rejected | Break invalid |
| 1536 | r2-correctness-cpslo-long-read-user | jojo (109) | Correctness | Rejected | Break invalid |
| 1537 | r2-correctness-cpslo-long-write-file | jojo (109) | Correctness | Rejected | Break invalid |
| 1547 | team108-integrity | sensodyne (104) | Integrity | Rejected | Break invalid |
| 1560 | team108-integrity-empty-file-forgery | sensodyne (104) | Integrity | Rejected | Break invalid |
| 1569 | team108-integrity | sensodyne (104) | Integrity | Rejected | Break invalid |
| 1582 | team108-integrity-empty-file-forgery | sensodyne (104) | Integrity | Rejected | Break invalid |
| 1596 | team108_tm_read_o_existing_file_clobber | 0xwizards (105) | Correctness | Pending | — |
| 1597 | team108_tm_read_with_i_accepted | 0xwizards (105) | Correctness | Pending | — |
| 1598 | team108_tm_tampered_db_read_o_creates_output | 0xwizards (105) | Integrity | Pending | — |
| 1599 | team108_tm_tampered_db_read_undetected | 0xwizards (105) | Integrity | Pending | — |
| 1600 | team108_tm_write_with_o_accepted | 0xwizards (105) | Correctness | Pending | — |
| 1624 | team108-integrity-empty-file-forgery | sensodyne (104) | Integrity | Tested | ✅ valid |
| 1718 | cpslo108-crash-fifo-output | GreatTeam26 (103) | Crash | Tested | ✅ valid |
