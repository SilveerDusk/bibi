# Sweep manifest — turnaround attacks built across all teams

Generated from the differential sweep. Oracle = `build/` (per instruction). **Not yet verified against the grader's true reference** (`build/stor-old.c`) — see caveats.

Confidence legend: **HIGH**=robust/crash, **LOW**=trailing-newline-only (grader-trim dependent), **CONTESTED**=long-* depends on oracle (build/ vs stor-old.c).

| Target | Team | Probe | Type | Confidence |
|--------|------|-------|------|-----------|
| 101 | GT | fifo-hang | crash | HIGH (crash) |
| 102 | via | fifo-hang | crash | HIGH (crash) |
| 104 | sensodyne | fifo-hang | crash | HIGH (crash) |
| 106 | kevwjin | fifo-hang | crash | HIGH (crash) |
| 107 | tpt | create-no-user | correctness | HIGH |
| 107 | tpt | fifo-hang | crash | HIGH (crash) |
| 109 | jojo | fifo-hang | crash | HIGH (crash) |
| 112 | SMK | fifo-hang | crash | HIGH (crash) |
| 114 | uw | fifo-hang | crash | HIGH (crash) |
| 115 | husker | fifo-hang | crash | HIGH (crash) |
| 102 | via | corrupt-db | correctness | LOW (newline) |
| 102 | via | create-no-user | correctness | LOW (newline) |
| 102 | via | register-no-key | correctness | LOW (newline) |
| 109 | jojo | create-no-user | correctness | LOW (newline) |
| 109 | jojo | register-no-key | correctness | LOW (newline) |
| 114 | uw | create-no-user | correctness | LOW (newline) |
| 114 | uw | register-no-key | correctness | LOW (newline) |
| 101 | GT | long-key | correctness | CONTESTED |
| 102 | via | long-filename | correctness | CONTESTED |
| 102 | via | long-key | correctness | CONTESTED |
| 102 | via | long-username | correctness | CONTESTED |
| 103 | greatteam26 | long-filename | correctness | CONTESTED |
| 103 | greatteam26 | long-key | correctness | CONTESTED |
| 103 | greatteam26 | long-username | correctness | CONTESTED |
| 104 | sensodyne | long-key | correctness | CONTESTED |
| 105 | wizards | long-filename | correctness | CONTESTED |
| 105 | wizards | long-key | correctness | CONTESTED |
| 105 | wizards | long-username | correctness | CONTESTED |
| 106 | kevwjin | long-filename | correctness | CONTESTED |
| 106 | kevwjin | long-key | correctness | CONTESTED |
| 106 | kevwjin | long-username | correctness | CONTESTED |
| 107 | tpt | long-filename | correctness | CONTESTED |
| 109 | jojo | long-filename | correctness | CONTESTED |
| 109 | jojo | long-key | correctness | CONTESTED |
| 109 | jojo | long-username | correctness | CONTESTED |
| 112 | SMK | long-key | correctness | CONTESTED |
| 114 | uw | long-filename | correctness | CONTESTED |
| 114 | uw | long-key | correctness | CONTESTED |
| 114 | uw | long-username | correctness | CONTESTED |

## Summary by confidence
- **HIGH (submit-ready):** 10 — all 9 FIFO crashes + tpt create-no-user.
- **LOW (newline-only):** 7 — only valid if grader does byte-exact stdout compare.
- **CONTESTED (long-*):** 22 — verify against build/stor-old.c first; likely INVALID if grader ref accepts 256-char.

## Not built (need manual per-team analysis, not mechanically verifiable)
- **#987 confidentiality** (key_hash == AES key) and **#953 integrity** (encrypted_len==0 skips GCM) — require per-team enc.db/crypto reverse-engineering.
