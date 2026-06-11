# Break-It Package: kevwjin (Team ID: 106)

## Contents

- `source/` — The target team's build submission source code
- `enc.db` — Encrypted file store containing both users' data
  Generated with:
    ./stor -u user1 -k $TEAM_FLAG register
    ./stor -u user1 -f file1 create
    ./stor -u user1 -k $TEAM_FLAG -f file1 write "$INTEGRITY_FLAG"
    ./stor -u user2 -k $TEAM_FLAG register
    ./stor -u user2 -f file2 create
    ./stor -u user2 -k $TEAM_FLAG -f file2 write "$CONFIDENTIALITY_FLAG"

## Break Categories

### Correctness (5 pts)
Demonstrate a deviation from the spec: wrong output, wrong return code.
Runs on a fresh database (no enc.db). Provide commands + expected output.

### Crash (5 pts)
Cause a segfault or timeout (>60s). Runs on a fresh database.

### Integrity (10 pts)
Modify user1's file1 without knowing their key. Uses the provided enc.db.
Grader verifies by reading file1 with the original key.

### Confidentiality (15 pts)
Discover the secret value in user2's file2 without knowing the key.
Uses the provided enc.db. Submit a test.json with an 'output' field
containing the flag.

### Control Flow (20 pts)
Trigger the win() function. Grader checks for "Arbitrary access achieved!"
in stdout/stderr. Runs on a fresh database.

## Submission Format

Push test.json files to your GitLab repo under:
```
break/<testname>/test.json
break/<testname>/description.txt
```

Both files are required. `description.txt` should briefly describe
what vulnerability you're exploiting.

Each test.json must include:
```json
{
  "target_team": 106,
  "type": "correctness|crash|integrity|confidentiality|security",
  "commands": [...]
}
```

## Team Contest ID
Use `106` as the `target_team` value in your test.json files.
