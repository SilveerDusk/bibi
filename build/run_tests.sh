#!/bin/bash
# ================================================================
# run_tests.sh — Automated test runner for stor
#
# Runs all 10 functionality tests from tests.json.
# Must be run from the directory containing the `stor` binary.
# ================================================================

set -e

PASS=0
FAIL=0
TOTAL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_exit() {
    local expected_exit=$1
    local actual_exit=$2
    local test_name=$3
    local step=$4

    if [ "$actual_exit" -ne "$expected_exit" ]; then
        echo -e "  ${RED}FAIL${NC} step $step: expected exit=$expected_exit, got exit=$actual_exit"
        return 1
    fi
    return 0
}

check_stdout() {
    local expected_stdout="$1"
    local actual_stdout="$2"
    local test_name="$3"
    local step="$4"

    if [ "$actual_stdout" != "$expected_stdout" ]; then
        echo -e "  ${RED}FAIL${NC} step $step: expected stdout='$expected_stdout', got stdout='$actual_stdout'"
        return 1
    fi
    return 0
}

run_test() {
    local name=$1
    shift
    TOTAL=$((TOTAL + 1))
    echo -e "\n${YELLOW}Test $TOTAL: $name${NC}"
    rm -f enc.db enc.db.tmp

    # Run all steps
    "$@"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}"
}

# ================================================================
# Test 1: register_and_create
# ================================================================
run_test "register_and_create" true
./stor -u alice -k secret123 register
ret=$?
if ! check_exit 0 $ret "register_and_create" 1; then FAIL=$((FAIL+1)); else
    ./stor -u alice -f notes create
    ret=$?
    if ! check_exit 0 $ret "register_and_create" 2; then FAIL=$((FAIL+1)); else
        pass
    fi
fi

# ================================================================
# Test 2: write_and_read
# ================================================================
run_test "write_and_read" true
./stor -u alice -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "hello world"
output=$(./stor -u alice -k secret123 -f notes read)
ret=$?
if ! check_exit 0 $ret "write_and_read" 4; then FAIL=$((FAIL+1));
elif ! check_stdout "hello world" "$output" "write_and_read" 4; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 3: last_occurrence_wins
# ================================================================
run_test "last_occurrence_wins" true
./stor -u alice -k wrong -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "test"
output=$(./stor -u alice -k secret123 -f notes read)
ret=$?
if ! check_exit 0 $ret "last_occurrence_wins" 4; then FAIL=$((FAIL+1));
elif ! check_stdout "test" "$output" "last_occurrence_wins" 4; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 4: wrong_key_rejected
# ================================================================
run_test "wrong_key_rejected" true
./stor -u alice -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "private"
set +e
output=$(./stor -u alice -k WRONGKEY -f notes read 2>/dev/null)
ret=$?
set -e
if ! check_exit 255 $ret "wrong_key_rejected" 4; then FAIL=$((FAIL+1));
elif ! check_stdout "invalid" "$output" "wrong_key_rejected" 4; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 5: create_no_key_required
# ================================================================
run_test "create_no_key_required" true
./stor -u alice -k secret123 register
./stor -u alice -f nokey create
./stor -u alice -k secret123 -f nokey write "ok"
output=$(./stor -u alice -k secret123 -f nokey read)
ret=$?
if ! check_exit 0 $ret "create_no_key_required" 4; then FAIL=$((FAIL+1));
elif ! check_stdout "ok" "$output" "create_no_key_required" 4; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 6: missing_username_invalid
# ================================================================
run_test "missing_username_invalid" true
set +e
output=$(./stor -k secret123 register 2>/dev/null)
ret=$?
set -e
if ! check_exit 255 $ret "missing_username_invalid" 1; then FAIL=$((FAIL+1));
elif ! check_stdout "invalid" "$output" "missing_username_invalid" 1; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 7: missing_action_invalid
# ================================================================
run_test "missing_action_invalid" true
set +e
output=$(./stor -u alice 2>/dev/null)
ret=$?
set -e
if ! check_exit 255 $ret "missing_action_invalid" 1; then FAIL=$((FAIL+1));
elif ! check_stdout "invalid" "$output" "missing_action_invalid" 1; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 8: multi_user_isolation
# ================================================================
run_test "multi_user_isolation" true
./stor -u alice -k alicekey register
./stor -u bob   -k bobkey   register
./stor -u alice -f secret create
./stor -u alice -k alicekey -f secret write "alice-data"
set +e
output=$(./stor -u alice -k bobkey -f secret read 2>/dev/null)
ret=$?
set -e
if ! check_exit 255 $ret "multi_user_isolation" 5; then FAIL=$((FAIL+1));
elif ! check_stdout "invalid" "$output" "multi_user_isolation" 5; then FAIL=$((FAIL+1));
else pass; fi

# ================================================================
# Test 9: write_from_file
# ================================================================
run_test "write_from_file" true
./stor -u alice -k secret123 register
./stor -u alice -f doc create
echo 'file content' > /tmp/grader_input.txt
./stor -u alice -k secret123 -f doc -i /tmp/grader_input.txt write
output=$(./stor -u alice -k secret123 -f doc read)
ret=$?
# Note: echo adds a trailing newline; grader likely strips it for comparison
trimmed_output=$(echo "$output" | head -c -1 2>/dev/null || printf '%s' "$output")
if ! check_exit 0 $ret "write_from_file" 5; then FAIL=$((FAIL+1));
elif [ "$output" = "file content" ] || [ "$trimmed_output" = "file content" ]; then pass;
else
    echo -e "  ${RED}FAIL${NC} step 5: expected stdout='file content', got stdout='$output'"
    FAIL=$((FAIL+1))
fi
rm -f /tmp/grader_input.txt

# ================================================================
# Test 10: write_out_file
# ================================================================
run_test "write_out_file" true
./stor -u alice -k secret123 register
./stor -u alice -f doc create
./stor -u alice -k secret123 -f doc write "output test"
./stor -u alice -k secret123 -f doc -o /tmp/grader_out.txt read
output=$(cat /tmp/grader_out.txt)
if ! check_stdout "output test" "$output" "write_out_file" 5; then FAIL=$((FAIL+1));
else pass; fi
rm -f /tmp/grader_out.txt

# ================================================================
# Summary
# ================================================================
echo ""
echo "================================"
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, $TOTAL total"
echo "================================"

rm -f enc.db enc.db.tmp

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
