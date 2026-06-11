#!/bin/bash
# Smoke test for stor — run inside the bibifi container.
set -u
cd /tmp
rm -f enc.db stor out.txt in.txt
cp /src/*.c /src/Makefile /tmp/

echo "=== compile ==="
gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c -lssl -lcrypto
echo "compile rc=$?"
[ -x ./stor ] || { echo "BUILD FAILED"; exit 1; }

pass=0; fail=0
check() { # desc  expected  actual
  if [ "$2" = "$3" ]; then echo "PASS: $1"; pass=$((pass+1));
  else echo "FAIL: $1 (expected [$2] got [$3])"; fail=$((fail+1)); fi
}

echo "=== basic round-trip (inline text) ==="
./stor -u alice -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "Hello"
out=$(./stor -u alice -k secret123 -f notes read)
check "read returns written content" "Hello" "$out"

echo "=== empty-content round-trip (write \"\" then read) ==="
./stor -u alice -k secret123 -f notes write ""
out=$(./stor -u alice -k secret123 -f notes read); rc=$?
check "empty write read-back is empty" "" "$out"
check "empty write read-back exit 0" "0" "$rc"
# restore content for later tests
./stor -u alice -k secret123 -f notes write "Hello"

echo "=== wrong key -> invalid / 255 ==="
out=$(./stor -u alice -k WRONG -f notes read); rc=$?
check "wrong key prints invalid" "invalid" "$out"
check "wrong key exit 255" "255" "$rc"

echo "=== stdin write ==="
printf 'world' | ./stor -u alice -k secret123 -f notes write
out=$(./stor -u alice -k secret123 -f notes read)
check "stdin content" "world" "$out"

echo "=== -i / -o flags ==="
printf 'fromfile' > in.txt
./stor -u alice -k secret123 -f notes write -i in.txt
./stor -u alice -k secret123 -f notes read -o out.txt
check "-i/-o round-trip" "fromfile" "$(cat out.txt)"

echo "=== second user, same secret, different file ==="
./stor -u bob -k secret123 register
./stor -u bob -f bobfile create
./stor -u bob -k secret123 -f bobfile write "bobdata"
check "bob reads own file" "bobdata" "$(./stor -u bob -k secret123 -f bobfile read)"
check "alice still intact"   "fromfile" "$(./stor -u alice -k secret123 -f notes read)"

echo "=== forgery: flip a byte in enc.db -> invalid, not crash ==="
cp enc.db enc.db.bak
# flip the last byte (inside bob's ciphertext/tag) to a guaranteed-different value
sz=$(stat -c %s enc.db)
off=$((sz-1))
orig=$(od -An -tu1 -j "$off" -N1 enc.db | tr -d ' ')
newv=$(( (orig+1) % 256 ))
printf "$(printf '\\x%02x' "$newv")" | dd of=enc.db bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
out=$(./stor -u bob -k secret123 -f bobfile read 2>/dev/null); rc=$?
check "tampered db prints invalid" "invalid" "$out"
check "tampered db exit 255 (no crash)" "255" "$rc"
cp enc.db.bak enc.db

echo "=== forgery: truncated db -> invalid, not crash ==="
head -c 20 enc.db > enc.db.trunc; mv enc.db.trunc enc.db
out=$(./stor -u bob -k secret123 -f bobfile read 2>/dev/null); rc=$?
check "truncated db invalid" "invalid" "$out"
check "truncated db exit 255 (no crash)" "255" "$rc"
cp enc.db.bak enc.db

echo "=== forgery: appended junk -> invalid ==="
printf 'JUNKJUNK' >> enc.db
out=$(./stor -u bob -k secret123 -f bobfile read 2>/dev/null); rc=$?
check "appended junk invalid" "invalid" "$out"
cp enc.db.bak enc.db

echo "=== forgery: oversized size field (overflow attempt) -> invalid, not crash ==="
# header = magic(4)+version(4); first record's size field is bytes 12..15.
# Set it to 0xFFFFFFFF to attempt the 32-bit (pos+size) overflow.
printf '\xff\xff\xff\xff' | dd of=enc.db bs=1 seek=12 count=4 conv=notrunc 2>/dev/null
out=$(./stor -u bob -k secret123 -f bobfile read 2>/dev/null); rc=$?
check "overflow size invalid" "invalid" "$out"
check "overflow size exit 255 (no segfault)" "255" "$rc"
cp enc.db.bak enc.db

echo "=== long username (200 chars) round-trip ==="
rm -f enc.db
longu=$(printf 'u%.0s' {1..200})
./stor -u "$longu" -k pw register
./stor -u "$longu" -f lf create
./stor -u "$longu" -k pw -f lf write "longname-ok"
check "200-char username round-trip" "longname-ok" "$(./stor -u "$longu" -k pw -f lf read)"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $fail
