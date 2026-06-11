#!/bin/bash
# Adversary probes — document this binary's ACTUAL behavior on spec-ambiguous
# cases a Break-It team would submit as correctness tests.
cd /tmp
cp /src/*.c /src/Makefile /tmp/ 2>/dev/null
gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c -lssl -lcrypto || exit 1

probe() { echo; echo ">>> $1"; }
show()  { echo "    stdout=[$1] exit=$2"; }

rm -f enc.db
./stor -u u1 -k sk register
./stor -u u1 -f f1 create

probe "read a created-but-never-written file"
out=$(./stor -u u1 -k sk -f f1 read); rc=$?; show "$out" "$rc"

probe "write with stray -o (output flag on write)"
out=$(./stor -u u1 -k sk -f f1 -o /tmp/x.txt write "hi"); rc=$?; show "$out" "$rc"

probe "read with a stray inline <text> argument"
out=$(./stor -u u1 -k sk -f f1 read EXTRA); rc=$?; show "$out" "$rc"

probe "create a file for an UNREGISTERED user"
out=$(./stor -u ghost -f gf create); rc=$?; show "$out" "$rc"

probe "register with an EMPTY key"
rm -f enc.db; out=$(./stor -u e -k '' register); rc=$?; show "$out" "$rc"

probe "register with an EMPTY username"
out=$(./stor -u '' -k k register); rc=$?; show "$out" "$rc"

probe "write with NO -i, NO inline text, EMPTY stdin"
rm -f enc.db; ./stor -u w -k k register >/dev/null; ./stor -u w -f wf create >/dev/null
out=$(printf '' | ./stor -u w -k k -f wf write); rc=$?; show "$out" "$rc"
out=$(./stor -u w -k k -f wf read); rc=$?; show "read-back=[$out]" "$rc"

probe "DoS attempt: 200MB stdin write (cap is 64MB) — time it"
rm -f enc.db; ./stor -u d -k k register >/dev/null; ./stor -u d -f df create >/dev/null
t0=$(date +%s.%N)
out=$(head -c 209715200 /dev/zero | ./stor -u d -k k -f df write 2>/dev/null); rc=$?
t1=$(date +%s.%N)
show "$out" "$rc"; echo "    elapsed=$(echo "$t1 - $t0" | bc)s"

probe "huge -u argument (1MB) — overflow/crash check"
out=$(./stor -u "$(head -c 1048576 /dev/zero | tr '\0' 'A')" -k k register 2>/dev/null); rc=$?; show "$out" "$rc"
