#!/bin/bash
# Mirror the grader: copy sources, run `make` (real dlmalloc), then exercise it.
set -e
rm -rf /tmp/b && mkdir /tmp/b && cp /src/*.c /src/Makefile /tmp/b/
cd /tmp/b

echo "=== make build (with real dlmalloc-2.7.2) ==="
make build
echo "make rc=$?"
file ./stor | sed 's/,/\n  /g' | head -3

echo "=== confirm dlmalloc is linked (not glibc) ==="
# dlmalloc 2.7.2 brings its own malloc; check the symbol is defined in the binary text
nm ./stor 2>/dev/null | grep -E ' [Tt] malloc$' && echo "  -> malloc provided by the binary (dlmalloc)" \
  || echo "  -> WARNING: malloc not a local symbol"

echo "=== OpenSSL crypto path still works with dlmalloc ==="
rm -f enc.db
./stor -u alice -k secret123 register
./stor -u alice -f notes create
./stor -u alice -k secret123 -f notes write "Hello dlmalloc"
got=$(./stor -u alice -k secret123 -f notes read)
[ "$got" = "Hello dlmalloc" ] && echo "PASS round-trip: [$got]" || { echo "FAIL: [$got]"; exit 1; }

echo "=== time one auth op (PBKDF2 200k iters) ==="
start=$(date +%s%N)
./stor -u alice -k secret123 -f notes read >/dev/null
end=$(date +%s%N)
echo "  one read (load+PBKDF2+GCM) = $(( (end-start)/1000000 )) ms  (limit 60000)"
