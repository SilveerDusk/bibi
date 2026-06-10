# Test Script Output

Date: 2026-06-10

Command:

```bash
docker run --rm --platform=linux/amd64 -v /Users/jasonjelincic/Coding/bibi/starter-package/build:/connect bibifi-sandbox -lc 'bash test.sh'
```

Exit code: 0

Output:

```text
mesg: ttyname failed: Inappropriate ioctl for device
gcc -O0 -g -fno-stack-protector -o stor stor.c malloc-2.7.2.c -lssl -lcrypto
malloc-2.7.2.c: In function 'realloc':
malloc-2.7.2.c:4163:17: warning: implicit declaration of function 'mremap'; did you mean 'munmap'? [-Wimplicit-function-declaration]
     cp = (char*)mremap((char*)oldp - offset, oldsize + offset, newsize, 1);
                 ^~~~~~
                 munmap
malloc-2.7.2.c:4163:10: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
     cp = (char*)mremap((char*)oldp - offset, oldsize + offset, newsize, 1);
          ^
execstack --set-execstack stor 2>/dev/null || true
=== TEST 1: Register ===
Exit: 0
=== TEST 2: Create ===
Exit: 0
=== TEST 3: Write ===
Exit: 0
=== TEST 4: Read ===
hello worldExit: 0
=== TEST 5: Wrong key ===
invalidExit: 255
=== TEST 6: Multi-user ===
Exit: 0
Exit: 0
Exit: 0
invalidExit (should be 255): 255
```
