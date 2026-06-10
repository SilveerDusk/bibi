#!/bin/bash
cd /connect
make -f Makefile.test 2>&1 | head -20

echo "=== TEST 1: Register ==="
./stor -u alice -k secret123 register
echo "Exit: $?"

echo "=== TEST 2: Create ==="
./stor -u alice -f notes create
echo "Exit: $?"

echo "=== TEST 3: Write ==="
./stor -u alice -k secret123 -f notes write "hello world"
echo "Exit: $?"

echo "=== TEST 4: Read ==="
./stor -u alice -k secret123 -f notes read
echo "Exit: $?"

echo "=== TEST 5: Wrong key ==="
./stor -u alice -k WRONGKEY -f notes read
echo "Exit: $?"

echo "=== TEST 6: Multi-user ==="
./stor -u bob -k bobkey register
echo "Exit: $?"
./stor -u bob -f secret create
echo "Exit: $?"
./stor -u bob -k bobkey -f secret write "bob-data"
echo "Exit: $?"
./stor -u bob -k alicekey -f secret read
echo "Exit (should be 255): $?"
