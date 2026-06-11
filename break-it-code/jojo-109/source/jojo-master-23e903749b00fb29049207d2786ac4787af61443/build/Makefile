# Build for the HPE Build-It "stor" entry.
#
# Mandated build line (do not change the flags or the malloc-2.7.2.c link):
#   gcc -O0 -g -m32 -fno-stack-protector -o stor <sources> malloc-2.7.2.c
# Mandated post step:
#   execstack --set-execstack stor
#
# `all` (the default target) chains build -> post so a bare `make` produces the
# execstack-marked ./stor. The grader may also invoke `build` or `post` by name.

CC      = gcc
CFLAGS  = -O0 -g -m32 -fno-stack-protector
SOURCES = stor.c args.c db.c cmd.c io.c malloc-2.7.2.c
LDLIBS  = -lsodium
TARGET  = stor

.PHONY: all build post clean

all: build post

build:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDLIBS)

post:
	execstack --set-execstack $(TARGET)

clean:
	rm -f $(TARGET) *.o enc.db
