build:
	gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c
	execstack --set-execstack stor

clean:
	rm -f stor