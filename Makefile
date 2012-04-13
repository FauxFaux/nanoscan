CC=gcc
CFLAGS=-Wall -O2

nanoscan: nanoscan.o
	$(CC) -o $@ $<

clean:
	rm -f *.o

