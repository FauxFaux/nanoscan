CC=gcc 
CFLAGS=-Wall

nanoscan: nanoscan.o
	$(CC) -o $@ $<

clean:
	rm -f *.o

