CC     = gcc
LIBDIR = /usr/local/lib/mfdf
CFLAGS = -Wall -Wextra -L$(LIBDIR)
LIB    = -lmfdfuser

build:
	$(CC) demo.c -o demo-mfdf $(CFLAGS) $(LIB)
	$(CC) test-cases.c -o test-cases $(CFLAGS) $(LIB)
clean:
	$(RM) demo-mfdf test-cases
