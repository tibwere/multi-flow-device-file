CC     = gcc
LIBDIR = /usr/local/lib/mfdf
CFLAGS = -Wall -Wextra -L$(LIBDIR)
LIB    = -lmfdfuser

build:
	$(CC) demo.c common.c -o demo-mfdf $(CFLAGS) $(LIB)
	$(CC) test-cases.c common.c -o test-cases $(CFLAGS) $(LIB) -pthread
clean:
	$(RM) demo-mfdf test-cases
