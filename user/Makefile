CC     = gcc
IDIR   = include/
CFLAGS = -I$(IDIR) -Wall -Wextra -fPIC
PREFIX = /usr/local

build:
	$(CC) -c $(CFLAGS) lib/user.c -o lib/user.o
	$(CC) -shared -o lib/libuser.so lib/user.o

install:
	mkdir -p $(PREFIX)/lib/mfdf
	install -m 755 include/user.h $(PREFIX)/include/mfdf/user.h
	install -m 755 lib/libuser.so $(PREFIX)/lib/mfdf/libuser.so
	ldconfig $(PREFIX)/lib

.PHONY: clean

clean:
	$(RM) lib/user.o lib/libuser.so

clean-all: clean
	$(RM) $(PREFIX)/include/mfdf/user.h $(PREFIX)/lib/mfdf/libuser.so
