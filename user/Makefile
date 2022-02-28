CC        = gcc
ARC       = ar rcs
CFLAGS    = -Wall -Wextra
GLOBALLIB = /usr/local/lib/mfdf
GLOBALHDR = /usr/local/include/mfdf

build:
	$(CC) -c user.c -o user.o $(CFLAGS)
	$(ARC) libmfdfuser.a user.o

install:
	mkdir -p $(GLOBALLIB)
	install -m 644 user.h $(GLOBALHDR)/user.h
	install -m 755 libmfdfuser.a $(GLOBALLIB)/libmfdfuser.a

.PHONY: clean, clean-all

clean:
	$(RM) -r user.o libmfdfuser.a

clean-all: clean
	$(RM) $(GLOBALLIB)/libmfdfuser.a $(GLOBALHDR)/user.h

