CC        = gcc
ARC       = ar rcs
CFLAGS    = -Wall -Wextra
GLOBALLIB = /usr/local/lib/mfdf
GLOBALHDR = /usr/local/include/mfdf
GLOBALMAN = /usr/local/share/man/man0p

build:
	$(CC) -c user.c -o user.o $(CFLAGS)
	$(ARC) libmfdfuser.a user.o

build-man:
	pandoc manpages/mfdf_user.h.0p.md -s -t man -o manpages/mfdf_user.h.0p

install: build build-man
	mkdir -p $(GLOBALLIB)
	mkdir -p $(GLOBALMAN)
	install -m 644 user.h $(GLOBALHDR)/user.h
	install -m 755 libmfdfuser.a $(GLOBALLIB)/libmfdfuser.a
	install -m 644 manpages/mfdf_user.h.0p $(GLOBALMAN)/mfdf_user.h.0p
	gzip $(GLOBALMAN)/mfdf_user.h.0p

.PHONY: clean, clean-all

clean:
	$(RM) -r user.o libmfdfuser.a manpages/mfdf_user.h.0p

clean-all: clean
	$(RM) $(GLOBALLIB)/libmfdfuser.a $(GLOBALHDR)/user.h $(GLOBALMAN)/mfdf_user.h.0p.gz

