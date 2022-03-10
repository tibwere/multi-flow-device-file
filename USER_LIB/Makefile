CC        = gcc
ARC       = ar rcs
CFLAGS    = -Wall -Wextra
GLOBALLIB = /usr/local/lib/mfdf
GLOBALHDR = /usr/local/include/mfdf
GLOBALMAN = /usr/local/share/man/man0p

build:
	$(CC) -c user.c -o user.o $(CFLAGS)
	$(ARC) libmfdfuser.a user.o

doc:
	pandoc mfdf_user.h.0p.md -s -t man -o mfdf_user.h.0p

install: build doc
	mkdir -p $(GLOBALLIB)
	mkdir -p $(GLOBALMAN)
	install -m 644 user.h $(GLOBALHDR)/user.h
	install -m 755 libmfdfuser.a $(GLOBALLIB)/libmfdfuser.a
	gzip mfdf_user.h.0p
	install -m 644 mfdf_user.h.0p.gz $(GLOBALMAN)/mfdf_user.h.0p.gz

.PHONY: clean, clean-all

clean:
	$(RM) -r user.o libmfdfuser.a mfdf_user.h.0p

clean-all: clean
	$(RM) $(GLOBALLIB)/libmfdfuser.a $(GLOBALHDR)/user.h $(GLOBALMAN)/mfdf_user.h.0p.gz

