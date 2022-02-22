obj-m += multi-flow-device-file.o

CC=gcc
IDIR=./user/include
CFLAGS=-I$(IDIR) -Wall -Wextra -fPIC
LIBSRC=./user/lib/mfdf.c
LIBDST=./user/lib/mfdf.o
LOCALSO=./user/lib/libmfdf.so
LOCALHDR=./user/include/mfdf.h
HDRDIR=/usr/local/include
LIBDIR=/usr/local/lib
REMOTESO=$(LIBDIR)/libmfdf.so
REMOTEHDR=$(HDRDIR)/mfdf.h
MODNAME=multi-flow-device-file

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(CC) -c $(CFLAGS) $(LIBSRC) -o $(LIBDST)
	$(CC) -shared -o $(LOCALSO) $(LIBDST)

install:
	insmod $(MODNAME).ko
	install -m 755 $(LOCALHDR) $(HDRDIR)
	install -m 755 $(LOCALSO) $(LIBDIR)
	ldconfig

.PHONY: clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	$(RM) $(LIBDST) $(LOCALSO) $(REMOTESO) $(REMOTEHDR)
	rmmod $(MODNAME)
	ldconfig
