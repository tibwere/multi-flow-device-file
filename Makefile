obj-m += multi-flow-device-file.o

CC            = gcc
IDIR          = ./user/include
CFLAGS        = -I$(IDIR) -Wall -Wextra -fPIC
LOCAL_LIB_DIR = ./user/lib
GLOBAL_PREFIX = /usr/local
LOCAL_SRC     = $(LOCAL_LIB_DIR)/mfdf.c
LOCAL_OBJ     = $(LOCAL_LIB_DIR)/mfdf.o
LOCAL_SO      = $(LOCAL_LIB_DIR)/libmfdf.so
LOCAL_HEADER  = ./user/include/mfdf.h
GLOBAL_SO     = $(GLOBAL_PREFIX)/lib/libmfdf.so
GLOBAL_HEADER = $(GLOBAL_PREFIX)/include/mfdf.h
MODNAME       = multi-flow-device-file

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(CC) -c $(CFLAGS) $(LOCAL_SRC) -o $(LOCAL_OBJ)
	$(CC) -shared -o $(LOCAL_SO) $(LOCAL_OBJ)

install:
	insmod $(MODNAME).ko
	install -m 755 $(LOCAL_HEADER) $(GLOBAL_HEADER)
	install -m 755 $(LOCAL_SO) $(GLOBAL_SO)
	ldconfig $(GLOBAL_PREFIX)/lib

.PHONY: clean clean-all

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	$(RM) $(LOCAL_OBJ) $(LOCAL_SO)

clean-all: clean
	$(RM) $(GLOBAL_SO) $(GLOBAL_HEADER)
	rmmod $(MODNAME)
	ldconfig
