obj-m += mfdf.o
# CFLAGS_mfdf.o := -DDEBUG

PREFIX  = /usr/local
MODNAME = mfdf
MOUNTED = $(shell /usr/bin/lsmod | /usr/bin/grep $(MODNAME))

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

install:
	insmod $(MODNAME).ko
	mkdir -p $(PREFIX)/include/mfdf
	install -m 644 include/ioctl.h $(PREFIX)/include/mfdf/ioctl.h

.PHONY: clean clean-all

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

clean-all: clean
	$(RM) $(PREFIX)/include/mfdf/ioctl.h
ifneq ($(MOUNTED),)
	rmmod $(MODNAME)
endif
