obj-m += mfdf.o

PREFIX  = /usr/local
MODNAME = mfdf

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

mount:
	insmod $(MODNAME).ko
	mkdir -p $(PREFIX)/include/mfdf
	install -m 755 include/ioctl.h $(PREFIX)/include/mfdf/ioctl.h

.PHONY: clean clean-all

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

clean-all: clean
	$(RM) $(PREFIX)/include/mfdf/ioctl.h
	rmmod $(MODNAME)
