obj-m += multi-flow-device-file.o

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc -c ./user/lib/mfdf.c -o ./user/lib/mfdf.o -I./user/include -Wall -Wextra
	ar rcs ./user/lib/libmfdf.a ./user/lib/mfdf.o

install:
	insmod multi-flow-device-file.ko
	install -m 644 ./user/include/mfdf.h /usr/local/include
	install -m 644 ./user/lib/libmfdf.a /usr/local/lib

.PHONY: clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm ./user/lib/libmfdf.a ./user/lib/mfdf.o
	rm /usr/local/lib/libmfdf.a /usr/local/include/mfdf.h
