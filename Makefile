obj-m += multi-flow-device-file.o

# Variables for testing client
IDIR = ./user/include/
CC = gcc
CFLAGS = -I$(IDIR) -Wall -Wextra
SOURCES = ./user/test.c ./user/lib/mfdf.c
BIN = ./user/tester

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

mount:
	insmod multi-flow-device-file.ko

unmount:
	rmmod multi-flow-device-file

tester:
	$(CC) -o $(BIN) $(SOURCES) $(CFLAGS)

.PHONY: clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm $(BIN)
