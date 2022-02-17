obj-m += multi-flow-device-file.o

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

mount:
	insmod multi-flow-device-file.ko

unmount:
	rmmod multi-flow-device-file
